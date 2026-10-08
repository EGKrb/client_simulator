"""Local transport server for ghidra-rpc.

Accepts newline-delimited JSON requests and dispatches to tool handlers.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import select
import socket
import sys
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any

from ghidra_rpc.session import Session
from ghidra_rpc import transport
from ghidra_rpc.server import cancel
from ghidra_rpc.server.rwlock import RWLock

logger = logging.getLogger("ghidra-rpc.server")

# Command registry: maps command name -> handler(ctx, args) -> result dict
_HANDLERS: dict[str, Any] = {}

# Handlers that never mutate program state, the project, or the daemon's set of
# loaded programs.  They run concurrently under the shared side of _RW_LOCK.
# Anything NOT listed here -- including every handler registered in future
# without updating this set -- runs exclusively, which is always safe.
READ_ONLY_COMMANDS: frozenset[str] = frozenset({
    "basic_blocks", "decompile", "decompile_all", "disassemble", "exports",
    "find_bytes", "function_diff", "functions", "functions_by_tag",
    "get_processor_context", "imports", "list_binaries", "list_bookmarks",
    "list_calling_conventions", "list_data_types", "list_equates",
    "list_labels", "list_namespaces", "list_project_programs", "list_tags",
    "list_vtable", "memory_map", "metadata", "pcode", "read_bytes",
    "read_pointers", "relocations", "search_decompiled", "strings", "symbols",
    "xrefs_from", "xrefs_to",
})

# Ghidra's transaction machinery is not safe for concurrent writes from
# different threads -- overlapping startTransaction/endTransaction calls on the
# same program cause "No transaction is open" or "Transaction not found"
# errors.  Writes therefore take this lock exclusively.  Reads share it, so a
# long decompile-all no longer blocks a quick `strings` from another client
# (it still blocks writes, which is what keeps its snapshot consistent).
_RW_LOCK = RWLock()

# Hard cap on a single request line.  Large batch-rename payloads are a few
# hundred KB; anything near this is a runaway or hostile client.
MAX_REQUEST_BYTES = 32 * 1024 * 1024

# How often the accept loop flushes dirty programs in deferred-save mode.
_DEFERRED_FLUSH_INTERVAL = 30.0


def register_handler(cmd: str, handler):
    """Register a command handler function."""
    _HANDLERS[cmd] = handler


def is_read_only(cmd: str) -> bool:
    return cmd in READ_ONLY_COMMANDS


def _send(conn: socket.socket, response: dict) -> None:
    conn.sendall((json.dumps(response) + "\n").encode())


def _watch_disconnect(conn: socket.socket, state, done: threading.Event) -> None:
    """Cancel *state* if the client hangs up before the handler finishes.

    The client sends exactly one request line and then only reads, so the
    socket becoming readable with a zero-byte peek means EOF: it gave up
    (socket timeout, Ctrl+C, killed agent).
    """
    while not done.is_set():
        try:
            readable, _, _ = select.select([conn], [], [], 0.5)
        except (OSError, ValueError):
            return
        if not readable or done.is_set():
            continue
        try:
            data = conn.recv(1, socket.MSG_PEEK)
        except BlockingIOError:
            continue
        except OSError:
            data = b""
        if data == b"":
            state.cancel("cancelled: client disconnected")
        # Either way stop watching: EOF is final, and unexpected extra bytes
        # would otherwise make select() spin.
        return


def _dispatch(cmd: str, args: dict, ctx: Any) -> dict:
    """Run a registered handler under the appropriate lock; return the result."""
    handler = _HANDLERS[cmd]
    lock = _RW_LOCK.read() if is_read_only(cmd) else _RW_LOCK.write()
    with lock:
        cancel.check_cancelled()  # may have been cancelled while queued
        return handler(ctx, args)


def _handle_connection(
    conn: socket.socket,
    ctx: Any,
    shutdown_event: threading.Event,
    session: Session,
    auth_token: str | None,
):
    """Handle a single client connection: read request, dispatch, send response."""
    try:
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
            if len(buf) > MAX_REQUEST_BYTES:
                _send(conn, {
                    "id": None,
                    "ok": False,
                    "error": "RequestTooLarge",
                    "message": f"Request exceeds {MAX_REQUEST_BYTES} bytes",
                })
                return

        line = buf.split(b"\n", 1)[0].decode("utf-8").strip()
        if not line:
            return

        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            _send(conn, {
                "id": None,
                "ok": False,
                "error": "InvalidJSON",
                "message": f"Malformed JSON: {e}",
            })
            return

        req_id = request.get("id", str(uuid.uuid4()))
        cmd = request.get("cmd", "")
        args = request.get("args", {})

        request_token = request.get("auth")
        if auth_token is not None and (
            not isinstance(request_token, str)
            or not secrets.compare_digest(request_token, auth_token)
        ):
            _send(conn, {
                "id": req_id,
                "ok": False,
                "error": "Unauthorized",
                "message": "Invalid daemon authentication token",
            })
            return

        # Built-in commands
        if cmd == "ping":
            response = {
                "id": req_id,
                "ok": True,
                "result": {
                    "status":      "alive",
                    "project_gpr": str(session.project_gpr),
                    "mode":        session.mode,
                    "pid":         os.getpid(),
                    "active_requests": [
                        {"id": s.id, "cmd": s.cmd,
                         "elapsed": round(time.time() - s.started, 1)}
                        for s in cancel.active()
                    ],
                },
            }
        elif cmd == "cancel":
            target = args.get("id") if isinstance(args, dict) else None
            cancelled = cancel.cancel_requests(target)
            response = {"id": req_id, "ok": True,
                        "result": {"cancelled": cancelled, "count": len(cancelled)}}
        elif cmd == "stop":
            _send(conn, {"id": req_id, "ok": True, "result": {"status": "stopping"}})
            shutdown_event.set()
            return
        elif cmd in _HANDLERS:
            state = cancel.begin(req_id, cmd)
            done = threading.Event()
            watcher = threading.Thread(
                target=_watch_disconnect, args=(conn, state, done), daemon=True,
            )
            watcher.start()
            try:
                result = _dispatch(cmd, args, ctx)
                if state.cancelled:
                    raise cancel.Cancelled(f"Request {req_id} ({cmd}) {state.reason}")
                response = {"id": req_id, "ok": True, "result": result}
            except Exception as e:
                if state.cancelled and not isinstance(e, cancel.Cancelled):
                    # A cancelled TaskMonitor surfaces as whatever Ghidra
                    # raises (CancelledException, an error message, ...).
                    e = cancel.Cancelled(f"Request {req_id} ({cmd}) {state.reason}")
                response = {
                    "id": req_id,
                    "ok": False,
                    "error": type(e).__name__,
                    "message": str(e),
                }
                if isinstance(e, cancel.Cancelled):
                    logger.info("Request %s (%s) %s", req_id, cmd, state.reason)
                else:
                    logger.error(f"Error handling '{cmd}': {e}", exc_info=True)
            finally:
                done.set()
                watcher.join(timeout=1.0)
                cancel.end(state)
        else:
            response = {
                "id": req_id,
                "ok": False,
                "error": "UnknownCommand",
                "message": f"Unknown command: {cmd}. Available: {sorted(list(_HANDLERS.keys()) + ['cancel', 'ping', 'stop'])}",
            }

        _send(conn, response)

    except Exception as e:
        logger.error(f"Connection handler error: {e}", exc_info=True)
    finally:
        conn.close()


def _flush_deferred(ctx: Any) -> None:
    try:
        with _RW_LOCK.write():
            ctx.flush_dirty()
    except Exception:  # noqa: BLE001
        logger.warning("Deferred save flush failed", exc_info=True)


def run_server(session: Session, ctx: Any) -> None:
    """Run the RPC server on the platform's local transport.

    Blocks until a 'stop' command is received or the process is interrupted.
    """
    # Configure logging so tool handlers' messages are visible
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    # Register tool handlers
    from ghidra_rpc.server.tools import register_all_tools
    register_all_tools()

    sock_path = session.socket_path

    server_sock, auth_token = transport.listen(sock_path)
    server_sock.settimeout(1.0)  # Allow periodic checking of shutdown event

    shutdown_event = threading.Event()

    logger.info(f"ghidra-rpc server listening on {sock_path}")

    deferred = getattr(ctx, "save_mode", None) == "deferred"
    last_flush = time.time()
    flusher: threading.Thread | None = None

    try:
        while not shutdown_event.is_set():
            if deferred and time.time() - last_flush >= _DEFERRED_FLUSH_INTERVAL:
                last_flush = time.time()
                if flusher is None or not flusher.is_alive():
                    flusher = threading.Thread(
                        target=_flush_deferred, args=(ctx,), daemon=True,
                        name="ghidra-rpc-flush",
                    )
                    flusher.start()
            try:
                conn, _ = server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            # Handle each connection in a thread so the server stays responsive
            t = threading.Thread(
                target=_handle_connection,
                args=(conn, ctx, shutdown_event, session, auth_token),
                daemon=True,
            )
            t.start()
    finally:
        server_sock.close()
        transport.remove_endpoint(sock_path)
        logger.info("Server shut down.")
