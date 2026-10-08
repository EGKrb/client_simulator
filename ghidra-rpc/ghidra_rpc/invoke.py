"""Run ghidra-rpc CLI commands in-process and capture their JSON envelope.

Shared by ``ghidra-rpc batch`` and the MCP server.  Going through the Click
commands (rather than building RPC requests directly) keeps a single source of
truth for argument names, defaults, validation and per-command socket
timeouts: a command added to cli.py is automatically available to both.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shlex

import click

# Commands that manage daemon lifecycle or would recurse; never run in-process.
EXCLUDED_COMMANDS = frozenset({"start", "stop", "restart", "batch", "mcp"})


def _capture_stream() -> io.TextIOWrapper:
    # A real text wrapper over bytes, like click.testing.CliRunner uses:
    # click.echo() special-cases some stream types on Windows.
    return io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="replace")


def _read(stream: io.TextIOWrapper) -> str:
    stream.flush()
    return stream.buffer.getvalue().decode("utf-8", errors="replace")


def run_cli(argv: list[str], *, project: str | None = None) -> dict:
    """Run one CLI command and return its JSON envelope as a dict.

    *project*, when given, is used as ``GHIDRA_RPC_PROJECT`` for the call
    (an explicit ``--project`` in *argv* still wins).
    """
    from ghidra_rpc.cli import cli

    if not argv:
        return {"ok": False, "error": "UsageError", "message": "Empty command"}
    if argv[0] in EXCLUDED_COMMANDS:
        return {"ok": False, "error": "UsageError",
                "message": f"'{argv[0]}' cannot be run from batch/MCP"}

    out, err = _capture_stream(), _capture_stream()
    saved_env = os.environ.get("GHIDRA_RPC_PROJECT")
    exit_code = 0
    try:
        if project:
            os.environ["GHIDRA_RPC_PROJECT"] = project
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                cli.main(args=list(argv), prog_name="ghidra-rpc", standalone_mode=False)
            except SystemExit as e:
                exit_code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
            except click.ClickException as e:
                return {"ok": False, "error": type(e).__name__, "message": e.format_message()}
            except click.exceptions.Abort:
                return {"ok": False, "error": "Aborted", "message": "Aborted"}
            except Exception as e:  # noqa: BLE001 - never let one command kill the caller
                return {"ok": False, "error": type(e).__name__, "message": str(e)}
    finally:
        if project:
            if saved_env is None:
                os.environ.pop("GHIDRA_RPC_PROJECT", None)
            else:
                os.environ["GHIDRA_RPC_PROJECT"] = saved_env

    stdout, stderr = _read(out).strip(), _read(err).strip()
    try:
        envelope = json.loads(stdout) if stdout else None
    except json.JSONDecodeError:
        envelope = None
    if not isinstance(envelope, dict):
        return {
            "ok": False,
            "error": "CommandFailed",
            "message": (stderr or stdout or f"exit code {exit_code}"),
        }
    if stderr:
        # e.g. the "verified=false" warning _rpc_command prints on stderr
        envelope.setdefault("warnings", []).append(stderr)
    return envelope


def _normalise(item) -> list[str]:
    if isinstance(item, str):
        return shlex.split(item)
    if isinstance(item, list) and all(isinstance(a, (str, int, float)) for a in item):
        return [str(a) for a in item]
    raise ValueError(
        f"Invalid batch item {item!r}: use an argv list like "
        '["decompile", "ls", "main"] or a command string like "decompile ls main"'
    )


def run_batch(commands: list, *, project: str | None = None,
              stop_on_error: bool = False) -> dict:
    argvs = [_normalise(c) for c in commands]  # validate everything up front
    results = []
    for index, argv in enumerate(argvs):
        response = run_cli(argv, project=project)
        ok = bool(response.get("ok"))
        results.append({"index": index, "argv": argv, "ok": ok, "response": response})
        if stop_on_error and not ok:
            break
    ok_count = sum(1 for r in results if r["ok"])
    return {
        "results": results,
        "count": len(results),
        "ok_count": ok_count,
        "error_count": len(results) - ok_count,
        "skipped": len(argvs) - len(results),
    }
