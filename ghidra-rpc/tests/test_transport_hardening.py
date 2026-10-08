"""POSIX socket hardening and client timeout reporting."""

from __future__ import annotations

import os
import socket
import stat
import threading

import pytest

from ghidra_rpc import transport

posix_only = pytest.mark.skipif(os.name == "nt", reason="AF_UNIX transport is POSIX-only")


@posix_only
def test_socket_created_owner_only(short_tmp_path):
    path = short_tmp_path / "s.sock"
    server, _ = transport.listen(path)
    try:
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    finally:
        server.close()
        transport.remove_endpoint(path)


@posix_only
def test_connect_refuses_non_socket(short_tmp_path):
    path = short_tmp_path / "fake.sock"
    path.write_text("not a socket")
    with pytest.raises(OSError, match="not a socket"):
        transport.connect(path, 1)


@posix_only
def test_connect_refuses_foreign_owner(short_tmp_path, monkeypatch):
    path = short_tmp_path / "s.sock"
    server, _ = transport.listen(path)
    try:
        monkeypatch.setattr(os, "getuid", lambda: os.stat(path).st_uid + 1)
        with pytest.raises(OSError, match="owned by uid"):
            transport.connect(path, 1)
        with pytest.raises(PermissionError):
            transport.remove_endpoint(path)
    finally:
        monkeypatch.undo()
        server.close()
        transport.remove_endpoint(path)


def test_remove_endpoint_missing_is_noop(tmp_path):
    transport.remove_endpoint(tmp_path / "absent.sock")


def test_client_timeout_is_a_clear_error(short_tmp_path):
    """A daemon that never answers yields DaemonError('Timeout'), not a bare
    TimeoutError, and the client closes its socket (which cancels the request)."""
    from ghidra_rpc.client import DaemonError, send_request

    path = short_tmp_path / "t.sock"
    server, _ = transport.listen(path)
    closed = threading.Event()

    def accept_and_hang():
        conn, _ = server.accept()
        conn.settimeout(5)
        try:
            while conn.recv(65536):
                pass
        except (socket.timeout, OSError):
            pass
        closed.set()
        conn.close()

    t = threading.Thread(target=accept_and_hang, daemon=True)
    t.start()
    try:
        with pytest.raises(DaemonError) as exc:
            send_request(path, "decompile", {}, socket_timeout=0.3)
        assert exc.value.error == "Timeout"
        assert exc.value.full_response["ok"] is False
        assert closed.wait(3), "client did not close its socket"
    finally:
        server.close()
        transport.remove_endpoint(path)
