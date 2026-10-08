"""Reader/writer dispatch, request cancellation and request-size limits,
exercised through a real server socket with fake handlers (no Ghidra)."""

from __future__ import annotations

import json
import threading
import time
import uuid

import pytest

from ghidra_rpc import transport
from ghidra_rpc.server import cancel
from ghidra_rpc.server.rwlock import RWLock


def _connect_and_send(sock_path, cmd, args=None, req_id=None):
    s, token = transport.connect(sock_path, 10)
    request = {"id": req_id or str(uuid.uuid4()), "cmd": cmd, "args": args or {}}
    if token is not None:
        request["auth"] = token
    s.sendall((json.dumps(request) + "\n").encode())
    return s


def _read_response(s):
    buf = b""
    try:
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    return json.loads(buf.decode().strip())


def _request(sock_path, cmd, args=None, req_id=None):
    return _read_response(_connect_and_send(sock_path, cmd, args, req_id))


def _wait_for(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


@pytest.fixture
def server(short_tmp_path):
    from unittest.mock import MagicMock

    from ghidra_rpc.server import main as server_main
    from ghidra_rpc.session import Session

    server_main._HANDLERS.clear()
    sock_path = short_tmp_path / "c.sock"
    session = Session(mode="headless", project_gpr=short_tmp_path / "c.gpr",
                      socket_path=sock_path)
    thread = threading.Thread(target=server_main.run_server,
                              args=(session, MagicMock()), daemon=True)
    thread.start()
    assert _wait_for(lambda: _try_ping(sock_path)), "server did not start"
    yield server_main, sock_path
    try:
        _request(sock_path, "stop")
    except OSError:
        pass
    thread.join(timeout=5)
    server_main._HANDLERS.clear()


def _try_ping(sock_path):
    try:
        return _request(sock_path, "ping").get("ok")
    except OSError:
        return False


class TestRWLock:
    def test_readers_share(self):
        lock = RWLock()
        inside = threading.Barrier(2, timeout=2)

        def reader():
            with lock.read():
                inside.wait()  # both readers must be inside at once

        threads = [threading.Thread(target=reader) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(3)
        assert not inside.broken

    def test_writer_excludes_readers(self):
        lock = RWLock()
        events = []
        with lock.write():
            t = threading.Thread(target=lambda: (lock.read().__enter__(), events.append("read")))
            t.start()
            time.sleep(0.1)
            assert events == []
        t.join(2)
        assert events == ["read"]

    def test_waiting_writer_blocks_new_readers(self):
        lock = RWLock()
        order = []
        first_reader = lock.read()
        first_reader.__enter__()

        def writer():
            with lock.write():
                order.append("write")

        def late_reader():
            with lock.read():
                order.append("read")

        w = threading.Thread(target=writer)
        w.start()
        time.sleep(0.1)  # writer is now waiting
        r = threading.Thread(target=late_reader)
        r.start()
        time.sleep(0.1)
        first_reader.__exit__(None, None, None)
        w.join(2)
        r.join(2)
        assert order == ["write", "read"]


class TestDispatch:
    def test_read_only_handlers_run_concurrently(self, server):
        server_main, sock = server
        barrier = threading.Barrier(2, timeout=3)

        def slow_read(ctx, args):
            barrier.wait()  # deadlocks (BrokenBarrierError) if serialised
            return {"ok": True}

        server_main.register_handler("decompile", slow_read)
        results = []
        threads = [threading.Thread(target=lambda: results.append(_request(sock, "decompile")))
                   for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        assert [r["ok"] for r in results] == [True, True]

    def test_write_handlers_are_exclusive(self, server):
        server_main, sock = server
        active = []
        overlap = []

        def write(ctx, args):
            active.append(1)
            if len(active) > 1:
                overlap.append(True)
            time.sleep(0.1)
            active.pop()
            return {}

        server_main.register_handler("rename_function", write)
        threads = [threading.Thread(target=_request, args=(sock, "rename_function"))
                   for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        assert overlap == []

    def test_unlisted_handlers_default_to_exclusive(self):
        from ghidra_rpc.server.main import is_read_only
        assert is_read_only("decompile")
        assert not is_read_only("some_future_command")
        assert not is_read_only("rename_function")


class TestCancellation:
    @staticmethod
    def _sweep_handler(started, finished):
        def handler(ctx, args):
            started.set()
            try:
                for _ in range(500):
                    cancel.check_cancelled()
                    time.sleep(0.01)
            except cancel.Cancelled:
                finished.append("cancelled")
                raise
            finished.append("completed")
            return {}
        return handler

    def test_client_disconnect_cancels_request(self, server):
        server_main, sock = server
        started, finished = threading.Event(), []
        server_main.register_handler("decompile_all", self._sweep_handler(started, finished))
        s = _connect_and_send(sock, "decompile_all")
        assert started.wait(3)
        s.close()  # client gives up
        assert _wait_for(lambda: finished, timeout=5)
        assert finished == ["cancelled"]

    def test_cancel_command_by_id(self, server):
        server_main, sock = server
        started, finished = threading.Event(), []
        server_main.register_handler("decompile_all", self._sweep_handler(started, finished))
        s = _connect_and_send(sock, "decompile_all", req_id="sweep-1")
        assert started.wait(3)

        ping = _request(sock, "ping")
        assert [r["id"] for r in ping["result"]["active_requests"]] == ["sweep-1"]

        resp = _request(sock, "cancel", {"id": "sweep-1"})
        assert resp["result"]["cancelled"] == [{"id": "sweep-1", "cmd": "decompile_all"}]
        reply = _read_response(s)
        assert reply["ok"] is False and reply["error"] == "Cancelled"
        assert finished == ["cancelled"]

    def test_queued_request_cancelled_before_running(self, server):
        server_main, sock = server
        release = threading.Event()
        ran = []

        def blocking_write(ctx, args):
            release.wait(5)
            return {}

        def second(ctx, args):
            ran.append(True)
            return {}

        server_main.register_handler("save", blocking_write)
        server_main.register_handler("set_comment", second)
        first = _connect_and_send(sock, "save")
        assert _wait_for(lambda: cancel.active())
        queued = _connect_and_send(sock, "set_comment", req_id="queued")
        assert _wait_for(lambda: any(s.id == "queued" for s in cancel.active()))
        _request(sock, "cancel", {"id": "queued"})
        release.set()
        assert _read_response(queued)["error"] == "Cancelled"
        assert _read_response(first)["ok"] is True
        assert ran == []

    def test_task_monitor_falls_back_without_ghidra(self, monkeypatch):
        import sys
        import types

        dummy = object()
        mod = types.ModuleType("ghidra.util.task")
        mod.TaskMonitor = types.SimpleNamespace(DUMMY=dummy)
        monkeypatch.setitem(sys.modules, "ghidra", types.ModuleType("ghidra"))
        monkeypatch.setitem(sys.modules, "ghidra.util", types.ModuleType("ghidra.util"))
        monkeypatch.setitem(sys.modules, "ghidra.util.task", mod)
        assert cancel.task_monitor() is dummy

    def test_monitor_cancelled_with_request(self, monkeypatch):
        import sys
        import types

        class FakeMonitor:
            def __init__(self, enabled):
                self.cancelled = False

            def cancel(self):
                self.cancelled = True

        mod = types.ModuleType("ghidra.util.task")
        mod.TaskMonitor = types.SimpleNamespace(DUMMY=object())
        mod.TaskMonitorAdapter = FakeMonitor
        monkeypatch.setitem(sys.modules, "ghidra", types.ModuleType("ghidra"))
        monkeypatch.setitem(sys.modules, "ghidra.util", types.ModuleType("ghidra.util"))
        monkeypatch.setitem(sys.modules, "ghidra.util.task", mod)

        state = cancel.begin("r1", "decompile")
        try:
            monitor = cancel.task_monitor()
            assert not monitor.cancelled
            state.cancel()
            assert monitor.cancelled
            # A monitor created after cancellation starts out cancelled.
            assert cancel.task_monitor().cancelled
        finally:
            cancel.end(state)


class TestRequestLimits:
    def test_oversized_request_rejected(self, server, monkeypatch):
        server_main, sock = server
        monkeypatch.setattr(server_main, "MAX_REQUEST_BYTES", 1000)
        s, token = transport.connect(sock, 5)
        s.sendall(b"x" * 5000)  # no newline, over the limit
        resp = _read_response(s)
        assert resp["error"] == "RequestTooLarge"
