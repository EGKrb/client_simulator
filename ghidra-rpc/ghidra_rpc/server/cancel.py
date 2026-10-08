"""Per-request cancellation for long-running daemon commands.

Every dispatched request gets a ``RequestState`` bound to the handler thread.
A request is cancelled when its client disconnects (e.g. the CLI's socket
timeout fired, or the user hit Ctrl+C) or when another client sends the
built-in ``cancel`` command.

Handlers cooperate in two ways:

* ``task_monitor()`` returns a Ghidra ``TaskMonitor`` that is cancelled along
  with the request -- pass it to ``decompileFunction`` & co. instead of
  ``TaskMonitor.DUMMY`` so an in-flight decompilation aborts promptly.
* ``check_cancelled()`` raises ``Cancelled`` between work items in sweeps
  (decompile_all, search_decompiled).

Before this, a timed-out client left the daemon grinding on the abandoned
request -- still holding the handler lock, so every following command queued
behind work nobody would ever read.
"""

from __future__ import annotations

import threading
import time


class Cancelled(Exception):
    """Raised inside a handler when its request has been cancelled."""


class RequestState:
    def __init__(self, req_id: str, cmd: str) -> None:
        self.id = req_id
        self.cmd = cmd
        self.started = time.time()
        self.reason: str | None = None
        self._event = threading.Event()
        self._monitors: list = []
        self._lock = threading.Lock()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self, reason: str = "cancelled") -> None:
        with self._lock:
            if self._event.is_set():
                return
            self.reason = reason
            self._event.set()
            monitors = list(self._monitors)
        for m in monitors:
            try:
                m.cancel()
            except Exception:  # noqa: BLE001 - best effort
                pass

    def add_monitor(self, monitor) -> None:
        with self._lock:
            self._monitors.append(monitor)
            already = self._event.is_set()
        if already:
            try:
                monitor.cancel()
            except Exception:  # noqa: BLE001
                pass


_local = threading.local()
_active: dict[str, RequestState] = {}
_active_lock = threading.Lock()


def begin(req_id: str, cmd: str) -> RequestState:
    state = RequestState(req_id, cmd)
    with _active_lock:
        _active[req_id] = state
    _local.state = state
    return state


def end(state: RequestState) -> None:
    with _active_lock:
        if _active.get(state.id) is state:
            del _active[state.id]
    if getattr(_local, "state", None) is state:
        _local.state = None


def current() -> RequestState | None:
    return getattr(_local, "state", None)


def bind(state: RequestState | None) -> None:
    """Attach *state* to the calling thread (for worker threads of a sweep)."""
    _local.state = state


def active() -> list[RequestState]:
    with _active_lock:
        return list(_active.values())


def cancel_requests(req_id: str | None = None) -> list[dict]:
    """Cancel one request by id, or every active request when *req_id* is None."""
    with _active_lock:
        targets = [s for s in _active.values() if req_id is None or s.id == req_id]
    for s in targets:
        s.cancel("cancelled by 'cancel' command")
    return [{"id": s.id, "cmd": s.cmd} for s in targets]


def check_cancelled() -> None:
    state = current()
    if state is not None and state.cancelled:
        raise Cancelled(f"Request {state.id} ({state.cmd}) {state.reason}")


def task_monitor():
    """Return a cancellable Ghidra TaskMonitor tied to the current request.

    Falls back to ``TaskMonitor.DUMMY`` when a cancellable monitor cannot be
    constructed (e.g. under the unit-test stubs of ``ghidra.util.task``).
    """
    from ghidra.util.task import TaskMonitor

    try:
        from ghidra.util.task import TaskMonitorAdapter
        monitor = TaskMonitorAdapter(True)
    except Exception:  # noqa: BLE001
        return TaskMonitor.DUMMY

    state = current()
    if state is not None:
        state.add_monitor(monitor)
    return monitor
