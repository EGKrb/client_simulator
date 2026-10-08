"""Reader/writer lock used to serialise daemon command handlers.

Read-only handlers (decompile, xrefs, strings, ...) may run concurrently;
write handlers (anything that opens a Ghidra transaction, loads a program or
saves) run exclusively.  The lock is writer-preferring: once a writer is
waiting, new readers queue behind it, so a steady stream of reads cannot
starve a rename.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager


class RWLock:
    def __init__(self) -> None:
        self._cond = threading.Condition(threading.Lock())
        self._readers = 0
        self._writer = False
        self._writers_waiting = 0

    @contextmanager
    def read(self):
        with self._cond:
            while self._writer or self._writers_waiting:
                self._cond.wait()
            self._readers += 1
        try:
            yield
        finally:
            with self._cond:
                self._readers -= 1
                if self._readers == 0:
                    self._cond.notify_all()

    @contextmanager
    def write(self):
        with self._cond:
            self._writers_waiting += 1
            try:
                while self._writer or self._readers:
                    self._cond.wait()
            finally:
                self._writers_waiting -= 1
            self._writer = True
        try:
            yield
        finally:
            with self._cond:
                self._writer = False
                self._cond.notify_all()
