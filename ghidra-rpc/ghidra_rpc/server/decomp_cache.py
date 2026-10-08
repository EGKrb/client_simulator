"""Per-program cache of decompiler output.

Agents decompile the same functions over and over (decompile, then
function-diff, then search-decompiled with a slightly different regex...), and
each decompilation costs tens of milliseconds to minutes.  Entries are keyed on
the function entry point and are only valid for one value of
``Program.getModificationNumber()``: any change to the program -- a rename
through ghidra-rpc, an edit in the GUI, a re-analysis -- bumps that number and
drops the whole cache, since a rename or retype in one function can change the
decompiled text of every caller.
"""

from __future__ import annotations

import threading
from collections import OrderedDict

DEFAULT_MAX_ENTRIES = 2048


class DecompileCache:
    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self._max = max(1, max_entries)
        self._data: OrderedDict[str, dict] = OrderedDict()
        self._modnum: object = None
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def _sync(self, modnum) -> None:
        if modnum != self._modnum:
            self._data.clear()
            self._modnum = modnum

    def get(self, modnum, key: str) -> dict | None:
        with self._lock:
            self._sync(modnum)
            value = self._data.get(key)
            if value is None:
                self.misses += 1
                return None
            self._data.move_to_end(key)
            self.hits += 1
            return value

    def put(self, modnum, key: str, value: dict) -> None:
        with self._lock:
            self._sync(modnum)
            self._data[key] = value
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self._modnum = None

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def stats(self) -> dict:
        with self._lock:
            return {"entries": len(self._data), "hits": self.hits, "misses": self.misses}
