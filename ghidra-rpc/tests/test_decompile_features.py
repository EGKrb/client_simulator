"""Decompile cache, output truncation, parallel decompile-all and deferred
saving, against fake Ghidra objects (no JVM)."""

from __future__ import annotations

import sys
import threading
import time
import types
from contextlib import contextmanager

import pytest

from ghidra_rpc.server import cancel
from ghidra_rpc.server.context import ProgramInfo, _SaveModeMixin
from ghidra_rpc.server.decomp_cache import DecompileCache


@pytest.fixture(autouse=True)
def fake_ghidra_util_task(monkeypatch):
    mod = types.ModuleType("ghidra.util.task")
    mod.TaskMonitor = types.SimpleNamespace(DUMMY=object())
    monkeypatch.setitem(sys.modules, "ghidra", types.ModuleType("ghidra"))
    monkeypatch.setitem(sys.modules, "ghidra.util", types.ModuleType("ghidra.util"))
    monkeypatch.setitem(sys.modules, "ghidra.util.task", mod)


class Func:
    def __init__(self, name, addr, c_code="", external=False, thunk=False):
        self._name, self._addr, self.c_code = name, addr, c_code
        self._external, self._thunk = external, thunk

    def getName(self):
        return self._name

    def getEntryPoint(self):
        return self._addr

    def getSignature(self):
        return f"void {self._name}(void)"

    def isExternal(self):
        return self._external

    def isThunk(self):
        return self._thunk

    def getSymbol(self):
        return types.SimpleNamespace(getName=lambda qualified=False: self._name)


class Result:
    def __init__(self, func, error=""):
        self.func, self.error = func, error

    def getErrorMessage(self):
        return self.error

    def getDecompiledFunction(self):
        if self.error:
            return None
        return types.SimpleNamespace(getC=lambda: self.func.c_code,
                                     getSignature=lambda: self.func.getSignature())


class Pool:
    """Counts decompilations and tracks peak concurrency."""

    def __init__(self, size=1, delay=0.0, fail=()):
        self.size, self.delay, self.fail = size, delay, set(fail)
        self.calls = 0
        self.active = 0
        self.peak = 0
        self._lock = threading.Lock()

    @contextmanager
    def acquire(self):
        pool = self

        class Decompiler:
            def decompileFunction(self, func, timeout, monitor):
                with pool._lock:
                    pool.calls += 1
                    pool.active += 1
                    pool.peak = max(pool.peak, pool.active)
                time.sleep(pool.delay)
                with pool._lock:
                    pool.active -= 1
                return Result(func, "boom" if func.getName() in pool.fail else "")

        yield Decompiler()


class Program:
    def __init__(self, funcs):
        self.funcs = funcs
        self.modnum = 1

    def getModificationNumber(self):
        return self.modnum

    def getFunctionManager(self):
        return types.SimpleNamespace(getFunctions=lambda forward: list(self.funcs))


def make_pi(funcs, pool=None):
    return ProgramInfo(name="bin", program=Program(funcs), flat_api=None,
                       decompiler_pool=pool or Pool(), metadata={})


def make_ctx(pi):
    return types.SimpleNamespace(get_program=lambda binary: pi)


class TestDecompileCache:
    def test_lru_eviction(self):
        cache = DecompileCache(max_entries=2)
        for key in "abc":
            cache.put(1, key, {"k": key})
        assert cache.get(1, "a") is None
        assert cache.get(1, "c") == {"k": "c"}

    def test_modification_number_change_drops_everything(self):
        cache = DecompileCache()
        cache.put(1, "a", {"k": 1})
        assert cache.get(2, "a") is None
        assert len(cache) == 0

    def test_decompile_function_hits_cache_until_program_changes(self):
        from ghidra_rpc.server.tools.decompiler import decompile_function

        f = Func("main", "00001000", "int main() {}")
        pi = make_pi([f])
        first = decompile_function(pi, f, 30)
        second = decompile_function(pi, f, 30)
        assert (first["cached"], second["cached"]) == (False, True)
        assert second["c_code"] == "int main() {}"
        assert pi.decompiler_pool.calls == 1

        pi.program.modnum += 1  # e.g. a rename anywhere in the program
        assert decompile_function(pi, f, 30)["cached"] is False
        assert pi.decompiler_pool.calls == 2

    def test_errors_are_not_cached(self):
        from ghidra_rpc.server.tools.decompiler import decompile_function

        f = Func("bad", "00001000")
        pi = make_pi([f], Pool(fail={"bad"}))
        decompile_function(pi, f, 30)
        decompile_function(pi, f, 30)
        assert pi.decompiler_pool.calls == 2


class TestDecompileHandler:
    def _decompile(self, pi, **args):
        from ghidra_rpc.server.tools import decompiler
        pi.program.getFunctionManager = None  # resolution is patched below
        return decompiler._handle_decompile(make_ctx(pi), {"binary": "bin", **args})

    def test_max_chars_truncates(self, monkeypatch):
        from ghidra_rpc.server.tools import decompiler
        f = Func("main", "00001000", "x" * 100)
        monkeypatch.setattr(decompiler, "_resolve_function", lambda pi, name: (f, "exact"))
        out = self._decompile(make_pi([f]), func="main", max_chars=10)
        assert out["c_code"] == "x" * 10
        assert out["truncated"] is True and out["c_code_length"] == 100

    def test_partial_resolution_is_flagged(self, monkeypatch):
        from ghidra_rpc.server.tools import decompiler
        f = Func("_init_helper", "00001000", "void f() {}")
        monkeypatch.setattr(decompiler, "_resolve_function", lambda pi, name: (f, "partial"))
        out = self._decompile(make_pi([f]), func="init")
        assert out["resolved_by"] == "partial"
        assert "_init_helper" in out["warning"]


class TestDecompileAll:
    def _run(self, pi, **args):
        from ghidra_rpc.server.tools.version_tracking import _handle_decompile_all
        return _handle_decompile_all(make_ctx(pi), {"binary": "bin", **args})

    def test_parallel_and_ordered(self):
        funcs = [Func(f"f{i}", f"{i:08x}", f"code{i}") for i in range(12)]
        pool = Pool(size=4, delay=0.05)
        out = self._run(make_pi(funcs, pool))
        assert [f["name"] for f in out["functions"]] == [f"f{i}" for i in range(12)]
        assert out["errors"] == 0 and out["total"] == 12
        assert pool.peak > 1

    def test_skips_external_and_thunks_and_counts_errors(self):
        funcs = [
            Func("ext", "1", external=True),
            Func("thunk", "2", thunk=True),
            Func("ok", "3", "c"),
            Func("bad", "4"),
        ]
        out = self._run(make_pi(funcs, Pool(fail={"bad"})))
        assert [f["name"] for f in out["functions"]] == ["ok", "bad"]
        assert out["errors"] == 1
        assert out["functions"][1]["c_code"] is None

    def test_max_chars_per_function(self):
        out = self._run(make_pi([Func("f", "1", "y" * 50)]), max_chars=5)
        assert out["functions"][0]["c_code"] == "yyyyy"
        assert out["functions"][0]["truncated"] is True

    def test_cancellation_stops_sweep(self):
        funcs = [Func(f"f{i}", str(i), "c") for i in range(200)]
        pool = Pool(size=2, delay=0.01)
        state = cancel.begin("r", "decompile_all")
        try:
            threading.Timer(0.1, state.cancel).start()
            with pytest.raises(cancel.Cancelled):
                self._run(make_pi(funcs, pool))
        finally:
            cancel.end(state)
        assert pool.calls < 200


class TestSearchDecompiledParallel:
    def test_parallel_search_keeps_order_and_limit(self):
        from ghidra_rpc.server.tools.decompiler import _handle_search_decompiled
        funcs = [Func(f"f{i}", str(i), "target();" if i % 2 else "none();") for i in range(20)]
        pool = Pool(size=4, delay=0.02)
        out = _handle_search_decompiled(make_ctx(make_pi(funcs, pool)),
                                        {"binary": "bin", "pattern": "target", "limit": 3})
        assert [m["function"] for m in out["matches"]] == ["f1", "f3", "f5"]
        assert out["truncated"] is True
        assert pool.peak > 1


class FakeContext(_SaveModeMixin):
    def __init__(self, mode):
        self._init_save_mode(types.SimpleNamespace(save_mode=mode))
        self.saved = []

    def _save_now(self, pi):
        self.saved.append(pi.name)


class TestSaveModes:
    def test_auto_saves_immediately(self):
        ctx = FakeContext("auto")
        ctx.save_program(make_pi([]))
        assert ctx.saved == ["bin"]

    def test_deferred_marks_dirty_until_flush(self):
        ctx = FakeContext("deferred")
        pi = make_pi([])
        ctx.save_program(pi)
        ctx.save_program(pi)
        assert ctx.saved == [] and ctx.dirty_programs() == ["bin"]
        assert ctx.flush_dirty() == ["bin"]
        assert ctx.saved == ["bin"] and ctx.dirty_programs() == []

    def test_force_saves_even_when_deferred(self):
        ctx = FakeContext("deferred")
        pi = make_pi([])
        ctx.save_program(pi)
        ctx.save_program(pi, force=True)
        assert ctx.saved == ["bin"] and ctx.dirty_programs() == []

    def test_failed_flush_keeps_program_dirty(self):
        ctx = FakeContext("deferred")

        def fail(pi):
            raise RuntimeError("disk full")

        ctx._save_now = fail
        ctx.save_program(make_pi([]))
        assert ctx.flush_dirty() == []
        assert ctx.dirty_programs() == ["bin"]

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValueError):
            FakeContext("sometimes")
