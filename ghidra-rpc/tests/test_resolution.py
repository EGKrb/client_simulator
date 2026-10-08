"""Function and binary name resolution, against fake Ghidra objects.

Covers the rules that protect write commands from acting on the wrong target:
exact names beat substrings, write commands never accept a substring match,
bare hex tokens prefer function names over addresses, and an exact binary name
is never reported as ambiguous just because it is a substring of another key.
"""

from __future__ import annotations

import pytest

from ghidra_rpc.server.context import ProgramInfo, match_program
from ghidra_rpc.server.tools.decompiler import (
    _find_function,
    _find_function_strict,
    _resolve_function,
)


class Addr:
    def __init__(self, offset: int, space: str = "ram"):
        self.offset = offset
        self.space = space

    def __str__(self):
        return f"{self.offset:08x}"

    def __eq__(self, other):
        return isinstance(other, Addr) and (self.offset, self.space) == (other.offset, other.space)

    def __hash__(self):
        return hash((self.offset, self.space))


class Sym:
    def __init__(self, func):
        self.func = func

    def getAddress(self):
        return self.func.entry

    def getName(self, qualified=False):
        return self.func.qualified if qualified else self.func.name


class Func:
    def __init__(self, name, offset, size=0x10, namespace=None, external=False):
        self.name = name
        self.entry = Addr(offset)
        self.size = size
        self.qualified = f"{namespace}::{name}" if namespace else name
        self.external = external

    def getName(self):
        return self.name

    def getEntryPoint(self):
        return self.entry

    def getSymbol(self):
        return Sym(self)

    def isExternal(self):
        return self.external

    def __repr__(self):
        return f"Func({self.qualified})"


class FunctionManager:
    def __init__(self, funcs):
        self.funcs = funcs

    def getFunctions(self, forward):
        return [f for f in self.funcs if not f.external]

    def getFunctionAt(self, addr):
        return next((f for f in self.funcs if f.entry == addr), None)

    def getFunctionContaining(self, addr):
        return next((f for f in self.funcs
                     if not f.external and f.entry.offset <= addr.offset < f.entry.offset + f.size),
                    None)


class SymbolTable:
    def __init__(self, funcs):
        self.funcs = funcs

    def getSymbols(self, name):
        return [Sym(f) for f in self.funcs if f.name == name]


class AddressFactory:
    def getAddress(self, text):
        if text.startswith("ram:"):
            text = text[4:]
        try:
            return Addr(int(text, 16))
        except ValueError:
            return None


class Program:
    def __init__(self, funcs):
        self._fm = FunctionManager(funcs)
        self._st = SymbolTable(funcs)

    def getFunctionManager(self):
        return self._fm

    def getSymbolTable(self):
        return self._st

    def getAddressFactory(self):
        return AddressFactory()


class PI:
    def __init__(self, funcs):
        self.program = Program(funcs)


@pytest.fixture
def pi():
    return PI([
        Func("main", 0x1000),
        Func("_init_array_helper", 0x2000),
        Func("add", 0x3000),
        Func("Parse", 0x4000),
        Func("dup", 0x5000, namespace="A"),
        Func("dup", 0x6000, namespace="B"),
        Func("strcmp", 0x7000, external=True),
    ])


class TestFunctionResolution:
    def test_exact_name_via_symbol_table(self, pi):
        func, how = _resolve_function(pi, "main")
        assert func.name == "main" and how == "exact"

    def test_hex_address_with_prefix(self, pi):
        func, how = _resolve_function(pi, "0x1000")
        assert func.name == "main" and how == "address"

    def test_address_inside_function_body(self, pi):
        assert _find_function(pi, "0x1004").name == "main"

    def test_space_prefixed_address(self, pi):
        func, how = _resolve_function(pi, "ram:00004000")
        assert func.name == "Parse" and how == "address"

    def test_bare_hex_prefers_function_name(self, pi):
        # "add" is valid hex (0xadd) but a function has that exact name.
        func, how = _resolve_function(pi, "add")
        assert func.name == "add" and how == "exact"

    def test_bare_hex_falls_back_to_address(self, pi):
        func, how = _resolve_function(pi, "2000")
        assert func.name == "_init_array_helper" and how == "address"

    def test_case_insensitive_exact(self, pi):
        func, how = _resolve_function(pi, "parse")
        assert func.name == "Parse" and how == "exact_nocase"

    def test_partial_match_allowed_for_reads(self, pi):
        func, how = _resolve_function(pi, "init_array")
        assert func.name == "_init_array_helper" and how == "partial"

    def test_strict_rejects_partial_match(self, pi):
        with pytest.raises(ValueError, match="exact name or an address"):
            _find_function_strict(pi, "init_array")

    def test_strict_still_accepts_exact_and_address(self, pi):
        assert _find_function_strict(pi, "main").name == "main"
        assert _find_function_strict(pi, "0x4000").name == "Parse"

    def test_ambiguous_exact_name_lists_addresses(self, pi):
        with pytest.raises(ValueError, match="Ambiguous") as exc:
            _find_function(pi, "dup")
        assert "00005000" in str(exc.value) and "00006000" in str(exc.value)

    def test_namespace_qualified_name_disambiguates(self, pi):
        assert _find_function(pi, "B::dup").entry.offset == 0x6000

    def test_external_functions_are_not_matched(self, pi):
        with pytest.raises(ValueError, match="not found"):
            _find_function(pi, "strcmp")

    def test_not_found(self, pi):
        with pytest.raises(ValueError, match="not found"):
            _find_function(pi, "nope_nothing")


def _info(name):
    return ProgramInfo(name=name, program=None, flat_api=None,
                       decompiler_pool=None, metadata={})


class TestBinaryResolution:
    def test_exact_name_beats_substring(self):
        programs = {"/ls-abc123": _info("ls-abc123"), "/lsblk-def456": _info("lsblk-def456")}
        # "ls" is a substring of both keys, but equals neither name: ambiguous...
        with pytest.raises(ValueError, match="Ambiguous"):
            match_program(programs, "ls", not_found_hint="")
        # ...while an exact name wins even though it is also a substring.
        programs = {"/ls": _info("ls"), "/lsblk": _info("lsblk")}
        assert match_program(programs, "ls", not_found_hint="").name == "ls"

    def test_unique_substring(self):
        programs = {"/target.exe-85cbcc": _info("target.exe-85cbcc")}
        assert match_program(programs, "target", not_found_hint="").name == "target.exe-85cbcc"

    def test_exact_key(self):
        programs = {"/a": _info("a"), "/ab": _info("ab")}
        assert match_program(programs, "/a", not_found_hint="").name == "a"

    def test_not_found_includes_hint(self):
        with pytest.raises(ValueError, match="load it"):
            match_program({}, "x", not_found_hint="load it")
