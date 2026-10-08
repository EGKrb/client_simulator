"""Decompiler tools: decompile functions to pseudo-C."""

from __future__ import annotations

import re

from ghidra_rpc.server import cancel
from ghidra_rpc.server.decomp_cache import DecompileCache
from ghidra_rpc.server.main import register_handler

# A bare token made only of hex digits ("401000", "add", "cafe") could be
# either an address or a function name; names win, see _resolve_function.
_BARE_HEX_RE = re.compile(r"[0-9a-fA-F]+")


def _address_candidate(prog, text: str):
    """Return a Ghidra Address if *text* is unambiguously an address, else None.

    Unambiguous forms: ``0x401000`` and ``ram:00401000`` (address-space
    prefix, as Ghidra itself prints addresses in listings and error messages).
    Namespace-qualified names (``Foo::bar``) are not addresses.
    """
    t = text.strip()
    af = prog.getAddressFactory()
    if t[:2].lower() == "0x":
        spec = t[2:]
    elif ":" in t and "::" not in t:
        spec = t
    else:
        return None
    try:
        return af.getAddress(spec)
    except Exception:  # noqa: BLE001
        return None


def _bare_hex_address(prog, text: str):
    t = text.strip()
    if not _BARE_HEX_RE.fullmatch(t):
        return None
    try:
        return prog.getAddressFactory().getAddress(t)
    except Exception:  # noqa: BLE001
        return None


def _function_at_or_containing(fm, addr):
    if addr is None:
        return None
    return fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)


def _describe(funcs, limit: int = 10) -> list[str]:
    return [f"{f.getName()} @ {f.getEntryPoint()}" for f in funcs[:limit]]


def _resolve_function(pi, name_or_address: str, *, allow_partial: bool = True):
    """Resolve a function by address or name; return ``(func, resolved_by)``.

    ``resolved_by`` is one of ``"address"``, ``"exact"``, ``"exact_nocase"``,
    ``"partial"``.  Resolution order:

    1. Unambiguous address syntax (``0x...``, ``space:offset``).
    2. Exact, case-sensitive name via the symbol table -- O(matches), not a
       scan of every function (matters on 50k+-function DEX programs).
       Namespace-qualified names (``Foo::bar``) are accepted.
    3. A bare hex token (``401000``) as an address.
    4. Full scan: case-insensitive exact name, then (if *allow_partial*)
       a unique substring match.

    Raises ValueError when nothing matches or the match is ambiguous.
    """
    prog = pi.program
    fm = prog.getFunctionManager()
    query = name_or_address.strip()

    addr = _address_candidate(prog, query)
    if addr is not None:
        func = _function_at_or_containing(fm, addr)
        if func is not None:
            return func, "address"

    # Fast path: exact name through the symbol table.
    simple_name = query.rsplit("::", 1)[-1] if "::" in query else query
    exact = []
    try:
        seen = set()
        for sym in prog.getSymbolTable().getSymbols(simple_name):
            func = fm.getFunctionAt(sym.getAddress())
            if func is None or func.isExternal():
                continue
            if "::" in query:
                if str(func.getSymbol().getName(True)) != query:
                    continue
            elif str(func.getName()) != query:
                continue
            key = str(func.getEntryPoint())
            if key not in seen:
                seen.add(key)
                exact.append(func)
    except Exception:  # noqa: BLE001 - fall through to the scan
        exact = []
    if len(exact) == 1:
        return exact[0], "exact"
    if len(exact) > 1:
        raise ValueError(
            f"Ambiguous function name '{name_or_address}'. Matches: {_describe(exact)}. "
            "Use the address instead."
        )

    func = _function_at_or_containing(fm, _bare_hex_address(prog, query))
    if func is not None:
        return func, "address"

    query_lower = query.lower()
    qualified = "::" in query
    nocase = []
    partial = []
    for func in fm.getFunctions(True):
        name = str(func.getSymbol().getName(True)) if qualified else str(func.getName())
        name_lower = name.lower()
        if name_lower == query_lower:
            nocase.append(func)
        elif query_lower in name_lower:
            partial.append(func)

    if len(nocase) == 1:
        return nocase[0], "exact_nocase"
    if len(nocase) > 1:
        raise ValueError(
            f"Ambiguous function name '{name_or_address}'. Matches: {_describe(nocase)}. "
            "Use the address instead."
        )

    if partial and not allow_partial:
        raise ValueError(
            f"No function named exactly '{name_or_address}'. Partial matches: "
            f"{_describe(partial)}. Commands that modify the program require an "
            "exact name or an address, so a substring match can never rename or "
            "delete the wrong function."
        )
    if len(partial) == 1:
        return partial[0], "partial"
    if len(partial) > 1:
        raise ValueError(
            f"Ambiguous function name '{name_or_address}'. Partial matches: {_describe(partial)}"
        )

    raise ValueError(f"Function '{name_or_address}' not found.")


def _find_function(pi, name_or_address: str, *, allow_partial: bool = True):
    """Resolve a function by name or address (see ``_resolve_function``)."""
    return _resolve_function(pi, name_or_address, allow_partial=allow_partial)[0]


def _find_function_strict(pi, name_or_address: str):
    """Like ``_find_function`` but never falls back to a substring match.

    Use this in every handler that modifies the program.
    """
    return _resolve_function(pi, name_or_address, allow_partial=False)[0]


def _truncate(text: str | None, max_chars) -> tuple[str | None, bool]:
    if text is None or not max_chars or max_chars <= 0 or len(text) <= max_chars:
        return text, False
    return text[:max_chars], True


def decompile_function(pi, func, timeout: int) -> dict:
    """Decompile *func*, using the program's decompile cache when possible.

    Returns ``{"c_code", "signature", "error", "cached"}``; ``c_code`` and
    ``signature`` are None when the decompiler produced no function, and
    ``error`` is the decompiler's (possibly empty) error message.  Only clean
    results are cached, so a timeout is retried on the next call.
    """
    cache = getattr(pi, "decomp_cache", None)
    if not isinstance(cache, DecompileCache):
        cache = None
    key = modnum = None
    if cache is not None:
        try:
            modnum = int(pi.program.getModificationNumber())
            key = str(func.getEntryPoint())
        except Exception:  # noqa: BLE001
            key = None
        if key is not None:
            hit = cache.get(modnum, key)
            if hit is not None:
                return dict(hit, cached=True)

    cancel.check_cancelled()
    monitor = cancel.task_monitor()
    with pi.decompiler_pool.acquire() as decompiler:
        result = decompiler.decompileFunction(func, timeout, monitor)

    error_msg = result.getErrorMessage()
    error = str(error_msg).strip() if error_msg is not None else ""
    decompiled = result.getDecompiledFunction()
    out = {
        "c_code": str(decompiled.getC()) if decompiled is not None else None,
        "signature": str(decompiled.getSignature()) if decompiled is not None else None,
        "error": error,
    }
    if key is not None and decompiled is not None and not error:
        cache.put(modnum, key, out)
    return dict(out, cached=False)


def _handle_decompile(ctx, args: dict) -> dict:
    """Decompile a function and return its pseudo-C code."""
    binary = args.get("binary", "")
    func_name = args.get("func", "")
    timeout = args.get("timeout", 120)
    max_chars = args.get("max_chars")

    if not func_name:
        raise ValueError("Missing required argument: func")

    pi = ctx.get_program(binary)
    func, resolved_by = _resolve_function(pi, func_name)

    out = decompile_function(pi, func, timeout)

    response: dict = {
        "name": str(func.getName()),
        "address": str(func.getEntryPoint()),
    }
    if resolved_by == "partial":
        response["resolved_by"] = "partial"
        response["warning"] = (
            f"No function named exactly '{func_name}'; resolved by substring "
            f"match to {func.getName()} @ {func.getEntryPoint()}."
        )

    if out["error"]:
        response.update({"c_code": None, "error": out["error"]})
        return response

    c_code, truncated = _truncate(out["c_code"] or "", max_chars)
    response["signature"] = out["signature"] or str(func.getSignature())
    response["c_code"] = c_code
    if truncated:
        response["truncated"] = True
        response["c_code_length"] = len(out["c_code"])
    if out["cached"]:
        response["cached"] = True
    return response


def _pool_workers(pi) -> int:
    size = getattr(pi.decompiler_pool, "size", 1)
    return size if isinstance(size, int) and size > 0 else 1


def _handle_search_decompiled(ctx, args: dict) -> dict:
    """Regex-search the decompiled C of many functions in one RPC call.

    Avoids the "enumerate with `symbols`, `decompile` each, grep the C
    client-side" pattern (one round-trip per function) for tasks like
    "which function builds this UUID / calls this callee / touches this
    struct field".

    Functions are decompiled in parallel across the program's decompiler
    pool, and results are served from the decompile cache when the program
    has not changed since they were produced.

    Args (in ``args`` dict):
        binary        -- program name / key
        pattern       -- regex to search for, applied per source line
        class_filter  -- optional: only search functions whose fully
                          qualified name (namespace path, e.g.
                          "com::example::Foo::bar") contains this substring
                          (case-insensitive)
        ignore_case   -- case-insensitive pattern match (default True)
        limit         -- max matching functions to return (default 50)
        max_functions -- safety cap on functions actually decompiled
                          (default 5000); stops the sweep early on very
                          large programs (e.g. 50k+-function DEX files)
        timeout       -- per-function decompiler timeout in seconds (default 60)

    Returns a dict with:
        matches             -- list of {function, address, matching_lines}
                                where matching_lines is a list of
                                {line, text}
        count               -- number of functions with at least one match
        functions_searched  -- number of functions actually decompiled
        functions_total     -- number of functions matching class_filter
                                (before the limit/max_functions cutoff)
        truncated           -- True if the sweep stopped before covering
                                every candidate function (limit or
                                max_functions reached)
    """
    from concurrent.futures import ThreadPoolExecutor

    binary        = args.get("binary", "")
    pattern_str   = args.get("pattern", "")
    class_filter  = args.get("class_filter", "")
    ignore_case   = bool(args.get("ignore_case", True))
    limit         = int(args.get("limit", 50))
    max_functions = int(args.get("max_functions", 5000))
    timeout       = int(args.get("timeout", 60))

    if not binary:
        raise ValueError("Missing required argument: binary")
    if not pattern_str:
        raise ValueError("Missing required argument: pattern")

    try:
        regex = re.compile(pattern_str, re.IGNORECASE if ignore_case else 0)
    except re.error as e:
        raise ValueError(f"Invalid regex pattern: {e}")

    pi = ctx.get_program(binary)
    fm = pi.program.getFunctionManager()
    class_filter_lower = class_filter.lower() if class_filter else None

    candidates = []
    for func in fm.getFunctions(True):
        if func.isExternal() or func.isThunk():
            continue
        qualified_name = str(func.getSymbol().getName(True))
        if class_filter_lower and class_filter_lower not in qualified_name.lower():
            continue
        candidates.append((func, qualified_name))

    total = len(candidates)
    state = cancel.current()

    def _c_code(func):
        cancel.bind(state)
        try:
            return decompile_function(pi, func, timeout)["c_code"]
        except cancel.Cancelled:
            raise
        except Exception:  # noqa: BLE001 - one bad function must not sink the sweep
            return None

    workers = _pool_workers(pi)
    matches: list[dict] = []
    functions_searched = 0
    truncated = False
    pos = 0

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="search-decomp") as ex:
        while pos < total:
            if len(matches) >= limit or functions_searched >= max_functions:
                truncated = True
                break
            cancel.check_cancelled()
            chunk = candidates[pos:pos + min(workers, max_functions - functions_searched)]
            pos += len(chunk)
            functions_searched += len(chunk)
            codes = list(ex.map(_c_code, [f for f, _ in chunk]))

            for i, ((func, qualified_name), c_code) in enumerate(zip(chunk, codes)):
                if len(matches) >= limit:
                    truncated = True
                    break
                if c_code is None:
                    continue
                matching_lines = [
                    {"line": n, "text": line.strip()}
                    for n, line in enumerate(c_code.splitlines(), start=1)
                    if regex.search(line)
                ]
                if matching_lines:
                    matches.append({
                        "function": qualified_name,
                        "address": str(func.getEntryPoint()),
                        "matching_lines": matching_lines,
                    })
            if truncated:
                break
        cancel.check_cancelled()

    return {
        "matches": matches,
        "count": len(matches),
        "functions_searched": functions_searched,
        "functions_total": total,
        "truncated": truncated,
    }


register_handler("decompile", _handle_decompile)
register_handler("search_decompiled", _handle_search_decompiled)
