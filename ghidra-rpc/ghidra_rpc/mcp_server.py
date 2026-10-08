"""Minimal MCP (Model Context Protocol) server over stdio.

Exposes every ghidra-rpc CLI command as an MCP tool.  Tool input schemas are
derived from the Click parameter declarations and calls are executed
in-process through ``invoke.run_cli``, so the MCP surface always matches the
CLI exactly and needs no extra dependency.

Wire format: newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP stdio
transport).  Only the tools capability is implemented.
"""

from __future__ import annotations

import inspect
import json
import sys
from typing import Any

import click

from ghidra_rpc import __version__
from ghidra_rpc.invoke import EXCLUDED_COMMANDS, run_cli

SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
_MAX_DESCRIPTION = 1500


# ─── Schema generation ────────────────────────────────────────────────────────

def _scalar_schema(ptype: click.ParamType) -> dict:
    if isinstance(ptype, click.Choice):
        return {"type": "string", "enum": [str(c) for c in ptype.choices]}
    if isinstance(ptype, click.types.BoolParamType):
        return {"type": "boolean"}
    if isinstance(ptype, click.types.IntParamType):
        return {"type": "integer"}
    if isinstance(ptype, click.types.FloatParamType):
        return {"type": "number"}
    if getattr(ptype, "name", "") == "integer":  # cli.HexInt: decimal or 0x hex
        return {"type": "string", "description": "Integer, decimal or 0x-prefixed hex."}
    return {"type": "string"}


def _param_schema(param: click.Parameter) -> dict:
    if isinstance(param, click.Option) and param.is_flag and not param.count:
        schema: dict = {"type": "boolean"}
    else:
        item = _scalar_schema(param.type)
        if param.nargs > 1:
            item = {"type": "array", "items": item, "minItems": param.nargs,
                    "maxItems": param.nargs}
        if param.nargs == -1 or getattr(param, "multiple", False):
            schema = {"type": "array", "items": item}
        else:
            schema = dict(item)

    help_text = getattr(param, "help", None)
    if not help_text and isinstance(param, click.Argument):
        help_text = f"Positional argument {param.human_readable_name}."
    if help_text:
        existing = schema.get("description")
        schema["description"] = f"{help_text} {existing}" if existing else help_text
    # Only plain JSON values: Click >= 8.2 uses an UNSET sentinel for "no default".
    default = param.default
    if (isinstance(default, (str, int, float, bool))
            and not (isinstance(param, click.Option) and param.is_flag and default is False)):
        schema["default"] = default
    return schema


def _is_required(param: click.Parameter) -> bool:
    return bool(param.required)


def tool_for_command(name: str, command: click.Command) -> dict:
    properties: dict[str, Any] = {}
    required: list[str] = []
    for param in command.params:
        if param.name is None:
            continue
        properties[param.name] = _param_schema(param)
        if _is_required(param):
            required.append(param.name)
    description = inspect.cleandoc(command.help or command.short_help or name)
    if len(description) > _MAX_DESCRIPTION:
        description = description[:_MAX_DESCRIPTION].rstrip() + " ..."
    schema: dict = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return {"name": name, "description": description, "inputSchema": schema}


def list_tools(group: click.Group | None = None) -> list[dict]:
    if group is None:
        from ghidra_rpc.cli import cli as group
    return [
        tool_for_command(name, cmd)
        for name, cmd in sorted(group.commands.items())
        if name not in EXCLUDED_COMMANDS and not getattr(cmd, "hidden", False)
    ]


# ─── Argument conversion ──────────────────────────────────────────────────────

def build_argv(command_name: str, command: click.Command, arguments: dict) -> list[str]:
    """Translate MCP tool arguments into a CLI argv for *command*.

    Options come first, then ``--``, then positionals, so positional values
    that begin with ``-`` (negative numbers, instruction text) are never
    mistaken for options.
    """
    arguments = dict(arguments or {})
    known = {p.name: p for p in command.params if p.name}
    unknown = sorted(set(arguments) - set(known))
    if unknown:
        raise ValueError(f"Unknown argument(s) for {command_name}: {unknown}")

    options: list[str] = []
    positionals: list[str] = []
    for param in command.params:
        if param.name not in arguments:
            if isinstance(param, click.Argument) and param.required:
                raise ValueError(f"Missing required argument: {param.name}")
            continue
        value = arguments[param.name]
        if value is None:
            continue

        if isinstance(param, click.Argument):
            if param.nargs == -1 or param.nargs > 1:
                if not isinstance(value, list):
                    raise ValueError(f"Argument {param.name} must be an array")
                positionals.extend(str(v) for v in value)
            else:
                positionals.append(str(value))
            continue

        opt = param.opts[0]
        if param.is_flag and not param.count:
            if value is True or value == "true":
                options.append(opt)
            elif param.secondary_opts:
                options.append(param.secondary_opts[0])
            continue

        values = value if (param.multiple and isinstance(value, list)) else [value]
        for v in values:
            if param.nargs > 1:
                if not isinstance(v, list) or len(v) != param.nargs:
                    raise ValueError(
                        f"Option {param.name} takes groups of {param.nargs} values"
                    )
                options.append(opt)
                options.extend(str(x) for x in v)
            else:
                options.extend([opt, str(v)])

    argv = [command_name, *options]
    if positionals:
        argv += ["--", *positionals]
    return argv


# ─── JSON-RPC loop ────────────────────────────────────────────────────────────

class McpServer:
    def __init__(self, default_project: str | None = None, group: click.Group | None = None):
        if group is None:
            from ghidra_rpc.cli import cli as group
        self.group = group
        self.default_project = default_project

    def _call_tool(self, params: dict) -> dict:
        name = params.get("name")
        command = self.group.commands.get(name) if isinstance(name, str) else None
        if command is None or name in EXCLUDED_COMMANDS:
            raise _RpcError(-32602, f"Unknown tool: {name}")
        try:
            argv = build_argv(name, command, params.get("arguments") or {})
        except ValueError as e:
            envelope = {"ok": False, "error": "InvalidArguments", "message": str(e)}
        else:
            envelope = run_cli(argv, project=self.default_project)
        return {
            "content": [{"type": "text", "text": json.dumps(envelope, indent=1)}],
            "isError": not envelope.get("ok", False),
        }

    def handle(self, message: dict) -> dict | None:
        """Handle one JSON-RPC message; return the response (None for notifications)."""
        method = message.get("method")
        msg_id = message.get("id")
        is_notification = "id" not in message
        params = message.get("params") or {}
        try:
            if method == "initialize":
                requested = params.get("protocolVersion")
                version = (requested if requested in SUPPORTED_PROTOCOL_VERSIONS
                           else SUPPORTED_PROTOCOL_VERSIONS[0])
                result: Any = {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "ghidra-rpc", "version": __version__},
                    "instructions": (
                        "Ghidra reverse-engineering tools. Every tool returns the "
                        "ghidra-rpc JSON envelope {ok, result | error, message}. "
                        "The daemon must be running (`ghidra-rpc start --detach "
                        "--headless -p <project.gpr>`); load a binary with the "
                        "'load' tool first, then pass its short_name as 'binary'."
                    ),
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": list_tools(self.group)}
            elif method == "tools/call":
                result = self._call_tool(params)
            elif is_notification:
                return None  # notifications/initialized, notifications/cancelled, ...
            else:
                raise _RpcError(-32601, f"Method not found: {method}")
        except _RpcError as e:
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": e.code, "message": e.message}}
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def serve(self, stdin=None, stdout=None) -> None:
        # Hold on to the real stdout: run_cli temporarily redirects sys.stdout
        # to capture each command's output.
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for raw in stdin:
            line = raw.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError as e:
                response: dict | None = {"jsonrpc": "2.0", "id": None,
                                         "error": {"code": -32700, "message": f"Parse error: {e}"}}
            else:
                if isinstance(message, list):  # JSON-RPC batch (2024-11-05 clients)
                    responses = [r for r in (self.handle(m) for m in message if isinstance(m, dict)) if r]
                    response = responses or None  # type: ignore[assignment]
                elif isinstance(message, dict):
                    response = self.handle(message)
                else:
                    response = {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32600, "message": "Invalid Request"}}
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()


class _RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def serve(default_project: str | None = None) -> None:
    # Binary-safe UTF-8 line I/O regardless of the console code page.
    stdin = open(sys.stdin.fileno(), "r", encoding="utf-8", closefd=False, newline="\n")
    stdout = open(sys.stdout.fileno(), "w", encoding="utf-8", closefd=False, newline="\n")
    McpServer(default_project=default_project).serve(stdin, stdout)
