"""MCP server and `batch` command: schema generation, argv conversion, the
JSON-RPC loop, and in-process command execution (no daemon needed)."""

from __future__ import annotations

import io
import json

import pytest
from click.testing import CliRunner

from ghidra_rpc import cli as cli_mod
from ghidra_rpc.cli import cli
from ghidra_rpc.invoke import EXCLUDED_COMMANDS, run_batch, run_cli
from ghidra_rpc.mcp_server import McpServer, build_argv, list_tools


@pytest.fixture
def isolated_state(tmp_path, monkeypatch):
    """No real daemons: empty registry and socket scan directory."""
    monkeypatch.setenv("GHIDRA_RPC_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(cli_mod, "_SOCKET_SCAN_DIR", tmp_path / "sockets")
    (tmp_path / "sockets").mkdir()
    return tmp_path


class TestSchemas:
    def test_every_command_but_lifecycle_is_a_tool(self):
        names = {t["name"] for t in list_tools()}
        assert names == set(cli.commands) - EXCLUDED_COMMANDS
        json.dumps(list_tools())  # must be JSON-serialisable

    def test_decompile_schema(self):
        tool = {t["name"]: t for t in list_tools()}["decompile"]
        schema = tool["inputSchema"]
        assert schema["required"] == ["binary", "func"]
        assert schema["properties"]["timeout"] == {
            "type": "integer", "default": 120,
            "description": schema["properties"]["timeout"]["description"],
        }
        assert schema["properties"]["max_chars"]["type"] == "integer"
        assert "pseudo-C" in tool["description"]

    def test_flags_choices_and_variadics(self):
        props = {t["name"]: t for t in list_tools()}
        assert props["xrefs-to"]["inputSchema"]["properties"]["all_binaries"]["type"] == "boolean"
        assert props["set-comment"]["inputSchema"]["properties"]["comment_type"]["enum"] == [
            "plate", "pre", "post", "eol", "repeatable"]
        assert props["assemble"]["inputSchema"]["properties"]["instructions"]["type"] == "array"
        field = props["create-struct"]["inputSchema"]["properties"]["explicit_fields"]
        assert field["items"]["minItems"] == 3


class TestBuildArgv:
    def test_options_before_positionals_with_separator(self):
        argv = build_argv("assemble", cli.commands["assemble"],
                          {"binary": "b", "address": "0x10", "instructions": ["mov eax, -1"]})
        assert argv == ["assemble", "--", "b", "0x10", "mov eax, -1"]

    def test_flags_and_values(self):
        argv = build_argv("xrefs-to", cli.commands["xrefs-to"],
                          {"binary": "b", "target": "main", "all_binaries": True,
                           "limit": 5})
        assert argv[:1] == ["xrefs-to"]
        assert "--all-binaries" in argv and argv[argv.index("--limit") + 1] == "5"
        assert argv[-3:] == ["--", "b", "main"]

    def test_false_flag_omitted(self):
        argv = build_argv("xrefs-to", cli.commands["xrefs-to"],
                          {"binary": "b", "target": "main", "all_binaries": False})
        assert "--all-binaries" not in argv

    def test_repeated_multi_value_option(self):
        argv = build_argv("create-struct", cli.commands["create-struct"],
                          {"binary": "b", "struct_name": "S",
                           "explicit_fields": [["0", "int", "a"], ["8", "char *", "p"]]})
        assert argv[1:9] == ["--field", "0", "int", "a", "--field", "8", "char *", "p"]

    def test_unknown_and_missing_arguments(self):
        with pytest.raises(ValueError, match="Unknown"):
            build_argv("decompile", cli.commands["decompile"],
                       {"binary": "b", "func": "f", "bogus": 1})
        with pytest.raises(ValueError, match="Missing required argument: func"):
            build_argv("decompile", cli.commands["decompile"], {"binary": "b"})

    def test_argv_parses_back_through_click(self):
        argv = build_argv("create-struct", cli.commands["create-struct"],
                          {"binary": "b", "struct_name": "S",
                           "explicit_fields": [["0x0", "int", "a"]], "if_not_exists": True})
        ctx = cli.commands["create-struct"].make_context("create-struct", argv[1:])
        assert ctx.params["explicit_fields"] == (("0x0", "int", "a"),)
        assert ctx.params["if_not_exists"] is True
        assert ctx.params["binary"] == "b" and ctx.params["struct_name"] == "S"


class TestJsonRpc:
    def test_initialize_negotiates_version(self):
        server = McpServer()
        resp = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                              "params": {"protocolVersion": "2024-11-05"}})
        assert resp["result"]["protocolVersion"] == "2024-11-05"
        assert "tools" in resp["result"]["capabilities"]
        resp = server.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize",
                              "params": {"protocolVersion": "1999-01-01"}})
        assert resp["result"]["protocolVersion"] == "2025-06-18"

    def test_notifications_get_no_response(self):
        assert McpServer().handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None

    def test_unknown_method_and_tool(self):
        server = McpServer()
        assert server.handle({"jsonrpc": "2.0", "id": 1, "method": "nope"})["error"]["code"] == -32601
        resp = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                              "params": {"name": "start", "arguments": {}}})
        assert resp["error"]["code"] == -32602

    def test_tool_call_returns_envelope(self, isolated_state):
        resp = McpServer().handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                   "params": {"name": "list-instances", "arguments": {}}})
        envelope = json.loads(resp["result"]["content"][0]["text"])
        assert resp["result"]["isError"] is False
        assert envelope["ok"] is True and envelope["result"]["count"] == 0

    def test_tool_call_without_daemon_is_an_error_result(self, tmp_path):
        resp = McpServer().handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "decompile",
            "arguments": {"binary": "b", "func": "main", "project": str(tmp_path / "p.gpr")},
        }})
        assert resp["result"]["isError"] is True
        assert json.loads(resp["result"]["content"][0]["text"])["error"] == "DaemonNotRunning"

    def test_serve_loop(self, isolated_state):
        stdin = io.StringIO(
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n"
            + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
            + "not json\n"
            + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n"
        )
        stdout = io.StringIO()
        McpServer().serve(stdin, stdout)
        lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
        assert [m.get("id") for m in lines] == [1, None, 2]
        assert lines[1]["error"]["code"] == -32700
        assert len(lines[2]["result"]["tools"]) == len(list_tools())


class TestRunCli:
    def test_success(self, isolated_state):
        assert run_cli(["list-instances"])["ok"] is True

    def test_usage_error_is_envelope(self):
        out = run_cli(["decompile"])
        assert out["ok"] is False and out["error"] == "MissingParameter"

    def test_excluded_command(self):
        assert run_cli(["start", "--headless"])["error"] == "UsageError"

    def test_missing_project_reports_stderr(self, monkeypatch):
        monkeypatch.delenv("GHIDRA_RPC_PROJECT", raising=False)
        out = run_cli(["decompile", "b", "f"])
        assert out["ok"] is False and "No project specified" in out["message"]

    def test_project_env_restored(self, monkeypatch, tmp_path):
        monkeypatch.setenv("GHIDRA_RPC_PROJECT", "original")
        run_cli(["decompile", "b", "f"], project=str(tmp_path / "p.gpr"))
        import os
        assert os.environ["GHIDRA_RPC_PROJECT"] == "original"


class TestBatch:
    def test_run_batch_mixed(self, isolated_state):
        out = run_batch([["list-instances"], "decompile", "list-instances --all"])
        assert out["count"] == 3 and out["ok_count"] == 2 and out["error_count"] == 1
        assert out["results"][1]["argv"] == ["decompile"]

    def test_stop_on_error(self, isolated_state):
        out = run_batch(["decompile", "list-instances"], stop_on_error=True)
        assert out["count"] == 1 and out["skipped"] == 1

    def test_invalid_item_rejected_up_front(self):
        with pytest.raises(ValueError):
            run_batch([["ok"], {"cmd": "x"}])

    def test_cli_command(self, isolated_state):
        result = CliRunner().invoke(cli, ["batch", "--json", '[["list-instances"]]'])
        data = json.loads(result.output)
        assert data["ok"] is True and data["result"]["ok_count"] == 1

    def test_cli_requires_exactly_one_source(self):
        result = CliRunner().invoke(cli, ["batch"])
        assert json.loads(result.output)["error"] == "UsageError"
