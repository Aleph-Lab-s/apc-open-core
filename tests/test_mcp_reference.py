from __future__ import annotations

import json
from pathlib import Path

import pytest

import apc_mcp.server as mcp_server


class FakeMCPServer:
    def __init__(self, name: str):
        self.name = name
        self.tools = {}

    def tool(self):
        def register(fn):
            self.tools[fn.__name__] = fn
            return fn
        return register


def test_mcp_demo_tools_are_effect_free(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(mcp_server, "_load_sdk", lambda: FakeMCPServer)
    monkeypatch.setenv("APC_DB_PATH", str(tmp_path / "mcp.db"))
    monkeypatch.delenv("APC_MCP_ENABLE_LAB", raising=False)
    server, service = mcp_server.build_server()
    try:
        assert set(server.tools) == {
            "apc_health", "apc_integration_status", "apc_evaluate_action", "apc_lab_sqlite_action"
        }
        result = server.tools["apc_evaluate_action"](
            "tenant-demo", "ticket.create", "ticket:1", json.dumps({"summary": "demo"})
        )
        assert result["status"] == "SIMULATED"
        assert result["result"]["effect_performed"] is False
        with pytest.raises(PermissionError):
            server.tools["apc_lab_sqlite_action"](
                "tenant-demo", "ticket.create", "ticket:1", "idem-1", "{}"
            )
    finally:
        service.close()


def test_mcp_lab_tool_is_explicit_opt_in_and_sandbox_only(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(mcp_server, "_load_sdk", lambda: FakeMCPServer)
    monkeypatch.setenv("APC_DB_PATH", str(tmp_path / "mcp-lab.db"))
    monkeypatch.setenv("APC_MCP_ENABLE_LAB", "1")
    server, service = mcp_server.build_server()
    try:
        result = server.tools["apc_lab_sqlite_action"](
            "tenant-lab", "inventory.adjust", "sku:1", "lab-idem-1", json.dumps({"delta": 1})
        )
        assert result["status"] in {"EFFECTED", "SUCCESS"}
        assert result["result"]["sink_id"] == "lab.sqlite"
        assert result["result"]["evidence"]["production_claim"] is False
    finally:
        service.close()
