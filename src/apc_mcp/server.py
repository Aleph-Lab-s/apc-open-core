"""APC MCP reference server.

The default tool is synthetic DEMO. A local SQLite LAB tool is opt-in and is
never connected to an external provider. The server does not intercept other
MCP servers and does not act as a customer's policy decision point.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from apc_product.service import APCService


def _load_sdk():
    try:
        from mcp.server import MCPServer
    except ImportError as exc:  # pragma: no cover - exercised by CLI users without extra
        raise RuntimeError(
            "The MCP SDK is optional. Install APC with `pip install 'apc-action-security[mcp]'`."
        ) from exc
    return MCPServer


def build_server():
    MCPServer = _load_sdk()
    server = MCPServer("APC Action Security Reference Server")
    db_path = os.getenv("APC_DB_PATH", str(Path.cwd() / "var" / "apc-mcp-demo.db"))
    service = APCService(db_path=db_path, mode="DEMO")

    @server.tool()
    def apc_health() -> dict[str, Any]:
        """Return APC's local runtime health and actual execution mode."""
        return service.health()

    @server.tool()
    def apc_integration_status() -> dict[str, Any]:
        """Return the integration catalog with SIMULATED/UNAVAILABLE labels."""
        return {"items": service.integrations()}

    @server.tool()
    def apc_evaluate_action(
        tenant: str,
        operation: str,
        target: str,
        payload_json: str = "{}",
    ) -> dict[str, Any]:
        """Run a synthetic APC action evaluation; it never performs an external effect."""
        try:
            payload = json.loads(payload_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"payload_json must be valid JSON: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise ValueError("payload_json must decode to a JSON object")
        return service.submit({
            "tenant": tenant,
            "operation": operation,
            "target": target,
            "policy_decision": "ALLOW",
            "policy_decision_id": "synthetic-demo-only",
            "sink": "synthetic.demo",
            "payload": payload,
            "mode": "DEMO",
        })

    @server.tool()
    def apc_lab_sqlite_action(
        tenant: str,
        operation: str,
        target: str,
        idempotency_key: str,
        payload_json: str = "{}",
    ) -> dict[str, Any]:
        """Opt-in local LAB test that writes only to APC's SQLite sandbox.

        Requires APC_MCP_ENABLE_LAB=1. It is not a live provider action and the
        local ALLOW decision is a test fixture, not a customer PDP integration.
        """
        if os.getenv("APC_MCP_ENABLE_LAB") != "1":
            raise PermissionError("LAB tool disabled; set APC_MCP_ENABLE_LAB=1 only for local sandbox tests")
        try:
            payload = json.loads(payload_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"payload_json must be valid JSON: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise ValueError("payload_json must decode to a JSON object")
        if not idempotency_key.strip():
            raise ValueError("idempotency_key is required")
        lab_service = APCService(db_path=db_path, mode="LAB")
        try:
            return lab_service.submit({
                "tenant": tenant,
                "operation": operation,
                "target": target,
                "policy_decision": "ALLOW",
                "policy_decision_id": "local-lab-fixture-not-a-customer-pdp",
                "sink": "lab.sqlite",
                "payload": payload,
                "mode": "LAB",
            }, idempotency_key=idempotency_key)
        finally:
            lab_service.close()

    return server, service


def main() -> int:
    server, service = build_server()
    try:
        server.run()  # MCP SDK v2 defaults to stdio transport.
    finally:
        service.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
