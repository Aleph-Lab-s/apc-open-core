from __future__ import annotations

from pathlib import Path

import apc_y
from apc_product.service import APCService
from apc_product.version import RELEASE_CHANNEL, VERSION


def test_package_imports_and_candidate_identity():
    assert apc_y.__version__ == "0.1.0a1"
    assert VERSION == "7.1.4"
    assert RELEASE_CHANNEL == "certification-candidate"


def test_demo_action_is_synthetic_and_has_no_effect(tmp_path: Path):
    svc = APCService(db_path=str(tmp_path / "apc.db"), mode="DEMO")
    try:
        result = svc.submit(
            {
                "tenant": "tenant-test",
                "operation": "ticket.create",
                "target": "ticket:123",
                "policy_decision": "ALLOW",
                "policy_decision_id": "test-fixture",
                "sink": "synthetic.demo",
                "payload": {"summary": "hello"},
                "mode": "DEMO",
            }
        )
        assert result["status"] == "SIMULATED"
        assert result["result"]["effect_performed"] is False
        assert result["result"]["classification"] == "SYNTHETIC_DEMO_ONLY"
    finally:
        svc.close()


def test_lab_writes_only_local_sqlite_and_requires_idempotency(tmp_path: Path):
    db = tmp_path / "lab.db"
    svc = APCService(db_path=str(db), mode="LAB")
    request = {
        "tenant": "tenant-lab",
        "operation": "inventory.adjust",
        "target": "sku:demo",
        "policy_decision": "ALLOW",
        "policy_decision_id": "local-fixture-not-pdp",
        "sink": "lab.sqlite",
        "payload": {"delta": 1},
        "mode": "LAB",
    }
    try:
        try:
            svc.submit(request)
            assert False, "LAB accepted missing idempotency key"
        except ValueError as exc:
            assert "Idempotency-Key" in str(exc)
        first = svc.submit(request, idempotency_key="same-request")
        assert first["status"] in {"EFFECTED", "SUCCESS"}
        replay = svc.submit(request, idempotency_key="same-request")
        assert replay.get("_idempotency_replayed") is True
    finally:
        svc.close()


def test_production_and_pilot_effects_are_blocked(tmp_path: Path):
    svc = APCService(db_path=str(tmp_path / "prod.db"), mode="DEMO")
    try:
        for mode in ("PILOT", "PRODUCTION"):
            got = svc.submit(
                {
                    "tenant": "tenant-test",
                    "operation": "account.update",
                    "target": "account:1",
                    "policy_decision": "ALLOW",
                    "policy_decision_id": "test",
                    "sink": "provider",
                    "payload": {"x": 1},
                    "mode": mode,
                },
                idempotency_key=f"key-{mode}",
            )
            assert got["status"] == "BLOCKED"
            assert got["result"]["classification"] == "NOT_PROVEN"
    finally:
        svc.close()


def test_mcp_module_import_is_lazy_without_optional_sdk():
    # Importing the package/server module is safe even when the MCP extra is absent.
    from apc_mcp import server

    assert callable(server.build_server)
