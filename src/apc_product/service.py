"""APC product runtime and safe evaluation orchestration."""

from __future__ import annotations

import os
from typing import Any

from .integrations.catalog import catalog
from .runtime.engine import APCEvaluationEngine, ExecutionRequest
from .store import Store
from .version import PRODUCT, RELEASE_CHANNEL, VERSION


def _contains_unicode_surrogate(value) -> bool:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in item):
                return True
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


class APCService:
    def __init__(self, db_path: str | None = None, mode: str | None = None):
        self.mode = (mode or os.getenv("APC_MODE", "DEMO")).upper()
        self.db_path = db_path or os.getenv("APC_DB_PATH", "./var/apc-product.db")
        self.store = Store(self.db_path)
        self._evaluation_engine: APCEvaluationEngine | None = None

    def _engine(self) -> APCEvaluationEngine:
        if self._evaluation_engine is None:
            self._evaluation_engine = APCEvaluationEngine(db_path=self.db_path)
        return self._evaluation_engine

    def close(self) -> None:
        if self._evaluation_engine is not None:
            self._evaluation_engine.close()
        self.store.close()

    def live(self):
        return {"status": "ALIVE", "version": VERSION}

    def health(self):
        event_chain = self.store.verify_chain()
        return {
            "service": PRODUCT + " Runtime",
            "version": VERSION,
            "mode": self.mode,
            "status": "OK" if event_chain.get("valid") else "DEGRADED",
            "effect_execution": "SANDBOX_ENABLED" if self.mode == "LAB" else "DISABLED",
            "security_core": "apc_y",
            "event_chain": event_chain,
            "delivery_model": "native-artifact-by-customer-intake",
            "release_channel": RELEASE_CHANNEL,
        }

    def integrations(self):
        return catalog()

    def submit(self, request: dict[str, Any], *, idempotency_key: str | None = None) -> dict:
        if _contains_unicode_surrogate(request):
            raise ValueError("request contains invalid Unicode surrogate code points")
        tenant = str(request.get("tenant", "")).strip()
        if not tenant:
            raise ValueError("tenant is required")
        requested_mode = str(request.get("mode", self.mode)).upper()
        if requested_mode not in {"DEMO", "LAB", "PILOT", "PRODUCTION"}:
            raise ValueError("invalid mode")
        if not request.get("operation") or not request.get("target"):
            raise ValueError("operation and target are required")

        if requested_mode in {"LAB", "PILOT", "PRODUCTION"} and not idempotency_key:
            raise ValueError("Idempotency-Key header is required for effect-capable modes")
        if idempotency_key:
            record, replayed = self.store.create_action_idempotent(tenant, request, idempotency_key)
            if replayed:
                record["_idempotency_replayed"] = True
                if record.get("status") == "RECEIVED":
                    record["_idempotency_in_progress"] = True
                return record
        else:
            record = self.store.create_action(tenant, request)
        if request.get("policy_decision") != "ALLOW" or not request.get("policy_decision_id"):
            return self.store.update_action(
                record["action_id"],
                "DENIED",
                {"reason": "missing or non-ALLOW customer PDP decision"},
            )
        if not request.get("sink"):
            return self.store.update_action(
                record["action_id"], "BLOCKED", {"reason": "explicit protected sink is required"}
            )

        if requested_mode == "DEMO":
            result = {
                "classification": "SYNTHETIC_DEMO_ONLY",
                "effect_performed": False,
                "provider": "synthetic",
                "operation": request["operation"],
                "target": request["target"],
                "correlation_id": record["action_id"],
                "reconciliation": "NOT_APPLICABLE",
            }
            return self.store.update_action(record["action_id"], "SIMULATED", result)

        if requested_mode != "LAB":
            return self.store.update_action(
                record["action_id"],
                "BLOCKED",
                {
                    "reason": "customer integration/profile required before PILOT/PRODUCTION execution",
                    "classification": "NOT_PROVEN",
                },
            )

        engine_request = ExecutionRequest(
            tenant=tenant,
            operation=str(request["operation"]),
            resource=str(request["target"]),
            parameters=dict(request.get("payload") or request.get("parameters") or {}),
            actor_id=str(request.get("actor_id", "agent:apc-lab")),
            principal_id=str(request.get("principal_id", "human:apc-lab")),
            workload_id=str(request.get("workload_id", "workload:apc-agent")),
            workload_issuer=str(request.get("workload_issuer", "lab-issuer")),
            audience=str(request.get("audience", "lab.sqlite")),
            sink_id=str(request.get("sink", "lab.sqlite")),
            policy_decision="ALLOW",
            policy_decision_id=str(request["policy_decision_id"]),
            policy_issuer=str(request.get("policy_issuer", "customer-pdp")),
            policy_version=str(request.get("policy_version", "policy-v1")),
            policy_epoch=int(request.get("policy_epoch", 1)),
            risk=int(request.get("risk", 10)),
            assurance=str(request.get("assurance", "A1")),
            authority_ttl_seconds=int(request.get("authority_ttl_seconds", 300)),
            single_use=bool(request.get("single_use", True)),
            mode="SANDBOX",
            purpose=str(request.get("purpose", "APC local evaluation")),
        )
        execution = self._engine().execute(engine_request)
        status = "EFFECTED" if execution.status == "EFFECTED" else execution.status
        return self.store.update_action(record["action_id"], status, execution.to_dict())

    def action(self, aid):
        return self.store.get_action(aid)

    def events(self, tenant=None, limit=100):
        return self.store.events(tenant, limit)

    def verify_evidence(self):
        # Verify both the product audit hash chain and every recorded APC run's
        # evidence manifest. This is still customer-local evaluation evidence.
        from pathlib import Path

        from apc_product.assurance.evidence_bundle import EvidenceBundleManifest

        base = Path(self.db_path).parent / "evidence"
        runs = []
        if base.exists():
            for run_dir in sorted(p for p in base.iterdir() if p.is_dir()):
                manifest_path = run_dir / "manifest.json"
                if not manifest_path.exists():
                    runs.append(
                        {"run_id": run_dir.name, "valid": False, "error": "manifest_missing"}
                    )
                    continue
                try:
                    manifest = EvidenceBundleManifest.from_json(manifest_path.read_bytes())
                    manifest.verify_directory(run_dir)
                    runs.append(
                        {"run_id": run_dir.name, "valid": True, "merkle_root": manifest.merkle_root}
                    )
                except Exception as exc:
                    runs.append({"run_id": run_dir.name, "valid": False, "error": repr(exc)})
        return {
            "event_chain": self.store.verify_chain(),
            "evidence_runs": runs,
            "valid": self.store.verify_chain()["valid"] and all(r["valid"] for r in runs),
        }
