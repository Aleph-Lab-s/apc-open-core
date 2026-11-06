from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class ConformanceCheck:
    check_id: str
    passed: bool
    message: str


class ProviderAdapter(Protocol):
    manifest: Any

    def health(self) -> dict[str, Any]: ...
    def execute(
        self, operation: str, projected_payload: dict[str, Any], idempotency_key: str
    ) -> Any: ...
    def reconcile(self, provider_reference: str) -> Any: ...


def run_adapter_conformance(adapter: ProviderAdapter) -> tuple[ConformanceCheck, ...]:
    m = adapter.manifest
    checks = [
        ConformanceCheck(
            "manifest",
            bool(getattr(m, "adapter_id", "") and getattr(m, "version", "")),
            "manifest identity/version",
        ),
        ConformanceCheck(
            "least-privilege",
            "Adapter cannot mint" in getattr(m, "security_boundary", ""),
            "adapter authority boundary declaration",
        ),
        ConformanceCheck(
            "mode-disclosure",
            getattr(m, "mode", "") in {"REAL", "SANDBOX", "SYNTHETIC", "SIMULATED", "UNAVAILABLE"},
            "implementation mode is explicit",
        ),
        ConformanceCheck("health", isinstance(adapter.health(), dict), "adapter health surface"),
    ]
    if getattr(m, "supports_idempotency", False):
        checks.append(
            ConformanceCheck("idempotency", True, "adapter declares provider idempotency support")
        )
    else:
        checks.append(
            ConformanceCheck(
                "idempotency", True, "adapter explicitly does not claim provider idempotency"
            )
        )
    if getattr(m, "supports_authoritative_reconciliation", False):
        checks.append(
            ConformanceCheck("reconciliation", True, "adapter declares reconciliation support")
        )
    return tuple(checks)
