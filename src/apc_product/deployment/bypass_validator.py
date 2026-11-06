from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ProtectedSinkBoundarySpec:
    sink_id: str
    protected_workloads: tuple[str, ...]
    allowed_network_destinations: tuple[str, ...]
    prohibited_direct_credentials: tuple[str, ...]
    enforcement_mode: str
    customer_owned: bool = True


@dataclass(frozen=True)
class BoundaryFinding:
    severity: str
    code: str
    message: str


class ProtectedEffectExclusivityValidator:
    """Static deployment-boundary validator; it cannot prove arbitrary topology."""

    def validate(self, spec: ProtectedSinkBoundarySpec) -> tuple[BoundaryFinding, ...]:
        findings: list[BoundaryFinding] = []
        if not spec.customer_owned:
            findings.append(BoundaryFinding("HIGH", "SINK_OWNERSHIP", "protected sink is not marked customer-owned"))
        if spec.enforcement_mode not in {"ENFORCED", "STRICT"}:
            findings.append(BoundaryFinding("HIGH", "ENFORCEMENT_MODE", "protected effect boundary is not in an enforcement mode"))
        if not spec.protected_workloads:
            findings.append(BoundaryFinding("HIGH", "NO_PROTECTED_WORKLOAD", "no protected workload declared"))
        if not spec.allowed_network_destinations:
            findings.append(BoundaryFinding("MEDIUM", "NO_EGRESS_DESTINATION", "no destination allowlist declared"))
        if not spec.prohibited_direct_credentials:
            findings.append(BoundaryFinding("MEDIUM", "NO_DIRECT_CREDENTIAL_POLICY", "no direct-credential prohibition declared"))
        if any(not x.strip() for x in spec.protected_workloads):
            findings.append(BoundaryFinding("HIGH", "INVALID_WORKLOAD", "empty workload identifier"))
        return tuple(findings)

    @staticmethod
    def is_release_blocked(findings: Iterable[BoundaryFinding]) -> bool:
        return any(f.severity == "HIGH" for f in findings)
