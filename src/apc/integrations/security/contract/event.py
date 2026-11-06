from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import hashlib
import json


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class SecurityEvent:
    """Canonical APC security event.

    The event is evidence/observability data only. It is never an authority.
    """
    event_id: str
    event_type: str
    timestamp: str
    severity: str
    outcome: str
    correlation_id: str
    invocation_id: Optional[str] = None
    authority_id: Optional[str] = None
    actor: Optional[str] = None
    principal: Optional[str] = None
    delegation: Optional[str] = None
    operation: Optional[str] = None
    resource: Optional[str] = None
    exact_act_digest: Optional[str] = None
    policy_decision_id: Optional[str] = None
    policy_version: Optional[str] = None
    policy_epoch: Optional[str] = None
    finality_sink: Optional[str] = None
    execution_reference: Optional[str] = None
    provider: Optional[str] = None
    error: Optional[str] = None
    reconciliation_state: Optional[str] = None
    evidence_reference: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def integrity_digest(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def to_cloudevent(self) -> dict[str, Any]:
        """Return an interoperable CloudEvents-style event envelope.

        APC evidence remains authoritative only as evidence; this envelope is
        transport interoperability and never an authorization mechanism.
        """
        return {
            "specversion": "1.0",
            "id": self.event_id,
            "type": f"com.alephlabs.apc.{self.event_type.lower()}",
            "source": "apc://security",
            "subject": self.authority_id or self.invocation_id or self.correlation_id,
            "time": self.timestamp,
            "datacontenttype": "application/json",
            "data": self.to_dict(),
        }

    def otel_attributes(self) -> dict[str, Any]:
        attrs = {
            "apc.event.type": self.event_type,
            "apc.event.outcome": self.outcome,
            "apc.event.severity": self.severity,
            "apc.correlation_id": self.correlation_id,
        }
        for name, value in {
            "apc.invocation_id": self.invocation_id,
            "apc.authority_id": self.authority_id,
            "apc.actor": self.actor,
            "apc.finality_sink": self.finality_sink,
            "apc.provider": self.provider,
            "apc.reconciliation_state": self.reconciliation_state,
        }.items():
            if value is not None:
                attrs[name] = value
        return attrs


def new_event(
    *,
    event_id: str,
    event_type: str,
    correlation_id: str,
    severity: str = "INFO",
    outcome: str = "OBSERVED",
    **kwargs: Any,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_type=event_type,
        timestamp=utc_now(),
        severity=severity,
        outcome=outcome,
        correlation_id=correlation_id,
        **kwargs,
    )
