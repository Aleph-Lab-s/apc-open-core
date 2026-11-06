from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from apc_y.errors import APCErrorCode


@dataclass(frozen=True)
class TroubleshootingFinding:
    code: str
    severity: str
    likely_owner: str
    first_actions: tuple[str, ...]
    runbook_hint: str


_OWNER_MAP: dict[str, tuple[str, str, tuple[str, ...]]] = {
    'INVALID_SIGNATURE': ('security', 'signature/trust validation', ('verify trusted key id and signing trust state', 'confirm artifact/authority schema versions', 'check key rotation/revocation state')),
    'EXPIRED_AUTHORITY': ('security', 'authority freshness', ('check authority issuance/expiry and clock synchronization', 'verify upstream policy freshness')),
    'REVOKED_AUTHORITY': ('security', 'revocation state', ('check revocation/epoch changes', 'verify identity/delegation status')),
    'REPLAYED_AUTHORITY': ('security', 'replay/single-use', ('inspect duplicate invocation or retry path', 'verify idempotency and reservation state')),
    'POLICY_STATE_INVALID': ('policy-owner', 'policy continuity', ('compare policy decision id/version/epoch', 'confirm PDP availability and current policy state')),
    'WORKLOAD_TRUST_INVALID': ('platform-security', 'workload identity', ('check workload identity/SPIFFE/SVID state', 'inspect trust epoch and rotation')),
    'SINK_CONTRACT_INVALID': ('integration-owner', 'protected sink contract', ('verify sink identity/audience/schema', 'confirm adapter points to intended endpoint')),
    'PRECONDITION_FAILED': ('application-owner', 'resource precondition', ('check resource version/precondition digest', 'reconcile concurrent mutation before retry')),
    'FRESHNESS_VIOLATION': ('security', 'freshness', ('inspect clock skew and freshness policy', 'verify policy-issued timestamp')),
}


def troubleshoot(code: APCErrorCode | str) -> TroubleshootingFinding:
    key = code.value if isinstance(code, APCErrorCode) else str(code)
    owner, hint, actions = _OWNER_MAP.get(key, ('support', 'unknown APC fault', ('collect redacted support bundle', 'check dependency health and recent configuration changes', 'escalate with correlation id')))
    severity = 'CRITICAL' if owner == 'security' else 'HIGH'
    return TroubleshootingFinding(key, severity, owner, actions, hint)


def build_case_context(*, correlation_id: str, error_code: APCErrorCode | str, integration_id: str, diagnostics: Mapping[str, Any]) -> dict[str, Any]:
    finding = troubleshoot(error_code)
    return {
        'correlation_id': correlation_id,
        'integration_id': integration_id,
        'error_code': finding.code,
        'severity': finding.severity,
        'likely_owner': finding.likely_owner,
        'runbook_hint': finding.runbook_hint,
        'first_actions': list(finding.first_actions),
        'diagnostics': dict(diagnostics),
    }
