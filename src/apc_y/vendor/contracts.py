from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Protocol, Sequence
import re


_SECRET_KEY = re.compile(r"(pass(word)?|secret|token|api[_-]?key|private[_-]?key|credential|client[_-]?secret)", re.I)


class AdapterLifecycle(str, Enum):
    DISCOVERED = 'DISCOVERED'
    VALIDATED = 'VALIDATED'
    READY = 'READY'
    DEGRADED = 'DEGRADED'
    DRAINING = 'DRAINING'
    UPGRADING = 'UPGRADING'
    FAILED = 'FAILED'
    DISABLED = 'DISABLED'


class AdapterCapability(str, Enum):
    HEALTH = 'health'
    DIAGNOSTICS = 'diagnostics'
    CONFIG_VALIDATION = 'config_validation'
    UPGRADE = 'upgrade'
    ROLLBACK = 'rollback'
    IDEMPOTENCY = 'idempotency'
    RECONCILIATION = 'reconciliation'
    WEBHOOK = 'webhook'
    HTTP = 'http'
    GRPC = 'grpc'
    OIDC = 'oidc'
    MTLS = 'mtls'
    SPIFFE = 'spiffe'
    EVENTS = 'events'
    CLOUD_EVENTS = 'cloudevents'
    OTEL = 'opentelemetry'


@dataclass(frozen=True)
class OwnerSet:
    business_owner: str
    engineering_owner: str
    security_owner: str
    support_owner: str

    def validate(self) -> None:
        for name, value in vars(self).items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f'{name} is required')


@dataclass(frozen=True)
class SupportPolicy:
    service_tier: str
    support_hours: str
    severity_critical_response_minutes: int
    severity_high_response_minutes: int
    escalation_path: tuple[str, ...]
    runbook_uri: str
    status_page_uri: str | None = None

    def validate(self) -> None:
        if self.severity_critical_response_minutes <= 0 or self.severity_high_response_minutes <= 0:
            raise ValueError('support response windows must be positive')
        if not self.escalation_path:
            raise ValueError('at least one escalation path is required')
        if not self.runbook_uri.strip():
            raise ValueError('runbook_uri is required')


@dataclass(frozen=True)
class SecretRef:
    uri: str

    def __post_init__(self):
        if not self.uri.startswith('secret://'):
            raise ValueError('SecretRef must use secret:// URI syntax')


@dataclass(frozen=True)
class UpgradePlan:
    from_version: str
    to_version: str
    strategy: str
    requires_drain: bool
    compatible: bool
    migration_steps: tuple[str, ...] = ()
    rollback_steps: tuple[str, ...] = ()
    validation_steps: tuple[str, ...] = ()
    risk_notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class IntegrationManifest:
    integration_id: str
    display_name: str
    vendor: str
    category: str
    protocol: str
    adapter_version: str
    min_apc_version: str
    max_apc_version: str | None
    environments: tuple[str, ...]
    capabilities: frozenset[AdapterCapability]
    auth_methods: tuple[str, ...]
    data_exchanged: tuple[str, ...]
    credential_owner: str
    permissions: tuple[str, ...]
    rate_limit_notes: str
    failure_behavior: str
    logging_behavior: str
    retention_behavior: str
    owners: OwnerSet
    support: SupportPolicy
    documentation_uri: str
    security_review_status: str
    legal_review_status: str
    privacy_review_status: str
    security_boundary: str
    data_classification: tuple[str, ...]
    business_criticality: str
    real_or_synthetic: str
    upgrade_policy: str
    exit_strategy: str
    schema_version: str = 'APC-INTEGRATION-MANIFEST-V1'

    def validate(self) -> None:
        for name in ('integration_id','display_name','vendor','category','protocol','adapter_version','min_apc_version','credential_owner','rate_limit_notes','failure_behavior','logging_behavior','retention_behavior','documentation_uri','security_review_status','legal_review_status','privacy_review_status','security_boundary','business_criticality','real_or_synthetic','upgrade_policy','exit_strategy'):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f'{name} is required')
        if not self.environments or not self.auth_methods:
            raise ValueError('environments and auth_methods are required')
        if not self.capabilities:
            raise ValueError('at least one capability is required')
        if not self.data_exchanged:
            raise ValueError('data_exchanged must be explicit')
        if not self.data_classification:
            raise ValueError('data_classification must be explicit')
        if self.business_criticality not in {'LOW','MEDIUM','HIGH','CRITICAL'}:
            raise ValueError('business_criticality must be LOW/MEDIUM/HIGH/CRITICAL')
        if not self.security_boundary.strip():
            raise ValueError('security_boundary is required')
        if self.real_or_synthetic not in {'REAL','SANDBOX','SYNTHETIC','SIMULATED','NOT_AVAILABLE','CUSTOMER_DEPENDENT'}:
            raise ValueError('invalid real_or_synthetic status')
        self.owners.validate()
        self.support.validate()


    def to_dict(self) -> dict[str, Any]:
        return {
            'integration_id': self.integration_id, 'display_name': self.display_name,
            'vendor': self.vendor, 'category': self.category, 'protocol': self.protocol,
            'adapter_version': self.adapter_version, 'min_apc_version': self.min_apc_version,
            'max_apc_version': self.max_apc_version, 'environments': list(self.environments),
            'capabilities': sorted(x.value for x in self.capabilities), 'auth_methods': list(self.auth_methods),
            'data_exchanged': list(self.data_exchanged), 'credential_owner': self.credential_owner,
            'permissions': list(self.permissions), 'rate_limit_notes': self.rate_limit_notes,
            'failure_behavior': self.failure_behavior, 'logging_behavior': self.logging_behavior,
            'retention_behavior': self.retention_behavior, 'owners': vars(self.owners).copy(),
            'support': vars(self.support).copy(), 'documentation_uri': self.documentation_uri,
            'security_review_status': self.security_review_status, 'legal_review_status': self.legal_review_status,
            'privacy_review_status': self.privacy_review_status, 'security_boundary': self.security_boundary,
            'data_classification': list(self.data_classification), 'business_criticality': self.business_criticality,
            'real_or_synthetic': self.real_or_synthetic, 'upgrade_policy': self.upgrade_policy,
            'exit_strategy': self.exit_strategy, 'schema_version': self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> 'IntegrationManifest':
        d = dict(data)
        d['capabilities'] = frozenset(AdapterCapability(x) for x in d.get('capabilities', ()))
        d['environments'] = tuple(d.get('environments', ()))
        d['auth_methods'] = tuple(d.get('auth_methods', ()))
        d['data_exchanged'] = tuple(d.get('data_exchanged', ()))
        d['permissions'] = tuple(d.get('permissions', ()))
        d['data_classification'] = tuple(d.get('data_classification', ()))
        d['owners'] = OwnerSet(**d['owners'])
        d['support'] = SupportPolicy(**d['support'])
        obj = cls(**d)
        obj.validate()
        return obj


@dataclass(frozen=True)
class AdapterHealth:
    status: str
    checked_at: str
    details: Mapping[str, Any] = field(default_factory=dict)


class VendorAdapter(Protocol):
    manifest: IntegrationManifest

    def validate_config(self, config: Mapping[str, Any]) -> None: ...
    def health(self) -> AdapterHealth: ...
    def diagnostics(self) -> Mapping[str, Any]: ...
    def plan_upgrade(self, target_version: str) -> UpgradePlan: ...
    def apply_upgrade(self, plan: UpgradePlan) -> None: ...
    def rollback(self, plan: UpgradePlan) -> None: ...
    def close(self) -> None: ...


def is_secret_key(key: object) -> bool:
    return isinstance(key, str) and bool(_SECRET_KEY.search(key))


def assert_no_raw_secrets(value: Any, path: str = 'config') -> None:
    if isinstance(value, SecretRef):
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if is_secret_key(key):
                if not isinstance(item, SecretRef):
                    raise ValueError(f'{path}.{key} must use SecretRef; raw secrets are forbidden')
            assert_no_raw_secrets(item, f'{path}.{key}')
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            assert_no_raw_secrets(item, f'{path}[{index}]')


def redact_secrets(value: Any) -> Any:
    if isinstance(value, SecretRef):
        return {'secret_ref': value.uri}
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            if isinstance(item, SecretRef):
                out[key] = {'secret_ref': item.uri}
            elif is_secret_key(key):
                out[key] = '<REDACTED>'
            else:
                out[key] = redact_secrets(item)
        return out
    if isinstance(value, list):
        return [redact_secrets(x) for x in value]
    if isinstance(value, tuple):
        return [redact_secrets(x) for x in value]
    return value
