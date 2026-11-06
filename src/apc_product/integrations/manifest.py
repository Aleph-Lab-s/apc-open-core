from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from apc_product.kernel.canonical import sha256_hex


@dataclass(frozen=True)
class IntegrationManifest:
    adapter_id: str
    version: str
    provider: str
    mode: str
    operations: tuple[str, ...]
    permissions: tuple[str, ...]
    projected_fields: tuple[str, ...]
    credential_reference_only: bool = True
    supports_idempotency: bool = False
    supports_reconciliation: bool = False
    webhook_verification: str = "NOT_IMPLEMENTED"
    network_destinations: tuple[str, ...] = ()
    security_review_status: str = "NOT_REVIEWED"
    metadata: Mapping[str, Any] = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            object.__setattr__(self, "metadata", {})
        if not self.credential_reference_only:
            raise ValueError("adapter manifests may only store credential references")

    @property
    def digest(self) -> str:
        return sha256_hex({
            "adapter_id": self.adapter_id,
            "version": self.version,
            "provider": self.provider,
            "mode": self.mode,
            "operations": self.operations,
            "permissions": self.permissions,
            "projected_fields": self.projected_fields,
            "credential_reference_only": self.credential_reference_only,
            "supports_idempotency": self.supports_idempotency,
            "supports_reconciliation": self.supports_reconciliation,
            "webhook_verification": self.webhook_verification,
            "network_destinations": self.network_destinations,
            "security_review_status": self.security_review_status,
            "metadata": dict(self.metadata),
        })
