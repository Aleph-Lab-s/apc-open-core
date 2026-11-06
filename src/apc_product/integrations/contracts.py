"""Provider integration contracts. Real provider execution is opt-in and adapter-specific."""

from dataclasses import asdict, dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class AdapterManifest:
    adapter_id: str
    version: str
    provider: str
    direction: str
    operations: tuple[str, ...]
    data_fields: tuple[str, ...]
    capabilities: tuple[str, ...]
    mode: str  # REAL, SANDBOX, SYNTHETIC, SIMULATED, UNAVAILABLE
    supports_idempotency: bool = False
    supports_authoritative_reconciliation: bool = False
    required_secrets: tuple[str, ...] = ()
    security_boundary: str = "Adapter cannot mint or expand APC authority."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Adapter(Protocol):
    manifest: AdapterManifest

    def health(self) -> dict[str, Any]: ...
    def execute(
        self, operation: str, projected_payload: dict[str, Any], idempotency_key: str
    ) -> dict[str, Any]: ...
    def reconcile(self, provider_reference: str) -> dict[str, Any]: ...


class UnconfiguredAdapter:
    """Safe placeholder: refuses effectful calls instead of simulating a success."""

    def __init__(self, manifest: AdapterManifest):
        self.manifest = manifest

    def health(self):
        return {
            "status": "NOT_CONFIGURED",
            "mode": self.manifest.mode,
            "adapter": self.manifest.adapter_id,
        }

    def execute(self, operation, projected_payload, idempotency_key):
        raise RuntimeError(f"adapter {self.manifest.adapter_id} is not configured; effect refused")

    def reconcile(self, provider_reference):
        return {
            "status": "UNKNOWN",
            "reason": "adapter is not configured",
            "provider_reference": provider_reference,
        }
