from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .canonical import canonical_json
from .crypto import verify_signature

ENTITLEMENT_SCHEMA = "APC-ENTITLEMENT-V1"
ENTITLEMENT_DOMAIN = "APC-ENTITLEMENT-V1"


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return dt.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True)
class EnterpriseEntitlement:
    customer_id: str
    installation_id: str
    product: str
    edition: str
    modules: tuple[str, ...]
    valid_from: datetime
    valid_until: datetime
    deployment_mode: str
    environment: str
    key_id: str
    signature: str
    schema_version: str = ENTITLEMENT_SCHEMA

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "crypto_domain": ENTITLEMENT_DOMAIN,
            "customer_id": self.customer_id,
            "installation_id": self.installation_id,
            "product": self.product,
            "edition": self.edition,
            "modules": self.modules,
            "valid_from": _iso(self.valid_from),
            "valid_until": _iso(self.valid_until),
            "deployment_mode": self.deployment_mode,
            "environment": self.environment,
            "key_id": self.key_id,
        }

    def verify(self, public_key_pem: str, now: datetime | None = None) -> None:
        verify_signature(self.payload(), self.signature, public_key_pem)
        now = now or datetime.now(timezone.utc)
        if now < self.valid_from or now >= self.valid_until:
            raise ValueError("enterprise entitlement is outside its validity window")
        if self.product != "APC":
            raise ValueError("entitlement product mismatch")
        if not self.customer_id or not self.installation_id:
            raise ValueError("customer and installation identity are required")


def issue_entitlement(signer, *, customer_id: str, installation_id: str,
                      edition: str, modules: tuple[str, ...],
                      valid_from: datetime, valid_until: datetime,
                      deployment_mode: str = "customer-controlled",
                      environment: str = "production") -> EnterpriseEntitlement:
    if valid_until <= valid_from:
        raise ValueError("valid_until must be after valid_from")
    unsigned = EnterpriseEntitlement(
        customer_id, installation_id, "APC", edition, tuple(sorted(set(modules))),
        valid_from, valid_until, deployment_mode, environment, signer.key_id, ""
    )
    return EnterpriseEntitlement(**{**unsigned.__dict__, "signature": signer.sign(unsigned.payload())})


def entitlement_json(entitlement: EnterpriseEntitlement) -> bytes:
    return canonical_json({**entitlement.payload(), "signature": entitlement.signature})
