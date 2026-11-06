from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .crypto import verify_signature
from .flagship import Delegation, _digest, _iso

DELEGATION_DOMAIN = "APC-DELEGATION-V1"


@dataclass(frozen=True)
class SignedDelegation:
    delegation: Delegation
    key_id: str
    signature: str
    schema_version: str = "APC-DELEGATION-V1"

    def payload(self) -> dict[str, Any]:
        d = self.delegation
        return {
            "schema_version": self.schema_version,
            "crypto_domain": DELEGATION_DOMAIN,
            "key_id": self.key_id,
            "root_principal_id": d.root_principal_id,
            "holder_id": d.holder_id,
            "parent_id": d.parent_id,
            "scope": d.scope,
            "expires_at": _iso(d.expires_at),
            "risk_ceiling": d.risk_ceiling,
            "audience": d.audience,
        }

    @property
    def digest(self):
        return _digest(self.payload())


def verify_delegation(
    sd: SignedDelegation, resolver, parent: SignedDelegation | None = None
) -> None:
    key = resolver(sd.key_id)
    if not key:
        raise ValueError("unknown delegation signing key")
    verify_signature(sd.payload(), sd.signature, key)
    if parent:
        if sd.delegation.parent_id != parent.delegation.holder_id:
            raise ValueError("delegation parent mismatch")
        if not sd.delegation.attenuates(parent.delegation):
            raise ValueError("delegation is not attenuated")


class DelegationIssuer:
    def __init__(self, signer):
        self.signer = signer

    def issue(self, delegation: Delegation) -> SignedDelegation:
        sd = SignedDelegation(delegation, self.signer.key_id, "")
        return SignedDelegation(delegation, self.signer.key_id, self.signer.sign(sd.payload()))
