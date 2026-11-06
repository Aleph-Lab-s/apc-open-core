from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from apc_product.kernel.canonical import sha256_hex


class SenderConstraintType(str, Enum):
    MTLS = "MTLS"
    SPIFFE = "SPIFFE"
    DPOP_JKT = "DPOP_JKT"
    SIGNING_KEY = "SIGNING_KEY"


@dataclass(frozen=True)
class SenderConstraint:
    kind: SenderConstraintType
    binding: str
    audience: str

    def __post_init__(self) -> None:
        if not self.binding.strip() or not self.audience.strip():
            raise ValueError("sender constraint binding and audience are required")

    @property
    def digest(self) -> str:
        return sha256_hex({"kind": self.kind.value, "binding": self.binding, "audience": self.audience})


@dataclass(frozen=True)
class SenderEvidence:
    kind: SenderConstraintType
    binding: str
    audience: str
    proof_reference: str
    verified: bool


def verify_sender_constraint(expected: SenderConstraint, observed: SenderEvidence) -> None:
    """Verify normalized sender-binding evidence at an APC transition boundary.

    DPoP, mTLS and SPIFFE adapters should perform protocol-specific cryptographic
    checks and hand APC the normalized evidence represented here. This function
    does not pretend to be a complete JOSE/TLS/SPIFFE verifier.
    """
    if not observed.verified:
        raise ValueError("sender evidence is not verified")
    if observed.kind is not expected.kind:
        raise ValueError("sender constraint type mismatch")
    if observed.binding != expected.binding:
        raise ValueError("sender binding mismatch")
    if observed.audience != expected.audience:
        raise ValueError("sender audience mismatch")
    if not observed.proof_reference.strip():
        raise ValueError("sender proof reference is required")
