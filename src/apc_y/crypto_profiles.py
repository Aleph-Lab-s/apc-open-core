from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Protocol

@dataclass(frozen=True)
class CryptoProfile:
    algorithm: str
    domain: str
    canonicalization: str
    security_level: str

ED25519_V1 = CryptoProfile("Ed25519", "APC-AUTHORITY-V3", "APC-CANONICAL-JSON-V2", "classical-128")

class Signer(Protocol):
    key_id: str
    profile: CryptoProfile
    def sign(self, payload: Any) -> str: ...
