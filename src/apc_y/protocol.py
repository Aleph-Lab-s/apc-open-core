from __future__ import annotations
import hashlib
from dataclasses import dataclass
from typing import Any
from .canonical import canonical_json

PROTOCOL_VERSION = "APC-PROTOCOL-1"
DOMAIN_ACTION = "APC-ACTION-1"
DOMAIN_INTENT = "APC-INTENT-1"
DOMAIN_AUTHORITY = "APC-AUTHORITY-2"
DOMAIN_DELEGATION = "APC-DELEGATION-1"

def domain_digest(domain: str, value: Any) -> str:
    b = domain.encode("ascii") + b"\x00" + canonical_json(value)
    return hashlib.sha256(b).hexdigest()

@dataclass(frozen=True)
class ProtocolProfile:
    version: str = PROTOCOL_VERSION
    canonicalization: str = "APC-CANONICAL-JSON-V2"
    hash_algorithm: str = "SHA-256"
    signature_algorithm: str = "Ed25519"
    max_clock_skew_seconds: int = 30
    def as_dict(self): return self.__dict__.copy()
