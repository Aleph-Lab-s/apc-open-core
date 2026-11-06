from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
import uuid

from apc_product.kernel.canonical import sha256_hex


class Signer(Protocol):
    key_id: str
    def sign(self, payload: Any) -> str: ...


class Verifier(Protocol):
    def verify(self, payload: Any, signature: str, key_id: str) -> None: ...


@dataclass(frozen=True)
class EvidenceCheckpoint:
    checkpoint_id: str
    sequence: int
    ledger_head: str
    created_at: datetime
    tenant: str
    key_id: str
    signature: str

    def payload(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "sequence": self.sequence,
            "ledger_head": self.ledger_head,
            "created_at": self.created_at,
            "tenant": self.tenant,
            "key_id": self.key_id,
        }

    @property
    def digest(self) -> str:
        return sha256_hex(self.payload())

    @classmethod
    def create(cls, *, sequence: int, ledger_head: str, tenant: str, signer: Signer) -> "EvidenceCheckpoint":
        now = datetime.now(timezone.utc)
        checkpoint = cls(str(uuid.uuid4()), sequence, ledger_head, now, tenant, signer.key_id, "")
        return cls(**{**checkpoint.__dict__, "signature": signer.sign(checkpoint.payload())})

    def verify(self, verifier: Verifier) -> None:
        verifier.verify(self.payload(), self.signature, self.key_id)
