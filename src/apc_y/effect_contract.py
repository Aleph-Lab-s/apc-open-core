from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class EffectContract:
    sink_id: str
    endpoint_identity: str
    action_schema: str
    audience: str
    supports_idempotency: bool = True
    supports_outcome_reconciliation: bool = True
    transactional: bool = False
    max_effect_age_seconds: int | None = None


class ProtectedSinkV2(Protocol):
    contract: EffectContract

    def execute(self, act: dict, idempotency_key: str) -> object: ...
    def reconcile(self, idempotency_key: str) -> object | None: ...
