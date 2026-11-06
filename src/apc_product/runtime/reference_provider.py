from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from threading import RLock
from typing import Any

from .sinks import EffectReceipt, SinkDescriptor


@dataclass(frozen=True)
class StoredEffect:
    status: str
    provider_reference: str
    operation: str
    parameters: Mapping[str, Any]
    idempotency_key: str


class StatefulReferenceSink:
    """Deterministic provider simulator for conformance/reconciliation labs.

    It models a provider that supports idempotency and authoritative lookup.
    It performs no real external side effect.
    """

    def __init__(self, sink_id: str = "reference.effect", audience: str = "reference.provider"):
        self.descriptor = SinkDescriptor(
            sink_id=sink_id,
            audience=audience,
            provider="reference-provider",
            operations=("mutate",),
            mode="SYNTHETIC",
            protected=True,
            supports_idempotency=True,
            supports_reconciliation=True,
        )
        self._lock = RLock()
        self._effects: dict[str, StoredEffect] = {}
        self.calls = 0

    def execute(
        self, operation: str, parameters: Mapping[str, Any], idempotency_key: str
    ) -> EffectReceipt:
        with self._lock:
            existing = self._effects.get(idempotency_key)
            if existing is not None:
                return EffectReceipt(
                    existing.status,
                    existing.provider_reference,
                    idempotency_key,
                    self.descriptor.sink_id,
                    {"deduplicated": True, "environment": "SYNTHETIC"},
                )
            self.calls += 1
            ref = "ref-" + uuid.uuid4().hex
            stored = StoredEffect("SUCCESS", ref, operation, dict(parameters), idempotency_key)
            self._effects[idempotency_key] = stored
            return EffectReceipt(
                "SUCCESS",
                ref,
                idempotency_key,
                self.descriptor.sink_id,
                {"deduplicated": False, "environment": "SYNTHETIC", "effect_performed": False},
            )

    def reconcile(self, idempotency_key: str) -> EffectReceipt | None:
        with self._lock:
            existing = self._effects.get(idempotency_key)
            if existing is None:
                return EffectReceipt(
                    "UNKNOWN",
                    None,
                    idempotency_key,
                    self.descriptor.sink_id,
                    {"environment": "SYNTHETIC"},
                )
            return EffectReceipt(
                existing.status,
                existing.provider_reference,
                idempotency_key,
                self.descriptor.sink_id,
                {"authoritative_lookup": True, "environment": "SYNTHETIC"},
            )

    @property
    def supports_idempotency(self) -> bool:
        return self.descriptor.supports_idempotency

    @property
    def supports_outcome_reconciliation(self) -> bool:
        return self.descriptor.supports_reconciliation
