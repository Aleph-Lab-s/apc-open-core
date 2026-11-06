from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class SinkDescriptor:
    sink_id: str
    audience: str
    provider: str
    operations: tuple[str, ...]
    mode: str
    protected: bool = True
    supports_idempotency: bool = False
    supports_reconciliation: bool = False
    data_fields: tuple[str, ...] = ()
    network_destinations: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.sink_id.strip() or not self.audience.strip():
            raise ValueError("sink_id and audience are required")
        if not self.protected:
            raise ValueError("APC protected effect boundary requires protected=True")


@dataclass(frozen=True)
class EffectReceipt:
    status: str
    provider_reference: str | None
    idempotency_key: str
    sink_id: str
    evidence: Mapping[str, Any] = field(default_factory=dict)


class Sink(Protocol):
    descriptor: SinkDescriptor

    def execute(
        self, operation: str, parameters: Mapping[str, Any], idempotency_key: str
    ) -> EffectReceipt: ...
    def reconcile(self, idempotency_key: str) -> EffectReceipt | None: ...


class SinkRegistry:
    def __init__(self) -> None:
        self._sinks: dict[str, Sink] = {}

    def register(self, sink: Sink) -> None:
        sid = sink.descriptor.sink_id
        if sid in self._sinks:
            raise ValueError(f"sink already registered: {sid}")
        self._sinks[sid] = sink

    def get(self, sink_id: str) -> Sink:
        try:
            return self._sinks[sink_id]
        except KeyError as exc:
            raise KeyError(f"unknown protected sink: {sink_id}") from exc

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "sink_id": s.descriptor.sink_id,
                "provider": s.descriptor.provider,
                "audience": s.descriptor.audience,
                "operations": list(s.descriptor.operations),
                "mode": s.descriptor.mode,
                "protected": s.descriptor.protected,
                "supports_idempotency": s.descriptor.supports_idempotency,
                "supports_reconciliation": s.descriptor.supports_reconciliation,
            }
            for s in self._sinks.values()
        ]


class SyntheticSink:
    """Explicit non-effecting sink for labs and demos."""

    def __init__(self, sink_id: str = "synthetic"):
        self.descriptor = SinkDescriptor(
            sink_id=sink_id,
            audience="synthetic-apc",
            provider="synthetic",
            operations=("*",),
            mode="SYNTHETIC",
            protected=True,
            supports_idempotency=True,
            supports_reconciliation=False,
        )

    def execute(
        self, operation: str, parameters: Mapping[str, Any], idempotency_key: str
    ) -> EffectReceipt:
        return EffectReceipt(
            status="SUCCESS",
            provider_reference=None,
            idempotency_key=idempotency_key,
            sink_id=self.descriptor.sink_id,
            evidence={"environment": "SYNTHETIC", "effect_performed": False},
        )

    def reconcile(self, idempotency_key: str) -> EffectReceipt | None:
        return None
