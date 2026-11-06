from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Protocol

from apc_y.errors import APCError, APCErrorCode
from apc_product.kernel.canonical import sha256_hex
from apc_product.runtime.sinks import EffectReceipt


class ReconciliationStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ReconciliationResult:
    status: ReconciliationStatus | str
    provider_reference: str | None = None
    data: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", ReconciliationStatus(self.status))
        if self.data is None:
            object.__setattr__(self, "data", {})
        elif not isinstance(self.data, dict):
            raise TypeError("reconciliation result data must be a dict")


class ReconciliationSink(Protocol):
    def reconcile(self, idempotency_key: str) -> ReconciliationResult | EffectReceipt | None: ...
    @property
    def supports_idempotency(self) -> bool: ...
    @property
    def supports_outcome_reconciliation(self) -> bool: ...


@dataclass(frozen=True)
class ReconciliationItem:
    authority_id: str
    idempotency_key: str
    sink_id: str
    reason: str


def effect_reservation_key(*, tenant: str, authority_id: str, sink_id: str) -> str:
    """Stable effect reservation key shared by execution and reconciliation."""
    return "apc-v8:" + sha256_hex(
        {
            "domain": "APC-EFFECT-RESERVATION-V1",
            "tenant": tenant,
            "authority_id": authority_id,
            "sink_id": sink_id,
        }
    )


@dataclass(frozen=True)
class ReconciliationReport:
    examined: int
    resolved_success: int
    resolved_failure: int
    reopened_for_retry: int
    still_unknown: int
    rejected: int


class ReconciliationController:
    """Consumes durable UNKNOWNs without treating retry as implicit authorization.

    A provider is queried authoritatively first. Re-entry for NOT_FOUND is only
    allowed when the sink explicitly supports idempotency and reconciliation.
    """

    def __init__(self, *, store, queue, sink_resolver: Callable[[str], ReconciliationSink]):
        self.store = store
        self.queue = queue
        self.sink_resolver = sink_resolver

    @staticmethod
    def _normalize(raw: Any) -> ReconciliationResult:
        if raw is None:
            return ReconciliationResult(ReconciliationStatus.UNKNOWN)
        if isinstance(raw, ReconciliationResult):
            return raw
        if isinstance(raw, EffectReceipt):
            return ReconciliationResult(raw.status, raw.provider_reference, dict(raw.evidence))
        status = getattr(raw, "status", None)
        if status is None:
            raise APCError(APCErrorCode.INVALID_EVIDENCE, "reconciliation returned no status")
        try:
            mapped = str(status).replace("ReconciliationStatus.", "")
            return ReconciliationResult(mapped, getattr(raw, "provider_reference", None), getattr(raw, "data", {}))
        except ValueError as exc:
            raise APCError(APCErrorCode.INVALID_EVIDENCE, f"unsupported reconciliation status: {status}") from exc

    def reconcile_pending(self, *, max_items: int | None = None) -> ReconciliationReport:
        items = list(self.queue.pending())
        if max_items is not None:
            items = items[:max_items]
        counters = {k: 0 for k in ("examined", "resolved_success", "resolved_failure", "reopened_for_retry", "still_unknown", "rejected")}
        for item in items:
            counters["examined"] += 1
            try:
                if self.store.state(item.authority_id) != "UNKNOWN":
                    counters["rejected"] += 1
                    continue
                sink = self.sink_resolver(item.sink_id)
                if not (getattr(sink, "supports_idempotency", False) and getattr(sink, "supports_outcome_reconciliation", False)):
                    counters["rejected"] += 1
                    continue
                result = self._normalize(sink.reconcile(item.idempotency_key))
            except Exception:
                counters["still_unknown"] += 1
                continue

            if result.status is ReconciliationStatus.SUCCESS:
                resolver = getattr(self.store, "resolve_unknown", None)
                if resolver is None:
                    counters["rejected"] += 1
                    continue
                resolver(item.authority_id, True)
                self.queue.resolve(item.authority_id)
                counters["resolved_success"] += 1
            elif result.status is ReconciliationStatus.FAILURE:
                resolver = getattr(self.store, "resolve_unknown", None)
                if resolver is None:
                    counters["rejected"] += 1
                    continue
                resolver(item.authority_id, False)
                self.queue.resolve(item.authority_id)
                counters["resolved_failure"] += 1
            elif result.status is ReconciliationStatus.NOT_FOUND:
                rearm = getattr(self.store, "rearm", None)
                if rearm is None:
                    counters["rejected"] += 1
                    continue
                rearm(item.authority_id)
                self.queue.resolve(item.authority_id)
                counters["reopened_for_retry"] += 1
            else:
                counters["still_unknown"] += 1
        return ReconciliationReport(**counters)
