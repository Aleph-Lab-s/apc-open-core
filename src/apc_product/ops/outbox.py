from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Any
import uuid

from apc_product.store import Store


@dataclass(frozen=True)
class OutboxFlushResult:
    examined: int
    delivered: int
    failed: int


class DurableSecurityEventWorker:
    """Transactional-outbox delivery worker for APC security events.

    The worker deliberately sits outside authorization/finality. Destination
    outage changes delivery state only; it must not change the protected-effect
    decision.
    """

    def __init__(self, store: Store, worker_id: str | None = None):
        self.store = store
        self.worker_id = worker_id or ("outbox-worker-" + uuid.uuid4().hex)

    def flush(self, deliver: Callable[[dict[str, Any]], None], *, limit: int = 100) -> OutboxFlushResult:
        rows = self.store.claim_outbox(self.worker_id, limit=limit)
        delivered = failed = 0
        for event in rows:
            try:
                deliver(event)
            except Exception as exc:
                self.store.mark_outbox_failed(event["event_id"], repr(exc), worker_id=self.worker_id)
                failed += 1
            else:
                self.store.mark_outbox_delivered(event["event_id"], worker_id=self.worker_id)
                delivered += 1
        return OutboxFlushResult(len(rows), delivered, failed)
