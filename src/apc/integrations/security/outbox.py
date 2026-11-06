from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import List, Tuple
from .contract.event import SecurityEvent
from .contract.adapter import SecurityEventAdapter


@dataclass
class OutboxRecord:
    event: SecurityEvent
    attempts: int = 0
    delivered: bool = False
    last_error: str | None = None


class DurableOutbox:
    """Reference outbox.

    Replace storage with the deployment's durable transactional database.
    Crucially, delivery failure does not change APC authorization semantics.
    """

    def __init__(self) -> None:
        self._records: List[OutboxRecord] = []
        self._lock = Lock()

    def append(self, event: SecurityEvent) -> None:
        with self._lock:
            self._records.append(OutboxRecord(event=event))

    def pending(self) -> List[OutboxRecord]:
        with self._lock:
            return [r for r in self._records if not r.delivered]

    def deliver(self, adapter: SecurityEventAdapter) -> Tuple[int, int]:
        delivered = failed = 0
        for record in self.pending():
            try:
                record.attempts += 1
                adapter.send(record.event)
                record.delivered = True
                record.last_error = None
                delivered += 1
            except Exception as exc:
                record.last_error = repr(exc)
                failed += 1
        return delivered, failed
