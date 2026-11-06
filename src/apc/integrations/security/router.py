from __future__ import annotations

from typing import Iterable, List
from .contract.event import SecurityEvent
from .contract.adapter import SecurityEventAdapter
from .outbox import DurableOutbox


class SecurityEventRouter:
    """Fan-out router with an outbox.

    Evidence is emitted independently of SIEM availability.
    """

    def __init__(self, adapters: Iterable[SecurityEventAdapter], outbox: DurableOutbox | None = None):
        self.adapters: List[SecurityEventAdapter] = list(adapters)
        self.outbox = outbox or DurableOutbox()

    def emit(self, event: SecurityEvent) -> None:
        # First establish durable local delivery intent.
        self.outbox.append(event)

    def flush(self) -> dict:
        result = {}
        for adapter in self.adapters:
            ok, failed = self.outbox.deliver(adapter)
            result[adapter.name] = {"delivered": ok, "failed": failed}
        return result
