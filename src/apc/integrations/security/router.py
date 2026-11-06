from __future__ import annotations

from collections.abc import Iterable

from .contract.adapter import SecurityEventAdapter
from .contract.event import SecurityEvent
from .outbox import DurableOutbox


class SecurityEventRouter:
    """Fan-out router with an outbox.

    Evidence is emitted independently of SIEM availability.
    """

    def __init__(
        self, adapters: Iterable[SecurityEventAdapter], outbox: DurableOutbox | None = None
    ):
        self.adapters: list[SecurityEventAdapter] = list(adapters)
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
