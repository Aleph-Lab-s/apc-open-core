from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True)
class SecurityEvent:
    event_type: str
    severity: str
    tenant: str
    authority_id: str | None
    invocation_id: str | None
    timestamp: datetime
    attributes: dict[str, Any]


class SecurityEventSink(Protocol):
    def emit(self, event: SecurityEvent) -> None: ...


class MemorySecurityEventSink:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)
