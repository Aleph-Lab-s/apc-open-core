from __future__ import annotations

from threading import Lock

from ..contract.event import SecurityEvent


class InMemorySink:
    name = "memory"

    def __init__(self) -> None:
        self._events: list[SecurityEvent] = []
        self._lock = Lock()

    def send(self, event: SecurityEvent) -> None:
        with self._lock:
            self._events.append(event)

    def health(self) -> bool:
        return True

    @property
    def events(self) -> list[SecurityEvent]:
        with self._lock:
            return list(self._events)
