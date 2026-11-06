from __future__ import annotations

from typing import Protocol

from .event import SecurityEvent


class SecurityEventAdapter(Protocol):
    """Destination adapter contract.

    Implementations should be transport adapters, not authorization components.
    """

    name: str

    def send(self, event: SecurityEvent) -> None: ...

    def health(self) -> bool: ...
