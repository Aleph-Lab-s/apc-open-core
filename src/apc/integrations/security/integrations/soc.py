from __future__ import annotations

from typing import Callable
from ..contract.event import SecurityEvent


class GenericSOCAdapter:
    """Vendor-neutral SOC/SOAR integration contract."""

    name = "generic-soc"

    def __init__(self, send_event: Callable[[dict], None]) -> None:
        self._send_event = send_event

    def send(self, event: SecurityEvent) -> None:
        self._send_event(event.to_dict())

    def health(self) -> bool:
        return True
