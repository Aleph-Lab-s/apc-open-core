from __future__ import annotations

from collections.abc import Callable

from ..contract.event import SecurityEvent


class GenericSIEMAdapter:
    """Vendor-neutral SIEM adapter.

    The injected transport should implement the organization's approved
    ingestion API, TLS, authentication, timeout and retry controls.
    """

    name = "generic-siem"

    def __init__(self, send_event: Callable[[dict], None]) -> None:
        self._send_event = send_event

    def send(self, event: SecurityEvent) -> None:
        self._send_event(event.to_dict())

    def health(self) -> bool:
        return True
