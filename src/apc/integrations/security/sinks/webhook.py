from __future__ import annotations

import json
from typing import Callable
from ..contract.event import SecurityEvent


class WebhookSink:
    """Generic HTTP/webhook adapter.

    The transport callable is injected so production deployments can use their
    approved HTTP client, TLS configuration, authentication and retry policy.
    """

    name = "webhook"

    def __init__(self, send_json: Callable[[dict], None]) -> None:
        self._send_json = send_json

    def send(self, event: SecurityEvent) -> None:
        self._send_json(event.to_dict())

    def health(self) -> bool:
        return True
