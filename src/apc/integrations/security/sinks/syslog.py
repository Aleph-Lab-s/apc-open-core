from __future__ import annotations

import json
import logging

from ..contract.event import SecurityEvent


class SyslogSink:
    name = "syslog"

    def __init__(self, logger_name: str = "apc.security") -> None:
        self._logger = logging.getLogger(logger_name)

    def send(self, event: SecurityEvent) -> None:
        self._logger.warning(json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")))

    def health(self) -> bool:
        return True
