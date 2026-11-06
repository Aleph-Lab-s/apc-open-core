from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from ..contract.event import SecurityEvent


class JsonLinesFileSink:
    name = "jsonl-file"

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def send(self, event: SecurityEvent) -> None:
        line = json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"))
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\\n")

    def health(self) -> bool:
        return True
