import json
from ..contract.event import SecurityEvent


class StdoutJsonSink:
    name = "stdout-json"

    def send(self, event: SecurityEvent) -> None:
        print(json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")))

    def health(self) -> bool:
        return True
