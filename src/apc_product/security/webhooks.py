from __future__ import annotations

import base64
import hashlib
import hmac
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class WebhookVerificationResult:
    valid: bool
    reason: str
    event_id: str


class ReplayCache:
    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = ttl_seconds
        self._items: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_record(self, event_id: str, now: float | None = None) -> bool:
        now = now or time.time()
        with self._lock:
            expired = [k for k, ts in self._items.items() if now - ts > self.ttl_seconds]
            for k in expired:
                self._items.pop(k, None)
            if event_id in self._items:
                return False
            self._items[event_id] = now
            return True


def verify_hmac_webhook(
    *,
    body: bytes,
    signature_b64: str,
    secret: bytes,
    event_id: str,
    timestamp: int,
    replay_cache: ReplayCache,
    tolerance_seconds: int = 300,
) -> WebhookVerificationResult:
    if abs(int(time.time()) - int(timestamp)) > tolerance_seconds:
        return WebhookVerificationResult(False, "timestamp_outside_tolerance", event_id)
    try:
        expected = hmac.new(secret, str(timestamp).encode() + b"." + body, hashlib.sha256).digest()
        provided = base64.urlsafe_b64decode(signature_b64.encode("ascii"))
    except Exception:
        return WebhookVerificationResult(False, "malformed_signature", event_id)
    if not hmac.compare_digest(expected, provided):
        return WebhookVerificationResult(False, "signature_mismatch", event_id)
    if not replay_cache.check_and_record(event_id):
        return WebhookVerificationResult(False, "replay_detected", event_id)
    return WebhookVerificationResult(True, "verified", event_id)
