from __future__ import annotations

import threading

from .errors import APCError, APCErrorCode


class AuthorityStateStore:
    """
    Thread-safe authority lifecycle store.

    Tracks:
    - revoked authorities
    - consumed authorities

    The check-and-consume operation is atomic so concurrent
    attempts cannot both consume the same single-use authority.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._revoked: set[str] = set()
        self._consumed: set[str] = set()

    def revoke(self, authority_id: str) -> None:
        with self._lock:
            self._revoked.add(authority_id)

    def is_revoked(self, authority_id: str) -> bool:
        with self._lock:
            return authority_id in self._revoked

    def is_consumed(self, authority_id: str) -> bool:
        with self._lock:
            return authority_id in self._consumed

    def assert_not_revoked(self, authority_id: str) -> None:
        with self._lock:
            if authority_id in self._revoked:
                raise APCError(
                    APCErrorCode.REVOKED_AUTHORITY,
                    "Authority has been revoked",
                )

    def consume(self, authority_id: str, *, single_use: bool) -> None:
        """
        Atomically checks lifecycle state and consumes the authority.

        If single_use=False, the authority is not recorded as consumed.
        Revocation always blocks.
        """

        with self._lock:

            if authority_id in self._revoked:
                raise APCError(
                    APCErrorCode.REVOKED_AUTHORITY,
                    "Authority has been revoked",
                )

            if single_use:

                if authority_id in self._consumed:
                    raise APCError(
                        APCErrorCode.REPLAYED_AUTHORITY,
                        "Authority has already been consumed",
                    )

                self._consumed.add(authority_id)

    def snapshot(self) -> dict[str, set[str]]:
        with self._lock:
            return {
                "revoked": set(self._revoked),
                "consumed": set(self._consumed),
            }
