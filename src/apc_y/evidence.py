from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timezone
from typing import Any

from .canonical import canonical_json
from .errors import APCError, APCErrorCode
from .models import APCModel


GENESIS_HASH = "0" * 64


class EvidenceRecord(APCModel):
    """
    Immutable post-action APC evidence record.

    This is NOT an authority artifact.

    It records facts observed after APC verification and/or
    executor completion.

    The record is linked cryptographically to the previous
    record through previous_hash.
    """

    sequence: int

    record_id: str

    invocation_id: str
    authority_id: str

    candidate_act_digest: str

    executing_actor_id: str

    event_type: str

    timestamp: datetime

    outcome: str

    execution_reference: str | None = None

    metadata: dict[str, Any]

    previous_hash: str

    record_hash: str


def _record_payload(
    *,
    sequence: int,
    record_id: str,
    invocation_id: str,
    authority_id: str,
    candidate_act_digest: str,
    executing_actor_id: str,
    event_type: str,
    timestamp: datetime,
    outcome: str,
    execution_reference: str | None,
    metadata: dict[str, Any],
    previous_hash: str,
) -> dict[str, Any]:

    return {
        "sequence": sequence,
        "record_id": record_id,
        "invocation_id": invocation_id,
        "authority_id": authority_id,
        "candidate_act_digest": candidate_act_digest,
        "executing_actor_id": executing_actor_id,
        "event_type": event_type,
        "timestamp": timestamp.isoformat(),
        "outcome": outcome,
        "execution_reference": execution_reference,
        "metadata": metadata,
        "previous_hash": previous_hash,
    }


def _hash_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json(payload)
    ).hexdigest()


class EvidenceChain:
    """
    Thread-safe append-only in-memory evidence chain.

    Production deployments should replace this storage with
    durable append-only infrastructure.

    Security properties provided here:

    - immutable records
    - continuous sequence numbers
    - previous-hash linkage
    - deterministic hash verification
    - tamper detection

    Security properties NOT claimed:

    - physical storage immutability
    - proof an external system actually performed an effect
    - root authority creation
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._records: list[EvidenceRecord] = []

    def append(
        self,
        *,
        record_id: str,
        invocation_id: str,
        authority_id: str,
        candidate_act_digest: str,
        executing_actor_id: str,
        event_type: str,
        outcome: str,
        execution_reference: str | None = None,
        metadata: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> EvidenceRecord:

        if not record_id or not record_id.strip():
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "record_id must be non-empty",
            )

        if not invocation_id or not invocation_id.strip():
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "invocation_id must be non-empty",
            )

        if not authority_id or not authority_id.strip():
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "authority_id must be non-empty",
            )

        if not candidate_act_digest or not candidate_act_digest.strip():
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "candidate_act_digest must be non-empty",
            )

        if not executing_actor_id or not executing_actor_id.strip():
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "executing_actor_id must be non-empty",
            )

        if not event_type or not event_type.strip():
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "event_type must be non-empty",
            )

        if not outcome or not outcome.strip():
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "outcome must be non-empty",
            )

        timestamp = timestamp or datetime.now(timezone.utc)

        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "Evidence timestamp must be timezone-aware",
            )

        metadata = metadata or {}

        with self._lock:

            sequence = len(self._records) + 1

            previous_hash = (
                self._records[-1].record_hash
                if self._records
                else GENESIS_HASH
            )

            payload = _record_payload(
                sequence=sequence,
                record_id=record_id,
                invocation_id=invocation_id,
                authority_id=authority_id,
                candidate_act_digest=candidate_act_digest,
                executing_actor_id=executing_actor_id,
                event_type=event_type,
                timestamp=timestamp,
                outcome=outcome,
                execution_reference=execution_reference,
                metadata=metadata,
                previous_hash=previous_hash,
            )

            record_hash = _hash_payload(payload)

            record = EvidenceRecord(
                sequence=sequence,
                record_id=record_id,
                invocation_id=invocation_id,
                authority_id=authority_id,
                candidate_act_digest=candidate_act_digest,
                executing_actor_id=executing_actor_id,
                event_type=event_type,
                timestamp=timestamp,
                outcome=outcome,
                execution_reference=execution_reference,
                metadata=metadata,
                previous_hash=previous_hash,
                record_hash=record_hash,
            )

            self._records.append(record)

            return record

    def records(self) -> tuple[EvidenceRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def head_hash(self) -> str:
        with self._lock:
            if not self._records:
                return GENESIS_HASH

            return self._records[-1].record_hash

    def verify(self) -> None:
        """
        Verify the entire evidence chain.

        Detects:

        - sequence gaps
        - modified record contents
        - broken previous_hash links
        - reordered records
        """

        with self._lock:

            expected_previous_hash = GENESIS_HASH
            expected_sequence = 1

            for record in self._records:

                if record.sequence != expected_sequence:
                    raise APCError(
                        APCErrorCode.INVALID_AUTHORITY,
                        "Evidence sequence gap or reordering detected",
                    )

                if record.previous_hash != expected_previous_hash:
                    raise APCError(
                        APCErrorCode.INVALID_AUTHORITY,
                        "Evidence previous_hash mismatch detected",
                    )

                payload = _record_payload(
                    sequence=record.sequence,
                    record_id=record.record_id,
                    invocation_id=record.invocation_id,
                    authority_id=record.authority_id,
                    candidate_act_digest=record.candidate_act_digest,
                    executing_actor_id=record.executing_actor_id,
                    event_type=record.event_type,
                    timestamp=record.timestamp,
                    outcome=record.outcome,
                    execution_reference=record.execution_reference,
                    metadata=record.metadata,
                    previous_hash=record.previous_hash,
                )

                expected_hash = _hash_payload(payload)

                if record.record_hash != expected_hash:
                    raise APCError(
                        APCErrorCode.INVALID_AUTHORITY,
                        "Evidence record hash mismatch detected",
                    )

                expected_previous_hash = record.record_hash
                expected_sequence += 1

    def find_by_invocation(
        self,
        invocation_id: str,
    ) -> tuple[EvidenceRecord, ...]:

        with self._lock:
            return tuple(
                record
                for record in self._records
                if record.invocation_id == invocation_id
            )
