from __future__ import annotations

import json
import sqlite3
import time
import uuid
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
from typing import Any

from .sinks import EffectReceipt, SinkDescriptor


class SQLiteProtectedSink:
    """A real local protected sink for APC evaluation labs.

    This sink performs an actual durable SQLite write, but never reaches an
    external customer/provider system. Idempotency is enforced by a UNIQUE
    database constraint and reconciliation is an authoritative local lookup.
    """

    def __init__(
        self, path: str | Path, *, sink_id: str = "lab.sqlite", audience: str = "lab.sqlite"
    ) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self.descriptor = SinkDescriptor(
            sink_id=sink_id,
            audience=audience,
            provider="sqlite-lab",
            operations=("*",),
            mode="SANDBOX",
            protected=True,
            supports_idempotency=True,
            supports_reconciliation=True,
        )
        self._init()
        self.simulate_unknown_after_commit = False
        self.simulate_failure_before_commit = False

    @property
    def supports_idempotency(self) -> bool:
        return self.descriptor.supports_idempotency

    @property
    def supports_outcome_reconciliation(self) -> bool:
        return self.descriptor.supports_reconciliation

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15, isolation_level="IMMEDIATE")
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init(self) -> None:
        with self._connection() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS apc_protected_effects(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    operation TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    parameters_json TEXT NOT NULL,
                    provider_reference TEXT NOT NULL UNIQUE,
                    created_at REAL NOT NULL
                )"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_apc_effect_resource ON apc_protected_effects(resource)"
            )

    def execute(
        self, operation: str, parameters: Mapping[str, Any], idempotency_key: str
    ) -> EffectReceipt:
        if not operation.strip():
            raise ValueError("operation is required")
        if not idempotency_key.strip():
            raise ValueError("idempotency_key is required")
        with self._lock, self._connection() as conn:
            if self.simulate_failure_before_commit:
                raise RuntimeError("lab sink fault injected before commit")
            row = conn.execute(
                "SELECT * FROM apc_protected_effects WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if row is not None:
                return EffectReceipt(
                    status="SUCCESS",
                    provider_reference=row["provider_reference"],
                    idempotency_key=idempotency_key,
                    sink_id=self.descriptor.sink_id,
                    evidence={
                        "environment": "SANDBOX",
                        "deduplicated": True,
                        "effect_performed": True,
                    },
                )
            provider_reference = "lab-" + uuid.uuid4().hex
            conn.execute(
                "INSERT INTO apc_protected_effects(idempotency_key,operation,resource,parameters_json,provider_reference,created_at) VALUES(?,?,?,?,?,?)",
                (
                    idempotency_key,
                    operation,
                    str(parameters.get("resource", "")),
                    json.dumps(dict(parameters), sort_keys=True, separators=(",", ":")),
                    provider_reference,
                    time.time(),
                ),
            )
            if self.simulate_unknown_after_commit:
                return EffectReceipt(
                    status="UNKNOWN",
                    provider_reference=None,
                    idempotency_key=idempotency_key,
                    sink_id=self.descriptor.sink_id,
                    evidence={
                        "environment": "SANDBOX",
                        "effect_committed": True,
                        "response_lost": True,
                    },
                )
            return EffectReceipt(
                status="SUCCESS",
                provider_reference=provider_reference,
                idempotency_key=idempotency_key,
                sink_id=self.descriptor.sink_id,
                evidence={
                    "environment": "SANDBOX",
                    "effect_performed": True,
                    "deduplicated": False,
                },
            )

    def reconcile(self, idempotency_key: str) -> EffectReceipt | None:
        with self._lock, self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM apc_protected_effects WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if row is None:
                return EffectReceipt(
                    status="UNKNOWN",
                    provider_reference=None,
                    idempotency_key=idempotency_key,
                    sink_id=self.descriptor.sink_id,
                    evidence={
                        "environment": "SANDBOX",
                        "authoritative_lookup": True,
                        "present": False,
                    },
                )
            return EffectReceipt(
                status="SUCCESS",
                provider_reference=row["provider_reference"],
                idempotency_key=idempotency_key,
                sink_id=self.descriptor.sink_id,
                evidence={"environment": "SANDBOX", "authoritative_lookup": True, "present": True},
            )

    def count(self) -> int:
        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM apc_protected_effects").fetchone()
            return int(row[0])

    def effects(self) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM apc_protected_effects ORDER BY id").fetchall()
        return [dict(r) for r in rows]
