from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from typing import Protocol

from .errors import APCError, APCErrorCode
from .flagship import AuthorityV2, _iso

STATES = {
    "ACTIVE",
    "RESERVED",
    "EXECUTING",
    "EFFECTED",
    "FAILED",
    "UNKNOWN",
    "EXPIRED",
    "REVOKED",
    "ABORTED",
}


class AuthorityStateStore(Protocol):
    def register(self, authority: AuthorityV2) -> None: ...
    def reserve(self, authority_id: str) -> None: ...
    def complete(self, authority_id: str, success: bool, unknown: bool = False) -> None: ...
    def resolve_unknown(self, authority_id: str, success: bool) -> None: ...
    def rearm(self, authority_id: str) -> None: ...
    def state(self, authority_id: str) -> str | None: ...
    def mark_unknown(self, authority_id: str) -> None: ...


class PostgresAuthorityStore:
    """Production adapter contract using psycopg 3. The caller owns connection pooling/TLS.

    The SQL uses row locks so only one process can reserve an authority. No provider
    credentials or customer secrets belong in this class.
    """

    def __init__(self, conn):
        self.conn = conn
        self._init()

    def _init(self):
        with self.conn.cursor() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS apc_authorities (
              authority_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, state TEXT NOT NULL,
              payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ NULL,
              CHECK (state IN ('ACTIVE','RESERVED','EXECUTING','EFFECTED','FAILED','UNKNOWN','EXPIRED','REVOKED','ABORTED'))
            )""")
        self.conn.commit()

    def register(self, authority: AuthorityV2):
        with self.conn.cursor() as c:
            c.execute(
                "INSERT INTO apc_authorities(authority_id,tenant,state,payload,created_at) VALUES(%s,%s,%s,%s::jsonb,%s)",
                (
                    authority.authority_id,
                    authority.context.tenant,
                    "ACTIVE",
                    json.dumps(authority.payload()),
                    authority.issued_at,
                ),
            )
        self.conn.commit()

    def reserve(self, authority_id: str):
        with self.conn.cursor() as c:
            c.execute("BEGIN")
            c.execute(
                "SELECT state FROM apc_authorities WHERE authority_id=%s FOR UPDATE",
                (authority_id,),
            )
            row = c.fetchone()
            if not row:
                self.conn.rollback()
                raise APCError(APCErrorCode.REVOKED_AUTHORITY, "authority missing")
            state = row[0]
            if state != "ACTIVE":
                self.conn.rollback()
                raise APCError(
                    APCErrorCode.REPLAYED_AUTHORITY
                    if state in {"RESERVED", "EXECUTING", "EFFECTED", "UNKNOWN"}
                    else APCErrorCode.REVOKED_AUTHORITY,
                    f"authority cannot be reserved: {state}",
                )
            c.execute(
                "UPDATE apc_authorities SET state='EXECUTING' WHERE authority_id=%s",
                (authority_id,),
            )
            self.conn.commit()

    def complete(self, authority_id: str, success: bool, unknown: bool = False):
        state = "UNKNOWN" if unknown else ("EFFECTED" if success else "FAILED")
        with self.conn.cursor() as c:
            c.execute(
                "UPDATE apc_authorities SET state=%s, consumed_at=NOW() WHERE authority_id=%s AND state='EXECUTING'",
                (state, authority_id),
            )
        self.conn.commit()

    def resolve_unknown(self, authority_id: str, success: bool):
        state = "EFFECTED" if success else "FAILED"
        with self.conn.cursor() as c:
            c.execute(
                "UPDATE apc_authorities SET state=%s, consumed_at=NOW() WHERE authority_id=%s AND state='UNKNOWN'",
                (state, authority_id),
            )
            if c.rowcount != 1:
                self.conn.rollback()
                raise APCError(
                    APCErrorCode.INVALID_EVIDENCE, f"authority is not UNKNOWN: {authority_id}"
                )
        self.conn.commit()

    def rearm(self, authority_id: str):
        with self.conn.cursor() as c:
            c.execute(
                "UPDATE apc_authorities SET state='ACTIVE', consumed_at=NULL WHERE authority_id=%s AND state='UNKNOWN'",
                (authority_id,),
            )
            if c.rowcount != 1:
                self.conn.rollback()
                raise APCError(
                    APCErrorCode.INVALID_EVIDENCE, f"authority is not UNKNOWN: {authority_id}"
                )
        self.conn.commit()

    def mark_unknown(self, authority_id: str):
        self.complete(authority_id, False, True)

    def state(self, authority_id: str):
        with self.conn.cursor() as c:
            c.execute("SELECT state FROM apc_authorities WHERE authority_id=%s", (authority_id,))
            r = c.fetchone()
            return r[0] if r else None


@dataclass(frozen=True)
class ReconciliationItem:
    authority_id: str
    idempotency_key: str
    sink_id: str
    reason: str


class DurableReconciliationQueue:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.lock = threading.RLock()
        self._closed = False
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS reconciliation(authority_id TEXT PRIMARY KEY,idempotency_key TEXT NOT NULL,sink_id TEXT NOT NULL,reason TEXT NOT NULL,created_at TEXT NOT NULL,resolved_at TEXT)"
        )

    def close(self):
        with self.lock:
            if not self._closed:
                self.db.close()
                self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def enqueue(self, item: ReconciliationItem):
        with self.lock:
            self.db.execute(
                "INSERT OR IGNORE INTO reconciliation VALUES(?,?,?,?,?,NULL)",
                (
                    item.authority_id,
                    item.idempotency_key,
                    item.sink_id,
                    item.reason,
                    _iso(__import__("datetime").datetime.now(__import__("datetime").timezone.utc)),
                ),
            )

    def pending(self):
        rows = self.db.execute(
            "SELECT authority_id,idempotency_key,sink_id,reason FROM reconciliation WHERE resolved_at IS NULL ORDER BY created_at"
        ).fetchall()
        return [ReconciliationItem(*r) for r in rows]

    def resolve(self, authority_id):
        with self.lock:
            self.db.execute(
                "UPDATE reconciliation SET resolved_at=? WHERE authority_id=? AND resolved_at IS NULL",
                (
                    _iso(__import__("datetime").datetime.now(__import__("datetime").timezone.utc)),
                    authority_id,
                ),
            )
