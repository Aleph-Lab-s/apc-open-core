"""Local durable product-control store for single-node evaluation environments.

SQLite is intentionally scoped to local/reference operation. The important
product invariant here is that action state and its audit/outbox event are
committed in the same transaction so a crash cannot silently separate them.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from contextlib import contextmanager


class IdempotencyConflictError(ValueError):
    """Raised when an idempotency key is reused for a different request."""


class Store:
    def __init__(self, path: str = "./var/apc-product.db"):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._closed = False
        with self._connection() as c:
            c.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS actions(
                  action_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, status TEXT NOT NULL,
                  request_json TEXT NOT NULL, result_json TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events(
                  seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL, tenant TEXT NOT NULL,
                  action_id TEXT, kind TEXT NOT NULL, payload_json TEXT NOT NULL,
                  previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL, created_at REAL NOT NULL, delivered_at REAL
                );
                CREATE TABLE IF NOT EXISTS outbox(
                  event_id TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
                  last_error TEXT, lease_owner TEXT, lease_until REAL
                );
                CREATE TABLE IF NOT EXISTS idempotency_keys(
                  tenant TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_digest TEXT NOT NULL,
                  action_id TEXT NOT NULL UNIQUE, created_at REAL NOT NULL,
                  PRIMARY KEY(tenant, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS idx_idempotency_action ON idempotency_keys(action_id);
                """
            )
            # Lightweight migration for evaluation databases created by the
            # prior schema version. SQLite has no IF NOT EXISTS form for ADD
            # COLUMN, so inspect first.
            columns = {row[1] for row in c.execute("PRAGMA table_info(outbox)").fetchall()}
            if "lease_owner" not in columns:
                c.execute("ALTER TABLE outbox ADD COLUMN lease_owner TEXT")
            if "lease_until" not in columns:
                c.execute("ALTER TABLE outbox ADD COLUMN lease_until REAL")

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError("APC product store is closed")

    def _connect(self) -> sqlite3.Connection:
        self._check_open()
        c = sqlite3.connect(self.path, timeout=15, isolation_level="IMMEDIATE")
        c.row_factory = sqlite3.Row
        return c

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _request_digest(request: dict[str, Any]) -> str:
        return hashlib.sha256(
            json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()

    @staticmethod
    def _event_digest(body: dict[str, Any]) -> str:
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()

    def _append_event_tx(
        self,
        c: sqlite3.Connection,
        *,
        tenant: str,
        kind: str,
        payload: dict[str, Any],
        action_id: str | None,
        now: float,
    ) -> dict[str, Any]:
        event_id = str(uuid.uuid4())
        row = c.execute("SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        previous_hash = row[0] if row else "0" * 64
        body = {
            "event_id": event_id,
            "tenant": tenant,
            "action_id": action_id,
            "kind": kind,
            "payload": payload,
            "previous_hash": previous_hash,
            "created_at": now,
        }
        event_hash = self._event_digest(body)
        c.execute(
            "INSERT INTO events(event_id,tenant,action_id,kind,payload_json,previous_hash,event_hash,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                event_id,
                tenant,
                action_id,
                kind,
                json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
                previous_hash,
                event_hash,
                now,
            ),
        )
        c.execute("INSERT INTO outbox(event_id) VALUES(?)", (event_id,))
        return {**body, "event_hash": event_hash}

    def emit(self, tenant: str, kind: str, payload: dict[str, Any], action_id: str | None = None) -> dict[str, Any]:
        with self._lock, self._connection() as c:
            now = time.time()
            return self._append_event_tx(
                c,
                tenant=tenant,
                kind=kind,
                payload=payload,
                action_id=action_id,
                now=now,
            )

    def create_action(self, tenant: str, request: dict[str, Any]) -> dict[str, Any]:
        aid = str(uuid.uuid4())
        now = time.time()
        with self._lock, self._connection() as c:
            c.execute(
                "INSERT INTO actions VALUES(?,?,?,?,?,?,?)",
                (aid, tenant, "RECEIVED", json.dumps(request, ensure_ascii=False), None, now, now),
            )
            self._append_event_tx(
                c,
                tenant=tenant,
                kind="ACTION_RECEIVED",
                payload={"request_digest": self._request_digest(request)},
                action_id=aid,
                now=now,
            )
        return self.get_action(aid)

    def create_action_idempotent(self, tenant: str, request: dict[str, Any], idempotency_key: str) -> tuple[dict[str, Any], bool]:
        """Atomically bind a client retry key to exactly one action per tenant."""
        key = str(idempotency_key or "").strip()
        if not key:
            raise ValueError("idempotency key is required")
        if len(key) > 256 or any(ord(ch) < 32 or ord(ch) == 127 for ch in key):
            raise ValueError("idempotency key is invalid or too long")
        digest = self._request_digest(request)
        with self._lock, self._connection() as c:
            existing = c.execute(
                "SELECT request_digest, action_id FROM idempotency_keys WHERE tenant=? AND idempotency_key=?",
                (tenant, key),
            ).fetchone()
            if existing is not None:
                if existing[0] != digest:
                    raise IdempotencyConflictError("idempotency key is already bound to a different request")
                return self.get_action(existing[1]), True
            aid = str(uuid.uuid4())
            now = time.time()
            c.execute(
                "INSERT INTO actions VALUES(?,?,?,?,?,?,?)",
                (aid, tenant, "RECEIVED", json.dumps(request, ensure_ascii=False), None, now, now),
            )
            c.execute(
                "INSERT INTO idempotency_keys(tenant,idempotency_key,request_digest,action_id,created_at) VALUES(?,?,?,?,?)",
                (tenant, key, digest, aid, now),
            )
            self._append_event_tx(
                c, tenant=tenant, kind="ACTION_RECEIVED",
                payload={"request_digest": digest, "idempotency_key_digest": hashlib.sha256(key.encode()).hexdigest()},
                action_id=aid, now=now,
            )
        return self.get_action(aid), False

    def update_action(self, aid: str, status: str, result: dict | None = None) -> dict[str, Any]:
        now = time.time()
        with self._lock, self._connection() as c:
            row = c.execute("SELECT tenant FROM actions WHERE action_id=?", (aid,)).fetchone()
            if not row:
                raise KeyError(aid)
            c.execute(
                "UPDATE actions SET status=?,result_json=?,updated_at=? WHERE action_id=?",
                (status, json.dumps(result, ensure_ascii=False) if result is not None else None, now, aid),
            )
            self._append_event_tx(
                c,
                tenant=row[0],
                kind="ACTION_" + status,
                payload={"status": status, "result": result},
                action_id=aid,
                now=now,
            )
        return self.get_action(aid)

    def get_action(self, aid: str) -> dict[str, Any] | None:
        with self._connection() as c:
            row = c.execute("SELECT * FROM actions WHERE action_id=?", (aid,)).fetchone()
        if not row:
            return None
        return {
            "action_id": row["action_id"],
            "tenant": row["tenant"],
            "status": row["status"],
            "request": json.loads(row["request_json"]),
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def events(self, tenant: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self._connection() as c:
            rows = (
                c.execute(
                    "SELECT * FROM events WHERE tenant=? ORDER BY seq DESC LIMIT ?", (tenant, limit)
                ).fetchall()
                if tenant
                else c.execute("SELECT * FROM events ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
            )
        return [
            {
                "seq": r["seq"],
                "event_id": r["event_id"],
                "tenant": r["tenant"],
                "action_id": r["action_id"],
                "kind": r["kind"],
                "payload": json.loads(r["payload_json"]),
                "previous_hash": r["previous_hash"],
                "event_hash": r["event_hash"],
                "created_at": r["created_at"],
                "delivered_at": r["delivered_at"],
            }
            for r in rows
        ]


    def claim_outbox(self, worker_id: str, limit: int = 100, lease_seconds: float = 30.0) -> list[dict[str, Any]]:
        """Atomically lease due outbox records to one delivery worker."""
        if not worker_id.strip():
            raise ValueError("worker_id is required")
        limit = max(1, min(int(limit), 1000))
        now = time.time()
        lease_until = now + max(1.0, min(float(lease_seconds), 3600.0))
        with self._lock, self._connection() as c:
            rows = c.execute(
                "SELECT e.*, o.attempts, o.next_attempt, o.last_error "
                "FROM outbox o JOIN events e ON e.event_id=o.event_id "
                "WHERE e.delivered_at IS NULL AND o.next_attempt <= ? "
                "AND (o.lease_until IS NULL OR o.lease_until < ?) "
                "ORDER BY e.seq ASC LIMIT ?",
                (now, now, limit),
            ).fetchall()
            event_ids = [r["event_id"] for r in rows]
            for event_id in event_ids:
                c.execute(
                    "UPDATE outbox SET lease_owner=?, lease_until=? WHERE event_id=? "
                    "AND (lease_until IS NULL OR lease_until < ?)",
                    (worker_id, lease_until, event_id, now),
                )
            claimed = []
            for r in rows:
                chk = c.execute("SELECT lease_owner, lease_until FROM outbox WHERE event_id=?", (r["event_id"],)).fetchone()
                if not chk or chk[0] != worker_id:
                    continue
                claimed.append({
                    "event_id": r["event_id"],
                    "tenant": r["tenant"],
                    "action_id": r["action_id"],
                    "kind": r["kind"],
                    "payload": json.loads(r["payload_json"]),
                    "previous_hash": r["previous_hash"],
                    "event_hash": r["event_hash"],
                    "created_at": r["created_at"],
                    "attempts": r["attempts"],
                    "next_attempt": r["next_attempt"],
                    "last_error": r["last_error"],
                    "lease_owner": worker_id,
                    "lease_until": chk[1],
                })
            return claimed

    def pending_outbox(self, limit: int = 100) -> list[dict[str, Any]]:
        """Inspect due, currently unleased security events without claiming them."""
        limit = max(1, min(int(limit), 1000))
        now = time.time()
        with self._connection() as c:
            rows = c.execute(
                "SELECT e.*, o.attempts, o.next_attempt, o.last_error, o.lease_owner, o.lease_until "
                "FROM outbox o JOIN events e ON e.event_id=o.event_id "
                "WHERE e.delivered_at IS NULL AND o.next_attempt <= ? "
                "AND (o.lease_until IS NULL OR o.lease_until < ?) "
                "ORDER BY e.seq ASC LIMIT ?",
                (now, now, limit),
            ).fetchall()
        return [
            {
                "event_id": r["event_id"], "tenant": r["tenant"], "action_id": r["action_id"],
                "kind": r["kind"], "payload": json.loads(r["payload_json"]),
                "previous_hash": r["previous_hash"], "event_hash": r["event_hash"],
                "created_at": r["created_at"], "attempts": r["attempts"],
                "next_attempt": r["next_attempt"], "last_error": r["last_error"],
                "lease_owner": r["lease_owner"], "lease_until": r["lease_until"],
            }
            for r in rows
        ]

    def mark_outbox_delivered(self, event_id: str, *, worker_id: str | None = None) -> None:
        with self._lock, self._connection() as c:
            now = time.time()
            if worker_id is None:
                c.execute("UPDATE events SET delivered_at=? WHERE event_id=? AND delivered_at IS NULL", (now, event_id))
                c.execute("DELETE FROM outbox WHERE event_id=?", (event_id,))
            else:
                c.execute(
                    "UPDATE events SET delivered_at=? WHERE event_id=? AND delivered_at IS NULL "
                    "AND EXISTS (SELECT 1 FROM outbox WHERE event_id=? AND lease_owner=?)",
                    (now, event_id, event_id, worker_id),
                )
                c.execute("DELETE FROM outbox WHERE event_id=? AND lease_owner=?", (event_id, worker_id))

    def mark_outbox_failed(self, event_id: str, error: str, *, base_delay: float = 1.0, worker_id: str | None = None) -> None:
        with self._lock, self._connection() as c:
            row = c.execute("SELECT attempts FROM outbox WHERE event_id=?", (event_id,)).fetchone()
            if not row:
                raise KeyError(event_id)
            attempts = int(row[0]) + 1
            delay = min(float(base_delay) * (2 ** min(attempts - 1, 10)), 3600.0)
            if worker_id is None:
                c.execute(
                    "UPDATE outbox SET attempts=?, next_attempt=?, last_error=?, lease_owner=NULL, lease_until=NULL WHERE event_id=?",
                    (attempts, time.time() + delay, str(error)[:2000], event_id),
                )
            else:
                c.execute(
                    "UPDATE outbox SET attempts=?, next_attempt=?, last_error=?, lease_owner=NULL, lease_until=NULL "
                    "WHERE event_id=? AND lease_owner=?",
                    (attempts, time.time() + delay, str(error)[:2000], event_id, worker_id),
                )

    def verify_chain(self) -> dict[str, Any]:
        with self._connection() as c:
            rows = c.execute("SELECT * FROM events ORDER BY seq ASC").fetchall()
        previous = "0" * 64
        for r in rows:
            body = {
                "event_id": r["event_id"],
                "tenant": r["tenant"],
                "action_id": r["action_id"],
                "kind": r["kind"],
                "payload": json.loads(r["payload_json"]),
                "previous_hash": r["previous_hash"],
                "created_at": r["created_at"],
            }
            actual = self._event_digest(body)
            if r["previous_hash"] != previous or r["event_hash"] != actual:
                return {"valid": False, "failed_seq": r["seq"]}
            previous = actual
        return {"valid": True, "events_checked": len(rows), "head": previous}
