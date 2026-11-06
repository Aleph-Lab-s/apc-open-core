from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from .canonical import CANONICALIZATION_VERSION, canonical_json
from .crypto import verify_signature
from .errors import APCError, APCErrorCode

SCHEMA_VERSION = "APC-AUTHORITY-V3"
LEGACY_SCHEMA_VERSION = "APC-AUTHORITY-V2"
# Canonicalization version is defined by canonical.py
CRYPTO_DOMAIN = "APC-AUTHORITY-V3"
LEGACY_CRYPTO_DOMAIN = "APC-AUTHORITY-V2"


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return dt.astimezone(UTC).isoformat()


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class IntentContract:
    intent_id: str
    intent: dict[str, Any]
    allowed_operations: tuple[str, ...]
    allowed_resources: tuple[str, ...]
    constraints: dict[str, Any]
    max_risk: int = 100

    def payload(self) -> dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "intent": self.intent,
            "allowed_operations": self.allowed_operations,
            "allowed_resources": self.allowed_resources,
            "constraints": self.constraints,
            "max_risk": self.max_risk,
        }

    @property
    def digest(self) -> str:
        return _digest(self.payload())

    def permits(self, act: dict[str, Any], risk: int) -> bool:
        if risk > self.max_risk:
            return False
        if act.get("operation") not in self.allowed_operations:
            return False
        if act.get("resource") not in self.allowed_resources:
            return False
        for k, v in self.constraints.items():
            if act.get("parameters", {}).get(k) != v and act.get("constraints", {}).get(k) != v:
                return False
        return True


@dataclass(frozen=True)
class WorkloadIdentity:
    workload_id: str
    issuer: str
    trust_epoch: int = 0


@dataclass(frozen=True)
class Delegation:
    root_principal_id: str
    holder_id: str
    parent_id: str | None
    scope: dict[str, Any]
    expires_at: datetime
    risk_ceiling: int
    audience: tuple[str, ...]

    def attenuation_scope(self):
        return {
            "operations": self.scope.get("operations", self.scope.get("operation")),
            "resources": self.scope.get("resources", self.scope.get("resource")),
            "audience": self.audience,
            "max_risk": self.risk_ceiling,
        }

    def attenuates(self, parent: Delegation | None) -> bool:
        if parent is None:
            return True
        if self.expires_at > parent.expires_at:
            return False
        if self.risk_ceiling > parent.risk_ceiling:
            return False
        if not set(self.audience).issubset(parent.audience):
            return False
        try:
            from .constraints import scope_attenuates

            if not scope_attenuates(self.attenuation_scope(), parent.attenuation_scope()):
                return False
        except Exception:
            return False
        for key, value in self.scope.items():
            if (
                key in parent.scope
                and key not in ("operations", "resources", "audience", "max_risk")
                and value != parent.scope[key]
            ):
                return False
        return True


@dataclass(frozen=True)
class SecurityState:
    policy_epoch: int = 0
    identity_epoch: int = 0
    delegation_epoch: int = 0
    tenant_epoch: int = 0
    risk_epoch: int = 0
    signer_epoch: int = 0
    sink_epoch: int = 0
    revocation_epoch: int = 0

    def digest(self) -> str:
        return _digest(self.__dict__)


@dataclass(frozen=True)
class ActionContext:
    tenant: str
    request_id: str
    invocation_id: str
    intent: IntentContract
    candidate_act: dict[str, Any]
    actor_id: str
    principal_id: str
    workload: WorkloadIdentity
    delegation: Delegation
    source_application: str
    decision_input: dict[str, Any]
    policy_decision_id: str
    policy_version: str
    policy_epoch: int
    risk: int
    assurance: str
    finality_sink: str
    security_state: SecurityState
    policy_issued_at: datetime | None = None
    resource_version: str | None = None
    precondition_digest: str | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant,
            "request_id": self.request_id,
            "invocation_id": self.invocation_id,
            "intent": self.intent.payload(),
            "candidate_act": self.candidate_act,
            "actor_id": self.actor_id,
            "principal_id": self.principal_id,
            "workload": {
                "workload_id": self.workload.workload_id,
                "issuer": self.workload.issuer,
                "trust_epoch": self.workload.trust_epoch,
            },
            "delegation": {
                "root_principal_id": self.delegation.root_principal_id,
                "holder_id": self.delegation.holder_id,
                "parent_id": self.delegation.parent_id,
                "scope": self.delegation.scope,
                "expires_at": _iso(self.delegation.expires_at),
                "risk_ceiling": self.delegation.risk_ceiling,
                "audience": self.delegation.audience,
            },
            "source_application": self.source_application,
            "decision_input": self.decision_input,
            "policy_decision_id": self.policy_decision_id,
            "policy_version": self.policy_version,
            "policy_epoch": self.policy_epoch,
            "risk": self.risk,
            "assurance": self.assurance,
            "finality_sink": self.finality_sink,
            "security_state": self.security_state.__dict__,
            "policy_issued_at": _iso(self.policy_issued_at) if self.policy_issued_at else None,
            "resource_version": self.resource_version,
            "precondition_digest": self.precondition_digest,
        }

    @property
    def context_digest(self) -> str:
        # Full-context cryptographic commitment.  This is deliberately broader
        # than security_context_digest: every field that can influence policy,
        # routing, state, execution, support/audit correlation, or sink choice
        # is covered by the authority signature.
        return _digest(self.payload())

    @property
    def candidate_act_digest(self) -> str:
        return _digest(self.candidate_act)

    @property
    def decision_input_digest(self) -> str:
        return _digest(self.decision_input)

    @property
    def security_context_digest(self) -> str:
        return _digest(
            {
                "tenant": self.tenant,
                "actor_id": self.actor_id,
                "principal_id": self.principal_id,
                "workload": {
                    "workload_id": self.workload.workload_id,
                    "issuer": self.workload.issuer,
                    "trust_epoch": self.workload.trust_epoch,
                },
                "delegation": {
                    "root_principal_id": self.delegation.root_principal_id,
                    "holder_id": self.delegation.holder_id,
                    "parent_id": self.delegation.parent_id,
                    "scope": self.delegation.scope,
                    "expires_at": _iso(self.delegation.expires_at),
                    "risk_ceiling": self.delegation.risk_ceiling,
                    "audience": self.delegation.audience,
                },
                "risk": self.risk,
                "assurance": self.assurance,
                "finality_sink": self.finality_sink,
            }
        )


@dataclass(frozen=True)
class AuthorityV2:
    authority_id: str
    context: ActionContext
    issued_at: datetime
    expires_at: datetime
    nonce: str
    single_use: bool
    key_id: str
    signature: str

    def payload(self) -> dict[str, Any]:
        c = self.context
        return {
            "schema_version": SCHEMA_VERSION,
            "canonicalization_version": CANONICALIZATION_VERSION,
            "crypto_domain": CRYPTO_DOMAIN,
            "authority_id": self.authority_id,
            "tenant": c.tenant,
            "request_id": c.request_id,
            "invocation_id": c.invocation_id,
            "intent_digest": c.intent.digest,
            "action_context_digest": c.context_digest,
            "candidate_act_digest": c.candidate_act_digest,
            "actor_id": c.actor_id,
            "principal_id": c.principal_id,
            "workload": c.workload.__dict__,
            "delegation": {
                "root_principal_id": c.delegation.root_principal_id,
                "holder_id": c.delegation.holder_id,
                "parent_id": c.delegation.parent_id,
                "scope": c.delegation.scope,
                "expires_at": _iso(c.delegation.expires_at),
                "risk_ceiling": c.delegation.risk_ceiling,
                "audience": c.delegation.audience,
            },
            "policy_decision_id": c.policy_decision_id,
            "policy_version": c.policy_version,
            "policy_epoch": c.policy_epoch,
            "decision_input_digest": c.decision_input_digest,
            "security_context_digest": c.security_context_digest,
            "security_state": c.security_state.__dict__,
            "risk": c.risk,
            "assurance": c.assurance,
            "finality_sink": c.finality_sink,
            "issued_at": _iso(self.issued_at),
            "expires_at": _iso(self.expires_at),
            "nonce": self.nonce,
            "single_use": self.single_use,
            "policy_issued_at": _iso(c.policy_issued_at) if c.policy_issued_at else None,
            "resource_version": c.resource_version,
            "precondition_digest": c.precondition_digest,
        }


class Signer(Protocol):
    key_id: str

    def sign(self, payload: Any) -> str: ...


class AuthorityFactory:
    def __init__(self, signer: Signer):
        self.signer = signer

    def issue(
        self, context: ActionContext, expires_at: datetime, single_use: bool = True
    ) -> AuthorityV2:
        now = _now()
        if context.policy_epoch != context.security_state.policy_epoch:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "policy epoch/context mismatch")
        if expires_at > context.delegation.expires_at:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "authority exceeds delegation lifetime")
        if expires_at <= now:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "authority already expired")
        if not context.intent.permits(context.candidate_act, context.risk):
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "candidate act violates intent contract")
        authority = AuthorityV2(
            str(uuid.uuid4()),
            context,
            now,
            expires_at,
            uuid.uuid4().hex,
            single_use,
            self.signer.key_id,
            "",
        )
        sig = self.signer.sign(authority.payload())
        return AuthorityV2(**{**authority.__dict__, "signature": sig})


class DurableAuthorityStore:
    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.RLock()
        self._closed = False
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS authorities (authority_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, state TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL, consumed_at TEXT)"
        )

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._db.close()
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

    def register(self, authority: AuthorityV2) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO authorities VALUES (?, ?, ?, ?, ?, NULL)",
                (
                    authority.authority_id,
                    authority.context.tenant,
                    "ACTIVE",
                    json.dumps(authority.payload(), sort_keys=True),
                    _iso(authority.issued_at),
                ),
            )

    def revoke(self, authority_id: str) -> None:
        with self._lock:
            cur = self._db.execute(
                "UPDATE authorities SET state='REVOKED' WHERE authority_id=? AND state IN ('ACTIVE','RESERVED')",
                (authority_id,),
            )
            if cur.rowcount != 1:
                raise APCError(APCErrorCode.REVOKED_AUTHORITY, "authority not active")

    def reserve(self, authority_id: str) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                cur = self._db.execute(
                    "UPDATE authorities SET state='RESERVED' WHERE authority_id=? AND state='ACTIVE'",
                    (authority_id,),
                )
                if cur.rowcount != 1:
                    row = self._db.execute(
                        "SELECT state FROM authorities WHERE authority_id=?", (authority_id,)
                    ).fetchone()
                    state = row[0] if row else "MISSING"
                    raise APCError(
                        APCErrorCode.REPLAYED_AUTHORITY
                        if state in ("RESERVED", "EXECUTING", "EFFECTED")
                        else APCErrorCode.REVOKED_AUTHORITY,
                        f"authority cannot be reserved: {state}",
                    )
                self._db.execute(
                    "UPDATE authorities SET state='EXECUTING' WHERE authority_id=?", (authority_id,)
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def complete(self, authority_id: str, success: bool, unknown: bool = False) -> None:
        state = "UNKNOWN" if unknown else ("EFFECTED" if success else "FAILED")
        with self._lock:
            self._db.execute(
                "UPDATE authorities SET state=?, consumed_at=? WHERE authority_id=? AND state='EXECUTING'",
                (state, _iso(_now()), authority_id),
            )

    def resolve_unknown(self, authority_id: str, success: bool) -> None:
        """Resolve an UNKNOWN only after an authoritative reconciliation result."""
        state = "EFFECTED" if success else "FAILED"
        with self._lock:
            cur = self._db.execute(
                "UPDATE authorities SET state=?, consumed_at=? WHERE authority_id=? AND state='UNKNOWN'",
                (state, _iso(_now()), authority_id),
            )
            if cur.rowcount != 1:
                raise APCError(
                    APCErrorCode.INVALID_EVIDENCE, f"authority is not UNKNOWN: {authority_id}"
                )

    def rearm(self, authority_id: str) -> None:
        """Reopen an UNKNOWN authority only when the protected sink reports NOT_FOUND."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE authorities SET state='ACTIVE', consumed_at=NULL WHERE authority_id=? AND state='UNKNOWN'",
                (authority_id,),
            )
            if cur.rowcount != 1:
                raise APCError(
                    APCErrorCode.INVALID_EVIDENCE, f"authority is not UNKNOWN: {authority_id}"
                )

    def state(self, authority_id: str) -> str | None:
        row = self._db.execute(
            "SELECT state FROM authorities WHERE authority_id=?", (authority_id,)
        ).fetchone()
        return row[0] if row else None


class FinalityEnforcer:
    def __init__(
        self,
        *,
        public_key_resolver: Callable[[str], str],
        store: DurableAuthorityStore,
        state_provider: Callable[[str], SecurityState],
        freshness_policy=None,
        policy_state_provider=None,
        workload_trust_provider=None,
        sink_contract_provider=None,
        resource_precondition_provider=None,
    ):
        self.keys, self.store, self.state_provider = public_key_resolver, store, state_provider
        self.freshness_policy = freshness_policy
        self.policy_state_provider = policy_state_provider
        self.workload_trust_provider = workload_trust_provider
        self.sink_contract_provider = sink_contract_provider
        self.resource_precondition_provider = resource_precondition_provider

    def verify(
        self,
        authority: AuthorityV2,
        actual_context: ActionContext,
        executing_actor_id: str,
        now: datetime | None = None,
    ) -> None:
        now = now or _now()
        p = authority.payload()

        # Schema/domain checks happen before any state transition.  A release
        # verifier must never silently accept a weaker/legacy authority format.
        if p.get("schema_version") != SCHEMA_VERSION:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "unsupported authority schema version")
        if p.get("canonicalization_version") != CANONICALIZATION_VERSION:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "canonicalization version mismatch")
        if p.get("crypto_domain") != CRYPTO_DOMAIN:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "crypto domain mismatch")

        if authority.context.tenant != actual_context.tenant:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "tenant mismatch")
        if authority.context.invocation_id != actual_context.invocation_id:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "invocation mismatch")

        key = self.keys(authority.key_id)
        if not key:
            raise APCError(APCErrorCode.INVALID_SIGNATURE, "unknown signing key")
        verify_signature(p, authority.signature, key)

        # NUCLEAR FINALITY BINDING: the complete immutable ActionContext is a
        # signed commitment.  No runtime caller can rewrite a policy field,
        # security-state field, resource precondition, sink, source application,
        # risk, assurance profile, identity, delegation, or decision input at the
        # final boundary without changing this digest and therefore failing.
        if p.get("action_context_digest") != authority.context.context_digest:
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "authority context commitment is internally inconsistent",
            )
        if authority.context.context_digest != actual_context.context_digest:
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "complete action context mismatch at finality boundary",
            )

        # Retain explicit checks for defense in depth and diagnosability.
        if authority.context.candidate_act_digest != actual_context.candidate_act_digest:
            raise APCError(APCErrorCode.DIGEST_MISMATCH, "exact act mismatch")
        if authority.context.intent.digest != actual_context.intent.digest:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "intent mismatch")
        if authority.context.decision_input_digest != actual_context.decision_input_digest:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "decision input mismatch")
        if authority.context.security_context_digest != actual_context.security_context_digest:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "security context mismatch")
        if authority.context.policy_decision_id != actual_context.policy_decision_id:
            raise APCError(APCErrorCode.POLICY_STATE_INVALID, "policy decision identity mismatch")
        if authority.context.policy_version != actual_context.policy_version:
            raise APCError(APCErrorCode.POLICY_STATE_INVALID, "policy version mismatch")
        if authority.context.policy_epoch != actual_context.policy_epoch:
            raise APCError(APCErrorCode.POLICY_STATE_INVALID, "policy epoch mismatch")
        if (
            authority.context.risk != actual_context.risk
            or authority.context.assurance != actual_context.assurance
        ):
            raise APCError(APCErrorCode.CONSTRAINT_VIOLATION, "risk/assurance mismatch")
        if authority.context.finality_sink != actual_context.finality_sink:
            raise APCError(APCErrorCode.AUDIENCE_MISMATCH, "finality sink mismatch")
        if authority.context.resource_version != actual_context.resource_version:
            raise APCError(APCErrorCode.PRECONDITION_FAILED, "resource version binding mismatch")
        if authority.context.precondition_digest != actual_context.precondition_digest:
            raise APCError(APCErrorCode.PRECONDITION_FAILED, "precondition binding mismatch")

        if (
            authority.context.actor_id != executing_actor_id
            or authority.context.delegation.holder_id != executing_actor_id
        ):
            raise APCError(APCErrorCode.ACTOR_MISMATCH, "executing actor mismatch")
        if now >= authority.expires_at:
            raise APCError(APCErrorCode.EXPIRED_AUTHORITY, "authority expired")
        if authority.expires_at <= authority.issued_at:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "invalid authority lifetime")
        if self.freshness_policy is not None:
            self.freshness_policy.validate(
                issued_at=authority.issued_at,
                expires_at=authority.expires_at,
                now=now,
                policy_issued_at=actual_context.policy_issued_at,
            )

        current = self.state_provider(actual_context.tenant)
        required = authority.context.security_state
        state_fields = (
            "policy_epoch",
            "identity_epoch",
            "delegation_epoch",
            "tenant_epoch",
            "risk_epoch",
            "signer_epoch",
            "sink_epoch",
            "revocation_epoch",
        )
        if any(getattr(current, f) != getattr(required, f) for f in state_fields):
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "required security state is stale")

        if self.workload_trust_provider is not None:
            observed = (
                self.workload_trust_provider.current_epoch(
                    actual_context.workload.workload_id, actual_context.tenant
                )
                if hasattr(self.workload_trust_provider, "current_epoch")
                else self.workload_trust_provider(
                    actual_context.workload.workload_id, actual_context.tenant
                )
            )
            if observed != actual_context.workload.trust_epoch:
                raise APCError(APCErrorCode.WORKLOAD_TRUST_INVALID, "workload trust state is stale")

        if self.policy_state_provider is not None:
            decision = (
                self.policy_state_provider.get(authority.context.policy_decision_id)
                if hasattr(self.policy_state_provider, "get")
                else self.policy_state_provider(authority.context.policy_decision_id)
            )
            if decision is None:
                raise APCError(APCErrorCode.POLICY_STATE_INVALID, "policy decision is unavailable")
            for field, expected in (
                ("policy_version", authority.context.policy_version),
                ("policy_epoch", authority.context.policy_epoch),
                ("decision_id", authority.context.policy_decision_id),
            ):
                if hasattr(decision, field) and getattr(decision, field) != expected:
                    raise APCError(APCErrorCode.POLICY_STATE_INVALID, f"{field} mismatch")
            if hasattr(decision, "decision") and str(decision.decision) not in (
                "ALLOW",
                "Decision.ALLOW",
            ):
                raise APCError(APCErrorCode.POLICY_STATE_INVALID, "decision is not ALLOW")

        if self.sink_contract_provider is not None:
            contract = self.sink_contract_provider(actual_context.finality_sink)
            if (
                contract is None
                or contract.sink_id != actual_context.finality_sink
                or contract.audience != actual_context.candidate_act.get("audience")
            ):
                raise APCError(
                    APCErrorCode.SINK_CONTRACT_INVALID, "protected sink contract mismatch"
                )

        if (
            self.resource_precondition_provider is not None
            and actual_context.resource_version is not None
        ):
            current_version = self.resource_precondition_provider(
                actual_context.candidate_act.get("resource")
            )
            if current_version != actual_context.resource_version:
                raise APCError(APCErrorCode.PRECONDITION_FAILED, "resource version changed")

        if not authority.context.intent.permits(actual_context.candidate_act, actual_context.risk):
            raise APCError(APCErrorCode.CONSTRAINT_VIOLATION, "intent contract violation")

        # The authority enters RESERVED/EXECUTING only after every security
        # check above has passed.  No failed request burns the authority.
        self.store.reserve(authority.authority_id)


@dataclass(frozen=True)
class EffectResult:
    status: str
    provider_reference: str | None
    data: dict[str, Any]

    VALID_STATUSES = frozenset({"SUCCESS", "FAILURE", "UNKNOWN"})

    def __post_init__(self):
        if self.status not in self.VALID_STATUSES:
            raise ValueError(f"unsupported effect result status: {self.status!r}")
        if not isinstance(self.data, dict):
            raise TypeError("effect result data must be a dict")


class ProtectedSink(Protocol):
    sink_id: str

    def execute(self, act: dict[str, Any], idempotency_key: str) -> EffectResult: ...
    def reconcile(self, idempotency_key: str) -> EffectResult | None: ...


class FlagshipProtectedExecutor:
    def __init__(
        self,
        enforcer: FinalityEnforcer,
        sink: ProtectedSink,
        store: DurableAuthorityStore,
        *,
        approval_gate=None,
        reconciliation_queue=None,
        event_sink=None,
    ):
        self.enforcer, self.sink, self.store = enforcer, sink, store
        self.approval_gate, self.reconciliation_queue, self.event_sink = (
            approval_gate,
            reconciliation_queue,
            event_sink,
        )

    def execute(
        self, authority: AuthorityV2, context: ActionContext, actor_id: str
    ) -> EffectResult:
        if self.approval_gate is not None and not self.approval_gate.satisfied(
            authority.authority_id
        ):
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "required approval not satisfied")
        if self.sink.sink_id != authority.context.finality_sink:
            raise APCError(
                APCErrorCode.SINK_CONTRACT_INVALID,
                "executor sink object does not match authority finality sink",
            )
        self.enforcer.verify(authority, context, actor_id)
        key = f"{authority.context.tenant}:{authority.authority_id}:{authority.nonce}"
        try:
            result = self.sink.execute(context.candidate_act, key)
            if result.status not in EffectResult.VALID_STATUSES:
                raise APCError(
                    APCErrorCode.INVALID_AUTHORITY,
                    "protected sink returned unsupported outcome status",
                )
            try:
                self.store.complete(
                    authority.authority_id,
                    result.status == "SUCCESS",
                    unknown=result.status == "UNKNOWN",
                )
            except Exception:
                if self.reconciliation_queue is not None:
                    from .persistence import ReconciliationItem

                    self.reconciliation_queue.enqueue(
                        ReconciliationItem(
                            authority.authority_id,
                            key,
                            self.sink.sink_id,
                            "state-persistence-failure-after-provider-call",
                        )
                    )
                raise
            if result.status == "UNKNOWN" and self.reconciliation_queue is not None:
                from .persistence import ReconciliationItem

                self.reconciliation_queue.enqueue(
                    ReconciliationItem(
                        authority.authority_id, key, self.sink.sink_id, "provider-reported-unknown"
                    )
                )
            if self.event_sink is not None:
                from .events import SecurityEvent

                self.event_sink.emit(
                    SecurityEvent(
                        "APC_EFFECT_OUTCOME",
                        "INFO",
                        context.tenant,
                        authority.authority_id,
                        context.invocation_id,
                        _now(),
                        {"status": result.status, "sink_id": self.sink.sink_id},
                    )
                )
            return result
        except Exception:
            try:
                self.store.complete(authority.authority_id, False, unknown=True)
            except Exception:
                pass
            if self.reconciliation_queue is not None:
                from .persistence import ReconciliationItem

                self.reconciliation_queue.enqueue(
                    ReconciliationItem(
                        authority.authority_id,
                        key,
                        self.sink.sink_id,
                        "provider-or-post-effect-unknown",
                    )
                )
            raise


class EvidenceLedger:
    def __init__(self):
        self._lock = threading.Lock()
        self._records = []
        self._last = "0" * 64

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            record = {
                "sequence": len(self._records) + 1,
                "prev_hash": self._last,
                "event": event,
                "recorded_at": _iso(_now()),
            }
            record["hash"] = _digest(record)
            self._last = record["hash"]
            self._records.append(record)
            return record

    def verify(self) -> bool:
        prev = "0" * 64
        for r in self._records:
            if r["prev_hash"] != prev or r["hash"] != _digest(
                {k: v for k, v in r.items() if k != "hash"}
            ):
                return False
            prev = r["hash"]
        return True

    def records(self):
        return list(self._records)
