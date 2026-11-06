from __future__ import annotations

"""APC Distributed Action Security Continuity vNext reference layer.

This module implements the v3.0 architecture-review concepts without changing
APC's existing v2 finality APIs:

* machine-verifiable security contracts;
* authenticated protocol envelopes;
* distributed transition enforcement points (TEPs);
* continuity witnesses;
* action-chain state and replay/fork protection;
* action-security graph;
* independent APC node self-assurance;
* security-operations pause/abort controls;
* a continuity-aware finality wrapper around the existing finality enforcer.

It is intentionally a reference implementation: durable multi-instance
persistence, HSM-backed attestation, network transports, and production
orchestration remain deployment integrations.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import hashlib
import threading
from typing import Any, Callable, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .canonical import canonical_json, CANONICALIZATION_VERSION
from .crypto import Ed25519KeyPair, verify_signature
from .errors import APCError, APCErrorCode

CONTINUITY_PROTOCOL_VERSION = "APC-CONTINUITY-1"
CONTINUITY_SCHEMA_VERSION = "APC-CONTINUITY-ENVELOPE-1"
CONTINUITY_WITNESS_SCHEMA = "APC-CONTINUITY-WITNESS-1"
CONTINUITY_CRYPTO_DOMAIN = "APC-CONTINUITY-TRANSITION-1"
WITNESS_CRYPTO_DOMAIN = "APC-CONTINUITY-WITNESS-1"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat()


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _nonempty(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be non-empty")
    return value


def _validate_dt(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value


class TransitionDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    HOLD = "HOLD"


class TransitionState(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    TRANSITIONED = "TRANSITIONED"
    BLOCKED = "BLOCKED"
    PAUSED = "PAUSED"
    ABORTED = "ABORTED"


class ContractMatch(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tenants: tuple[str, ...] = ()
    senders: tuple[str, ...] = ()
    sender_workloads: tuple[str, ...] = ()
    receivers: tuple[str, ...] = ()
    receiver_workloads: tuple[str, ...] = ()
    operations: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    sinks: tuple[str, ...] = ()
    assurance_profiles: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()

    @field_validator(
        "tenants", "senders", "sender_workloads", "receivers", "receiver_workloads",
        "operations", "targets", "sinks", "assurance_profiles", "required_capabilities",
    )
    @classmethod
    def validate_tuple(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            _nonempty(item, "match item")
        return value


class SecurityContract(BaseModel):
    """Declarative APC security contract for one transition class."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    contract_id: str
    version: str
    match: ContractMatch = Field(default_factory=ContractMatch)
    allowed_edge_labels: tuple[str, ...] = ()
    required_assurance: str = "A0"
    require_transformation_witness: bool = False
    require_continuity_witness: bool = True
    max_clock_skew_seconds: int = 30
    freshness_seconds: int | None = None
    fail_closed_on_unknown: bool = True
    require_sender_signature: bool = True
    require_authority: bool = True
    require_same_chain: bool = True

    @field_validator("contract_id", "version", "required_assurance")
    @classmethod
    def validate_nonempty(cls, value: str, info) -> str:
        return _nonempty(value, info.field_name)

    @field_validator("allowed_edge_labels")
    @classmethod
    def validate_edges(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            _nonempty(item, "allowed_edge_labels item")
        return value

    @model_validator(mode="after")
    def validate_numbers(self) -> "SecurityContract":
        if self.max_clock_skew_seconds < 0:
            raise ValueError("max_clock_skew_seconds cannot be negative")
        if self.freshness_seconds is not None and self.freshness_seconds <= 0:
            raise ValueError("freshness_seconds must be positive when set")
        return self

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SecurityContract":
        """Compile the customer-facing contract mapping into a typed contract."""
        return cls.model_validate(value)

    @property
    def digest(self) -> str:
        return _digest(self.model_dump(mode="json", exclude_none=False))

    def allows(self, envelope: "APCProtocolEnvelope") -> bool:
        m = self.match
        if m.tenants and envelope.tenant not in m.tenants:
            return False
        if m.senders and envelope.sender_identity not in m.senders:
            return False
        if m.sender_workloads and envelope.sender_workload_identity not in m.sender_workloads:
            return False
        if m.receivers and envelope.receiver_identity not in m.receivers:
            return False
        if m.receiver_workloads and envelope.receiver_workload_identity not in m.receiver_workloads:
            return False
        if m.operations and envelope.operation not in m.operations:
            return False
        if m.targets and envelope.target not in m.targets:
            return False
        if m.sinks and envelope.finality_sink not in m.sinks:
            return False
        if m.assurance_profiles and envelope.assurance_profile not in m.assurance_profiles:
            return False
        if m.required_capabilities:
            if not set(m.required_capabilities).issubset(set(envelope.capabilities)):
                return False
        if self.allowed_edge_labels:
            label = envelope.edge_label
            if label not in self.allowed_edge_labels and "*" not in self.allowed_edge_labels:
                return False
        return True


class APCProtocolEnvelope(BaseModel):
    """Authenticated state transition envelope carried across APC-governed edges."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol_version: str = CONTINUITY_PROTOCOL_VERSION
    contract_id: str
    contract_version: str
    schema_version: str = CONTINUITY_SCHEMA_VERSION
    canonicalization_version: str = CANONICALIZATION_VERSION
    cryptographic_domain: str = CONTINUITY_CRYPTO_DOMAIN

    tenant: str
    transition_id: str
    parent_transition_id: str | None = None
    action_chain_id: str
    invocation_id: str

    sender_identity: str
    sender_workload_identity: str
    receiver_identity: str
    receiver_workload_identity: str
    principal: str

    authority_id: str
    delegation_id: str | None = None
    parent_authority_id: str | None = None
    policy_decision_id: str
    policy_version: str
    policy_epoch: int

    decision_input_digest: str
    security_context_digest: str
    intent_digest: str
    candidate_act_digest: str
    exact_act_digest: str
    transformation_digest: str | None = None

    target: str
    operation: str
    capabilities: tuple[str, ...] = ()
    constraints: dict[str, Any] = Field(default_factory=dict)
    finality_sink: str

    nonce: str
    issued_at: datetime
    expires_at: datetime
    freshness_seconds: int | None = None
    assurance_profile: str = "A0"
    allowed_next_transitions: tuple[str, ...] = ()
    transition_counter: int = 0
    state: str = TransitionState.AUTHORIZED.value

    sender_key_id: str
    sender_signature: str

    @field_validator(
        "protocol_version", "contract_id", "contract_version", "schema_version",
        "canonicalization_version", "cryptographic_domain", "tenant", "transition_id",
        "action_chain_id", "invocation_id", "sender_identity", "sender_workload_identity",
        "receiver_identity", "receiver_workload_identity", "principal", "authority_id",
        "policy_decision_id", "policy_version", "decision_input_digest", "security_context_digest",
        "intent_digest", "candidate_act_digest", "exact_act_digest", "target", "operation",
        "finality_sink", "nonce", "sender_key_id", "sender_signature",
    )
    @classmethod
    def validate_strings(cls, value: str, info) -> str:
        return _nonempty(value, info.field_name)

    @field_validator("capabilities", "allowed_next_transitions")
    @classmethod
    def validate_string_tuples(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            _nonempty(item, "tuple item")
        return value

    @field_validator("constraints")
    @classmethod
    def validate_constraints(cls, value: dict[str, Any]) -> dict[str, Any]:
        # canonical_json provides the hard JSON boundary; use it here to reject
        # bytes/custom objects/non-finite values before signing.
        canonical_json(value)
        return value

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_times(cls, value: datetime, info) -> datetime:
        return _validate_dt(value, info.field_name)

    @model_validator(mode="after")
    def validate_order(self) -> "APCProtocolEnvelope":
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be later than issued_at")
        if self.transition_counter < 0:
            raise ValueError("transition_counter cannot be negative")
        if self.freshness_seconds is not None and self.freshness_seconds <= 0:
            raise ValueError("freshness_seconds must be positive when set")
        if self.parent_transition_id is None and self.transition_counter != 0:
            raise ValueError("root transition must have transition_counter=0")
        if self.parent_transition_id is not None and self.transition_counter == 0:
            raise ValueError("non-root transition must have positive counter")
        return self

    @property
    def edge_label(self) -> str:
        return f"{self.receiver_identity}:{self.operation}"

    def unsigned_payload(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        data.pop("sender_signature", None)
        return data

    @property
    def digest(self) -> str:
        return _digest(self.unsigned_payload())

    def signed_bytes(self) -> bytes:
        return canonical_json(self.unsigned_payload())


@dataclass(frozen=True)
class ContinuityWitness:
    witness_id: str
    transition_id: str
    parent_transition_id: str | None
    action_chain_id: str
    predecessor_digest: str | None
    envelope_digest: str
    transformation_digest: str | None
    issued_at: datetime
    verifier_node_id: str
    key_id: str
    signature: str
    schema_version: str = CONTINUITY_WITNESS_SCHEMA
    crypto_domain: str = WITNESS_CRYPTO_DOMAIN

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "crypto_domain": self.crypto_domain,
            "witness_id": self.witness_id,
            "transition_id": self.transition_id,
            "parent_transition_id": self.parent_transition_id,
            "action_chain_id": self.action_chain_id,
            "predecessor_digest": self.predecessor_digest,
            "envelope_digest": self.envelope_digest,
            "transformation_digest": self.transformation_digest,
            "issued_at": _iso(self.issued_at),
            "verifier_node_id": self.verifier_node_id,
            "key_id": self.key_id,
        }

    @property
    def digest(self) -> str:
        return _digest(self.payload())


@dataclass(frozen=True)
class TransitionRecord:
    envelope: APCProtocolEnvelope
    witness: ContinuityWitness
    predecessor_digest: str | None
    accepted_at: datetime


class ContinuityStore:
    """Thread-safe reference state store for governed action transitions."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: dict[str, TransitionRecord] = {}
        self._nonces: set[tuple[str, str]] = set()
        self._chain_heads: dict[str, set[str]] = {}

    def get(self, transition_id: str) -> TransitionRecord | None:
        with self._lock:
            return self._records.get(transition_id)

    def require(self, transition_id: str) -> TransitionRecord:
        record = self.get(transition_id)
        if record is None:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "unknown parent transition")
        return record

    def nonce_seen(self, sender_key_id: str, nonce: str) -> bool:
        with self._lock:
            return (sender_key_id, nonce) in self._nonces

    def put(self, record: TransitionRecord) -> None:
        with self._lock:
            if record.envelope.transition_id in self._records:
                raise APCError(APCErrorCode.REPLAYED_AUTHORITY, "transition_id replay")
            nonce_key = (record.envelope.sender_key_id, record.envelope.nonce)
            if nonce_key in self._nonces:
                raise APCError(APCErrorCode.REPLAYED_AUTHORITY, "transition nonce replay")
            self._records[record.envelope.transition_id] = record
            self._nonces.add(nonce_key)
            self._chain_heads.setdefault(record.envelope.action_chain_id, set()).add(
                record.envelope.transition_id
            )

    def records(self, chain_id: str | None = None) -> list[TransitionRecord]:
        with self._lock:
            records = list(self._records.values())
            if chain_id is not None:
                records = [r for r in records if r.envelope.action_chain_id == chain_id]
            return sorted(records, key=lambda r: (r.envelope.transition_counter, r.envelope.transition_id))


@dataclass(frozen=True)
class APCAuthorityReference:
    """Minimal machine-verifiable anchor linking a transition to authorized state."""

    authority_id: str
    tenant: str
    invocation_id: str
    principal: str
    policy_decision_id: str
    policy_version: str
    policy_epoch: int
    decision_input_digest: str
    security_context_digest: str
    intent_digest: str
    candidate_act_digest: str
    exact_act_digest: str
    finality_sink: str
    assurance_profile: str = "A0"
    expires_at: datetime | None = None

    def validate_envelope(self, envelope: "APCProtocolEnvelope", *, root: bool = False) -> None:
        checks = (
            ("authority_id", self.authority_id), ("tenant", self.tenant),
            ("invocation_id", self.invocation_id), ("principal", self.principal),
            ("policy_decision_id", self.policy_decision_id), ("policy_version", self.policy_version),
            ("policy_epoch", self.policy_epoch), ("decision_input_digest", self.decision_input_digest),
            ("security_context_digest", self.security_context_digest), ("intent_digest", self.intent_digest),
            ("candidate_act_digest", self.candidate_act_digest), ("exact_act_digest", self.exact_act_digest),
            ("finality_sink", self.finality_sink), ("assurance_profile", self.assurance_profile),
        )
        for field, expected in checks:
            if getattr(envelope, field) != expected:
                raise APCError(APCErrorCode.INVALID_AUTHORITY, f"authority reference {field} mismatch")
        if self.expires_at is not None and envelope.expires_at > self.expires_at:
            raise APCError(APCErrorCode.EXPIRED_AUTHORITY, "transition outlives authority")
        if root and envelope.parent_transition_id is None:
            # The root must begin with the authority's own exact act commitment.
            if envelope.exact_act_digest != self.exact_act_digest:
                raise APCError(APCErrorCode.DIGEST_MISMATCH, "root transition is not bound to the authorized exact act")


@dataclass(frozen=True)
class APCNodeAttestation:
    node_id: str
    protocol_version: str
    implementation_version: str
    runtime_measurement: str
    policy_contract_digest: str
    trust_state: str
    issued_at: datetime
    expires_at: datetime
    key_id: str
    signature: str

    def payload(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "protocol_version": self.protocol_version,
            "implementation_version": self.implementation_version,
            "runtime_measurement": self.runtime_measurement,
            "policy_contract_digest": self.policy_contract_digest,
            "trust_state": self.trust_state,
            "issued_at": _iso(self.issued_at),
            "expires_at": _iso(self.expires_at),
            "key_id": self.key_id,
        }


class APCNodeAssuranceVerifier:
    """Independent verifier for APC node security state."""

    def __init__(self, *, public_key_resolver: Callable[[str], str]) -> None:
        self._keys = public_key_resolver
        self.available = True

    def verify(
        self,
        attestation: APCNodeAttestation,
        *,
        expected_runtime_measurement: str,
        expected_contract_digest: str,
        expected_node_id: str | None = None,
        now: datetime | None = None,
    ) -> None:
        if not self.available:
            raise APCError(APCErrorCode.ASSURANCE_UNAVAILABLE, "APC assurance verifier unavailable")
        now = now or _now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise APCError(APCErrorCode.ASSURANCE_INVALID, "verification time must be timezone-aware")
        if attestation.protocol_version != CONTINUITY_PROTOCOL_VERSION:
            raise APCError(APCErrorCode.PROTOCOL_VERSION_INVALID, "APC node protocol version mismatch")
        if expected_node_id is not None and attestation.node_id != expected_node_id:
            raise APCError(APCErrorCode.ASSURANCE_INVALID, "attested node identity mismatch")
        if attestation.runtime_measurement != expected_runtime_measurement:
            raise APCError(APCErrorCode.ASSURANCE_INVALID, "runtime measurement mismatch")
        if attestation.policy_contract_digest != expected_contract_digest:
            raise APCError(APCErrorCode.ASSURANCE_INVALID, "security contract digest mismatch")
        if attestation.trust_state != "TRUSTED":
            raise APCError(APCErrorCode.ASSURANCE_INVALID, "node trust state is not TRUSTED")
        if now >= attestation.expires_at:
            raise APCError(APCErrorCode.ASSURANCE_EXPIRED, "node attestation expired")
        if attestation.expires_at <= attestation.issued_at:
            raise APCError(APCErrorCode.ASSURANCE_INVALID, "invalid attestation lifetime")
        public_key = self._keys(attestation.key_id)
        if not public_key:
            raise APCError(APCErrorCode.INVALID_SIGNATURE, "unknown APC node key")
        verify_signature(attestation.payload(), attestation.signature, public_key)


class APCSecurityOperations:
    """Reference intervention registry consumed by every governed TEP."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._paused_actions: set[str] = set()
        self._aborted_chains: set[str] = set()
        self._paused_chains: set[str] = set()
        self._disabled_nodes: set[str] = set()

    def pause_action(self, action_chain_id: str) -> None:
        with self._lock:
            self._paused_actions.add(action_chain_id)

    def resume_action(self, action_chain_id: str) -> None:
        with self._lock:
            self._paused_actions.discard(action_chain_id)

    def pause_chain(self, action_chain_id: str) -> None:
        with self._lock:
            self._paused_chains.add(action_chain_id)

    def resume_chain(self, action_chain_id: str) -> None:
        with self._lock:
            self._paused_chains.discard(action_chain_id)

    def abort_chain(self, action_chain_id: str) -> None:
        with self._lock:
            self._aborted_chains.add(action_chain_id)

    def disable_node(self, node_id: str) -> None:
        with self._lock:
            self._disabled_nodes.add(node_id)

    def enable_node(self, node_id: str) -> None:
        with self._lock:
            self._disabled_nodes.discard(node_id)

    def check(self, action_chain_id: str, node_id: str) -> None:
        with self._lock:
            if node_id in self._disabled_nodes:
                raise APCError(APCErrorCode.NODE_DISABLED, "APC node disabled")
            if action_chain_id in self._aborted_chains:
                raise APCError(APCErrorCode.CHAIN_ABORTED, "action chain aborted")
            if action_chain_id in self._paused_actions or action_chain_id in self._paused_chains:
                raise APCError(APCErrorCode.CHAIN_PAUSED, "action chain paused")

    def snapshot(self) -> dict[str, set[str]]:
        with self._lock:
            return {
                "paused_actions": set(self._paused_actions),
                "paused_chains": set(self._paused_chains),
                "aborted_chains": set(self._aborted_chains),
                "disabled_nodes": set(self._disabled_nodes),
            }


@dataclass
class ActionSecurityGraph:
    """Security-focused graph derived from accepted APC transitions."""

    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)
    expected_edges: set[tuple[str, str, str]] = field(default_factory=set)

    def expect_edge(self, sender: str, receiver: str, operation: str) -> None:
        self.expected_edges.add((sender, receiver, operation))

    def unenforced_expected_edges(self) -> set[tuple[str, str, str]]:
        observed = {(e["sender"], e["receiver"], e["operation"]) for e in self.edges if e["enforced"]}
        return set(self.expected_edges) - observed

    def add_transition(self, record: TransitionRecord) -> None:
        e = record.envelope
        self.nodes.setdefault(e.sender_identity, {"kind": "principal"})
        self.nodes.setdefault(e.receiver_identity, {"kind": "component"})
        self.nodes.setdefault(e.authority_id, {"kind": "authority"})
        self.nodes.setdefault(e.finality_sink, {"kind": "sink"})
        self.edges.append({
            "transition_id": e.transition_id,
            "parent_transition_id": e.parent_transition_id,
            "action_chain_id": e.action_chain_id,
            "sender": e.sender_identity,
            "receiver": e.receiver_identity,
            "operation": e.operation,
            "target": e.target,
            "authority_id": e.authority_id,
            "finality_sink": e.finality_sink,
            "witness_id": record.witness.witness_id,
            "witness_digest": record.witness.digest,
            "enforced": True,
        })

    def chain(self, action_chain_id: str) -> list[dict[str, Any]]:
        return [e for e in self.edges if e["action_chain_id"] == action_chain_id]

    def has_enforced_path(self, action_chain_id: str, transition_id: str) -> bool:
        records = self.chain(action_chain_id)
        by_id = {e["transition_id"]: e for e in records}
        current = by_id.get(transition_id)
        if current is None:
            return False
        seen: set[str] = set()
        while current is not None:
            tid = current["transition_id"]
            if tid in seen:
                return False
            seen.add(tid)
            parent = current["parent_transition_id"]
            if parent is None:
                return True
            current = by_id.get(parent)
        return False

    def summary(self, action_chain_id: str) -> dict[str, Any]:
        records = self.chain(action_chain_id)
        return {
            "action_chain_id": action_chain_id,
            "transitions": len(records),
            "participants": sorted({e["sender"] for e in records} | {e["receiver"] for e in records}),
            "sinks": sorted({e["finality_sink"] for e in records}),
            "all_enforced": all(e["enforced"] for e in records),
        }


class APCTransitionEnforcer:
    """Distributed APC TEP reference implementation."""

    def __init__(
        self,
        *,
        node_id: str,
        key_pair: Ed25519KeyPair,
        public_key_resolver: Callable[[str], str],
        contract_resolver: Callable[[str, str], SecurityContract],
        store: ContinuityStore,
        operations: APCSecurityOperations | None = None,
        assurance_verifier: APCNodeAssuranceVerifier | None = None,
        node_attestation: APCNodeAttestation | None = None,
        expected_runtime_measurement: str | None = None,
        expected_contract_digest: str | None = None,
        implementation_version: str = "v7.0.0",
        node_identity: str | None = None,
        node_workload_identity: str | None = None,
        authority_resolver: Callable[[str], APCAuthorityReference] | None = None,
    ) -> None:
        self.node_id = _nonempty(node_id, "node_id")
        self.node_identity = node_identity or node_id
        self.node_workload_identity = node_workload_identity or node_id
        self.key_pair = key_pair
        self._keys = public_key_resolver
        self._contracts = contract_resolver
        self.store = store
        self.operations = operations or APCSecurityOperations()
        self.assurance_verifier = assurance_verifier
        self.node_attestation = node_attestation
        self.expected_runtime_measurement = expected_runtime_measurement
        self.expected_contract_digest = expected_contract_digest
        self.implementation_version = implementation_version
        self.authority_resolver = authority_resolver
        self.graph: ActionSecurityGraph | None = None

    def verify_sender_signature(self, envelope: APCProtocolEnvelope) -> None:
        try:
            public_key = self._keys(envelope.sender_key_id)
        except Exception as exc:
            raise APCError(APCErrorCode.INVALID_SIGNATURE, "unable to resolve transition signer") from exc
        if not public_key:
            raise APCError(APCErrorCode.INVALID_SIGNATURE, "unknown transition signer")
        verify_signature(envelope.unsigned_payload(), envelope.sender_signature, public_key)

    def _check_freshness(self, envelope: APCProtocolEnvelope, now: datetime, contract: SecurityContract) -> None:
        if now >= envelope.expires_at:
            raise APCError(APCErrorCode.EXPIRED_AUTHORITY, "transition expired")
        skew = abs((now - envelope.issued_at).total_seconds())
        if skew > contract.max_clock_skew_seconds and now > envelope.issued_at:
            raise APCError(APCErrorCode.FRESHNESS_VIOLATION, "transition exceeds clock-skew window")
        if contract.freshness_seconds is not None:
            age = (now - envelope.issued_at).total_seconds()
            if age > contract.freshness_seconds:
                raise APCError(APCErrorCode.FRESHNESS_VIOLATION, "transition freshness exceeded")

    def _check_parent(self, envelope: APCProtocolEnvelope) -> str | None:
        if envelope.parent_transition_id is None:
            return None
        parent = self.store.require(envelope.parent_transition_id)
        p = parent.envelope
        if p.action_chain_id != envelope.action_chain_id:
            raise APCError(APCErrorCode.CHAIN_MISMATCH, "parent belongs to different action chain")
        if envelope.transition_counter != p.transition_counter + 1:
            raise APCError(APCErrorCode.TRANSITION_ORDER_INVALID, "transition counter is not parent+1")
        expected_label = envelope.edge_label
        if p.allowed_next_transitions and expected_label not in p.allowed_next_transitions and "*" not in p.allowed_next_transitions:
            raise APCError(APCErrorCode.TRANSITION_NOT_ALLOWED, "receiver/operation is not an allowed next transition")
        if envelope.parent_authority_id is None:
            raise APCError(APCErrorCode.DELEGATION_INVALID, "non-root transition must carry parent authority reference")
        if envelope.parent_authority_id != p.authority_id:
            raise APCError(APCErrorCode.DELEGATION_INVALID, "parent authority reference mismatch")

        # Continuity is not established merely because the next component has
        # a valid signature. Security context inherited from the parent state
        # remains fixed unless the contract explicitly represents a bounded
        # transformation/delegation. This prevents a downstream component from
        # re-signing an altered security context as if it were the same action.
        inherited_fields = (
            ("tenant", "tenant"),
            ("invocation_id", "invocation"),
            ("principal", "principal"),
            ("policy_decision_id", "policy decision"),
            ("policy_version", "policy version"),
            ("policy_epoch", "policy epoch"),
            ("decision_input_digest", "decision-input digest"),
            ("security_context_digest", "security-context digest"),
            ("intent_digest", "intent digest"),
            ("finality_sink", "finality sink"),
        )
        for field, label in inherited_fields:
            if getattr(envelope, field) != getattr(p, field):
                raise APCError(APCErrorCode.CONTINUITY_VIOLATION, f"inherited {label} changed across transition")

        if envelope.sender_identity != p.receiver_identity:
            raise APCError(APCErrorCode.ACTOR_MISMATCH, "child sender is not the parent's receiver")
        if envelope.sender_workload_identity != p.receiver_workload_identity:
            raise APCError(APCErrorCode.WORKLOAD_TRUST_INVALID, "child sender workload is not the parent's receiver workload")

        if envelope.authority_id != p.authority_id:
            if not envelope.delegation_id or envelope.delegation_id == p.delegation_id:
                raise APCError(APCErrorCode.DELEGATION_INVALID, "authority change requires a new explicit delegation")
        elif envelope.delegation_id != p.delegation_id and envelope.parent_authority_id == p.authority_id:
            # A new delegation identifier with the same authority is allowed only
            # as a bounded sub-delegation marker; the authority itself stays fixed.
            pass

        # Material action changes must carry an explicit transformation witness
        # reference. The reference is authenticated by the sender signature and
        # chained into the continuity witness.
        material_fields = ("operation", "target", "candidate_act_digest", "exact_act_digest")
        if any(getattr(envelope, f) != getattr(p, f) for f in material_fields) and not envelope.transformation_digest:
            raise APCError(APCErrorCode.WITNESS_INVALID, "material action change requires transformation witness")

        if not set(envelope.capabilities).issubset(set(p.capabilities)):
            raise APCError(APCErrorCode.DELEGATION_INVALID, "child capabilities exceed parent capabilities")
        if envelope.assurance_profile not in ("A0", "A1", "A2", "A3"):
            raise APCError(APCErrorCode.ASSURANCE_INVALID, "unknown assurance profile")
        assurance_rank = {"A0": 0, "A1": 1, "A2": 2, "A3": 3}
        if assurance_rank.get(envelope.assurance_profile, -1) < assurance_rank.get(p.assurance_profile, -1):
            raise APCError(APCErrorCode.ASSURANCE_INVALID, "child assurance cannot weaken parent assurance")
        if envelope.expires_at > p.expires_at:
            raise APCError(APCErrorCode.EXPIRED_AUTHORITY, "child transition outlives parent transition")

        # Constraints can only become more restrictive. Scalar/dict equality is
        # deliberately conservative for this reference implementation.
        if p.constraints and envelope.constraints != p.constraints:
            parent_constraints = p.constraints
            child_constraints = envelope.constraints
            if set(child_constraints) - set(parent_constraints):
                raise APCError(APCErrorCode.DELEGATION_INVALID, "child constraints introduce new dimensions")
            for key, parent_value in parent_constraints.items():
                if key not in child_constraints:
                    raise APCError(APCErrorCode.DELEGATION_INVALID, "child constraints cannot remove parent limits")
                child_value = child_constraints[key]
                if isinstance(parent_value, (int, float)) and isinstance(child_value, (int, float)):
                    if key.lower().startswith(("max", "limit", "ceiling")) and child_value > parent_value:
                        raise APCError(APCErrorCode.DELEGATION_INVALID, "child numeric constraint exceeds parent bound")
                    if key.lower().startswith(("min", "floor")) and child_value < parent_value:
                        raise APCError(APCErrorCode.DELEGATION_INVALID, "child numeric constraint weakens parent lower bound")
                elif child_value != parent_value:
                    raise APCError(APCErrorCode.DELEGATION_INVALID, "non-numeric constraint changed without supported attenuation rule")
        return p.digest

    def validate(
        self,
        envelope: APCProtocolEnvelope,
        *,
        now: datetime | None = None,
        require_assurance: bool = False,
    ) -> None:
        now = now or _now()
        self.operations.check(envelope.action_chain_id, self.node_id)
        contract = self._contracts(envelope.contract_id, envelope.contract_version)
        if envelope.receiver_identity != self.node_identity:
            raise APCError(APCErrorCode.ACTOR_MISMATCH, "transition receiver is not this APC enforcement endpoint")
        if envelope.receiver_workload_identity != self.node_workload_identity:
            raise APCError(APCErrorCode.WORKLOAD_TRUST_INVALID, "transition receiver workload is not this APC enforcement endpoint")
        if envelope.protocol_version != CONTINUITY_PROTOCOL_VERSION:
            raise APCError(APCErrorCode.PROTOCOL_VERSION_INVALID, "unsupported APC continuity protocol")
        if envelope.schema_version != CONTINUITY_SCHEMA_VERSION:
            raise APCError(APCErrorCode.SCHEMA_VERSION_INVALID, "unsupported APC envelope schema")
        if envelope.canonicalization_version != CANONICALIZATION_VERSION:
            raise APCError(APCErrorCode.CANONICALIZATION_VERSION_INVALID, "canonicalization mismatch")
        if envelope.cryptographic_domain != CONTINUITY_CRYPTO_DOMAIN:
            raise APCError(APCErrorCode.CRYPTO_DOMAIN_INVALID, "cryptographic domain mismatch")
        if envelope.contract_id != contract.contract_id or envelope.contract_version != contract.version:
            raise APCError(APCErrorCode.CONTRACT_INVALID, "contract reference mismatch")
        if contract.require_authority:
            if self.authority_resolver is None:
                raise APCError(APCErrorCode.INVALID_AUTHORITY, "transition authority verifier is not configured")
            try:
                authority_ref = self.authority_resolver(envelope.authority_id)
            except Exception as exc:
                raise APCError(APCErrorCode.INVALID_AUTHORITY, "unable to resolve referenced authority") from exc
            if authority_ref is None:
                raise APCError(APCErrorCode.INVALID_AUTHORITY, "referenced authority is unavailable")
            authority_ref.validate_envelope(envelope, root=envelope.parent_transition_id is None)
        if not contract.allows(envelope):
            raise APCError(APCErrorCode.CONTRACT_VIOLATION, "transition violates APC security contract")
        if contract.require_transformation_witness and not envelope.transformation_digest:
            raise APCError(APCErrorCode.WITNESS_INVALID, "material transformation requires a transformation witness")
        if contract.require_sender_signature:
            self.verify_sender_signature(envelope)
        self._check_freshness(envelope, now, contract)
        if self.store.nonce_seen(envelope.sender_key_id, envelope.nonce):
            raise APCError(APCErrorCode.REPLAYED_AUTHORITY, "transition nonce replay")
        predecessor = self._check_parent(envelope)
        assurance_required = require_assurance or contract.required_assurance in ("A2", "A3")
        if assurance_required:
            if self.assurance_verifier is None or self.node_attestation is None:
                raise APCError(APCErrorCode.ASSURANCE_UNAVAILABLE, "independent APC assurance is required but not configured")
            if self.expected_runtime_measurement is None or self.expected_contract_digest is None:
                raise APCError(APCErrorCode.ASSURANCE_UNAVAILABLE, "assurance expectations are not configured")
            self.assurance_verifier.verify(
                self.node_attestation,
                expected_runtime_measurement=self.expected_runtime_measurement,
                expected_contract_digest=self.expected_contract_digest,
                expected_node_id=self.node_id,
                now=now,
            )
        return predecessor

    def accept(
        self,
        envelope: APCProtocolEnvelope,
        *,
        now: datetime | None = None,
        require_assurance: bool = False,
    ) -> ContinuityWitness:
        predecessor = self.validate(envelope, now=now, require_assurance=require_assurance)
        witness_payload = {
            "schema_version": CONTINUITY_WITNESS_SCHEMA,
            "crypto_domain": WITNESS_CRYPTO_DOMAIN,
            "witness_id": f"wit-{envelope.transition_id}",
            "transition_id": envelope.transition_id,
            "parent_transition_id": envelope.parent_transition_id,
            "action_chain_id": envelope.action_chain_id,
            "predecessor_digest": predecessor,
            "envelope_digest": envelope.digest,
            "transformation_digest": envelope.transformation_digest,
            "issued_at": _iso(now or _now()),
            "verifier_node_id": self.node_id,
            "key_id": self.key_pair.key_id,
        }
        witness = ContinuityWitness(
            witness_id=witness_payload["witness_id"],
            transition_id=envelope.transition_id,
            parent_transition_id=envelope.parent_transition_id,
            action_chain_id=envelope.action_chain_id,
            predecessor_digest=predecessor,
            envelope_digest=envelope.digest,
            transformation_digest=envelope.transformation_digest,
            issued_at=datetime.fromisoformat(witness_payload["issued_at"]),
            verifier_node_id=self.node_id,
            key_id=self.key_pair.key_id,
            signature=self.key_pair.sign(witness_payload),
        )
        try:
            self.store.put(TransitionRecord(envelope, witness, predecessor, now or _now()))
        except APCError:
            raise
        except Exception as exc:
            raise APCError(APCErrorCode.STATE_UNAVAILABLE, "transition state persistence unavailable") from exc
        if self.graph is not None:
            self.graph.add_transition(self.store.require(envelope.transition_id))
        return witness


class ContinuityFinalityVerifier:
    """Requires a complete, enforced transition path before invoking APC finality."""

    def __init__(self, *, finality_enforcer: Any, store: ContinuityStore, public_key_resolver: Callable[[str], str], operations: APCSecurityOperations | None = None, node_id: str = "finality"):
        self._finality = finality_enforcer
        self._store = store
        self._keys = public_key_resolver
        self._operations = operations or APCSecurityOperations()
        self._node_id = node_id

    def verify_chain(self, *, action_chain_id: str, final_transition_id: str) -> list[TransitionRecord]:
        record = self._store.get(final_transition_id)
        if record is None:
            raise APCError(APCErrorCode.CHAIN_MISMATCH, "final transition not found")
        if record.envelope.action_chain_id != action_chain_id:
            raise APCError(APCErrorCode.CHAIN_MISMATCH, "final transition belongs to wrong chain")
        chain: list[TransitionRecord] = []
        seen: set[str] = set()
        current = record
        while current is not None:
            tid = current.envelope.transition_id
            if tid in seen:
                raise APCError(APCErrorCode.CHAIN_LOOP, "cycle detected in transition chain")
            seen.add(tid)
            self._verify_witness(current)
            chain.append(current)
            parent_id = current.envelope.parent_transition_id
            if parent_id is None:
                break
            parent = self._store.get(parent_id)
            if parent is None:
                raise APCError(APCErrorCode.CHAIN_MISMATCH, "missing transition predecessor")
            if parent.envelope.action_chain_id != action_chain_id:
                raise APCError(APCErrorCode.CHAIN_MISMATCH, "predecessor chain mismatch")
            if current.envelope.transition_counter != parent.envelope.transition_counter + 1:
                raise APCError(APCErrorCode.TRANSITION_ORDER_INVALID, "non-contiguous transition chain")
            if current.witness.predecessor_digest != parent.envelope.digest:
                raise APCError(APCErrorCode.CHAIN_MISMATCH, "continuity witness predecessor mismatch")
            current = parent
        chain.reverse()
        for index, item in enumerate(chain):
            if item.envelope.transition_counter != index:
                raise APCError(APCErrorCode.TRANSITION_ORDER_INVALID, "transition counters are not contiguous")
        return chain

    def _verify_witness(self, record: TransitionRecord) -> None:
        witness = record.witness
        if witness.schema_version != CONTINUITY_WITNESS_SCHEMA or witness.crypto_domain != WITNESS_CRYPTO_DOMAIN:
            raise APCError(APCErrorCode.WITNESS_INVALID, "unsupported continuity witness schema/domain")
        if witness.action_chain_id != record.envelope.action_chain_id:
            raise APCError(APCErrorCode.WITNESS_INVALID, "witness chain mismatch")
        if witness.transition_id != record.envelope.transition_id:
            raise APCError(APCErrorCode.WITNESS_INVALID, "witness transition mismatch")
        if witness.envelope_digest != record.envelope.digest:
            raise APCError(APCErrorCode.WITNESS_INVALID, "witness does not bind envelope")
        public_key = self._keys(witness.key_id)
        if not public_key:
            raise APCError(APCErrorCode.INVALID_SIGNATURE, "unknown witness key")
        verify_signature(witness.payload(), witness.signature, public_key)

    def verify_and_enforce(
        self,
        *,
        action_chain_id: str,
        final_transition_id: str,
        authority: Any,
        actual_context: Any,
        executing_actor_id: str,
        now: datetime | None = None,
    ) -> None:
        self._operations.check(action_chain_id, self._node_id)
        chain = self.verify_chain(action_chain_id=action_chain_id, final_transition_id=final_transition_id)
        final = chain[-1].envelope
        if final.authority_id != authority.authority_id:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "final transition authority mismatch")
        if final.exact_act_digest != actual_context.candidate_act_digest:
            raise APCError(APCErrorCode.DIGEST_MISMATCH, "final transition exact-act mismatch")
        if final.finality_sink != actual_context.finality_sink:
            raise APCError(APCErrorCode.AUDIENCE_MISMATCH, "finality sink mismatch")
        self._finality.verify(authority, actual_context, executing_actor_id, now=now)


class ContinuityProtectedExecutor:
    """Continuity-aware protected effect executor.

    The transition chain is verified first. The existing APC finality verifier
    then performs the original exact-act/authority/security-state checks before
    this class invokes the customer protected sink.
    """

    def __init__(
        self,
        *,
        continuity_finality: ContinuityFinalityVerifier,
        store: ContinuityStore,
        sink: Any,
        mark_complete: Callable[[str, bool, bool], None] | None = None,
    ) -> None:
        self._continuity_finality = continuity_finality
        self._store = store
        self._sink = sink
        self._mark_complete = mark_complete

    def execute(
        self,
        *,
        action_chain_id: str,
        final_transition_id: str,
        authority: Any,
        actual_context: Any,
        executing_actor_id: str,
        now: datetime | None = None,
    ) -> Any:
        self._continuity_finality.verify_and_enforce(
            action_chain_id=action_chain_id,
            final_transition_id=final_transition_id,
            authority=authority,
            actual_context=actual_context,
            executing_actor_id=executing_actor_id,
            now=now,
        )
        idem = f"{authority.authority_id}:{authority.nonce}"
        try:
            result = self._sink.execute(actual_context.candidate_act, idem)
            status = getattr(result, "status", None)
            if self._mark_complete is not None:
                if status == "UNKNOWN":
                    self._mark_complete(authority.authority_id, False, True)
                else:
                    self._mark_complete(authority.authority_id, status == "SUCCESS", False)
            return result
        except Exception:
            if self._mark_complete is not None:
                self._mark_complete(authority.authority_id, False, True)
            raise


class SecurityContractRegistry:
    def __init__(self, contracts: Iterable[SecurityContract] = ()) -> None:
        self._contracts: dict[tuple[str, str], SecurityContract] = {}
        for contract in contracts:
            self.register(contract)

    def register(self, contract: SecurityContract) -> None:
        key = (contract.contract_id, contract.version)
        self._contracts[key] = contract

    def resolve(self, contract_id: str, version: str) -> SecurityContract:
        contract = self._contracts.get((contract_id, version))
        if contract is None:
            raise APCError(APCErrorCode.CONTRACT_INVALID, f"unknown security contract {contract_id}@{version}")
        return contract

    def digest(self) -> str:
        payload = [c.model_dump(mode="json") for c in sorted(self._contracts.values(), key=lambda c: (c.contract_id, c.version))]
        return _digest(payload)


def sign_envelope(envelope_without_signature: Mapping[str, Any], key_pair: Ed25519KeyPair) -> APCProtocolEnvelope:
    """Create a signed envelope from a mapping; signature covers the normalized payload."""
    data = dict(envelope_without_signature)
    data.setdefault("protocol_version", CONTINUITY_PROTOCOL_VERSION)
    data.setdefault("schema_version", CONTINUITY_SCHEMA_VERSION)
    data.setdefault("canonicalization_version", CANONICALIZATION_VERSION)
    data.setdefault("cryptographic_domain", CONTINUITY_CRYPTO_DOMAIN)
    data["sender_key_id"] = key_pair.key_id
    data["sender_signature"] = "placeholder"
    provisional = APCProtocolEnvelope.model_validate(data)
    data["sender_signature"] = key_pair.sign(provisional.unsigned_payload())
    return APCProtocolEnvelope.model_validate(data)


def create_attestation(
    *,
    node_id: str,
    implementation_version: str,
    runtime_measurement: str,
    policy_contract_digest: str,
    key_pair: Ed25519KeyPair,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    trust_state: str = "TRUSTED",
) -> APCNodeAttestation:
    issued_at = issued_at or _now()
    expires_at = expires_at or (issued_at + timedelta(minutes=5))
    signature_payload = {
        "node_id": node_id,
        "protocol_version": CONTINUITY_PROTOCOL_VERSION,
        "implementation_version": implementation_version,
        "runtime_measurement": runtime_measurement,
        "policy_contract_digest": policy_contract_digest,
        "trust_state": trust_state,
        "issued_at": _iso(issued_at),
        "expires_at": _iso(expires_at),
        "key_id": key_pair.key_id,
    }
    return APCNodeAttestation(
        node_id=node_id, protocol_version=CONTINUITY_PROTOCOL_VERSION,
        implementation_version=implementation_version, runtime_measurement=runtime_measurement,
        policy_contract_digest=policy_contract_digest, trust_state=trust_state,
        issued_at=issued_at, expires_at=expires_at, key_id=key_pair.key_id,
        signature=key_pair.sign(signature_payload),
    )
