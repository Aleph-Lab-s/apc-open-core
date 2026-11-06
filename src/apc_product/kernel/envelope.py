from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol
import uuid

from .canonical import canonical_json, sha256_hex


class Signer(Protocol):
    key_id: str
    def sign(self, payload: Any) -> str: ...


class Verifier(Protocol):
    def verify(self, payload: Any, signature: str, key_id: str) -> None: ...


@dataclass(frozen=True)
class ProtocolEnvelope:
    protocol_version: str
    schema_version: str
    canonicalization_version: str
    crypto_domain: str
    tenant: str
    transition_id: str
    action_chain_id: str
    invocation_id: str
    sender_identity: str
    sender_workload_identity: str
    receiver_identity: str
    receiver_workload_identity: str
    parent_transition_id: str | None
    authority_id: str
    policy_decision_id: str
    policy_version: str
    policy_epoch: int
    decision_input_digest: str
    security_context_digest: str
    intent_digest: str
    candidate_act_digest: str
    exact_act_digest: str
    target: str
    capability: str
    constraints: Mapping[str, Any]
    finality_sink: str
    nonce: str
    issued_at: datetime
    expires_at: datetime
    assurance_profile: str
    allowed_next_transitions: tuple[str, ...] = ()
    transition_counter: int = 0
    sender_key_id: str = ""
    sender_signature: str = ""

    def __post_init__(self) -> None:
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("envelope timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("envelope expiry must be after issue time")
        if self.transition_counter < 0:
            raise ValueError("transition_counter cannot be negative")
        for name in ("tenant", "transition_id", "action_chain_id", "invocation_id", "authority_id", "nonce", "finality_sink"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} is required")

    def unsigned(self) -> dict[str, Any]:
        data = {
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "canonicalization_version": self.canonicalization_version,
            "crypto_domain": self.crypto_domain,
            "tenant": self.tenant,
            "transition_id": self.transition_id,
            "action_chain_id": self.action_chain_id,
            "invocation_id": self.invocation_id,
            "sender_identity": self.sender_identity,
            "sender_workload_identity": self.sender_workload_identity,
            "receiver_identity": self.receiver_identity,
            "receiver_workload_identity": self.receiver_workload_identity,
            "parent_transition_id": self.parent_transition_id,
            "authority_id": self.authority_id,
            "policy_decision_id": self.policy_decision_id,
            "policy_version": self.policy_version,
            "policy_epoch": self.policy_epoch,
            "decision_input_digest": self.decision_input_digest,
            "security_context_digest": self.security_context_digest,
            "intent_digest": self.intent_digest,
            "candidate_act_digest": self.candidate_act_digest,
            "exact_act_digest": self.exact_act_digest,
            "target": self.target,
            "capability": self.capability,
            "constraints": dict(self.constraints),
            "finality_sink": self.finality_sink,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "assurance_profile": self.assurance_profile,
            "allowed_next_transitions": self.allowed_next_transitions,
            "transition_counter": self.transition_counter,
            "sender_key_id": self.sender_key_id,
        }
        return data

    @property
    def digest(self) -> str:
        return sha256_hex(self.unsigned())

    def sign(self, signer: Signer) -> "ProtocolEnvelope":
        if not signer.key_id.strip():
            raise ValueError("signer key_id is required")
        unsigned = replace(self, sender_key_id=signer.key_id, sender_signature="")
        sig = signer.sign(unsigned.unsigned())
        return replace(unsigned, sender_signature=sig)

    def verify(self, verifier: Verifier, now: datetime | None = None) -> None:
        if not self.sender_key_id or not self.sender_signature:
            raise ValueError("unsigned envelope")
        verifier.verify(self.unsigned(), self.sender_signature, self.sender_key_id)
        now = now or datetime.now(timezone.utc)
        if now >= self.expires_at:
            raise ValueError("expired envelope")
        if now < self.issued_at:
            raise ValueError("envelope is not yet valid")
