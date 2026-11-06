from __future__ import annotations

"""Multi-hop authorization-to-effect continuity for APC.

This module is deliberately independent of the transport/runtime used by an
agent platform. It verifies the security lineage that must survive across
agent -> agent -> tool -> adapter -> finality hops.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from apc_product.kernel.canonical import sha256_hex


@dataclass(frozen=True)
class Hop:
    chain_id: str
    hop_id: str
    parent_hop_id: str | None
    sender_identity: str
    sender_workload: str
    receiver_identity: str
    receiver_workload: str
    authority_id: str
    policy_decision_id: str
    policy_version: str
    policy_epoch: int
    security_context_digest: str
    intent_digest: str
    candidate_act_digest: str
    exact_act_digest: str
    finality_sink: str
    capability: str
    capabilities: tuple[str, ...] = ()
    constraint_digest: str = ""
    transformation_digest: str | None = None
    nonce: str = ""
    counter: int = 0
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    allowed_next_receivers: tuple[str, ...] = ()
    provenance: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in (
            "chain_id", "hop_id", "sender_identity", "sender_workload",
            "receiver_identity", "receiver_workload", "authority_id",
            "policy_decision_id", "policy_version", "security_context_digest",
            "intent_digest", "candidate_act_digest", "exact_act_digest",
            "finality_sink", "capability", "nonce",
        ):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"{name} is required")
        if self.policy_epoch < 0 or self.counter < 0:
            raise ValueError("policy_epoch and counter cannot be negative")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("hop timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("hop expiry must be after issue time")

    @property
    def digest(self) -> str:
        return sha256_hex({
            "chain_id": self.chain_id,
            "hop_id": self.hop_id,
            "parent_hop_id": self.parent_hop_id,
            "sender_identity": self.sender_identity,
            "sender_workload": self.sender_workload,
            "receiver_identity": self.receiver_identity,
            "receiver_workload": self.receiver_workload,
            "authority_id": self.authority_id,
            "policy_decision_id": self.policy_decision_id,
            "policy_version": self.policy_version,
            "policy_epoch": self.policy_epoch,
            "security_context_digest": self.security_context_digest,
            "intent_digest": self.intent_digest,
            "candidate_act_digest": self.candidate_act_digest,
            "exact_act_digest": self.exact_act_digest,
            "finality_sink": self.finality_sink,
            "capability": self.capability,
            "capabilities": self.capabilities,
            "constraint_digest": self.constraint_digest,
            "transformation_digest": self.transformation_digest,
            "nonce": self.nonce,
            "counter": self.counter,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "allowed_next_receivers": self.allowed_next_receivers,
            "provenance": dict(self.provenance),
        })


@dataclass(frozen=True)
class ContinuityReport:
    valid: bool
    chain_id: str
    hop_count: int
    path_digest: str | None
    reason: str = "OK"
    failures: tuple[str, ...] = ()


class MultiHopContinuityVerifier:
    """Verify that a governed act survives every security-relevant hop."""

    def __init__(self, *, finality_receiver: str | None = None):
        self.finality_receiver = finality_receiver

    def verify(self, hops: Iterable[Hop], *, now: datetime | None = None) -> ContinuityReport:
        ordered = tuple(hops)
        if not ordered:
            return ContinuityReport(False, "", 0, None, "EMPTY_HOP_CHAIN", ("hop chain is empty",))
        now = now or datetime.now(timezone.utc)
        failures: list[str] = []
        root = ordered[0]
        if root.counter != 0 or root.parent_hop_id is not None:
            failures.append("root_hop_invalid")

        expected_chain = root.chain_id
        expected_authority = root.authority_id
        expected_action = root.exact_act_digest
        expected_sink = root.finality_sink
        expected_policy = (root.policy_decision_id, root.policy_version, root.policy_epoch)
        expected_security = root.security_context_digest
        expected_intent = root.intent_digest
        used_nonces: set[str] = set()
        used_hop_ids: set[str] = set()

        for i, hop in enumerate(ordered):
            if hop.hop_id in used_hop_ids:
                failures.append(f"duplicate_hop_id:{hop.hop_id}")
            used_hop_ids.add(hop.hop_id)
            if hop.chain_id != expected_chain:
                failures.append(f"chain_mismatch:{hop.hop_id}")
            if hop.authority_id != expected_authority:
                failures.append(f"authority_mismatch:{hop.hop_id}")
            if hop.finality_sink != expected_sink:
                failures.append(f"sink_mismatch:{hop.hop_id}")
            if (hop.policy_decision_id, hop.policy_version, hop.policy_epoch) != expected_policy:
                failures.append(f"policy_continuity_mismatch:{hop.hop_id}")
            if hop.security_context_digest != expected_security:
                failures.append(f"security_context_mismatch:{hop.hop_id}")
            if hop.intent_digest != expected_intent:
                failures.append(f"intent_mismatch:{hop.hop_id}")
            if hop.exact_act_digest != expected_action:
                failures.append(f"exact_act_changed:{hop.hop_id}")
            if hop.nonce in used_nonces:
                failures.append(f"nonce_replay:{hop.hop_id}")
            used_nonces.add(hop.nonce)
            if hop.issued_at > now or now >= hop.expires_at:
                failures.append(f"hop_not_current:{hop.hop_id}")
            if i == 0:
                continue
            previous = ordered[i - 1]
            if hop.parent_hop_id != previous.hop_id:
                failures.append(f"parent_mismatch:{hop.hop_id}")
            if hop.counter != previous.counter + 1:
                failures.append(f"counter_not_monotonic:{hop.hop_id}")
            if hop.sender_identity != previous.receiver_identity:
                failures.append(f"sender_identity_not_previous_receiver:{hop.hop_id}")
            if hop.sender_workload != previous.receiver_workload:
                failures.append(f"sender_workload_not_previous_receiver:{hop.hop_id}")
            if previous.allowed_next_receivers and hop.receiver_identity not in previous.allowed_next_receivers:
                failures.append(f"receiver_not_allowed:{hop.hop_id}")
            if hop.expires_at > previous.expires_at:
                failures.append(f"expiry_extended:{hop.hop_id}")
            parent_caps = set(previous.capabilities or (previous.capability,))
            child_caps = set(hop.capabilities or (hop.capability,))
            if not child_caps.issubset(parent_caps):
                failures.append(f"capability_expansion:{hop.hop_id}")
        if self.finality_receiver and ordered[-1].receiver_identity != self.finality_receiver:
            failures.append("finality_receiver_mismatch")

        path_digest = sha256_hex({"hops": [hop.digest for hop in ordered]})
        if failures:
            return ContinuityReport(False, expected_chain, len(ordered), path_digest, "CHAIN_REJECTED", tuple(failures))
        return ContinuityReport(True, expected_chain, len(ordered), path_digest)
