from __future__ import annotations

"""Versioned policy lifecycle with monotonic epochs and proof gates."""

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from apc_product.kernel.canonical import sha256_hex


@dataclass(frozen=True)
class PolicySnapshot:
    tenant: str
    epoch: int
    version: str
    policy: Mapping[str, Any]
    digest: str

    @classmethod
    def create(cls, tenant: str, epoch: int, version: str, policy: Mapping[str, Any]) -> "PolicySnapshot":
        if epoch < 0:
            raise ValueError("epoch cannot be negative")
        material = {"tenant": tenant, "epoch": epoch, "version": version, "policy": dict(policy)}
        return cls(tenant, epoch, version, dict(policy), sha256_hex(material))

    def verify(self) -> None:
        expected = sha256_hex({"tenant": self.tenant, "epoch": self.epoch, "version": self.version, "policy": dict(self.policy)})
        if expected != self.digest:
            raise ValueError("policy snapshot integrity failure")


@dataclass(frozen=True)
class PolicyProof:
    valid: bool
    verifier: str
    report: str = ""


@dataclass(frozen=True)
class PolicyAdmission:
    accepted: bool
    reason: str
    previous_epoch: int
    candidate_epoch: int
    privilege_expansion: bool
    proof_required: bool


class PolicyChangeGate:
    """Admit dynamic policy changes without allowing silent privilege expansion."""

    def __init__(self, *, require_proof_for_expansion: bool = True, proof_hook: Callable[[PolicySnapshot, PolicySnapshot], PolicyProof] | None = None):
        self.require_proof_for_expansion = require_proof_for_expansion
        self.proof_hook = proof_hook

    @staticmethod
    def _flatten_keys(value: Mapping[str, Any], prefix: str = "") -> set[str]:
        out: set[str] = set()
        for k, v in value.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            out.add(p)
            if isinstance(v, Mapping):
                out.update(PolicyChangeGate._flatten_keys(v, p))
        return out

    def _expands_privilege(self, old: Mapping[str, Any], new: Mapping[str, Any]) -> bool:
        # Conservative baseline: added endpoints/binaries/methods/credentials,
        # or any list whose new value is a strict superset, requires proof.
        sensitive_names = {"endpoints", "hosts", "binaries", "methods", "credentials", "allowed", "permissions", "capabilities"}
        for key in set(old) | set(new):
            ov, nv = old.get(key), new.get(key)
            if isinstance(ov, list) and isinstance(nv, list):
                if set(map(repr, ov)) > set(map(repr, nv)):
                    continue
                if set(map(repr, nv)) > set(map(repr, ov)):
                    if str(key).lower() in sensitive_names or len(set(nv)) > len(set(ov)):
                        return True
            elif isinstance(ov, Mapping) and isinstance(nv, Mapping):
                if self._expands_privilege(ov, nv):
                    return True
            elif nv is not None and ov is None and str(key).lower() in sensitive_names:
                return True
        return False

    def admit(self, previous: PolicySnapshot, candidate: PolicySnapshot) -> PolicyAdmission:
        previous.verify(); candidate.verify()
        if previous.tenant != candidate.tenant:
            return PolicyAdmission(False, "tenant_mismatch", previous.epoch, candidate.epoch, False, False)
        if candidate.epoch <= previous.epoch:
            return PolicyAdmission(False, "epoch_rollback_or_duplicate", previous.epoch, candidate.epoch, False, False)
        expands = self._expands_privilege(previous.policy, candidate.policy)
        proof_required = expands and self.require_proof_for_expansion
        if not proof_required:
            return PolicyAdmission(True, "accepted", previous.epoch, candidate.epoch, expands, False)
        if self.proof_hook is None:
            return PolicyAdmission(False, "privilege_expansion_requires_verified_proof", previous.epoch, candidate.epoch, expands, True)
        proof = self.proof_hook(previous, candidate)
        if not proof.valid:
            return PolicyAdmission(False, "policy_proof_failed", previous.epoch, candidate.epoch, expands, True)
        return PolicyAdmission(True, "accepted_with_verified_proof", previous.epoch, candidate.epoch, expands, True)
