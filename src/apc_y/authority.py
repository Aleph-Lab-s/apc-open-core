from __future__ import annotations

from datetime import UTC, datetime

from .canonical import candidate_act_digest
from .crypto import Ed25519KeyPair, verify_signature
from .errors import APCError, APCErrorCode
from .models import (
    AuthorityBinding,
    CandidateAct,
    DelegationContext,
    ExecutionAuthority,
    IdentityContext,
    PolicyDecision,
)


def authority_payload(
    binding: AuthorityBinding,
) -> dict:
    return {
        "authority_id": binding.authority_id,
        "identity": binding.identity.model_dump(mode="json"),
        "delegation": binding.delegation.model_dump(mode="json"),
        "policy_decision_id": binding.policy_decision_id,
        "candidate_act_digest": binding.candidate_act_digest,
        "issued_at": binding.issued_at.isoformat(),
        "expires_at": binding.expires_at.isoformat(),
        "single_use": binding.single_use,
    }


def issue_authority(
    *,
    authority_id: str,
    identity: IdentityContext,
    delegation: DelegationContext,
    policy_decision: PolicyDecision,
    candidate_act: CandidateAct,
    key_pair: Ed25519KeyPair,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    single_use: bool = True,
) -> ExecutionAuthority:

    if policy_decision.decision.value != "ALLOW":
        raise APCError(
            APCErrorCode.INVALID_AUTHORITY,
            "Cannot issue APC authority from a DENY decision",
        )

    issued_at = issued_at or datetime.now(UTC)

    if expires_at is None:
        expires_at = policy_decision.expires_at

    if expires_at > policy_decision.expires_at:
        raise APCError(
            APCErrorCode.INVALID_AUTHORITY,
            "Authority cannot outlive upstream policy decision",
        )

    binding = AuthorityBinding(
        authority_id=authority_id,
        identity=identity,
        delegation=delegation,
        policy_decision_id=policy_decision.decision_id,
        candidate_act_digest=candidate_act_digest(candidate_act),
        issued_at=issued_at,
        expires_at=expires_at,
        single_use=single_use,
    )

    signature = key_pair.sign(authority_payload(binding))

    return ExecutionAuthority(
        binding=binding,
        algorithm="Ed25519",
        key_id=key_pair.key_id,
        signature=signature,
    )


def verify_execution_authority_signature(
    authority: ExecutionAuthority,
    public_key_pem: str,
) -> None:

    if authority.algorithm != "Ed25519":
        raise APCError(
            APCErrorCode.INVALID_SIGNATURE,
            f"Unsupported algorithm: {authority.algorithm}",
        )

    verify_signature(
        authority_payload(authority.binding),
        authority.signature,
        public_key_pem,
    )


def verify_authority_matches_act(
    authority: ExecutionAuthority,
    candidate_act: CandidateAct,
) -> None:

    actual_digest = candidate_act_digest(candidate_act)

    expected_digest = authority.binding.candidate_act_digest

    if actual_digest != expected_digest:
        raise APCError(
            APCErrorCode.DIGEST_MISMATCH,
            "CandidateAct does not match the act cryptographically bound into authority",
        )
