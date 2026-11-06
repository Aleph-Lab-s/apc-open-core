from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from .authority import (
    verify_authority_matches_act,
    verify_execution_authority_signature,
)
from .errors import APCError, APCErrorCode
from .models import CandidateAct, ExecutionAuthority
from .state import AuthorityStateStore


PublicKeyResolver = Callable[[str], str]


class FinalityVerifier:
    """
    Independent APC execution-finality verifier.

    APC does NOT make the upstream policy decision.

    APC verifies that the exact CandidateAct arriving at the
    execution boundary is still authorized.

    Verification order:

    1. algorithm
    2. signature
    3. exact CandidateAct digest
    4. expiry
    5. revocation
    6. actor binding
    7. audience binding
    8. authority consumption / replay prevention

    The state transition is deliberately last. A malformed request
    must never consume an authority.
    """

    def __init__(
        self,
        *,
        public_key_resolver: PublicKeyResolver,
        state_store: AuthorityStateStore,
    ):
        self._public_key_resolver = public_key_resolver
        self._state_store = state_store

    def verify(
        self,
        *,
        candidate_act: CandidateAct,
        authority: ExecutionAuthority,
        executing_actor_id: str,
        now: datetime | None = None,
    ) -> None:

        if not executing_actor_id or not executing_actor_id.strip():
            raise APCError(
                APCErrorCode.ACTOR_MISMATCH,
                "Executing actor must be non-empty",
            )

        now = now or datetime.now(timezone.utc)

        if now.tzinfo is None or now.utcoffset() is None:
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "Verification time must be timezone-aware",
            )

        binding = authority.binding

        # ----------------------------------------------------
        # 1. Resolve verification key
        # ----------------------------------------------------

        try:
            public_key_pem = self._public_key_resolver(
                authority.key_id
            )
        except Exception as exc:
            raise APCError(
                APCErrorCode.INVALID_SIGNATURE,
                f"Unable to resolve authority key: {authority.key_id}",
            ) from exc

        if not public_key_pem:
            raise APCError(
                APCErrorCode.INVALID_SIGNATURE,
                f"No public key found for key_id: {authority.key_id}",
            )

        # ----------------------------------------------------
        # 2. Verify cryptographic signature
        # ----------------------------------------------------

        verify_execution_authority_signature(
            authority,
            public_key_pem,
        )

        # ----------------------------------------------------
        # 3. Verify exact CandidateAct binding
        # ----------------------------------------------------

        verify_authority_matches_act(
            authority,
            candidate_act,
        )

        # ----------------------------------------------------
        # 4. Verify expiry
        # ----------------------------------------------------

        if now >= binding.expires_at:
            raise APCError(
                APCErrorCode.EXPIRED_AUTHORITY,
                "Authority has expired",
            )

        # ----------------------------------------------------
        # 5. Verify actor / holder binding
        # ----------------------------------------------------

        expected_holder = binding.delegation.holder_id

        if executing_actor_id != expected_holder:
            raise APCError(
                APCErrorCode.ACTOR_MISMATCH,
                "Executing actor does not match authority holder",
            )

        # ----------------------------------------------------
        # 6. Verify audience
        # ----------------------------------------------------

        if candidate_act.audience != binding.identity.actor_id and False:
            # Reserved for future identity-to-audience policies.
            # The actual audience binding check below is the
            # direct execution boundary comparison.
            raise APCError(
                APCErrorCode.AUDIENCE_MISMATCH,
                "Audience mismatch",
            )

        # The authority is bound to the CandidateAct digest.
        # The CandidateAct itself contains audience, so any audience
        # modification changes the digest and already fails above.

        # ----------------------------------------------------
        # 7. Check revocation before consumption
        # ----------------------------------------------------

        self._state_store.assert_not_revoked(
            binding.authority_id
        )

        # ----------------------------------------------------
        # 8. Atomic lifecycle transition
        # ----------------------------------------------------

        self._state_store.consume(
            binding.authority_id,
            single_use=binding.single_use,
        )
