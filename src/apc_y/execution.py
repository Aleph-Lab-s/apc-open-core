from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .errors import APCError, APCErrorCode
from .finality import FinalityVerifier
from .models import CandidateAct, ExecutionAuthority

# ============================================================
# EXECUTION RESULT
# ============================================================


@dataclass(frozen=True)
class ExecutionResult:
    invocation_id: str
    authority_id: str
    executed: bool
    result: dict[str, Any]


# ============================================================
# INTERNAL EXECUTION ADMISSION
#
# This is deliberately NOT something an agent provides.
#
# It is minted only after APC FinalityVerifier succeeds.
#
# The protected executor requires this admission object.
# ============================================================


@dataclass(frozen=True)
class _ExecutionAdmission:
    invocation_id: str
    authority_id: str
    nonce: str
    issued_at: datetime
    # Per-executor capability. This is defense-in-depth against manually
    # constructing an admission object outside the gate. It is deliberately
    # identity-compared rather than serialized or user-controlled.
    capability: object


# ============================================================
# PROTECTED EXECUTOR
#
# This represents the real side-effecting system.
#
# It will NOT execute without:
#
#   1. an APC-generated admission
#   2. matching invocation_id
#   3. matching authority_id
#
# The admission type is private by convention and is created
# only inside APCExecutionGate.
#
# ============================================================


class ProtectedExecutor:
    def __init__(
        self,
        execute_fn: Callable[[CandidateAct], dict[str, Any]],
    ):
        self._execute_fn = execute_fn
        # Unique in-memory capability for this executor instance. A Python
        # process that has already achieved arbitrary code execution is not a
        # trustworthy security boundary; this is defense-in-depth for accidental
        # or API-level admission forgery.
        self.__admission_capability = object()

    def _mint_admission(
        self,
        *,
        invocation_id: str,
        authority_id: str,
    ) -> _ExecutionAdmission:
        return _ExecutionAdmission(
            invocation_id=invocation_id,
            authority_id=authority_id,
            nonce=secrets.token_urlsafe(32),
            issued_at=datetime.now(UTC),
            capability=self.__admission_capability,
        )

    def _execute(
        self,
        *,
        candidate_act: CandidateAct,
        admission: _ExecutionAdmission,
    ) -> dict[str, Any]:

        if not isinstance(
            admission,
            _ExecutionAdmission,
        ):
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "Executor requires APC execution admission",
            )

        if admission.capability is not self.__admission_capability:
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "Execution admission capability mismatch",
            )

        if admission.invocation_id != candidate_act.invocation_id:
            raise APCError(
                APCErrorCode.INVALID_AUTHORITY,
                "Execution admission invocation mismatch",
            )

        return self._execute_fn(candidate_act)


# ============================================================
# APC EXECUTION GATE
#
# THIS IS THE EXECUTION BOUNDARY.
#
# The gate:
#
# 1. receives the real CandidateAct
# 2. verifies authority at the last responsible moment
# 3. consumes single-use authority
# 4. creates internal execution admission
# 5. invokes protected executor
#
# If verification fails:
#
#     executor is never called
#
# ============================================================


class APCExecutionGate:
    def __init__(
        self,
        *,
        finality_verifier: FinalityVerifier,
        protected_executor: ProtectedExecutor,
    ):
        self._finality_verifier = finality_verifier
        self._protected_executor = protected_executor

    def dispatch(
        self,
        *,
        candidate_act: CandidateAct,
        authority: ExecutionAuthority,
        executing_actor_id: str,
        now: datetime | None = None,
    ) -> ExecutionResult:

        # ----------------------------------------------------
        # FINALITY CHECK
        #
        # If this raises, execution NEVER happens.
        # ----------------------------------------------------

        self._finality_verifier.verify(
            candidate_act=candidate_act,
            authority=authority,
            executing_actor_id=executing_actor_id,
            now=now,
        )

        # ----------------------------------------------------
        # APC admission is created ONLY AFTER successful
        # finality verification.
        # ----------------------------------------------------

        admission = self._protected_executor._mint_admission(
            invocation_id=candidate_act.invocation_id,
            authority_id=authority.binding.authority_id,
        )

        # ----------------------------------------------------
        # REAL SIDE EFFECT
        #
        # This line is unreachable if APC verification fails.
        # ----------------------------------------------------

        result = self._protected_executor._execute(
            candidate_act=candidate_act,
            admission=admission,
        )

        return ExecutionResult(
            invocation_id=candidate_act.invocation_id,
            authority_id=authority.binding.authority_id,
            executed=True,
            result=result,
        )


# ============================================================
# SYNTHETIC PAYMENT LEDGER
#
# Represents a consequential downstream system.
#
# IMPORTANT:
#
# The ledger is not updated by the agent.
#
# It is updated only through ProtectedExecutor after APC
# admission succeeds.
#
# ============================================================


class PaymentLedger:
    def __init__(self):
        self._refunds: list[dict[str, Any]] = []

    def apply_refund(
        self,
        candidate_act: CandidateAct,
    ) -> dict[str, Any]:

        if candidate_act.operation != "refund":
            raise ValueError("PaymentLedger only supports refund operations")

        parameters = candidate_act.parameters

        record = {
            "customer_id": parameters["customer_id"],
            "amount": parameters["amount"],
            "currency": parameters["currency"],
            "invocation_id": candidate_act.invocation_id,
        }

        self._refunds.append(record)

        return {
            "status": "REFUND_EXECUTED",
            "record": record,
        }

    def refunds(self) -> list[dict[str, Any]]:
        return list(self._refunds)

    def count(self) -> int:
        return len(self._refunds)
