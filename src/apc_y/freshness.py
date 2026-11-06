from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from .errors import APCError, APCErrorCode


@dataclass(frozen=True)
class FreshnessProfile:
    max_authority_age: timedelta = timedelta(minutes=5)
    max_decision_age: timedelta | None = timedelta(minutes=5)
    max_effect_age: timedelta | None = None
    allowed_clock_skew: timedelta = timedelta(seconds=30)
    require_policy_state: bool = True
    require_workload_state: bool = False
    require_resource_precondition: bool = False

    def validate(
        self,
        *,
        issued_at: datetime,
        expires_at: datetime,
        now: datetime,
        policy_issued_at: datetime | None = None,
    ) -> None:
        for name, value in (("issued_at", issued_at), ("expires_at", expires_at), ("now", now)):
            if value.tzinfo is None or value.utcoffset() is None:
                raise APCError(APCErrorCode.INVALID_AUTHORITY, f"{name} must be timezone-aware")
        if expires_at <= issued_at:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "authority expiry must follow issuance")
        if issued_at - now > self.allowed_clock_skew:
            raise APCError(APCErrorCode.INVALID_AUTHORITY, "authority issued too far in the future")
        if now - issued_at > self.max_authority_age + self.allowed_clock_skew:
            raise APCError(APCErrorCode.EXPIRED_AUTHORITY, "authority exceeds maximum age")
        if policy_issued_at is not None:
            if policy_issued_at.tzinfo is None or policy_issued_at.utcoffset() is None:
                raise APCError(
                    APCErrorCode.INVALID_AUTHORITY, "policy_issued_at must be timezone-aware"
                )
            if policy_issued_at > issued_at + self.allowed_clock_skew:
                raise APCError(
                    APCErrorCode.INVALID_AUTHORITY, "policy decision issued after authority"
                )
            if (
                self.max_decision_age is not None
                and now - policy_issued_at > self.max_decision_age + self.allowed_clock_skew
            ):
                raise APCError(
                    APCErrorCode.EXPIRED_AUTHORITY, "policy decision exceeds maximum age"
                )


class SecurityStateProvider(Protocol):
    def current(self, tenant: str) -> object: ...


class PolicyDecisionStateProvider(Protocol):
    def get(self, decision_id: str) -> object | None: ...


class WorkloadTrustProvider(Protocol):
    def current_epoch(self, workload_id: str, tenant: str) -> int: ...
