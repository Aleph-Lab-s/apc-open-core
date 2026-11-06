from __future__ import annotations

from datetime import datetime
from enum import Enum
from math import isfinite
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class APCModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )


class AuthorityState(str, Enum):
    ISSUED = "ISSUED"
    CONSUMED = "CONSUMED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


def _require_non_empty(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _require_aware_datetime(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


def validate_json_value(value: Any, path: str = "value") -> Any:
    if value is None:
        return value

    # JSON does not permit NaN or +/-Infinity even though Python's float type does.
    # Reject them at the earliest model boundary so they cannot survive into
    # canonicalization, hashing, signing, policy evaluation, or a protected sink.
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError(f"{path} contains a non-finite floating-point value")
        return value

    if isinstance(value, (str, int, bool)):
        return value

    if isinstance(value, list):
        return [
            validate_json_value(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]

    if isinstance(value, tuple):
        return tuple(
            validate_json_value(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        )

    if isinstance(value, dict):
        validated = {}

        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(
                    f"{path} contains a non-string dictionary key"
                )

            validated[key] = validate_json_value(
                item,
                f"{path}.{key}",
            )

        return validated

    raise ValueError(
        f"{path} contains a non JSON-compatible value: "
        f"{type(value).__name__}"
    )


class IdentityContext(APCModel):
    principal_id: str
    actor_id: str
    actor_type: str
    issuer: str

    @field_validator(
        "principal_id",
        "actor_id",
        "actor_type",
        "issuer",
    )
    @classmethod
    def validate_non_empty(
        cls,
        value: str,
        info,
    ) -> str:
        return _require_non_empty(value, info.field_name)


class DelegationContext(APCModel):
    root_principal_id: str
    holder_id: str
    delegation_chain: tuple[str, ...] = ()

    @field_validator(
        "root_principal_id",
        "holder_id",
    )
    @classmethod
    def validate_non_empty(
        cls,
        value: str,
        info,
    ) -> str:
        return _require_non_empty(value, info.field_name)

    @field_validator("delegation_chain")
    @classmethod
    def validate_chain(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        for item in value:
            _require_non_empty(item, "delegation_chain item")
        return value


class PolicyDecision(APCModel):
    decision_id: str
    issuer: str
    decision: Decision
    policy_reference: str | None = None
    issued_at: datetime
    expires_at: datetime

    @field_validator(
        "decision_id",
        "issuer",
    )
    @classmethod
    def validate_non_empty(
        cls,
        value: str,
        info,
    ) -> str:
        return _require_non_empty(value, info.field_name)

    @field_validator(
        "issued_at",
        "expires_at",
    )
    @classmethod
    def validate_time(
        cls,
        value: datetime,
        info,
    ) -> datetime:
        return _require_aware_datetime(value, info.field_name)

    @model_validator(mode="after")
    def validate_order(self):
        if self.expires_at <= self.issued_at:
            raise ValueError(
                "expires_at must be later than issued_at"
            )
        return self


class CandidateAct(APCModel):
    invocation_id: str
    operation: str
    resource: str
    parameters: dict[str, Any]
    constraints: dict[str, Any] = Field(default_factory=dict)
    audience: str

    @field_validator(
        "invocation_id",
        "operation",
        "resource",
        "audience",
    )
    @classmethod
    def validate_non_empty(
        cls,
        value: str,
        info,
    ) -> str:
        return _require_non_empty(value, info.field_name)

    @field_validator(
        "parameters",
        "constraints",
    )
    @classmethod
    def validate_json(
        cls,
        value: dict[str, Any],
        info,
    ) -> dict[str, Any]:
        return validate_json_value(
            value,
            info.field_name,
        )


class AuthorityBinding(APCModel):
    authority_id: str

    identity: IdentityContext
    delegation: DelegationContext

    policy_decision_id: str

    candidate_act_digest: str

    issued_at: datetime
    expires_at: datetime

    single_use: bool = True

    @field_validator(
        "authority_id",
        "policy_decision_id",
        "candidate_act_digest",
    )
    @classmethod
    def validate_non_empty(
        cls,
        value: str,
        info,
    ) -> str:
        return _require_non_empty(value, info.field_name)

    @field_validator(
        "issued_at",
        "expires_at",
    )
    @classmethod
    def validate_time(
        cls,
        value: datetime,
        info,
    ) -> datetime:
        return _require_aware_datetime(value, info.field_name)

    @model_validator(mode="after")
    def validate_order(self):
        if self.expires_at <= self.issued_at:
            raise ValueError(
                "expires_at must be later than issued_at"
            )
        return self


class ExecutionAuthority(APCModel):
    binding: AuthorityBinding

    algorithm: str
    key_id: str
    signature: str

    @field_validator(
        "algorithm",
        "key_id",
        "signature",
    )
    @classmethod
    def validate_non_empty(
        cls,
        value: str,
        info,
    ) -> str:
        return _require_non_empty(value, info.field_name)


class EffectuationRequest(APCModel):
    candidate_act: CandidateAct
    authority: ExecutionAuthority


class EvidenceEvent(APCModel):
    event_id: str
    invocation_id: str
    event_type: str

    timestamp: datetime

    previous_event_hash: str | None = None

    payload: dict[str, Any]

    @field_validator(
        "event_id",
        "invocation_id",
        "event_type",
    )
    @classmethod
    def validate_non_empty(
        cls,
        value: str,
        info,
    ) -> str:
        return _require_non_empty(value, info.field_name)

    @field_validator("timestamp")
    @classmethod
    def validate_time(
        cls,
        value: datetime,
    ) -> datetime:
        return _require_aware_datetime(
            value,
            "timestamp",
        )

    @field_validator("payload")
    @classmethod
    def validate_payload(
        cls,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        return validate_json_value(
            value,
            "payload",
        )
