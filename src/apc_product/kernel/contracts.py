from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .canonical import sha256_hex

ALLOWED_MODES = frozenset({"REAL", "SANDBOX", "SYNTHETIC", "SIMULATED", "UNAVAILABLE"})


@dataclass(frozen=True)
class SecurityContract:
    contract_id: str
    version: str
    required_assurance: str = "A0"
    require_authority: bool = True
    require_sender_binding: bool = True
    require_freshness: bool = True
    require_exact_act: bool = True
    require_sink_binding: bool = True
    fail_closed_on_security_error: bool = True
    fail_closed_on_unknown_security_state: bool = True
    max_clock_skew_seconds: int = 30
    allowed_operations: tuple[str, ...] = ()
    allowed_sinks: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.contract_id.strip() or not self.version.strip():
            raise ValueError("contract_id and version are required")
        if self.max_clock_skew_seconds < 0:
            raise ValueError("max_clock_skew_seconds cannot be negative")
        if not self.fail_closed_on_security_error:
            raise ValueError("APC production security contracts must fail closed")

    @property
    def digest(self) -> str:
        return sha256_hex({
            "contract_id": self.contract_id,
            "version": self.version,
            "required_assurance": self.required_assurance,
            "require_authority": self.require_authority,
            "require_sender_binding": self.require_sender_binding,
            "require_freshness": self.require_freshness,
            "require_exact_act": self.require_exact_act,
            "require_sink_binding": self.require_sink_binding,
            "fail_closed_on_security_error": self.fail_closed_on_security_error,
            "fail_closed_on_unknown_security_state": self.fail_closed_on_unknown_security_state,
            "max_clock_skew_seconds": self.max_clock_skew_seconds,
            "allowed_operations": self.allowed_operations,
            "allowed_sinks": self.allowed_sinks,
            "metadata": dict(self.metadata),
        })

    def validate_mode(self, mode: str) -> str:
        mode = mode.upper()
        if mode not in ALLOWED_MODES:
            raise ValueError(f"unsupported integration mode: {mode}")
        if mode in {"SIMULATED", "UNAVAILABLE"} and self.required_assurance in {"A2", "A3"}:
            # Simulation is acceptable for demonstrations, not as evidence of a high-assurance effect.
            raise ValueError("simulation/unavailable cannot satisfy A2/A3 protected-effect evidence")
        return mode
