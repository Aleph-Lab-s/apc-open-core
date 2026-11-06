from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from apc_product.kernel.canonical import sha256_hex


@dataclass(frozen=True)
class SecurityConfigSnapshot:
    tenant: str
    config_epoch: int
    values: Mapping[str, Any]
    digest: str

    @classmethod
    def create(
        cls, tenant: str, config_epoch: int, values: Mapping[str, Any]
    ) -> SecurityConfigSnapshot:
        if config_epoch < 0:
            raise ValueError("config_epoch cannot be negative")
        material = {"tenant": tenant, "config_epoch": config_epoch, "values": dict(values)}
        return cls(tenant, config_epoch, dict(values), sha256_hex(material))

    def verify(self) -> None:
        expected = sha256_hex(
            {"tenant": self.tenant, "config_epoch": self.config_epoch, "values": dict(self.values)}
        )
        if expected != self.digest:
            raise ValueError("security configuration integrity failure")


def require_monotonic_config_epoch(previous: int, current: int) -> None:
    if current < previous:
        raise ValueError("security configuration epoch rollback detected")
