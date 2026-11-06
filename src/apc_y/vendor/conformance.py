from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .contracts import (
    AdapterCapability,
    AdapterHealth,
    UpgradePlan,
    VendorAdapter,
    assert_no_raw_secrets,
)


@dataclass(frozen=True)
class ConformanceResult:
    passed: bool
    checks: tuple[str, ...]
    failures: tuple[str, ...]


def run_conformance(adapter: VendorAdapter, config: Mapping[str, Any]) -> ConformanceResult:
    checks: list[str] = []
    failures: list[str] = []
    manifest = adapter.manifest
    try:
        manifest.validate()
        checks.append("manifest")
    except Exception as exc:
        failures.append(f"manifest: {exc}")
    try:
        assert_no_raw_secrets(config)
        adapter.validate_config(config)
        checks.append("config")
    except Exception as exc:
        failures.append(f"config: {exc}")
    try:
        health = adapter.health()
        if not isinstance(health, AdapterHealth):
            raise TypeError("health() must return AdapterHealth")
        checks.append("health")
    except Exception as exc:
        failures.append(f"health: {exc}")
    try:
        diagnostics = adapter.diagnostics()
        if not isinstance(diagnostics, Mapping):
            raise TypeError("diagnostics() must return a mapping")
        checks.append("diagnostics")
    except Exception as exc:
        failures.append(f"diagnostics: {exc}")
    if AdapterCapability.UPGRADE in manifest.capabilities:
        try:
            plan = adapter.plan_upgrade(manifest.adapter_version)
            if not isinstance(plan, UpgradePlan):
                raise TypeError("plan_upgrade() must return UpgradePlan")
            checks.append("upgrade-plan")
        except Exception as exc:
            failures.append(f"upgrade-plan: {exc}")
    if AdapterCapability.ROLLBACK in manifest.capabilities:
        try:
            plan = adapter.plan_upgrade(manifest.adapter_version)
            adapter.rollback(plan)
            checks.append("rollback")
        except Exception as exc:
            failures.append(f"rollback: {exc}")
    return ConformanceResult(not failures, tuple(checks), tuple(failures))
