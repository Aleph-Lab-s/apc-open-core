from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Mapping
import threading
import re

from .contracts import AdapterLifecycle, IntegrationManifest, UpgradePlan, VendorAdapter, assert_no_raw_secrets, redact_secrets


class IntegrationManager:
    """Vendor-neutral lifecycle manager.

    It deliberately keeps vendor-specific behavior behind the adapter SPI and
    centralizes operational controls needed for enterprise supportability.
    """

    def __init__(self, current_apc_version: str = "6.0.0") -> None:
        self.current_apc_version = current_apc_version
        self._adapters: dict[str, VendorAdapter] = {}
        self._state: dict[str, AdapterLifecycle] = {}
        self._configs: dict[str, Mapping[str, Any]] = {}
        self._mutex = threading.RLock()

    def register(self, adapter: VendorAdapter, config: Mapping[str, Any]) -> IntegrationManifest:
        with self._lock():
            manifest = adapter.manifest
            manifest.validate()
            if not self.compatible_with_current_apc(manifest):
                raise ValueError(f'integration {manifest.integration_id} is incompatible with APC {self.current_apc_version}')
            if manifest.integration_id in self._adapters:
                raise ValueError(f'duplicate integration_id: {manifest.integration_id}')
            assert_no_raw_secrets(config)
            adapter.validate_config(config)
            self._adapters[manifest.integration_id] = adapter
            self._configs[manifest.integration_id] = redact_secrets(config)
            self._state[manifest.integration_id] = AdapterLifecycle.VALIDATED
            return manifest

    def activate(self, integration_id: str) -> None:
        adapter = self._get(integration_id)
        health = adapter.health()
        if health.status not in {'READY', 'HEALTHY', 'OK'}:
            self._state[integration_id] = AdapterLifecycle.DEGRADED
            raise RuntimeError(f'integration {integration_id} is not healthy: {health.status}')
        self._state[integration_id] = AdapterLifecycle.READY

    def health(self, integration_id: str):
        return self._get(integration_id).health()

    def diagnostics(self, integration_id: str) -> Mapping[str, Any]:
        return redact_secrets(dict(self._get(integration_id).diagnostics()))

    def plan_upgrade(self, integration_id: str, target_version: str) -> UpgradePlan:
        return self._get(integration_id).plan_upgrade(target_version)

    def upgrade(self, integration_id: str, target_version: str) -> UpgradePlan:
        adapter = self._get(integration_id)
        plan = adapter.plan_upgrade(target_version)
        if not plan.compatible:
            raise RuntimeError(f'upgrade rejected as incompatible: {integration_id} -> {target_version}')
        self._state[integration_id] = AdapterLifecycle.DRAINING if plan.requires_drain else AdapterLifecycle.UPGRADING
        try:
            adapter.apply_upgrade(plan)
            if adapter.health().status not in {'READY', 'HEALTHY', 'OK'}:
                raise RuntimeError('post-upgrade health check failed')
            self._state[integration_id] = AdapterLifecycle.READY
            return plan
        except Exception as exc:
            # Enterprise rule: an upgrade that cannot prove healthy completion must
            # attempt deterministic rollback before declaring the integration failed.
            rollback_error = None
            try:
                adapter.rollback(plan)
                if adapter.health().status in {'READY', 'HEALTHY', 'OK'}:
                    self._state[integration_id] = AdapterLifecycle.READY
                    return plan
                rollback_error = 'post-rollback health check failed'
            except Exception as rb_exc:
                rollback_error = repr(rb_exc)
            self._state[integration_id] = AdapterLifecycle.FAILED
            raise RuntimeError(f'upgrade failed and rollback was not healthy: {exc}; rollback={rollback_error}') from exc

    def rollback(self, integration_id: str, plan: UpgradePlan) -> None:
        adapter = self._get(integration_id)
        self._state[integration_id] = AdapterLifecycle.UPGRADING
        try:
            adapter.rollback(plan)
            if adapter.health().status not in {'READY', 'HEALTHY', 'OK'}:
                raise RuntimeError('post-rollback health check failed')
            self._state[integration_id] = AdapterLifecycle.READY
        except Exception:
            self._state[integration_id] = AdapterLifecycle.FAILED
            raise

    def disable(self, integration_id: str) -> None:
        self._get(integration_id).close()
        self._state[integration_id] = AdapterLifecycle.DISABLED

    def status(self, integration_id: str) -> dict[str, Any]:
        adapter = self._get(integration_id)
        return {
            'integration_id': integration_id,
            'state': self._state[integration_id].value,
            'vendor': adapter.manifest.vendor,
            'adapter_version': adapter.manifest.adapter_version,
            'checked_at': datetime.now(timezone.utc).isoformat(),
        }

    def compatible_with_current_apc(self, manifest: IntegrationManifest) -> bool:
        cur = self._version_tuple(self.current_apc_version)
        if cur < self._version_tuple(manifest.min_apc_version):
            return False
        if manifest.max_apc_version is not None and cur > self._version_tuple(manifest.max_apc_version):
            return False
        return True

    @staticmethod
    def _version_tuple(value: str) -> tuple[int, ...]:
        parts = re.findall(r"\d+", value)
        if not parts:
            raise ValueError(f'invalid version: {value}')
        return tuple(int(x) for x in parts[:4])

    def _lock(self):
        return self._mutex

    def _get(self, integration_id: str) -> VendorAdapter:
        if integration_id not in self._adapters:
            raise KeyError(integration_id)
        return self._adapters[integration_id]


class SupportBundleBuilder:
    """Build redacted, vendor-safe troubleshooting evidence."""

    @staticmethod
    def build(adapter: VendorAdapter, config: Mapping[str, Any], extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
        adapter.manifest.validate()
        assert_no_raw_secrets(config)
        return {
            'bundle_schema': 'APC-SUPPORT-BUNDLE-V1',
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'integration': {
                'id': adapter.manifest.integration_id,
                'vendor': adapter.manifest.vendor,
                'category': adapter.manifest.category,
                'protocol': adapter.manifest.protocol,
                'adapter_version': adapter.manifest.adapter_version,
                'security_review_status': adapter.manifest.security_review_status,
                'real_or_synthetic': adapter.manifest.real_or_synthetic,
            },
            'health': asdict(adapter.health()),
            'diagnostics': redact_secrets(dict(adapter.diagnostics())),
            'config': redact_secrets(config),
            'extra': redact_secrets(dict(extra or {})),
        }
