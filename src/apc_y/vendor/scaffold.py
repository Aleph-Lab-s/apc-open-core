from __future__ import annotations

import argparse
from pathlib import Path

TEMPLATE = """from apc_y.vendor import AdapterCapability, AdapterHealth, IntegrationManifest, OwnerSet, SupportPolicy, UpgradePlan

# Generated APC vendor adapter scaffold. Replace ONLY vendor-specific transport/API code.
class {class_name}:
    manifest = ...  # build an IntegrationManifest for {vendor}

    def validate_config(self, config):
        raise NotImplementedError

    def health(self):
        raise NotImplementedError

    def diagnostics(self):
        raise NotImplementedError

    def plan_upgrade(self, target_version):
        raise NotImplementedError

    def apply_upgrade(self, plan):
        raise NotImplementedError

    def rollback(self, plan):
        raise NotImplementedError

    def close(self):
        pass


def build_adapter():
    return {class_name}()
"""


def generate(vendor: str, integration_id: str, destination: str | Path) -> Path:
    name = "".join(x.title() for x in integration_id.replace("_", "-").split("-")) + "Adapter"
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(TEMPLATE.format(class_name=name, vendor=vendor, integration_id=integration_id))
    return path


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("vendor")
    p.add_argument("integration_id")
    p.add_argument("destination")
    a = p.parse_args()
    print(generate(a.vendor, a.integration_id, a.destination))
