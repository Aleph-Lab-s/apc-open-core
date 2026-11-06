from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_helm_chart_defaults_are_single_replica_demo():
    chart = yaml.safe_load((ROOT / "deploy/helm/apc/Chart.yaml").read_text())
    values = yaml.safe_load((ROOT / "deploy/helm/apc/values.yaml").read_text())
    assert chart["version"] == "0.1.0-alpha.1"
    assert values["profile"] == "demo"
    assert values["runtimeMode"] == "DEMO"
    assert values["replicaCount"] == 1
    assert values["ha"]["enabled"] is False
    assert values["persistence"]["enabled"] is True
    assert values["persistence"]["accessModes"] == ["ReadWriteOnce"]
    assert values["networkPolicy"]["enabled"] is True
    assert values["podSecurityContext"]["runAsNonRoot"] is True
    assert values["containerSecurityContext"]["readOnlyRootFilesystem"] is True
    schema = json.loads((ROOT / "deploy/helm/apc/values.schema.json").read_text())
    assert schema["properties"]["profile"]["enum"] == ["demo"]
    assert schema["properties"]["runtimeMode"]["enum"] == ["DEMO"]
    deployment = (ROOT / "deploy/helm/apc/templates/deployment.yaml").read_text()
    assert "supports only profile=demo" in deployment
    assert "supports only runtimeMode=DEMO" in deployment


def test_registry_descriptor_is_a_draft_stdio_pypi_server():
    data = json.loads((ROOT / "registry/server.json").read_text())
    assert data["packages"][0]["registryType"] == "pypi"
    assert data["packages"][0]["transport"]["type"] == "stdio"
    assert data["packages"][0]["identifier"] == "apc-action-security"
    assert "does not intercept" in data["description"]
    assert json.loads((ROOT / "server.json").read_text()) == data
