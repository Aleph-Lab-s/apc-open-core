from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

DEPLOYMENT_PROFILES = frozenset(
    {
        "customer-hosted-container",
        "kubernetes",
        "openshift",
        "linux-native",
        "air-gapped-linux",
        "python-oem",
    }
)
PDP_OPTIONS = frozenset({"customer-pdp", "opa", "cedar", "reference-lab"})
IDENTITY_OPTIONS = frozenset({"customer-idp", "oidc", "spiffe", "mTLS", "reference-lab"})
ARTIFACT_OPTIONS = frozenset(
    {"oci", "kubernetes-bundle", "openshift-bundle", "deb", "run", "wheel"}
)
NETWORK_OPTIONS = frozenset(
    {"customer-network", "restricted-egress", "air-gapped", "internet-allowed"}
)
ARCH_OPTIONS = frozenset({"amd64", "arm64", "x86_64", "aarch64", "unspecified"})


@dataclass(frozen=True)
class CustomerIntake:
    """Customer delivery requirements; never contains credentials or private keys."""

    customer_id: str
    deployment_profile: str
    environment: str
    region: str
    pdp: str
    identity: str
    protected_sink: str
    evidence_storage: str
    ha_required: bool
    air_gapped: bool = False
    oem_language: str | None = None
    requested_version: str = "7.1.4"
    support_plan: str = "standard"
    entitlement_id: str | None = None
    artifact_format: str | None = None
    requirements: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> CustomerIntake:
        obj = cls(**dict(value))
        obj.validate()
        return obj

    def validate(self) -> None:
        if not self.customer_id.strip():
            raise ValueError("customer_id is required")
        if self.deployment_profile not in DEPLOYMENT_PROFILES:
            raise ValueError(f"unsupported deployment_profile: {self.deployment_profile}")
        if self.pdp not in PDP_OPTIONS:
            raise ValueError(f"unsupported pdp: {self.pdp}")
        if self.identity not in IDENTITY_OPTIONS:
            raise ValueError(f"unsupported identity: {self.identity}")
        if self.artifact_format and self.artifact_format not in ARTIFACT_OPTIONS:
            raise ValueError(f"unsupported artifact_format: {self.artifact_format}")
        if self.deployment_profile == "python-oem" and self.oem_language != "python":
            raise ValueError("the current OEM-native implementation supports oem_language=python")
        if self.air_gapped and self.deployment_profile not in {"air-gapped-linux", "linux-native"}:
            raise ValueError(
                "air_gapped intake requires an air-gapped-capable Linux delivery profile"
            )
        if self.deployment_profile == "air-gapped-linux" and not self.air_gapped:
            raise ValueError("air-gapped-linux deployment_profile requires air_gapped=true")
        for field_name in (
            "environment",
            "region",
            "protected_sink",
            "evidence_storage",
            "support_plan",
            "requested_version",
        ):
            if not str(getattr(self, field_name)).strip():
                raise ValueError(f"{field_name} is required")

        network = str(self.requirements.get("network_mode", "customer-network"))
        if network not in NETWORK_OPTIONS:
            raise ValueError(f"unsupported requirements.network_mode: {network}")
        architecture = str(self.requirements.get("architecture", "unspecified"))
        if architecture not in ARCH_OPTIONS:
            raise ValueError(f"unsupported requirements.architecture: {architecture}")
        if (
            self.deployment_profile in {"kubernetes", "openshift"}
            and not str(self.requirements.get("cluster", "")).strip()
        ):
            raise ValueError("requirements.cluster is required for Kubernetes/OpenShift delivery")
        if (
            self.deployment_profile == "customer-hosted-container"
            and not str(self.requirements.get("registry", "")).strip()
        ):
            raise ValueError(
                "requirements.registry is required for customer-hosted-container delivery"
            )
        if (
            self.deployment_profile == "python-oem"
            and not str(self.requirements.get("oem_embedding_mode", "")).strip()
        ):
            raise ValueError("requirements.oem_embedding_mode is required for OEM delivery")
        self._reject_secret_like_values(self.to_dict())

    @staticmethod
    def _reject_secret_like_values(value: Any, path: str = "") -> None:
        exact_forbidden = {
            "secret",
            "password",
            "private_key",
            "token",
            "api_key",
            "bearer",
            "credential",
            "credentials",
        }
        if isinstance(value, Mapping):
            for key, child in value.items():
                lower = str(key).lower()
                secret_named = lower in exact_forbidden or lower.endswith(
                    ("_secret", "_password", "_private_key", "_token", "_api_key")
                )
                if secret_named and child:
                    raise ValueError(
                        f"secret-bearing intake field is not permitted: {path + str(key)}"
                    )
                CustomerIntake._reject_secret_like_values(child, path + str(key) + ".")
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                CustomerIntake._reject_secret_like_values(child, f"{path}{index}.")

    def resolved_artifact_format(self) -> str:
        if self.artifact_format:
            return self.artifact_format
        return {
            "customer-hosted-container": "oci",
            "kubernetes": "kubernetes-bundle",
            "openshift": "openshift-bundle",
            "linux-native": "deb",
            "air-gapped-linux": "run",
            "python-oem": "wheel",
        }[self.deployment_profile]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
