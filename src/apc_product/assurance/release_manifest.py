from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from apc_product.kernel.canonical import sha256_hex


class Signer(Protocol):
    key_id: str
    def sign(self, payload: Any) -> str: ...


class Verifier(Protocol):
    def verify(self, payload: Any, signature: str, key_id: str) -> None: ...


@dataclass(frozen=True)
class ReleaseManifest:
    product: str
    version: str
    source_revision: str
    artifact_digests: Mapping[str, str]
    minimum_supported_version: str | None
    key_id: str
    signature: str

    def unsigned(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "version": self.version,
            "source_revision": self.source_revision,
            "artifact_digests": dict(self.artifact_digests),
            "minimum_supported_version": self.minimum_supported_version,
            "key_id": self.key_id,
        }

    @property
    def digest(self) -> str:
        return sha256_hex(self.unsigned())

    @classmethod
    def create(cls, *, product: str, version: str, source_revision: str, artifact_digests: Mapping[str, str], minimum_supported_version: str | None, signer: Signer) -> "ReleaseManifest":
        unsigned = cls(product, version, source_revision, dict(artifact_digests), minimum_supported_version, signer.key_id, "")
        return cls(**{**unsigned.__dict__, "signature": signer.sign(unsigned.unsigned())})

    def verify(self, verifier: Verifier) -> None:
        if not self.signature:
            raise ValueError("release manifest is unsigned")
        verifier.verify(self.unsigned(), self.signature, self.key_id)


def require_no_rollback(*, installed_version: str, candidate_version: str, min_supported_version: str | None = None) -> None:
    def parse(v: str) -> tuple[int, ...]:
        base = v.split("+", 1)[0].lstrip("v").replace("-", ".")
        out = []
        for part in base.split("."):
            digits = "".join(ch for ch in part if ch.isdigit())
            out.append(int(digits or 0))
        return tuple(out)
    if parse(candidate_version) < parse(installed_version):
        raise ValueError("release rollback blocked")
    if min_supported_version and parse(candidate_version) < parse(min_supported_version):
        raise ValueError("candidate is below minimum supported security version")
