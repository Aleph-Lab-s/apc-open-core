from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from apc_product.kernel.canonical import canonical_json


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merkle_root(digests: Iterable[str]) -> str:
    level = [bytes.fromhex(d) for d in sorted(digests)]
    if not level:
        return _h(b"")
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


@dataclass(frozen=True)
class EvidenceArtifact:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class EvidenceBundleManifest:
    bundle_version: str
    artifacts: tuple[EvidenceArtifact, ...]
    merkle_root: str

    @classmethod
    def from_directory(
        cls, root: str | Path, *, bundle_version: str = "1"
    ) -> EvidenceBundleManifest:
        base = Path(root)
        artifacts: list[EvidenceArtifact] = []
        for p in sorted(x for x in base.rglob("*") if x.is_file()):
            data = p.read_bytes()
            artifacts.append(
                EvidenceArtifact(str(p.relative_to(base)).replace("\\", "/"), _h(data), len(data))
            )
        return cls(bundle_version, tuple(artifacts), merkle_root(a.sha256 for a in artifacts))

    @classmethod
    def from_json(cls, value: str | bytes) -> EvidenceBundleManifest:
        raw = json.loads(value)
        artifacts = tuple(EvidenceArtifact(**item) for item in raw["artifacts"])
        return cls(str(raw["bundle_version"]), artifacts, str(raw["merkle_root"]))

    def verify_directory(self, root: str | Path) -> None:
        base = Path(root)
        observed: list[str] = []
        expected_paths = {item.path for item in self.artifacts}
        actual_paths = {
            str(p.relative_to(base)).replace("\\", "/")
            for p in base.rglob("*")
            if p.is_file() and p.name != "manifest.json"
        }
        extras = sorted(actual_paths - expected_paths)
        missing = sorted(expected_paths - actual_paths)
        if extras:
            raise ValueError(f"unexpected evidence artifacts: {extras}")
        if missing:
            raise ValueError(f"missing evidence artifacts: {missing}")
        for item in self.artifacts:
            if item.path.startswith("/") or ".." in Path(item.path).parts:
                raise ValueError(f"unsafe evidence artifact path: {item.path}")
            data = (base / item.path).read_bytes()
            if len(data) != item.size or _h(data) != item.sha256:
                raise ValueError(f"evidence artifact mismatch: {item.path}")
            observed.append(item.sha256)
        if merkle_root(observed) != self.merkle_root:
            raise ValueError("evidence Merkle root mismatch")

    def to_json(self) -> str:
        return canonical_json(
            {
                "bundle_version": self.bundle_version,
                "artifacts": [a.__dict__ for a in self.artifacts],
                "merkle_root": self.merkle_root,
            }
        ).decode("utf-8")
