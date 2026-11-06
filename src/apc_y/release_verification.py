from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_manifest(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text())
    required = {"product", "release", "artifacts"}
    missing = required - data.keys()
    if missing:
        raise ValueError(f"manifest missing fields: {sorted(missing)}")
    return data
