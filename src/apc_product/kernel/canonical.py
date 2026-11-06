from __future__ import annotations

"""Strict canonicalization for APC security-critical hashes and signatures.

The goal is deterministic cross-language representation, not clever serialization.
Only JSON-native values plus Pydantic models and timezone-aware datetimes are accepted.
"""

from datetime import date, datetime, timezone
from decimal import Decimal
import hashlib
import json
import math
from typing import Any, Mapping, Sequence


def _normalize(value: Any, path: str = "value") -> Any:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="python")

    if value is None or isinstance(value, (str, bool, int)):
        return value

    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path}: non-finite float is forbidden")
        return value

    if isinstance(value, (datetime, date)):
        if isinstance(value, datetime):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{path}: datetime must be timezone-aware")
            value = value.astimezone(timezone.utc)
            return value.isoformat().replace("+00:00", "Z")
        return value.isoformat()

    if isinstance(value, Decimal):
        # Decimal is not admitted directly: silently turning it into float can
        # change a security-bound numeric value. Callers should supply strings or ints.
        raise TypeError(f"{path}: Decimal must be represented explicitly as a string")

    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path}: object keys must be strings")
            out[key] = _normalize(item, f"{path}.{key}")
        return out

    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [_normalize(item, f"{path}[{i}]") for i, item in enumerate(value)]

    raise TypeError(f"{path}: unsupported canonical type {type(value).__name__}")


def canonical_obj(value: Any) -> Any:
    return _normalize(value)


def canonical_json(value: Any) -> bytes:
    normalized = _normalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()
