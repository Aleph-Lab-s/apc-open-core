from __future__ import annotations
import hashlib, json, math
from typing import Any
from .errors import APCError, APCErrorCode

CANONICALIZATION_VERSION = "APC-CANONICAL-JSON-V2"

def _validate(value: Any, path: str = "value") -> Any:
    if value is None or isinstance(value, (str, bool, int)): return value
    if isinstance(value, float):
        if not math.isfinite(value): raise ValueError(f"{path} contains non-finite number")
        return value
    if isinstance(value, list): return [_validate(v, f"{path}[{i}]") for i,v in enumerate(value)]
    if isinstance(value, tuple): return [_validate(v, f"{path}[{i}]") for i,v in enumerate(value)]
    if isinstance(value, dict):
        out={}
        for k,v in value.items():
            if not isinstance(k,str): raise ValueError(f"{path} contains non-string dictionary key")
            if k in out: raise ValueError(f"{path} contains duplicate key {k!r}")
            out[k]=_validate(v,f"{path}.{k}")
        return out
    raise ValueError(f"{path} contains unsupported type {type(value).__name__}")

def canonical_json(value: Any) -> bytes:
    try:
        validated=_validate(value)
        return json.dumps(validated, sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except Exception as exc:
        raise APCError(APCErrorCode.INVALID_CANONICAL_DATA, str(exc)) from exc

def sha256_hex(value: Any) -> str: return hashlib.sha256(canonical_json(value)).hexdigest()

def candidate_act_payload(act):
    return {"invocation_id":act.invocation_id,"operation":act.operation,"resource":act.resource,"parameters":act.parameters,"constraints":act.constraints,"audience":act.audience}

def candidate_act_digest(act): return sha256_hex(candidate_act_payload(act))
