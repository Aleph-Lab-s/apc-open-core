from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from .canonical import canonical_json
from .protocol import domain_digest

@dataclass(frozen=True)
class ConformanceVector:
    name:str; input:Any; expected_digest:str

def verify_vector(v:ConformanceVector)->bool:
    return domain_digest(v.name,v.input)==v.expected_digest

def canonical_bytes(value): return canonical_json(value)
