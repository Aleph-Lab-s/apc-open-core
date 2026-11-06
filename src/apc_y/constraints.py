from __future__ import annotations
from dataclasses import dataclass
from typing import Any

class ConstraintError(ValueError): pass

def _set(value: Any) -> set[str]:
    if isinstance(value, str): return {value}
    if isinstance(value, (list, tuple, set, frozenset)): return {str(x) for x in value}
    raise ConstraintError("set constraint must be a string or sequence")

def scope_attenuates(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    """Conservative monotone constraint relation: unknown semantics fail closed."""
    known = {"operations", "resources", "audience", "max_risk"}
    if set(child) - known or set(parent) - known:
        return False
    if "operations" in parent and child.get("operations") is not None and not _set(child["operations"]).issubset(_set(parent["operations"])): return False
    if "resources" in parent and child.get("resources") is not None and not _set(child["resources"]).issubset(_set(parent["resources"])): return False
    if "audience" in parent and child.get("audience") is not None and not _set(child["audience"]).issubset(_set(parent["audience"])): return False
    if "max_risk" in parent and int(child.get("max_risk", parent["max_risk"])) > int(parent["max_risk"]): return False
    return True
