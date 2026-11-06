from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from apc_product.kernel.canonical import sha256_hex


@dataclass(frozen=True)
class ToolRule:
    tool_name: str
    allowed_operations: tuple[str, ...]
    allowed_targets: tuple[str, ...] = ()
    required_assurance: str = "A0"


class MCPInvocationGuard:
    """Treats tool discovery as non-authoritative and invocation as an APC-bound act."""
    def __init__(self, rules: tuple[ToolRule, ...]):
        self._rules = {r.tool_name: r for r in rules}

    def visible_tools(self) -> list[str]:
        return sorted(self._rules)

    def authorize_invocation(self, *, tool_name: str, operation: str, target: str, parameters: Mapping[str, Any], authorized_tool_names: tuple[str, ...]) -> str:
        if tool_name not in authorized_tool_names:
            raise PermissionError("tool not authorized by the caller's APC-scoped capability")
        rule = self._rules.get(tool_name)
        if rule is None:
            raise PermissionError("unknown tool")
        if operation not in rule.allowed_operations and "*" not in rule.allowed_operations:
            raise PermissionError("operation not authorized")
        if rule.allowed_targets and target not in rule.allowed_targets:
            raise PermissionError("target not authorized")
        return sha256_hex({"tool": tool_name, "operation": operation, "target": target, "parameters": dict(parameters)})
