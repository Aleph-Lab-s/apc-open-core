from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class AdapterContext:
    """Vendor-neutral integration context. Adapters translate; APC semantics stay central."""

    tenant: str
    request_id: str
    invocation_id: str
    actor_id: str
    workload_id: str
    audience: str


@dataclass(frozen=True)
class CandidateAction:
    operation: str
    resource: str
    parameters: dict[str, Any]
    constraints: dict[str, Any]


class IdentityAdapter(Protocol):
    def resolve(self, external_request: Any) -> tuple[str, str, str]:
        """Return actor_id, principal_id, workload_id."""


class PolicyAdapter(Protocol):
    def authorize(self, action: CandidateAction, context: AdapterContext) -> dict[str, Any]:
        """Return a PDP decision; adapter must not create APC authority."""


class ToolAdapter(Protocol):
    def reconstruct(self, external_call: Any) -> CandidateAction:
        """Reconstruct the exact concrete act at the finality boundary."""


class SinkAdapter(Protocol):
    sink_id: str

    def execute(self, action: CandidateAction, idempotency_key: str) -> Any: ...
    def reconcile(self, idempotency_key: str) -> Any: ...


class AgentAdapter(Protocol):
    def candidate_action(self, agent_output: Any, context: AdapterContext) -> CandidateAction:
        """Agents propose. The adapter never turns agent output directly into authority."""


class MCPToolAdapter(Protocol):
    def candidate_action(self, tool_call: Any, context: AdapterContext) -> CandidateAction:
        """MCP/tool invocation is an input surface, not a trust boundary."""


# Important integration rule:
# external systems may supply identity, policy decisions, candidate actions, and effects.
# Only APC creates/enforces APC authority and finality semantics.
