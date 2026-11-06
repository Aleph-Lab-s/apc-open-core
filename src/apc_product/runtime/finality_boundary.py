from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from apc_y.flagship import ActionContext, AuthorityV2, FinalityEnforcer
from apc_y.persistence import DurableReconciliationQueue, ReconciliationItem

from .sinks import EffectReceipt, SinkRegistry


@dataclass(frozen=True)
class FinalityDecision:
    admitted: bool
    authority_id: str
    sink_id: str
    reason: str
    effect: EffectReceipt | None = None


class ProtectedEffectBoundary:
    """Single integration point between APC authorization state and effect adapters.

    It deliberately requires an authority already issued upstream, then performs
    independent finality verification and exact sink binding before any sink call.
    """

    def __init__(self, enforcer: FinalityEnforcer, sinks: SinkRegistry, reconciliation: DurableReconciliationQueue | None = None):
        self.enforcer = enforcer
        self.sinks = sinks
        self.reconciliation = reconciliation

    def execute(self, authority: AuthorityV2, context: ActionContext, executing_actor_id: str) -> FinalityDecision:
        sink = self.sinks.get(context.finality_sink)
        descriptor = sink.descriptor

        if context.finality_sink != authority.context.finality_sink:
            raise ValueError("finality sink mismatch")
        if context.candidate_act.get("operation") not in descriptor.operations and "*" not in descriptor.operations:
            raise ValueError("operation not admitted by protected sink")
        if context.candidate_act.get("audience") != descriptor.audience:
            raise ValueError("sink audience mismatch")

        # Critical ordering: no provider call happens before finality verification.
        self.enforcer.verify(authority, context, executing_actor_id)

        idempotency_key = f"{context.tenant}:{authority.authority_id}:{authority.nonce}"
        try:
            effect = sink.execute(context.candidate_act["operation"], context.candidate_act.get("parameters", {}), idempotency_key)
            if effect.status not in {"SUCCESS", "FAILURE", "UNKNOWN"}:
                raise ValueError("protected sink returned unsupported effect status")
            try:
                self.enforcer.store.complete(authority.authority_id, effect.status == "SUCCESS", unknown=effect.status == "UNKNOWN")
            except Exception as exc:
                if self.reconciliation is not None:
                    self.reconciliation.enqueue(ReconciliationItem(authority.authority_id, idempotency_key, descriptor.sink_id, "state-persistence-failure-after-provider-call"))
                raise RuntimeError("provider effect occurred but APC state persistence failed") from exc
            if effect.status == "UNKNOWN" and self.reconciliation is not None:
                self.reconciliation.enqueue(ReconciliationItem(authority.authority_id, idempotency_key, descriptor.sink_id, "protected-effect-unknown"))
            return FinalityDecision(True, authority.authority_id, descriptor.sink_id, "FINALITY_ADMITTED", effect)
        except Exception:
            # If the provider call or post-effect state transition fails, APC cannot
            # safely assert failure; preserve UNKNOWN for authoritative reconciliation.
            try:
                self.enforcer.store.complete(authority.authority_id, False, unknown=True)
            except Exception:
                pass
            if self.reconciliation is not None:
                self.reconciliation.enqueue(ReconciliationItem(authority.authority_id, idempotency_key, descriptor.sink_id, "provider-or-post-effect-unknown"))
            raise
