from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from apc_product.assurance.evidence_bundle import EvidenceBundleManifest
from apc_product.runtime.lab_sink import SQLiteProtectedSink
from apc_product.runtime.reconciliation import ReconciliationController, ReconciliationItem
from apc_product.version import VERSION
from apc_y import (
    ActionContext,
    AuthorityFactory,
    Delegation,
    DurableAuthorityStore,
    Ed25519KeyPair,
    EffectResult,
    FinalityEnforcer,
    IntentContract,
    SecurityState,
    WorkloadIdentity,
)
from apc_y.continuity import (
    ActionSecurityGraph,
    APCAuthorityReference,
    APCSecurityOperations,
    APCTransitionEnforcer,
    ContinuityFinalityVerifier,
    ContinuityProtectedExecutor,
    ContinuityStore,
    ContractMatch,
    SecurityContract,
    SecurityContractRegistry,
    sign_envelope,
)
from apc_y.errors import APCError
from apc_y.persistence import DurableReconciliationQueue


@dataclass(frozen=True)
class ExecutionRequest:
    tenant: str
    operation: str
    resource: str
    parameters: dict[str, Any]
    actor_id: str
    principal_id: str
    workload_id: str
    workload_issuer: str
    audience: str
    sink_id: str
    policy_decision: str
    policy_decision_id: str
    policy_issuer: str = "customer-pdp"
    policy_version: str = "policy-v1"
    policy_epoch: int = 1
    risk: int = 10
    assurance: str = "A1"
    authority_ttl_seconds: int = 300
    single_use: bool = True
    mode: str = "SANDBOX"
    purpose: str = "APC evaluation"


@dataclass(frozen=True)
class ExecutionRecord:
    run_id: str
    status: str
    decision: str
    authority_id: str | None
    effect_status: str | None
    provider_reference: str | None
    sink_id: str
    trace: list[dict[str, Any]]
    evidence: dict[str, Any]
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "decision": self.decision,
            "authority_id": self.authority_id,
            "effect_status": self.effect_status,
            "provider_reference": self.provider_reference,
            "sink_id": self.sink_id,
            "trace": self.trace,
            "evidence": self.evidence,
            "errors": self.errors,
        }


class APCEvaluationEngine:
    """One APC evaluation runtime built around the existing apc_y security core.

    The engine does not replace customer authorization. A customer PDP decision
    is an input. APC turns that decision into an exact-action authority and then
    re-verifies the action at the final protected-effect boundary.
    """

    def __init__(
        self,
        *,
        db_path: str | Path,
        simulate_unknown_after_commit: bool = False,
        simulate_failure_before_commit: bool = False,
    ) -> None:
        self.db_path = str(db_path)
        base = Path(self.db_path).parent
        base.mkdir(parents=True, exist_ok=True)
        self.authority_store = DurableAuthorityStore(self.db_path + ".authority")
        self.sink = SQLiteProtectedSink(self.db_path + ".effects")
        self.sink.simulate_unknown_after_commit = simulate_unknown_after_commit
        self.sink.simulate_failure_before_commit = simulate_failure_before_commit
        self.reconciliation_queue = DurableReconciliationQueue(self.db_path + ".reconciliation")
        self.reconciliation_controller = ReconciliationController(
            store=self.authority_store,
            queue=self.reconciliation_queue,
            sink_resolver=lambda sink_id: (
                self.sink
                if sink_id == self.sink.descriptor.sink_id
                else (_ for _ in ()).throw(KeyError(sink_id))
            ),
        )
        self.authority_key = Ed25519KeyPair.generate("apc-lab-authority")
        self.agent_key = Ed25519KeyPair.generate("apc-lab-agent")
        self.tool_key = Ed25519KeyPair.generate("apc-lab-tool")
        self.finality_key = Ed25519KeyPair.generate("apc-lab-finality")
        self.keys = {
            key.key_id: key.public_key_pem()
            for key in (self.authority_key, self.agent_key, self.tool_key, self.finality_key)
        }

    def close(self) -> None:
        self.reconciliation_queue.close()
        self.authority_store.close()

    def _make_contracts(
        self, *, sink_id: str, operation: str, resource: str
    ) -> SecurityContractRegistry:
        sink = sink_id
        return SecurityContractRegistry(
            [
                SecurityContract(
                    contract_id="apc.lab.prepare",
                    version="1",
                    match=ContractMatch(
                        tenants=(),
                        senders=("agent:apc-lab",),
                        sender_workloads=("workload:apc-agent",),
                        receivers=("tool:apc-lab",),
                        receiver_workloads=("workload:apc-tool",),
                        operations=("prepare",),
                        targets=(resource,),
                        sinks=(sink,),
                    ),
                    allowed_edge_labels=("tool:apc-lab:prepare",),
                    required_assurance="A0",
                    require_authority=True,
                    require_sender_signature=True,
                ),
                SecurityContract(
                    contract_id="apc.lab.finalize",
                    version="1",
                    match=ContractMatch(
                        senders=("tool:apc-lab",),
                        sender_workloads=("workload:apc-tool",),
                        receivers=("finality:apc-lab",),
                        receiver_workloads=("workload:apc-finality",),
                        operations=("commit",),
                        targets=(resource,),
                        sinks=(sink,),
                    ),
                    allowed_edge_labels=("finality:apc-lab:commit",),
                    required_assurance="A0",
                    require_authority=True,
                    require_sender_signature=True,
                ),
            ]
        )

    def execute(self, request: ExecutionRequest) -> ExecutionRecord:
        run_id = "run-" + uuid.uuid4().hex
        now = datetime.now(UTC)
        trace: list[dict[str, Any]] = []

        def t(stage: str, outcome: str, **details: Any) -> None:
            trace.append({"stage": stage, "outcome": outcome, "details": details})

        try:
            t("INGRESS", "ACCEPTED", mode=request.mode, tenant=request.tenant)
            if request.policy_decision.upper() != "ALLOW":
                t("PDP", "DENY", decision_id=request.policy_decision_id)
                return ExecutionRecord(
                    run_id,
                    "DENIED",
                    "DENY",
                    None,
                    None,
                    None,
                    request.sink_id,
                    trace,
                    {"production_claim": False},
                )

            t(
                "PDP",
                "ALLOW",
                decision_id=request.policy_decision_id,
                policy_version=request.policy_version,
            )
            state = SecurityState(
                policy_epoch=request.policy_epoch,
                identity_epoch=1,
                delegation_epoch=1,
                tenant_epoch=1,
                risk_epoch=1,
                signer_epoch=1,
                sink_epoch=1,
                revocation_epoch=1,
            )
            intent = IntentContract(
                intent_id="intent-" + run_id,
                intent={"purpose": request.purpose},
                allowed_operations=(request.operation,),
                allowed_resources=(request.resource,),
                constraints={},
                max_risk=request.risk,
            )
            workload = WorkloadIdentity(request.workload_id, request.workload_issuer, 1)
            delegation = Delegation(
                request.principal_id,
                request.actor_id,
                None,
                {"resource": request.resource},
                now + timedelta(seconds=request.authority_ttl_seconds),
                request.risk,
                (request.sink_id,),
            )
            candidate_act = {
                "operation": request.operation,
                "resource": request.resource,
                "parameters": dict(request.parameters),
                "constraints": {},
                "audience": request.audience,
            }
            context = ActionContext(
                request.tenant,
                run_id,
                "inv-" + run_id,
                intent,
                candidate_act,
                request.actor_id,
                request.principal_id,
                workload,
                delegation,
                "customer-application",
                dict(request.parameters),
                request.policy_decision_id,
                request.policy_version,
                request.policy_epoch,
                request.risk,
                request.assurance,
                request.sink_id,
                state,
                now,
                None,
                None,
            )
            authority = AuthorityFactory(self.authority_key).issue(
                context,
                now + timedelta(seconds=request.authority_ttl_seconds),
                single_use=request.single_use,
            )
            self.authority_store.register(authority)
            ref = APCAuthorityReference(
                authority_id=authority.authority_id,
                tenant=context.tenant,
                invocation_id=context.invocation_id,
                principal=context.principal_id,
                policy_decision_id=context.policy_decision_id,
                policy_version=context.policy_version,
                policy_epoch=context.policy_epoch,
                decision_input_digest=context.decision_input_digest,
                security_context_digest=context.security_context_digest,
                intent_digest=context.intent.digest,
                candidate_act_digest=context.candidate_act_digest,
                exact_act_digest=context.candidate_act_digest,
                finality_sink=context.finality_sink,
                assurance_profile="A0",
                expires_at=authority.expires_at,
            )
            t(
                "AUTHORITY",
                "ISSUED",
                authority_id=authority.authority_id,
                exact_act_digest=context.candidate_act_digest,
            )

            finality = FinalityEnforcer(
                public_key_resolver=self.keys.__getitem__,
                store=self.authority_store,
                state_provider=lambda _: state,
                policy_state_provider={
                    request.policy_decision_id: type(
                        "DecisionState",
                        (),
                        {
                            "decision_id": request.policy_decision_id,
                            "policy_version": request.policy_version,
                            "policy_epoch": request.policy_epoch,
                            "decision": "ALLOW",
                        },
                    )()
                },
                sink_contract_provider=lambda sid: (
                    self.sink.descriptor if sid == request.sink_id else None
                ),
            )

            registry = self._make_contracts(
                sink_id=request.sink_id, operation=request.operation, resource=request.resource
            )
            chain_store = ContinuityStore()
            operations = APCSecurityOperations()
            graph = ActionSecurityGraph()
            ops = ("delegate", "invoke")

            common = dict(
                tenant=request.tenant,
                action_chain_id=run_id,
                invocation_id=context.invocation_id,
                principal=context.principal_id,
                authority_id=authority.authority_id,
                target=request.resource,
                finality_sink=request.sink_id,
                expires_at=authority.expires_at,
                policy_decision_id=context.policy_decision_id,
                policy_version=context.policy_version,
                policy_epoch=context.policy_epoch,
                decision_input_digest=context.decision_input_digest,
                security_context_digest=context.security_context_digest,
                intent_digest=context.intent.digest,
                candidate_act_digest=context.candidate_act_digest,
                exact_act_digest=context.candidate_act_digest,
                assurance_profile="A0",
                issued_at=now,
            )
            root = sign_envelope(
                {
                    **common,
                    "contract_id": "apc.lab.prepare",
                    "contract_version": "1",
                    "transition_id": run_id + ":t0",
                    "parent_transition_id": None,
                    "sender_identity": "agent:apc-lab",
                    "sender_workload_identity": "workload:apc-agent",
                    "receiver_identity": "tool:apc-lab",
                    "receiver_workload_identity": "workload:apc-tool",
                    "delegation_id": "delegation-" + authority.authority_id,
                    "parent_authority_id": None,
                    "operation": "prepare",
                    "capabilities": ops,
                    "constraints": {},
                    "nonce": run_id + ":nonce:0",
                    "allowed_next_transitions": ("finality:apc-lab:commit",),
                    "transition_counter": 0,
                    "state": "AUTHORIZED",
                },
                self.agent_key,
            )
            final = sign_envelope(
                {
                    **common,
                    "contract_id": "apc.lab.finalize",
                    "contract_version": "1",
                    "transition_id": run_id + ":t1",
                    "parent_transition_id": run_id + ":t0",
                    "sender_identity": "tool:apc-lab",
                    "sender_workload_identity": "workload:apc-tool",
                    "receiver_identity": "finality:apc-lab",
                    "receiver_workload_identity": "workload:apc-finality",
                    "delegation_id": "delegation-" + authority.authority_id,
                    "parent_authority_id": authority.authority_id,
                    "operation": "commit",
                    "capabilities": ("invoke",),
                    "constraints": {},
                    "nonce": run_id + ":nonce:1",
                    "allowed_next_transitions": (),
                    "transition_counter": 1,
                    "state": "AUTHORIZED",
                    "transformation_digest": "transition-transform:" + context.candidate_act_digest,
                },
                self.tool_key,
            )
            authority_resolver = lambda aid: ref if aid == authority.authority_id else None
            tep_tool = APCTransitionEnforcer(
                node_id="tool:apc-lab",
                node_identity="tool:apc-lab",
                node_workload_identity="workload:apc-tool",
                key_pair=self.tool_key,
                public_key_resolver=self.keys.__getitem__,
                contract_resolver=registry.resolve,
                store=chain_store,
                operations=operations,
                authority_resolver=authority_resolver,
                implementation_version=VERSION,
            )
            tep_finality = APCTransitionEnforcer(
                node_id="finality:apc-lab",
                node_identity="finality:apc-lab",
                node_workload_identity="workload:apc-finality",
                key_pair=self.finality_key,
                public_key_resolver=self.keys.__getitem__,
                contract_resolver=registry.resolve,
                store=chain_store,
                operations=operations,
                authority_resolver=authority_resolver,
                implementation_version=VERSION,
            )
            tep_tool.graph = graph
            tep_finality.graph = graph
            tep_tool.accept(root, now=now)
            t(
                "TRANSITION",
                "ENFORCED",
                transition_id=root.transition_id,
                receiver=root.receiver_identity,
            )
            tep_finality.accept(final, now=now)
            t(
                "TRANSITION",
                "ENFORCED",
                transition_id=final.transition_id,
                receiver=final.receiver_identity,
            )

            cv = ContinuityFinalityVerifier(
                finality_enforcer=finality,
                store=chain_store,
                public_key_resolver=self.keys.__getitem__,
                operations=operations,
                node_id="finality:apc-lab",
            )
            executor = ContinuityProtectedExecutor(
                continuity_finality=cv,
                store=chain_store,
                sink=_ContinuitySinkAdapter(self.sink, request.resource),
                mark_complete=self.authority_store.complete,
            )
            t("FINALITY", "VERIFYING", action_chain_id=run_id)
            effect = executor.execute(
                action_chain_id=run_id,
                final_transition_id=final.transition_id,
                authority=authority,
                actual_context=context,
                executing_actor_id=request.actor_id,
                now=now,
            )
            t(
                "EFFECT",
                effect.status,
                provider_reference=effect.provider_reference,
                sink=request.sink_id,
                idempotency_key=f"{authority.authority_id}:{authority.nonce}",
            )

            reconciliation = None
            if effect.status == "UNKNOWN":
                idem = f"{authority.authority_id}:{authority.nonce}"
                self.reconciliation_queue.enqueue(
                    ReconciliationItem(
                        authority_id=authority.authority_id,
                        idempotency_key=idem,
                        sink_id=request.sink_id,
                        reason="provider outcome UNKNOWN after protected effect attempt",
                    )
                )
                report = self.reconciliation_controller.reconcile_pending()
                reconciliation = {
                    "examined": report.examined,
                    "resolved_success": report.resolved_success,
                    "resolved_failure": report.resolved_failure,
                    "reopened_for_retry": report.reopened_for_retry,
                    "still_unknown": report.still_unknown,
                    "rejected": report.rejected,
                }
                if report.resolved_success:
                    resolved = self.sink.reconcile(idem)
                    provider_reference = resolved.provider_reference if resolved else None
                    t(
                        "RECONCILIATION",
                        "SUCCESS",
                        provider_reference=provider_reference,
                        authority_state=self.authority_store.state(authority.authority_id),
                    )
                    effect_status = "SUCCESS"
                else:
                    provider_reference = effect.provider_reference
                    effect_status = effect.status
            else:
                provider_reference = effect.provider_reference
                effect_status = effect.status

            evidence_dir = Path(self.db_path).parent / "evidence" / run_id
            evidence_dir.mkdir(parents=True, exist_ok=True)
            _write_json(
                evidence_dir / "run.json",
                {
                    "request": request.__dict__,
                    "effect": effect.__dict__,
                    "reconciliation": reconciliation,
                    "final_authority_state": self.authority_store.state(authority.authority_id),
                    "trace": trace,
                    "graph": graph.summary(run_id),
                },
            )
            _write_json(evidence_dir / "authority.json", authority.payload())
            _write_json(
                evidence_dir / "transitions.json",
                [root.model_dump(mode="json"), final.model_dump(mode="json")],
            )
            manifest = EvidenceBundleManifest.from_directory(evidence_dir)
            _write_text(evidence_dir / "manifest.json", manifest.to_json())
            t(
                "EVIDENCE",
                "RECORDED",
                merkle_root=manifest.merkle_root,
                artifacts=len(manifest.artifacts),
            )

            return ExecutionRecord(
                run_id,
                "EFFECTED" if effect_status == "SUCCESS" else effect_status,
                "ALLOW",
                authority.authority_id,
                effect_status,
                provider_reference,
                request.sink_id,
                trace,
                {
                    "merkle_root": manifest.merkle_root,
                    "evidence_directory": str(evidence_dir),
                    "production_claim": False,
                },
            )
        except APCError as exc:
            t("SECURITY", "BLOCKED", code=exc.code.value, detail=str(exc))
            return ExecutionRecord(
                run_id,
                "BLOCKED",
                "ALLOW",
                None,
                None,
                None,
                request.sink_id,
                trace,
                {"production_claim": False},
                [f"{exc.code.value}: {exc}"],
            )
        except Exception as exc:
            t("RUNTIME", "ERROR", error=repr(exc))
            return ExecutionRecord(
                run_id,
                "ERROR",
                "ALLOW",
                None,
                None,
                None,
                request.sink_id,
                trace,
                {"production_claim": False},
                [repr(exc)],
            )

    def reconcile_pending(self, max_items: int | None = None) -> dict[str, int]:
        """Run authoritative reconciliation for durable UNKNOWN effects."""
        report = self.reconciliation_controller.reconcile_pending(max_items=max_items)
        return {
            "examined": report.examined,
            "resolved_success": report.resolved_success,
            "resolved_failure": report.resolved_failure,
            "reopened_for_retry": report.reopened_for_retry,
            "still_unknown": report.still_unknown,
            "rejected": report.rejected,
        }


class _ContinuitySinkAdapter:
    def __init__(self, sink: SQLiteProtectedSink, resource: str) -> None:
        self._sink = sink
        self._resource = resource

    def execute(self, act: dict[str, Any], idempotency_key: str) -> EffectResult:
        parameters = dict(act.get("parameters", {}))
        parameters.setdefault("resource", act.get("resource", self._resource))
        receipt = self._sink.execute(act["operation"], parameters, idempotency_key)
        return EffectResult(receipt.status, receipt.provider_reference, dict(receipt.evidence))

    def reconcile(self, idempotency_key: str) -> EffectResult | None:
        receipt = self._sink.reconcile(idempotency_key)
        if receipt is None:
            return None
        return EffectResult(receipt.status, receipt.provider_reference, dict(receipt.evidence))


def _write_json(path: Path, value: Any) -> None:
    from apc_product.kernel.canonical import canonical_json

    path.write_bytes(canonical_json(value))


def _write_text(path: Path, value: str) -> None:
    path.write_text(value + "\n", encoding="utf-8")
