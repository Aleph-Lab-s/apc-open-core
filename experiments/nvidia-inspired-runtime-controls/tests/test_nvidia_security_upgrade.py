from __future__ import annotations

from datetime import datetime, timedelta, timezone

from apc_product.integrations.multihop_continuity import Hop, MultiHopContinuityVerifier
from apc_product.integrations.egress_guard import EgressGuard, EndpointRule
from apc_product.integrations.credential_broker import CredentialBinding, CredentialBroker
from apc_product.integrations.policy_gate import PolicyChangeGate, PolicyProof, PolicySnapshot
from apc_product.integrations.topology_guard import Edge, Node, TopologyGuard


TEST_NOW = datetime.now(timezone.utc)

def _hop(i: int, *, exact="act-digest", prev=None, sender=None, receiver=None, allowed=()):
    now = TEST_NOW
    return Hop(
        chain_id="chain-1", hop_id=f"h{i}", parent_hop_id=prev,
        sender_identity=sender or f"n{i-1}", sender_workload=f"w{i-1}",
        receiver_identity=receiver or f"n{i}", receiver_workload=f"w{i}",
        authority_id="auth-1", policy_decision_id="dec-1", policy_version="p1", policy_epoch=3,
        security_context_digest="sec-1", intent_digest="intent-1", candidate_act_digest=exact,
        exact_act_digest=exact, finality_sink="sink-1", capability="invoke",
        capabilities=("invoke",), nonce=f"nonce-{i}", counter=i,
        issued_at=now - timedelta(seconds=1), expires_at=now + timedelta(minutes=5),
        allowed_next_receivers=allowed,
    )


def test_multihop_continuity_accepts_four_hops():
    hops = [
        _hop(0, receiver="agent-b", allowed=("tool-a",)),
        _hop(1, prev="h0", sender="agent-b", receiver="tool-a", allowed=("adapter-a",)),
        _hop(2, prev="h1", sender="tool-a", receiver="adapter-a", allowed=("finality",)),
        _hop(3, prev="h2", sender="adapter-a", receiver="finality"),
    ]
    report = MultiHopContinuityVerifier(finality_receiver="finality").verify(hops)
    assert report.valid, report
    assert report.hop_count == 4


def test_multihop_rejects_exact_act_mutation():
    hops = [_hop(0, receiver="agent-b", allowed=("tool-a",)), _hop(1, prev="h0", sender="agent-b", receiver="tool-a", exact="mutated")]
    report = MultiHopContinuityVerifier().verify(hops)
    assert not report.valid
    assert any("exact_act_changed" in x for x in report.failures)


def test_multihop_rejects_capability_expansion():
    a = _hop(0, receiver="agent-b", allowed=("tool-a",))
    b = _hop(1, prev="h0", sender="agent-b", receiver="tool-a")
    object.__setattr__(b, "capabilities", ("invoke", "delete"))
    report = MultiHopContinuityVerifier().verify([a, b])
    assert not report.valid
    assert any("capability_expansion" in x for x in report.failures)


def test_egress_is_default_deny_and_l7_scoped():
    guard = EgressGuard((EndpointRule("github-read", ("api.github.com",), methods=("GET",), path_prefixes=("/repos/",), binaries=("/usr/bin/gh",)),))
    assert guard.authorize(url="https://api.github.com/repos/x/y", method="GET", binary="/usr/bin/gh").allowed
    assert not guard.authorize(url="https://api.github.com/repos/x/y", method="POST", binary="/usr/bin/gh").allowed
    assert not guard.authorize(url="https://example.com", method="GET", binary="/usr/bin/gh").allowed


def test_credential_is_endpoint_bound():
    broker = CredentialBroker(lambda profile, name, revision: f"secret:{profile}:{name}:{revision}")
    ph = broker.issue_placeholder(CredentialBinding("github", "token", "api.github.com", 443, "/repos/"))
    allow = EgressGuard((EndpointRule("github", ("api.github.com",), methods=("GET",), path_prefixes=("/repos/",), credential_profiles=("github",)),)).authorize(
        url="https://api.github.com/repos/a/b", method="GET", binary="gh", credential_profile="github"
    )
    assert broker.resolve(ph, host="api.github.com", port=443, path="/repos/a/b", decision=allow).startswith("secret:")
    try:
        broker.resolve(ph, host="attacker.example", port=443, path="/", decision=allow)
    except PermissionError:
        pass
    else:
        raise AssertionError("credential leaked outside endpoint binding")


def test_policy_gate_rejects_privilege_expansion_without_proof():
    old = PolicySnapshot.create("t", 1, "p1", {"endpoints": ["a"]})
    new = PolicySnapshot.create("t", 2, "p2", {"endpoints": ["a", "b"]})
    result = PolicyChangeGate().admit(old, new)
    assert not result.accepted
    assert result.proof_required


def test_policy_gate_accepts_verified_expansion():
    old = PolicySnapshot.create("t", 1, "p1", {"endpoints": ["a"]})
    new = PolicySnapshot.create("t", 2, "p2", {"endpoints": ["a", "b"]})
    gate = PolicyChangeGate(proof_hook=lambda _o, _n: PolicyProof(True, "test-prover", "ok"))
    result = gate.admit(old, new)
    assert result.accepted


def test_topology_guard_detects_direct_bypass():
    nodes = (Node("agent", "agent"), Node("finality", "finality"), Node("sink", "sink"))
    edges = (Edge("agent", "sink", governed=False), Edge("agent", "finality", governed=True), Edge("finality", "sink", governed=True))
    findings = TopologyGuard(nodes, edges).ungoverned_paths("agent", "sink")
    assert any("without finality" in x.reason for x in findings)
