# APC NVIDIA-Inspired Security Upgrade — Candidate Patch

Status: ENGINEERING CANDIDATE — NOT A CERTIFICATION OR PRODUCTION RELEASE

This patch adds five APC product capabilities inspired by gaps closed by NVIDIA OpenShell:

- `multihop_continuity.py`: arbitrary-hop continuity verification with parent-chain, action, policy, security-state, sink, capability, expiry and nonce checks.
- `egress_guard.py`: deny-by-default, destination/method/path/binary-scoped egress admission.
- `credential_broker.py`: opaque credential placeholders with endpoint/path binding and no secret persistence in APC.
- `policy_gate.py`: monotonic policy epochs and proof-gated privilege expansion.
- `topology_guard.py`: deployment graph analysis for ungoverned paths to protected sinks.

These modules intentionally sit above the existing cryptographic kernel and below provider/network integration. They do not replace customer IdP/PDP, Kubernetes/OpenShift, a secret manager, service mesh, or provider APIs.

## Integration order

1. Insert `MultiHopContinuityVerifier` before accepting a successor transition and again immediately before finality.
2. Make every effect-capable adapter declare an `EndpointRule` set and route its outbound calls through `EgressGuard`.
3. Replace direct secret exposure with `CredentialBroker` placeholders backed by a customer KMS/secret resolver.
4. Run `TopologyGuard` during deployment validation and record the topology hash in APC evidence.
5. Route dynamic Security Contract / egress / provider-policy changes through `PolicyChangeGate`; persist the new epoch only after admission.
6. Add Kubernetes/OpenShift/sidecar/mesh adapters that connect these controls to the actual runtime network path.

## Required next engineering milestone

The modules must be wired into the actual APC `APCEvaluationEngine` and real adapters, then re-run the full hostile-world, HTTP, concurrency, static, packaging, and release suites. No new production/certification claim should be made until that happens.
