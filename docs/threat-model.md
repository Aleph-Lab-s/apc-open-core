# Threat model (public summary)

## Assets

- Integrity of approved action parameters and target/resource.
- Authority scope, expiry and delegation constraints.
- Tenant separation and revocation/policy epoch state.
- Integrity and provenance of effect-result evidence.
- Credentials and secrets held by the integrating application/provider.

## Adversaries and failure modes considered by the kernel

- An agent or tool attempts to mutate operation, resource, parameters, audience/sink or actor after approval.
- A valid authority is replayed or used after expiry/revocation/state change.
- A delegate attempts to widen authority beyond its parent scope.
- Duplicate or concurrent requests race at a single-use execution boundary.
- A response is lost after a protected effect may already have occurred.
- Evidence records are modified after creation.

The local adversarial kernel test harness exercises a subset of these classes. Passing those tests means only that the named test cases passed against the tested source and environment.

## Out of scope / not yet proven

- A universal guarantee across arbitrary MCP servers or tool frameworks.
- Host or kernel compromise, malicious runtime maintainers, compromised dependencies, or a compromised customer PDP/IdP.
- Correctness of every provider's idempotency and reconciliation implementation.
- Complete mediation of direct/alternate execution paths unless the customer constrains them.
- Production KMS/HSM key custody, key rotation, workload identity, distributed fencing/quorum, multi-region consistency, HA/DR, and formal verification.

## Secure integration principle

The strongest boundary is where the actual protected side effect is invoked—not a dashboard, log collector or proxy that only observes an upstream request. A customer integration must show that no alternate route can mutate the same protected resource outside the boundary, or explicitly narrow its guarantee.

## Responsible testing

Test only systems you own or are authorized to assess. Use local fake providers and synthetic data. Never add production secrets or customer data to test fixtures, logs, issue trackers or public evidence bundles.
