# APC architecture overview

## The security question

An upstream authorization decision is not necessarily proof that the same action reaches the protected system. Between decision and effect, an agent, tool, delegate, workflow or adapter may change the actor, action, resource, parameters, tenant, sink or policy state.

APC's design goal is to preserve an action-bound authority contract through the execution path and verify it again at the final protected side-effect boundary.

## Conceptual flow

1. **Decision input:** a customer-controlled PDP decides whether an identity may request an operation. APC does not replace that PDP.
2. **Action commitment:** APC's kernel represents the actor, tenant, operation, resource, material parameters, sink/audience and relevant security state.
3. **Authority continuity:** authority is bounded, signed and carried through permitted transitions/delegation.
4. **Finality check:** the protected boundary verifies the exact action and current state before the sink is invoked.
5. **Outcome evidence:** the run records the result. A lost/ambiguous provider response must be treated as UNKNOWN until authoritative reconciliation.

## Current implementation shape

- `apc_y` contains reusable authority, canonicalization, crypto, delegation, freshness, continuity, finality and evidence primitives.
- `apc_product` orchestrates the evaluation runtime, event store, API and SQLite sandbox sink.
- `apc` contains event and sink integration code.
- `apc_mcp` is an optional MCP SDK v2 reference server. It exposes the local APC evaluation service; it is not a universal MCP proxy.

## Trust boundaries and assumptions

- Customer identity and authorization remain external inputs and must be authenticated/validated by the integrating application.
- Agents and tool arguments are untrusted; never accept their claims as proof of a trusted principal, workload, PDP decision or credential.
- The integration author must ensure every protected mutation goes through the APC boundary. An alternate database client, direct SDK call, shell tool, network route or background worker may bypass APC unless explicitly controlled.
- Provider-side idempotency and authoritative reconciliation are provider-specific. APC's SQLite sandbox cannot prove behavior of a real SaaS/cloud/payment provider.
- Local generated keys and SQLite stores are evaluation components, not a KMS/HSM or distributed consistency architecture.

See `threat-model.md`, `integration-status.md` and `production-readiness.md` before using the project.
