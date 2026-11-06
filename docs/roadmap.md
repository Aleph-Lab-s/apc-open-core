# Open-source roadmap

Roadmap items are proposals, not delivered functionality. Priorities may change after community review.

## P0 — Make the alpha reviewable

- [x] Assemble a public-source snapshot, tests, limitations, threat assumptions and release metadata in one reviewable repository tree.
- [ ] Make the first public repository push only after source-ownership and provenance approval.
- [x] Add a minimal MCP SDK v2 reference server with synthetic-only default behavior.
- [ ] Confirm source ownership/provenance and third-party licensing before the first public push.
- [ ] Complete full dependency, secrets, malware and license scans on a clean CI runner.
- [ ] Run MCP Inspector / official SDK interoperability tests and validate registry metadata.
- [ ] Obtain independent review of cryptographic and finality code.

## P1 — Close the integration gap

- Implement trusted identity/workload context adapters.
- Implement real customer PDP adapters with decision provenance and revocation.
- Build provider-specific sink adapters with final-boundary enforcement, native idempotency and authoritative reconciliation.
- Build route/bypass inventories and negative tests for each integration.
- Integrate the experimental egress, credential and topology controls only after design/security review.

## P2 — Enterprise engineering

- KMS/HSM backed signing, rotation, revocation and recovery.
- Linearizable multi-node state with fencing/quorum and partition behavior.
- HA, backup/restore, disaster recovery and customer SLOs.
- Observability, evidence export, tamper-evident customer-controlled retention and incident response.
- Kubernetes/OpenShift runtime testing and supported upgrade/rollback procedure.
- Independent penetration test, threat-model review, dependency/SBOM/provenance controls and remediation publication.

## P3 — Ecosystem

- Python integration helper/decorator with explicit trusted PDP and sink dependencies.
- TypeScript/Node implementation after protocol stability.
- Agent framework integrations based on verified demand.
- Official MCP Registry package and dedicated GitHub Action repository after each has a clear runnable/user value proposition.
- A transparent governance and maintainer process as the contributor base grows.

## Definition of done

A connector is not done when it imports. It is done when its identity provenance, PDP call, final side-effect path, idempotency, reconciliation, bypass behavior, operational failure modes and evidence are tested in a controlled environment and independently reviewed to the assurance level claimed.
