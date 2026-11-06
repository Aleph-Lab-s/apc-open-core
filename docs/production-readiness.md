# Production readiness — current blocker register

**Status: NOT APPROVED for production execution of sensitive external actions.**

The supplied APC Enterprise 7.1.4 candidate has meaningful local kernel/runtime tests and a hardened single-replica deployment design. Those artifacts do not close the external and operational gates below.

| Gate | Current evidence | Needed before sensitive live actions |
|---|---|---|
| Identity | Test/local identity fixtures | Customer IdP and workload identity integration; proof and revocation lifecycle |
| Policy | Decision inputs and simulated OPA/Cedar catalog entries | Real customer PDP call, authenticated decision provenance, policy-change/revocation path |
| Key custody | In-process ephemeral Ed25519 keys in evaluation engine | Customer-controlled KMS/HSM, key rotation, separation of duties, recovery |
| Final side-effect | SQLite sandbox sink | Provider-specific protected boundary, credentials isolation and complete route mediation |
| Idempotency | Local SQLite uniqueness | Provider-native idempotency and retry semantics per operation |
| Reconciliation | Local authoritative SQLite lookup | Provider-authoritative lookup and tested UNKNOWN-state resolution |
| Distributed state | SQLite/local durable components | Linearizable shared store, fencing/quorum and partition/concurrency tests |
| Deployment | Static Helm chart; one replica, RWO/local DB | Runtime cluster qualification, HA/DR and failover evidence |
| Security assurance | Internal test and static scripts | Independent penetration test, crypto review, supply-chain audit and remediation evidence |
| Operations | Local evidence/events | Customer-controlled immutable evidence, SLOs, alerting, DR/RTO/RPO, incident/rollback procedure |
| Compliance/channel | Channel artifacts exist in supplied bundle | Actual third-party certification/marketplace review and written approvals |

No certification, production SLA, external security review or production provider integration is claimed by this release. A pilot is not a production deployment; any pilot must remain a bounded customer-approved evaluation with explicit stop conditions and no sensitive live actions until the gates are closed.
