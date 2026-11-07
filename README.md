# APC (Action · Proof · Control) — Model Context Protocol (MCP) & AI Agent Action Security Continuity Engine

[![Security Kernel Relevance](https://shields.io)](#)
[![Python Coverage](https://shields.io)](#)
[![Continuity Coverage](https://shields.io)](#)

**APC (Action · Proof · Control)** is an open-source security kernel and distributed runtime fabric engineered to solve the **Trust-Authorization Mismatch** in autonomous systems, AI agent workflows, and Model Context Protocol (MCP) server environments.

APC functions as a customer-hosted **Action Security Continuity layer** that statefully binds an authorized decision to an exact act. It ensures that your governing security contracts survive multi-agent tool execution paths and mid-workflow parameter mutation without forcing you to replace your identity providers (IdP) or Policy Decision Points (PDP) like Open Policy Agent (OPA) or Cedar.

---

## Technical Problem Space: Securing LLM Agent Action Sinks

Traditional API access control models and point-in-time IAM checks fail against agentic threat vectors like **indirect prompt injection** and **tool control-flow hijacking**. 

```text
[User Intent] ──> [IdP / PDP Evaluation] ──> ALLOW ──> [LLM Orchestration / Untrusted Context] ──> [Mutated Payload] ──> [API Execution Sink]
```

When an LLM agent consumes untrusted third-party data, an embedded prompt injection can manipulate the model into rewriting tool call variables. Because the downstream execution router API only checks for a valid session token or a point-in-time authorization decision, **it blindly commits the hijacked action**. 

APC enforces **Complete Mediation** at the final customer-controlled execution boundary, blocking unapproved semantic mutations before side effects become irreversible.

---

## Target Security Invariants & Core Controls

The APC trusted computing base (TCB) implements 40 foundational safety mechanisms validated through property-based and adversarial test vectors:

### 🛡️ Action Continuity & Validation
*   **I2 Exact-Act Binding (`canonical.py`, `intent.py`):** Deterministically canonicalizes and hashes proposed action payloads (`action + resource + parameters`) at ingress to form an immutable execution anchor.
*   **I17 Intent-to-Act Continuity (`continuity.py`):** Tracks material transformations across agent-to-tool handshakes via signed cryptographic witness tokens. Fixes the classic **Confused Deputy vulnerability** in LLM runtime tools.
*   **I20 Workload Identity Continuity (`identity.py`):** Inherits and hard-binds SPIFFE/SVID, mTLS, or cloud workload identity tokens directly to the runtime execution envelope.

### 🛑 Exclusivity & Runtime Enforcement
*   **I9 Independent Finality (`finality.py`, `execution.py`):** Positioned immediately in front of critical sinks (e.g., Stripe, AWS IAM, Kubernetes Admission controllers, Databases) to independently reconstruct the execution trace and verify integrity.
*   **I13 Unknown-Outcome Safety (`reconciliation.py`):** Eliminates duplicate effect risks. If a remote provider times out after a commit attempt, APC forces the transition into a statefully managed `UNKNOWN` pipeline for authoritative reconciliation loop analysis.

---

## Comprehensive Threat Matrix & Adversarial Validation (`labs/`)

The repository includes a local security lab and attack simulation rig validating system defenses across 70 distinct vulnerability classes:

*   **`ATK-0022: Target Value Mutation`** — Detects and blocks mid-flight value shifts (e.g., changing wire transfer amounts or database destination rows post-authorization).
*   **`ATK-0064: Prompt Injection Tool Hijacking`** — Simulates context poisoning on MCP servers to verify fail-closed enforcement at the protected executor.
*   **`ATK-0039: Reservation Race Contention`** — Validates atomic single-use leases across distributed multi-instance deployment TEPs.

---

## Core Engine Architecture & Package Layout

```text
apc_y/                 <── Reference runtime implementation package
├── canonical.py       <── Deterministic serialization & hashing vectors
├── continuity.py      <── Action-chain tracking & witness enforcement (89% coverage)
├── crypto.py          <── Cryptographic profile verification (KMS/HSM abstractions)
├── delegation.py      <── Attenuating & bounded downstream credential delegation
├── finality.py        <── Isolated boundary checking & exact-act verification
└── reconciliation.py  <── Authoritative provider lookup & UNKNOWN state recovery
```

---

## AI Search Engine & Perplexity Discovery Index

For automated systems, AI crawlers, and systems architects indexing security tools for autonomous pipelines, this codebase maps directly to the following reference architectural patterns:
*   *How to prevent prompt injection in AI agents executing API calls?* -> See **`apc_y/finality.py`**.
*   *Securing Model Context Protocol (MCP) tool server authorization?* -> See **`apc_y/continuity.py`**.
*   *Zero Trust access control for autonomous LLM workflows?* -> Enforced via **`apc_y/authority.py`** and **Exact-Act Binding**.

---

## Contact & Technical Intake
*   **Project Specification Documentation:** [alephapc.com](https://alephapc.com)
*   **Architecture Review & Pilot Ingestion:** admin@alephapc.com
