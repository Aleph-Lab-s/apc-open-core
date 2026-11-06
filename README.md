<!-- mcp-name: io.github.Aleph-Lab-s/apc-security-reference-server -->

# APC — Action • Proof • Control

**Open-source community alpha.** APC explores how an agent's authority can remain bound to the exact operation, target, and material parameters that reach a protected side-effect boundary—and how the result can be evidenced.

> **Important:** This repository is a developer-evaluation release, not a production security certification. Do not use it to authorize live payments, account changes, infrastructure mutations, or other sensitive external actions. The bundled runtime defaults to synthetic DEMO mode. Its LAB mode writes to a local SQLite sandbox only.

## Why APC exists

Agent systems cross model, tool, workflow, and provider boundaries. An approval at one point does not by itself prove that the same operation and parameters reach the final system. APC's design goal is to bind approval context to an action and re-check that binding at the final protected effect boundary.

APC is complementary to—not a replacement for—customer identity providers, OAuth/OIDC, policy decision points such as OPA or Cedar, agent frameworks, MCP, workflow orchestrators, cloud IAM, provider idempotency, or SIEM platforms.

## Repository contents

| Area | What is included | Status |
|---|---|---|
| `src/apc_y` | Reusable authority, delegation, cryptographic, continuity and finality kernel | Internal tests available; not independently reviewed |
| `src/apc_product` | APC 7.1.4 candidate service/runtime, API, evidence, SQLite LAB sink and CLI | DEMO/LAB evaluation profile |
| `src/apc` | Security-event and sink integration modules | Verify each adapter before use |
| `src/apc_mcp` | MCP SDK v2 reference server exposing health, catalog and synthetic evaluation | Reference/demo; no universal MCP interception |
| `tests` | Package, runtime and adversarial kernel tests | Local tests only; see release report |
| `deploy/helm` | Single-replica Kubernetes evaluation chart | Static artifact; cluster deployment not validated here |
| `experiments` | NVIDIA-inspired control candidates | Experimental, unintegrated, unsupported |
| `spec` | Draft action-authority and continuity protocol description | Non-standard draft; cross-language conformance not established |
| `docs` | Architecture, security assumptions, status, roadmap and contribution material | Community review requested |

## Quick start — source checkout

Requires Python 3.11 or newer.

```bash
git clone https://github.com/Aleph-Lab-s/apc-open-core.git
cd apc-open-core
python -m venv .venv
. .venv/bin/activate                 # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e ".[test,mcp]"
apc status
apc integrations
```

The GitHub URL above is the intended repository name, not a claim that it has already been created. The root `server.json` is a draft MCP Registry descriptor; it has not been submitted or approved. Until the package is published to PyPI, install from a local checkout as shown above. After publication, the planned install form is:

```bash
python -m pip install "apc-action-security[mcp]"
```

## Run the MCP reference server

```bash
python -m pip install -e ".[mcp]"
apc-mcp
```

The server uses stdio. Add it to an MCP client using that client's local process configuration. Available tools:

- `apc_health` — runtime health and mode.
- `apc_integration_status` — catalog with honest implementation labels.
- `apc_evaluate_action` — synthetic action evaluation; no external side effect.
- `apc_lab_sqlite_action` — disabled by default; when deliberately enabled with `APC_MCP_ENABLE_LAB=1`, writes only to a local SQLite sandbox using a test-only ALLOW fixture.

This server does **not** transparently instrument other MCP servers, inspect every tool call in a host process, or guarantee coverage of bypass paths. A protected integration must be added server-side, and the actual provider mutation must pass through the protected wrapper.

## Run the local tests

```bash
python -m pytest -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python tests/deep_security_test.py
```

## Actual implementation limits

- `APC_MODE=DEMO` is synthetic and performs no protected external effect.
- `LAB` uses local SQLite as a reference sink. It is not a real customer/provider adapter.
- `PILOT` and `PRODUCTION` effect execution are blocked by the current service until a customer integration/profile exists.
- The default evaluation engine generates in-process ephemeral signing keys. This is not a deployment-grade KMS/HSM/key-rotation design.
- The current Kubernetes chart is one replica with local SQLite/RWO storage. It is not an HA/distributed profile.
- OPA and Cedar entries are simulated; Okta, GitHub, AWS and GCP event/effect adapters are unavailable in this build; Stripe entry is a sandbox declaration only. See `docs/integration-status.md`.
- No independent penetration test, cryptographic review, formal verification, certification, production SLA, or live-provider conformance is claimed.

## Project status and release note

Public package version: `0.1.0a1` (community alpha). The included `apc_product` runtime identifies its source snapshot as APC Enterprise `7.1.4`, release channel `certification-candidate`. The 7.1.4 internal candidate test evidence is not an external certification and is not a production guarantee. See `docs/release-validation.md` and `docs/production-readiness.md`.

## Contribute

We want tough technical review: threat-model criticism, bypass demonstrations in controlled test environments, reproducible bugs, adapter conformance ideas, documentation improvements, and integration pull requests. Start with [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [spec/APC-Action-Continuity-Protocol-0.1-DRAFT.md](spec/APC-Action-Continuity-Protocol-0.1-DRAFT.md), and [docs/roadmap.md](docs/roadmap.md).

## License

Apache License 2.0 is proposed for this public source release. Before pushing publicly, the project owner must confirm copyright ownership, contributor authority, source provenance, and dependency/license obligations. See `docs/licensing-and-ownership.md`.
