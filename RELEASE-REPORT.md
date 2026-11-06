# APC 0.1.0a1 — Release Validation Report

**Build date:** 2026-11-06  
**Status:** PREPARED — NOT PUBLISHED  
**Distribution:** `apc-action-security`  
**Runtime source snapshot:** APC Enterprise 7.1.4 certification-candidate  
**Python:** 3.13.5 / Linux-6.18.57-x86_64-with-glibc2.41

## What was packaged

The repository contains `apc_y`, `apc_product`, `apc`, and an optional MCP SDK v2 reference server. It includes a draft public action-continuity protocol, developer documentation, tests, threat-model and production-readiness notes, GitHub CI/security workflows, a root composite GitHub Action, draft MCP Registry descriptors, a Dockerfile, Compose example, and a single-replica DEMO-only Kubernetes evaluation chart.

The five NVIDIA-inspired runtime-control modules are isolated in `experiments/`. They are not integrated with the supported runtime and are not covered by its guarantees. The internal master specification and pricing formula were not included.

## Validation performed

| Check | Result |
|---|---|
| Public pytest suite | **10 passed, 1 skipped, 0 failed** |
| Deep kernel adversarial harness | **28 passed, 0 failed** |
| Python compileall | PASS |
| YAML/JSON syntax | PASS for descriptors, chart, values schema, action and Compose files |
| Helm values JSON Schema | PASS for default values |
| Shell script syntax | PASS |
| Source token-pattern scan | No matches for selected PEM/AWS/GitHub/Slack token patterns; not a full secret audit |
| Wheel build | PASS |
| Source distribution build | PASS |
| Wheel imports | PASS for `apc_y`, `apc_product`, `apc`, `apc_mcp` |
| Installed CLI smoke | PASS: `apc status`, `doctor`, `integrations`, `evidence-verify` |

The installed runtime reported `mode=DEMO` and `effect_execution=DISABLED` during CLI smoke checks. The single skipped test needs the optional MCP SDK v2 package, which is not installed in this local build environment. MCP behavior was tested with a test double, but the real SDK runtime and MCP Inspector were not verified here.

## Artifacts

- Wheel: `apc_action_security-0.1.0a1-py3-none-any.whl`  
  SHA-256: `74478d1bfb90c733ba4d10736099af6fde5d4c377fbd8b0647ed5badd139a663`
- Source distribution: `apc_action_security-0.1.0a1.tar.gz`
- Repository ZIP and TAR.GZ plus all distributions are bundled in the release kit. See its `SHA256SUMS.txt` for final artifact hashes.

## Not performed / not claimed

- No GitHub repository push, release tag, GitHub Marketplace publication, PyPI upload, or MCP Registry submission occurred. The PyPI name and namespace ownership have not been confirmed; the Registry descriptor is a draft only.
- Twine, Ruff and pip-audit were unavailable in the build environment; no results are claimed for them.
- Docker build, Helm lint/render, cluster deployment, HA/failover and performance/SLO testing were not performed.
- No SBOM, signed provenance, independent penetration test, cryptographic review, formal verification or certification is claimed.
- No production customer IdP, PDP/revocation integration, KMS/HSM, workload identity, real provider effect adapter, provider idempotency, or authoritative provider reconciliation is included.

## Legal and release gate

Apache-2.0 is the proposed repository license, not proof that every recovered source file is legally cleared. The project owner must confirm source ownership, provenance, contributor rights, and dependency/third-party license obligations before a public push. The runtime was recovered from the supplied OCI candidate; the NVIDIA-inspired candidate also requires provenance review.

**This is a community alpha for inspection and bounded local evaluation only. It is not an enterprise production release and must not authorize sensitive live external actions.**
