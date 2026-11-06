# Changelog

## 0.1.0a1 — 2026-11-06

Initial public-source community alpha assembled from the supplied APC Enterprise 7.1.4 certification-candidate runtime source recovered from its OCI image, with a new public package envelope and MCP Python SDK v2 reference server.

- Includes `apc_y`, `apc_product` and `apc` source packages.
- Adds MCP reference server for synthetic evaluation and opt-in local SQLite sandbox tests.
- Adds a draft action-continuity protocol, public documentation, governance, security policy, issue templates, CI, a local GitHub Action smoke check, a draft MCP Registry descriptor, Docker/Compose files and a DEMO-only single-replica evaluation Helm chart.
- Preserves the NVIDIA-inspired security-control candidate under `experiments/` as unintegrated and unsupported.
- Does not include production provider integrations, external certification, independent security review or HA/distributed runtime.
