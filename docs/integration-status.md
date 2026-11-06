# Integration status matrix

This table reflects the integration catalog in the included APC runtime snapshot. It is not a statement about external vendors' general capabilities.

| Integration entry | Declared status in this build | Meaning |
|---|---|---|
| OPA HTTP | `SIMULATED` | Catalog/contract placeholder; no production PDP adapter |
| Cedar bridge | `SIMULATED` | Catalog/contract placeholder; no production PDP adapter |
| Okta events | `UNAVAILABLE` | Not implemented in this source build |
| GitHub events | `UNAVAILABLE` | Not implemented in this source build |
| AWS events/effects | `UNAVAILABLE` | Not implemented in this source build |
| GCP events/effects | `UNAVAILABLE` | Not implemented in this source build |
| Stripe test | `SANDBOX` | Catalog declaration only; no live payment execution claim |
| Generic SIEM webhook | `SIMULATED` | No production delivery guarantee |
| SQLite protected sink | `SANDBOX` | Local durable write and local reconciliation only |
| MCP Python SDK v2 server | `REFERENCE` | Synthetic evaluation tools; local SQLite LAB tool opt-in |

The MCP server intentionally does not intercept other MCP servers. Every integration must be verified at its actual side-effect boundary, not just by a successful handshake or catalog entry.
