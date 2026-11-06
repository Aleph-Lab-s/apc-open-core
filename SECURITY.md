# Security policy

## Scope

This repository is an alpha security project. It is not certified or approved for production sensitive-action enforcement. Security review of this code does not imply that all MCP servers, provider paths, or side effects are mediated.

## Reporting

Do not publish exploit details, secrets, customer data, private deployment addresses, or a live bypass before coordinated disclosure. Once this repository is published on GitHub, use **Security → Report a vulnerability** (private vulnerability reporting / GitHub Security Advisory). For a pre-publication copy, contact the project owner through a verified official channel; no email address is asserted in this file.

Include the affected commit/version, environment, impact, minimal safe reproduction, and mitigation if known. Avoid touching systems you do not own or have written authorization to test.

## Supported security boundaries

The current explicit coverage is limited to effects routed through the APC evaluation engine's local SQLite sandbox and synthetic DEMO workflow. An application must explicitly integrate APC server-side and route the actual protected side effect through the boundary to obtain any APC enforcement. Alternate paths remain outside its guarantee.

## Response expectations

This is a community alpha without a staffed security response SLA. The maintainers will triage reports as capacity allows. Do not rely on APC as your sole security control.
