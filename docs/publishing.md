# Publishing guide — not yet published

## GitHub

Create the repository under the intended organization, verify the owner spelling and access control, push the reviewed source and tag a release. Enable private vulnerability reporting, Discussions, branch protection, signed commits/tags where practical, and CODEOWNERS review. No push was performed by this build task.

## PyPI

The public package name in `pyproject.toml` is `apc-action-security`; availability has not been checked and the package has not been uploaded. Configure PyPI Trusted Publishing for the exact GitHub owner/repository/workflow and `pypi` environment. The included release workflow uses OIDC Trusted Publishing and does not store a long-lived PyPI API token. Do not trigger it until legal, dependency, test, metadata and ownership gates are complete.

Planned install after actual publication:

```bash
python -m pip install "apc-action-security[mcp]"
```

## MCP Registry

The repository contains matching draft descriptors at root `server.json` and `registry/server.json`, not a registry submission. PyPI publication and namespace proof must be done first. Follow the registry's current server.json format and publisher verification requirements; run the official validator before submission. The MCP server is a reference/evaluation server, not a universal interceptor.

## GitHub Marketplace

The root `action.yml` defines a composite smoke-check Action, but it has not been published. The Action runs APC's own local DEMO health/catalog/evidence checks. It does not prove the calling repository protects its actions. Validate its usefulness, pin dependencies/actions, tag a release and follow Marketplace publication requirements before listing.

## Website

The website page prepared separately in a previous task has not been deployed. Verify the actual hosting path and update links only after the repository and PyPI release are live.
