# MCP Registry publication checklist

`server.json` is a **draft descriptor** based on the official registry's `server.json` format. It has not been submitted, validated by the registry service, or approved. The package is not yet published on PyPI and the repository URL is an intended location, not a verified live repository.

The PyPI ownership convention requires the published package README to include the exact `mcp-name: <server-name>` marker; this repository README includes a provisional marker for `io.github.Aleph-Lab-s/apc-security-reference-server`. The registry must still verify package and namespace ownership at publish time.

Before submitting:

1. Confirm the GitHub namespace spelling and control of the `Aleph-Lab-s` organization.
2. Confirm the PyPI name `apc-action-security` is available and publish the exact version with Trusted Publishing.
3. Validate this descriptor against the registry's current schema and official validation endpoint/CLI.
4. Run a clean install using `uvx --from apc-action-security apc-mcp` and verify MCP SDK v2 interoperability / MCP Inspector.
5. Publish only after the actual GitHub repository URL and package are live.
6. Label the listing as an evaluation/reference server and preserve the no-universal-interception limitation.

Official reference: https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/generic-server-json.md
