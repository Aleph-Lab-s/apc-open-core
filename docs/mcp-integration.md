# MCP integration

## What ships

`apc_mcp` is an optional MCP SDK v2 server that exposes APC health, the current integration catalog, and a synthetic action evaluation. An additional local SQLite LAB tool is disabled unless `APC_MCP_ENABLE_LAB=1` is explicitly set.

Install the SDK extra from a source checkout:

```bash
python -m pip install -e ".[mcp]"
apc-mcp
```

The server uses stdio by default. Configure your MCP client to launch the `apc-mcp` executable with the appropriate environment. Do not copy secrets into an untrusted MCP client configuration.

## What it does not do

- It is not a universal gateway/proxy for every MCP server.
- It does not transparently patch or wrap tools in another server process.
- It does not provide customer IdP, OAuth, workload identity or a real PDP connection.
- Its DEMO tool produces synthetic results only; the LAB tool writes to local SQLite only.
- It does not execute live external provider actions or reconcile with provider APIs.

## Correct integration direction

The host MCP server (or its trusted application backend) should obtain identity and authorization from trusted customer systems, derive the action parameters server-side, and route the actual external mutation through a protected APC boundary. The integration must prove there is no alternate path to the protected resource. Merely placing an observing proxy between an MCP client and server is not enough to prove final-effect integrity if the server can mutate the provider through a different route.

## Next work

- Harden MCP SDK v2 interoperability and add client/Inspector conformance tests.
- Develop per-tool server-side integration helpers that require trusted context resolvers and protected sink adapters.
- Add TypeScript support only after the Python contract and finality boundary are independently reviewed.
- Publish a separate runnable reference server to the official MCP Registry only after the PyPI package, README naming convention, namespace ownership proof and registry schema validation are complete.
