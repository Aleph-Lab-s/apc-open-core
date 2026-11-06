from __future__ import annotations

import pytest


def test_build_server_with_installed_mcp_sdk():
    sdk = pytest.importorskip("mcp.server")
    from apc_mcp.server import build_server

    server, service = build_server()
    try:
        assert isinstance(server, sdk.MCPServer)
    finally:
        service.close()
