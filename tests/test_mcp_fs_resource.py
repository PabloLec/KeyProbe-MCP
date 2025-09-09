import pytest
from mcp.shared.exceptions import McpError

@pytest.mark.asyncio
async def test_fs_stat_outside_allowlist(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYPROBE_ALLOWLIST_DIRS", str(tmp_path))
    import os
    outside_path = os.getcwd()

    from fastmcp import Client
    from keyprobe.server import mcp

    async with Client(mcp) as client:
        uri = f"kp://fs/{outside_path}"
        # Sur échec ressource, le client lève McpError
        with pytest.raises(McpError):
            await client.read_resource_mcp(uri)
        # (équivalent)
        with pytest.raises(McpError):
            await client.read_resource(uri)
