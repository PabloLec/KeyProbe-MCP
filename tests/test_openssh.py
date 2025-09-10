import pytest
from fastmcp import Client
from _util import FIX, require, EXP
from snapshot import assert_snapshot

@pytest.mark.asyncio
async def test_file_metadata_openssh_priv_enc():
    p = require(FIX / "openssh" / "id_ed25519_enc")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("analyze_from_local_path", {"path": str(p)})
        assert_snapshot(res.data, EXP / "openssh_priv_enc.json")

@pytest.mark.asyncio
async def test_file_metadata_openssh_priv_unenc():
    p = require(FIX / "openssh" / "id_ed25519")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("analyze_from_local_path", {"path": str(p)})
        assert_snapshot(res.data, EXP / "openssh_priv_unenc.json")

@pytest.mark.asyncio
async def test_file_metadata_openssh_pub():
    p = require(FIX / "openssh" / "id_ed25519.pub")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("analyze_from_local_path", {"path": str(p)})
        assert_snapshot(res.data, EXP / "openssh_pub.json")
