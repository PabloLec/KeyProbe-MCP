# tests/integration/test_e2e_file_metadata_openssh_priv_unenc.py
import pytest
from fastmcp import Client
from _util import FIX, require, EXP
from snapshot import assert_snapshot

@pytest.mark.asyncio
async def test_file_metadata_openssh_priv_unenc_snapshot():
    p = require(FIX / "openssh" / "id_ed25519")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("file_metadata", {"path": str(p)})
        assert_snapshot(res.data, EXP / "file_metadata" / "openssh_priv_unenc.json")
