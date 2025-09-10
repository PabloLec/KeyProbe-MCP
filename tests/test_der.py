import pytest
from fastmcp import Client
from _util import FIX, require, EXP
from snapshot import assert_snapshot

@pytest.mark.asyncio
async def test_file_metadata_der_leaf():
    p = require(FIX / "der" / "leaf.cert.der")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("analyze_from_local_path", {"path": str(p)})
        assert_snapshot(res.data, EXP / "der_leaf.json")
