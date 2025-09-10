import pytest
from _util import EXP, FIX, require
from fastmcp import Client
from snapshot import assert_snapshot


@pytest.mark.asyncio
async def test_file_metadata_unknown():
    p = require(FIX / "misc" / "unknown.bin")
    from keyprobe.server import mcp

    async with Client(mcp) as client:
        res = await client.call_tool("analyze_from_local_path", {"path": str(p)})
        assert_snapshot(res.data, EXP / "unknown.json")
