# tests/integration/test_e2e_file_metadata_jks_minimal.py
import pytest
from fastmcp import Client
from _util import FIX, require, EXP
from snapshot import assert_snapshot

@pytest.mark.asyncio
async def test_file_metadata_jks_minimal_snapshot():
    p = require(FIX / "jks" / "test.jks")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("file_metadata", {"path": str(p)})
        assert_snapshot(res.data, EXP / "file_metadata" / "jks.json")
