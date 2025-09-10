import pytest
from fastmcp import Client

from _util import FIX, require, EXP, b64_of
from snapshot import assert_snapshot


@pytest.mark.asyncio
async def test_jks_summary_ok():
    p = require(FIX / "jks" / "test.jks")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        meta = (await client.call_tool("analyze_from_local_path", {"path": str(p), "password": "changeit"})).data
        assert_snapshot(meta, EXP / "jks_ok.json")

@pytest.mark.asyncio
async def test_jks_summary_bad():
    p = require(FIX / "jks" / "test.jks")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        meta = (await client.call_tool("analyze_from_local_path", {"path": str(p), "password": "wrongpass"})).data
        assert_snapshot(meta, EXP / "jks_bad.json")

@pytest.mark.asyncio
async def test_jks_summary_from_b64_ok():
    p = require(FIX / "jks" / "test.jks")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        meta = (await client.call_tool("analyze_from_b64_string", {
            "filename": p.name, "content_b64": b64_of(p), "password": "changeit"
        })).data
        assert_snapshot(meta, EXP / "jks_b64_ok.json")
