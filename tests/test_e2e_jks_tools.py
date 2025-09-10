# tests/integration/test_e2e_jks_tools.py
import pytest
from fastmcp import Client
from _util import FIX, require, EXP, b64_of
from snapshot import assert_snapshot

@pytest.mark.asyncio
async def test_jks_summary_ok_snapshot():
    p = require(FIX / "jks" / "test.jks")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        meta = (await client.call_tool("jks_summary", {"path": str(p), "password": "changeit"})).data
        assert_snapshot(meta, EXP / "tools" / "jks_ok.json")

@pytest.mark.asyncio
async def test_jks_summary_bad_snapshot():
    p = require(FIX / "jks" / "test.jks")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        meta = (await client.call_tool("jks_summary", {"path": str(p), "password": "wrongpass"})).data
        assert_snapshot(meta, EXP / "tools" / "jks_bad.json")

@pytest.mark.asyncio
async def test_jks_summary_from_b64_ok_snapshot():
    p = require(FIX / "jks" / "test.jks")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        meta = (await client.call_tool("jks_summary_from_b64", {
            "filename": p.name, "content_b64": b64_of(p), "password": "changeit"
        })).data
        assert_snapshot(meta, EXP / "tools" / "jks_b64_ok.json")
