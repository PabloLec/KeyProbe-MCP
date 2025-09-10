import pytest
from _util import EXP, FIX, require
from fastmcp import Client
from snapshot import assert_snapshot


@pytest.mark.asyncio
async def test_file_metadata_pkcs7_der():
    p = require(FIX / "pkcs7" / "chain.p7b")
    from keyprobe.server import mcp

    async with Client(mcp) as client:
        res = await client.call_tool("analyze_from_local_path", {"path": str(p)})
        assert_snapshot(res.data, EXP / "pkcs7_chain_der.json")


@pytest.mark.asyncio
async def test_file_metadata_pkcs7_pem():
    p = require(FIX / "pkcs7" / "chain.pem.p7b")
    from keyprobe.server import mcp

    async with Client(mcp) as client:
        res = await client.call_tool("analyze_from_local_path", {"path": str(p)})
        assert_snapshot(res.data, EXP / "pkcs7_chain_pem.json")
