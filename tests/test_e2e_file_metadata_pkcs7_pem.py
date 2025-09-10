# tests/integration/test_e2e_file_metadata_pkcs7_pem.py
import pytest
from fastmcp import Client
from _util import FIX, require, EXP
from snapshot import assert_snapshot

@pytest.mark.asyncio
async def test_file_metadata_pkcs7_pem_snapshot():
    p = require(FIX / "pkcs7" / "chain.pem.p7b")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("file_metadata", {"path": str(p)})
        assert_snapshot(res.data, EXP / "file_metadata" / "pkcs7_chain_pem.json")
