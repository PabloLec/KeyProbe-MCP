# tests/integration/test_e2e_file_metadata_pkcs7_der.py
import pytest
from fastmcp import Client
from _util import FIX, require, EXP
from snapshot import assert_snapshot

@pytest.mark.asyncio
async def test_file_metadata_pkcs7_der_snapshot():
    p = require(FIX / "pkcs7" / "chain.p7b")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("analyze_from_local_path", {"path": str(p)})
        assert_snapshot(res.data, EXP / "file_metadata" / "pkcs7_chain_der.json")
