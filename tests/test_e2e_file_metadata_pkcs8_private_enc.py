# tests/integration/test_e2e_file_metadata_pkcs8_private_enc.py
import pytest
from fastmcp import Client
from _util import FIX, require, EXP
from snapshot import assert_snapshot

@pytest.mark.asyncio
async def test_file_metadata_pkcs8_private_enc_snapshot():
    p = require(FIX / "pkcs8" / "key_pkcs8_encrypted.pem")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("analyze_from_local_path", {"path": str(p)})
        assert_snapshot(res.data, EXP / "file_metadata" / "pkcs8_private_enc.json")
