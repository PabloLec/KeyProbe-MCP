import pytest
from _util import EXP, FIX, require
from fastmcp import Client
from snapshot import assert_snapshot


@pytest.mark.asyncio
async def test_file_metadata_pkcs8_private_enc():
    p = require(FIX / "pkcs8" / "key_pkcs8_encrypted.pem")
    from keyprobe.server import mcp

    async with Client(mcp) as client:
        res = await client.call_tool("analyze_from_local_path", {"path": str(p)})
        assert_snapshot(res.data, EXP / "pkcs8_private_enc.json")


@pytest.mark.asyncio
async def test_file_metadata_pkcs8_private_unenc():
    p = require(FIX / "pkcs8" / "key_pkcs8_unenc.pem")
    from keyprobe.server import mcp

    async with Client(mcp) as client:
        res = await client.call_tool("analyze_from_local_path", {"path": str(p)})
        assert_snapshot(res.data, EXP / "pkcs8_private_unenc.json")


@pytest.mark.asyncio
async def test_file_metadata_pkcs8_public():
    p = require(FIX / "pkcs8" / "pubkey_pkcs8.pem")
    from keyprobe.server import mcp

    async with Client(mcp) as client:
        res = await client.call_tool("analyze_from_local_path", {"path": str(p)})
        assert_snapshot(res.data, EXP / "pkcs8_public.json")
