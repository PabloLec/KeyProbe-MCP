from __future__ import annotations
import base64
import json
import pytest
from fastmcp import Client

from _util import FIX, read_bytes, require

@pytest.mark.asyncio
async def test_file_metadata_with_path_pem():
    p = require(FIX / "pem" / "leaf.cert.pem")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("file_metadata", {"path": str(p)})
        meta = res.data
        assert meta["format"] == "PEM"
        assert "x509" in meta and meta["x509"]["subject_cn"] == "leaf.example.com"

@pytest.mark.asyncio
async def test_file_metadata_from_b64_pem():
    p = require(FIX / "pem" / "leaf.cert.pem")
    data_b64 = base64.b64encode(read_bytes(p)).decode("ascii")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("file_metadata_from_b64", {"filename": p.name, "content_b64": data_b64})
        meta = res.data
        assert meta["format"] == "PEM"
        assert "x509" in meta and meta["x509"]["subject_cn"] == "leaf.example.com"

@pytest.mark.asyncio
async def test_fs_stat_resource():
    p = require(FIX / "pem" / "leaf.cert.pem")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        content = await client.read_resource(f"kp://fs/{p}")
        info = json.loads(content[0].text)
        assert info["resolved"] == str(p.resolve())
        assert info["exists"] is True
        assert info["is_file"] is True
        assert info["size"] > 0
