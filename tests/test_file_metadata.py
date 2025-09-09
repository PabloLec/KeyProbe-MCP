import pytest
from fastmcp import Client

PEM_SAMPLE = b"""-----BEGIN CERTIFICATE-----
MIIB+jCCAaCgAwIBAgIUeW5tZW5vbmNlLWp1c3RlLXVuLW1vY2swdDAKBggqhkjO
PQQDAjASMRAwDgYDVQQDDAdUZXN0Q0EwHhcNMjUwMTAxMDAwMDAwWhcNMjUwMTAx
MDAwMDAwWjASMRAwDgYDVQQDDAdUZXN0Q0EwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAAS1vQmZf2vGZl0b3u3e1v7g9v6zv3f0gq2oGJmQn0Hqtk9Wwz/7G7cWc0Rh
H3x6cJ3m4j6qg3Pzj9LmfiY4wGgPMB8wHQYDVR0OBBYEFE0o1YbQe4cwZ3VZZZZZ
ZZZZZZZZZZZZMAoGCCqGSM49BAMCA0cAMEQCIH8Y8p7z8wK7iF3p1qS9/8Q2Jq1m
0nI6v4S6Hc1f6KcNAiBnJc0h7lX9b+0tM7XoO4hL8CIV4vQJQm8nQ2r5Jf8Fjg==
-----END CERTIFICATE-----"""

def _mk_file(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return p

@pytest.mark.asyncio
async def test_file_metadata_pem(tmp_path):
    pem = _mk_file(tmp_path, "cert.pem", PEM_SAMPLE)
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("file_metadata", {"path": str(pem)})
        meta = res.data
        assert meta["path"] == str(pem.resolve())
        assert meta["format"] == "PEM"
        assert meta["size"] == pem.stat().st_size
        assert len(meta["digest_sha256"]) == 64

@pytest.mark.asyncio
async def test_file_metadata_jks_magic(tmp_path):
    jks = _mk_file(tmp_path, "test.jks", b"\xFE\xED\xFE\xED" + b"\x00" * 16)
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("file_metadata", {"path": str(jks)})
        assert res.data["format"] == "JKS"
