import json
import pytest
from fastmcp import Client

@pytest.mark.asyncio
async def test_fs_stat_basic(tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("abc")

    from keyprobe.server import mcp
    async with Client(mcp) as client:
        uri = f"kp://fs/{target}"
        content = await client.read_resource(uri)
        info = json.loads(content[0].text)
        assert info["resolved"] == str(target.resolve())
        assert info["exists"] is True
        assert info["is_file"] is True
        assert info["size"] == 3
