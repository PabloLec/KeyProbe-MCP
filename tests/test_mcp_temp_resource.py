import json
import pytest
from fastmcp import Client

@pytest.mark.asyncio
async def test_put_and_read_temp_resource():
    from keyprobe.server import mcp

    async with Client(mcp) as client:
        # 1) On stocke un summary et on récupère l'URI (string dans result.data)
        put_res = await client.call_tool("put_temp", {"summary": {"hello": "world"}})
        uri = put_res.data
        assert isinstance(uri, str)
        assert uri.startswith("kp://temp/")

        # 2) On lit la resource via l'URI retournée
        content = await client.read_resource(uri)
        assert content and hasattr(content[0], "text")
        data = json.loads(content[0].text)
        assert data == {"hello": "world"}
