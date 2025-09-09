import pytest
from fastmcp import Client

@pytest.mark.asyncio
async def test_server_name_and_ping():
    from keyprobe.server import mcp

    assert getattr(mcp, "name", "") == "KeyProbe"

    async with Client(mcp) as client:
        result = await client.call_tool("ping", {})
        # Valeur structurée "déroulée"
        assert result.data == "pong"
        # (optionnel) vérifs supplémentaires utiles pour comprendre le format
        assert result.structured_content == {"result": "pong"}
        assert result.content and getattr(result.content[0], "text", None) == "pong"
