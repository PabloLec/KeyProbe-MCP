from __future__ import annotations
from .settings import Settings
from .logging_conf import setup_logging
from fastmcp import FastMCP

mcp = FastMCP(name="KeyProbe")

@mcp.tool
def ping() -> str:
    """Petit outil de fumée pour vérifier que le serveur répond."""
    return "pong"

if __name__ == "__main__":
    # Exécute le serveur en transport STDIO par défaut.
    # Peut aussi être lancé via `fastmcp run` ou le CLI `uv`.
    mcp.run()


def bootstrap_runtime() -> Settings:
    s = Settings.from_env()
    setup_logging(s)
    return s