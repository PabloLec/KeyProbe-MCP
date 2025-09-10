
import base64
import hashlib
from typing import Optional

from fastmcp import FastMCP

from .logging_conf import setup_logging
from .resource_store import ResourceStore
from .settings import Settings
from .path_utils import resolve_path
from .summary import summarize_bytes

mcp = FastMCP(name="KeyProbe")

_SETTINGS: Optional[Settings] = None
_STORE: Optional[ResourceStore] = None


def _settings() -> Settings:
    global _SETTINGS
    if _SETTINGS is None:
        _SETTINGS = Settings.from_env()
        setup_logging(_SETTINGS)
    return _SETTINGS


def _store() -> ResourceStore:
    global _STORE
    if _STORE is None:
        _STORE = ResourceStore(ttl_seconds=_settings().RESOURCE_TTL_SEC)
    return _STORE


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _analyze_from_bytes(name_key: str, name_val: str, data: bytes, password: Optional[str]) -> dict:
    meta = summarize_bytes(data, filename=name_val, password=password)
    meta.setdefault("size", len(data))
    meta.setdefault("digest_sha256", _sha256(data))
    return {name_key: name_val, **meta}


@mcp.tool
def analyze_from_local_path(path: str, password: Optional[str] = None) -> dict:
    """
    Analyse un fichier (PKCS#12, JKS, PEM, DER, PKCS#8, PKCS#7, OpenSSH, etc.)
    et retourne un résumé détaillé. 'password' est optionnel (utile pour .p12/.jks).
    """
    p = resolve_path(path)
    data = p.read_bytes()
    return _analyze_from_bytes("path", str(p), data, password)


@mcp.tool
def analyze_from_b64_string(filename: str, content_b64: str, password: Optional[str] = None) -> dict:
    """
    Variante base64 de 'analyze'.
    """
    data = base64.b64decode(content_b64, validate=True)
    return _analyze_from_bytes("filename", filename, data, password)


@mcp.tool
def put_temp(summary: dict) -> str:
    rid = _store().put(summary)
    return f"kp://temp/{rid}"


@mcp.resource("kp://temp/{rid}", mime_type="application/json")
def get_temp(rid: str) -> dict:
    return _store().get(rid).summary


@mcp.resource("kp://fs/{path*}", mime_type="application/json")
def fs_stat(path: str) -> dict:
    p = resolve_path(path)
    return {
        "input": path,
        "resolved": str(p),
        "exists": p.exists(),
        "is_file": p.is_file(),
        "is_dir": p.is_dir(),
        "size": p.stat().st_size if p.exists() and p.is_file() else None,
    }


if __name__ == "__main__":
    mcp.run()
