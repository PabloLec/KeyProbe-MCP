from __future__ import annotations

import base64
import hashlib
from typing import Optional, Dict, Any

from fastmcp import FastMCP

from .logging_conf import setup_logging
from .resource_store import ResourceStore
from .settings import Settings
from .path_utils import resolve_path
from .summary import summarize_bytes

from .formats.pkcs12 import summarize_with_password_bytes as p12_summarize_with_password_bytes
from .formats.jks import summarize_with_password_bytes as jks_summarize_with_password_bytes

mcp = FastMCP(name="KeyProbe")

_SETTINGS: Optional[Settings] = None
_STORE: Optional[ResourceStore] = None


def _get_settings() -> Settings:
    global _SETTINGS
    if _SETTINGS is None:
        _SETTINGS = Settings.from_env()
        setup_logging(_SETTINGS)
    return _SETTINGS


def _get_store() -> ResourceStore:
    global _STORE
    if _STORE is None:
        s = _get_settings()
        _STORE = ResourceStore(ttl_seconds=s.RESOURCE_TTL_SEC)
    return _STORE


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@mcp.tool
def put_temp(summary: dict) -> str:
    rid = _get_store().put(summary)
    return f"kp://temp/{rid}"


@mcp.resource("kp://temp/{rid}", mime_type="application/json")
def get_temp(rid: str) -> dict:
    entry = _get_store().get(rid)
    return entry.summary


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


@mcp.tool
def file_metadata(path: str) -> dict:
    p = resolve_path(path)
    data = p.read_bytes()
    meta = summarize_bytes(data, filename=str(p))
    meta.setdefault("size", len(data))
    meta.setdefault("digest_sha256", _sha256_hex(data))
    return {"path": str(p), **meta}


@mcp.tool
def file_metadata_from_b64(filename: str, content_b64: str) -> dict:
    data = base64.b64decode(content_b64, validate=True)
    meta = summarize_bytes(data, filename=filename)
    meta.setdefault("size", len(data))
    meta.setdefault("digest_sha256", _sha256_hex(data))
    return {"filename": filename, **meta}


@mcp.tool
def p12_summary(path: str, password: str) -> dict:
    p = resolve_path(path)
    data = p.read_bytes()
    meta = p12_summarize_with_password_bytes(data, password)
    meta.setdefault("size", len(data))
    meta.setdefault("digest_sha256", _sha256_hex(data))
    meta["path"] = str(p)
    return meta


@mcp.tool
def p12_summary_from_b64(filename: str, content_b64: str, password: str) -> dict:
    data = base64.b64decode(content_b64, validate=True)
    meta = p12_summarize_with_password_bytes(data, password)
    meta.setdefault("size", len(data))
    meta.setdefault("digest_sha256", _sha256_hex(data))
    meta["filename"] = filename
    return meta


@mcp.tool
def jks_summary(path: str, password: str) -> dict:
    p = resolve_path(path)
    data = p.read_bytes()
    meta = jks_summarize_with_password_bytes(data, password)
    meta.setdefault("size", len(data))
    meta.setdefault("digest_sha256", _sha256_hex(data))
    meta["path"] = str(p)
    return meta


@mcp.tool
def jks_summary_from_b64(filename: str, content_b64: str, password: str) -> dict:
    data = base64.b64decode(content_b64, validate=True)
    meta = jks_summarize_with_password_bytes(data, password)
    meta.setdefault("size", len(data))
    meta.setdefault("digest_sha256", _sha256_hex(data))
    meta["filename"] = filename
    return meta


@mcp.tool
def ping() -> str:
    return "pong"


if __name__ == "__main__":
    mcp.run()
