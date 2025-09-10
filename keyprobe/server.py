# keyprobe/server.py
from __future__ import annotations

import base64
import hashlib
from typing import Optional

from fastmcp import FastMCP

from .logging_conf import setup_logging
from .resource_store import ResourceStore
from .settings import Settings
from .path_utils import resolve_path
from .summary import summarize_bytes

from .formats.pkcs12 import load_key_and_certificates
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
    resolved = resolve_path(path)
    info = {
        "input": path,
        "resolved": str(resolved),
        "exists": resolved.exists(),
        "is_file": resolved.is_file(),
        "is_dir": resolved.is_dir(),
        "size": resolved.stat().st_size if resolved.exists() and resolved.is_file() else None,
    }
    return info

@mcp.tool
def file_metadata(path: str) -> dict:
    resolved = resolve_path(path)
    data = resolved.read_bytes()
    meta = summarize_bytes(data, filename=str(resolved))
    return {"path": str(resolved), **meta}

@mcp.tool
def file_metadata_from_b64(filename: str, content_b64: str) -> dict:
    data = base64.b64decode(content_b64, validate=True)
    meta = summarize_bytes(data, filename=filename)
    return {"filename": filename, **meta}

@mcp.tool
def p12_summary(path: str, password: str) -> dict:
    p = resolve_path(path)
    data = p.read_bytes()
    try:
        key, cert, chain = load_key_and_certificates(data, password.encode("utf-8"))
        out = {
            "path": str(p),
            "format": "PKCS12",
            "size": len(data),
            "digest_sha256": hashlib.sha256(data).hexdigest(),
            "encrypted": False,
            "has_key": key is not None,
        }
        certs = []
        if cert is not None:
            from .crypto_utils import x509_cert_to_meta
            certs.append(x509_cert_to_meta(cert))
        if chain:
            from .crypto_utils import x509_cert_to_meta
            certs.extend(x509_cert_to_meta(c) for c in chain)
        if certs:
            out["x509"] = certs[0] if len(certs) == 1 else None
            if len(certs) > 1:
                out["x509_chain"] = certs
        return out
    except Exception:
        return {
            "path": str(p),
            "format": "PKCS12",
            "size": len(data),
            "digest_sha256": hashlib.sha256(data).hexdigest(),
            "encrypted": True,
            "error": "BadPasswordError",
        }

# PKCS#12 (b64)
@mcp.tool
def p12_summary_from_b64(filename: str, content_b64: str, password: str) -> dict:
    data = base64.b64decode(content_b64, validate=True)
    try:
        key, cert, chain = load_key_and_certificates(data, password.encode("utf-8"))
        out = {
            "filename": filename,
            "format": "PKCS12",
            "size": len(data),
            "digest_sha256": hashlib.sha256(data).hexdigest(),
            "encrypted": False,
            "has_key": key is not None,
        }
        certs = []
        if cert is not None:
            from .crypto_utils import x509_cert_to_meta
            certs.append(x509_cert_to_meta(cert))
        if chain:
            from .crypto_utils import x509_cert_to_meta
            certs.extend(x509_cert_to_meta(c) for c in chain)
        if certs:
            out["x509"] = certs[0] if len(certs) == 1 else None
            if len(certs) > 1:
                out["x509_chain"] = certs
        return out
    except Exception:
        return {
            "filename": filename,
            "format": "PKCS12",
            "size": len(data),
            "digest_sha256": hashlib.sha256(data).hexdigest(),
            "encrypted": True,
            "error": "BadPasswordError",
        }

from .formats.jks import summarize_with_password_bytes
import base64

@mcp.tool
def jks_summary(path: str, password: str) -> dict:
    p = resolve_path(path)
    data = p.read_bytes()  # ✅ on passe des BYTES
    meta = summarize_with_password_bytes(data, password)
    meta.update({"path": str(p)})
    return meta

@mcp.tool
def jks_summary_from_b64(filename: str, content_b64: str, password: str) -> dict:
    data = base64.b64decode(content_b64, validate=True)  # ✅ bytes
    meta = summarize_with_password_bytes(data, password)
    meta.update({"filename": filename})
    return meta
@mcp.tool
def ping() -> str:
    return "pong"

if __name__ == "__main__":
    mcp.run()
