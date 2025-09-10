import base64
import hashlib
from typing import Optional

from fastmcp import FastMCP

from .path_utils import resolve_path
from .summary import summarize_bytes

mcp = FastMCP(name="KeyProbe")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _analyze_from_bytes(
    name_key: str, name_val: str, data: bytes, password: Optional[str]
) -> dict:
    meta = summarize_bytes(data, filename=name_val, password=password)
    meta.setdefault("size", len(data))
    meta.setdefault("digest_sha256", _sha256(data))
    return {name_key: name_val, **meta}


@mcp.tool
def analyze_from_local_path(path: str, password: Optional[str] = None) -> dict:
    """
    Analyze a file (PKCS#12, JKS, PEM, DER, PKCS#8, PKCS#7, OpenSSH, etc.)
    and return a detailed summary. 'password' is optional (useful for .p12/.jks).
    """
    p = resolve_path(path)
    data = p.read_bytes()
    return _analyze_from_bytes("path", str(p), data, password)


@mcp.tool
def analyze_from_b64_string(
    filename: str, content_b64: str, password: Optional[str] = None
) -> dict:
    """
    Base64 variant of 'analyze'.
    """
    data = base64.b64decode(content_b64, validate=True)
    return _analyze_from_bytes("filename", filename, data, password)


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
