from __future__ import annotations
import base64
import hashlib
from typing import Dict, Any

MAGIC = b"openssh-key-v1\x00"

def _read_u32(buf: bytes, i: int) -> tuple[int, int]:
    return int.from_bytes(buf[i:i+4], "big"), i + 4

def _read_string(buf: bytes, i: int) -> tuple[bytes, int]:
    ln, i = _read_u32(buf, i)
    return buf[i:i+ln], i + ln

def _ssh_fingerprint_sha256(blob: bytes) -> str:
    digest = hashlib.sha256(blob).digest()
    b64 = base64.b64encode(digest).decode("ascii")
    return "SHA256:" + b64.rstrip("=")

def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "OPENSSH"}

    # Public key line
    first_line = data.splitlines()[0] if data else b""
    if first_line.startswith((b"ssh-rsa ", b"ssh-ed25519 ", b"ecdsa-sha2-nistp256 ")):
        parts = first_line.split(None, 2)
        algo = parts[0].decode("ascii", "ignore")
        blob_b64 = parts[1] if len(parts) > 1 else b""
        try:
            blob = base64.b64decode(blob_b64, validate=True)
            out["public"] = {"type": algo, "fingerprint_sha256": _ssh_fingerprint_sha256(blob)}
        except Exception:
            out["public"] = {"type": algo}
        return out

    # Private key block (openssh-key-v1)
    try:
        b64 = b"".join(line for line in data.splitlines() if not line.startswith(b"-----"))
        blob = base64.b64decode(b64, validate=True)
        if not blob.startswith(MAGIC):
            return out
        i = len(MAGIC)
        ciphername, i = _read_string(blob, i)
        kdfname, i = _read_string(blob, i)
        kdfopts, i = _read_string(blob, i)
        nkeys, i = _read_u32(blob, i)
        pub_fp = None
        try:
            if nkeys >= 1:
                pub_blob, i = _read_string(blob, i)
                pub_fp = _ssh_fingerprint_sha256(pub_blob)
        except Exception:
            pass
        enc = ciphername != b"none"
        priv = {"cipher": ciphername.decode("utf-8", "replace"), "encrypted": enc}
        if pub_fp:
            priv["public_fingerprint_sha256"] = pub_fp
        out["private"] = priv
        return out
    except Exception:
        return out
