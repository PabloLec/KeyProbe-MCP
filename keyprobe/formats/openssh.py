# keyprobe/formats/openssh.py
from __future__ import annotations
import base64
from typing import Dict, Any

MAGIC = b"openssh-key-v1\x00"

def _read_u32(buf: bytes, i: int) -> tuple[int, int]:
    return int.from_bytes(buf[i:i+4], "big"), i + 4

def _read_string(buf: bytes, i: int) -> tuple[bytes, int]:
    ln, i = _read_u32(buf, i)
    return buf[i:i+ln], i + ln

def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "OPENSSH"}

    first_line = data.splitlines()[0] if data else b""
    if first_line.startswith((b"ssh-rsa ", b"ssh-ed25519 ", b"ecdsa-sha2-nistp256 ")):
        algo = first_line.split(b" ", 1)[0].decode("ascii", "ignore")
        out["public"] = {"type": algo}
        return out

    # bloc privé v1
    try:
        b64 = b"".join(line for line in data.splitlines() if not line.startswith(b"-----"))
        blob = base64.b64decode(b64, validate=True)
        if not blob.startswith(MAGIC):
            return out
        i = len(MAGIC)
        ciphername, i = _read_string(blob, i)
        kdfname, i = _read_string(blob, i)
        kdfopts, i = _read_string(blob, i)
        # nkeys, pubkeys… (inutile ici pour savoir si chiffré)
        enc = ciphername != b"none"
        out["private"] = {"cipher": ciphername.decode("utf-8", "replace"), "encrypted": enc}
        return out
    except Exception:
        return out
