import base64
import hashlib
from typing import Any, Dict, List, Optional, Tuple

MAGIC = b"openssh-key-v1\x00"


def _u32(buf: bytes, i: int) -> Tuple[int, int]:
    return int.from_bytes(buf[i : i + 4], "big"), i + 4


def _read_bytes(buf: bytes, i: int) -> Tuple[bytes, int]:
    ln, i = _u32(buf, i)
    return buf[i : i + ln], i + ln


def _fp_sha256(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode(
        "ascii"
    ).rstrip("=")


def _parse_public_line(line: bytes) -> Optional[Dict[str, Any]]:
    if not line or not line.startswith(
        (b"ssh-rsa ", b"ssh-ed25519 ", b"ecdsa-sha2-nistp256 ")
    ):
        return None
    parts = line.split(None, 2)
    algo = parts[0].decode("ascii", "ignore")
    blob_b64 = parts[1] if len(parts) > 1 else b""
    try:
        blob = base64.b64decode(blob_b64, validate=True)
        return {"type": algo, "fingerprint_sha256": _fp_sha256(blob)}
    except Exception:
        return {"type": algo}


def _read_private_blob(data: bytes) -> Optional[bytes]:
    try:
        b64 = b"".join(
            line for line in data.splitlines() if not line.startswith(b"-----")
        )
        blob = base64.b64decode(b64, validate=True)
        return blob if blob.startswith(MAGIC) else None
    except Exception:
        return None


def _parse_private_blob(blob: bytes) -> Dict[str, Any]:
    i = len(MAGIC)
    ciphername, i = _read_bytes(blob, i)
    kdfname, i = _read_bytes(blob, i)
    kdfopts, i = _read_bytes(blob, i)
    nkeys, i = _u32(blob, i)

    pub_fp = None
    try:
        if nkeys >= 1:
            pub_blob, _ = _read_bytes(blob, i)
            pub_fp = _fp_sha256(pub_blob)
    except Exception:
        pass

    encrypted = ciphername != b"none"
    priv: Dict[str, Any] = {
        "cipher": ciphername.decode("utf-8", "replace"),
        "encrypted": encrypted,
    }
    if kdfname:
        kdf = kdfname.decode("utf-8", "replace")
        priv["kdf"] = kdf
        if kdf == "bcrypt":
            try:
                j = 0
                salt, j = _read_bytes(kdfopts, j)
                rounds, _ = _u32(kdfopts, j)
                priv["kdf_opts"] = {
                    "salt_b64": base64.b64encode(salt).decode("ascii"),
                    "rounds": rounds,
                }
            except Exception:
                pass
    if pub_fp:
        priv["public_fingerprint_sha256"] = pub_fp
    return priv


def _warnings_for_private(priv: Dict[str, Any]) -> List[dict]:
    warns: List[dict] = []
    if not priv.get("encrypted"):
        warns.append(
            {
                "code": "OPENSSH_UNENCRYPTED_KEY",
                "message": "OpenSSH private key is unencrypted",
                "severity": "warn",
            }
        )
    if priv.get("kdf") == "bcrypt":
        rounds = int(priv.get("kdf_opts", {}).get("rounds", 0))
        if rounds and rounds < 16:
            warns.append(
                {
                    "code": "OPENSSH_LOW_BCRYPT_ROUNDS",
                    "message": f"bcrypt rounds={rounds} look low",
                    "severity": "warn",
                }
            )
    return warns


def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "OPENSSH"}

    pub = _parse_public_line(data.splitlines()[0] if data else b"")
    if pub:
        out["public"] = pub
        return out

    blob = _read_private_blob(data)
    if not blob:
        return out

    priv = _parse_private_blob(blob)
    out["private"] = priv
    warns = _warnings_for_private(priv)
    if warns:
        out["warnings"] = warns
    return out
