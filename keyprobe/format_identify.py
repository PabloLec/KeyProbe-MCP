import re
from typing import Optional

_JKS_MAGIC = b"\xfe\xed\xfe\xed"
_PEM_BEGIN = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----")
_OPENSSH_PRIV = b"-----BEGIN OPENSSH PRIVATE KEY-----"
_OPENSSH_PUB_PREFIXES = (b"ssh-rsa ", b"ssh-ed25519 ", b"ecdsa-sha2-nistp256 ")


def guess_format(data: bytes, filename: Optional[str] = None) -> str:
    if data.startswith(_OPENSSH_PRIV) or any(
        data.startswith(p) for p in _OPENSSH_PUB_PREFIXES
    ):
        return "OPENSSH"
    if _PEM_BEGIN.search(data[:4096]):
        label = _PEM_BEGIN.search(data[:4096]).group(1).decode("ascii", "ignore")
        if "PKCS7" in label:
            return "PKCS7"
        return "PEM"
    if data.startswith(_JKS_MAGIC):
        return "JKS"
    if filename and filename.lower().endswith((".p12", ".pfx")):
        return "PKCS12"
    if data[:1] in (b"\x30", b"\x02"):
        return "DER"
    return "UNKNOWN"
