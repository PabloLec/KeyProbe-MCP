# keyprobe/format_identify.py
from __future__ import annotations
import re
from typing import Optional

_JKS_MAGIC = b"\xFE\xED\xFE\xED"

_PEM_BEGIN = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----")
_OPENSSH_PRIV = b"-----BEGIN OPENSSH PRIVATE KEY-----"
_OPENSSH_PUB_PREFIXES = (b"ssh-rsa ", b"ssh-ed25519 ", b"ecdsa-sha2-nistp256 ")

def guess_format(data: bytes, filename: Optional[str] = None) -> str:
    """
    Retourne une étiquette de format à haut niveau, sans parsing cryptographique.
    Valeurs possibles (pour l’instant) : 'PEM', 'PKCS7', 'OPENSSH', 'JKS', 'PKCS12', 'DER', 'UNKNOWN'
    """
    # OpenSSH
    if data.startswith(_OPENSSH_PRIV) or any(data.startswith(p) for p in _OPENSSH_PUB_PREFIXES):
        return "OPENSSH"

    # PEM (BEGIN ... END ...)
    m = _PEM_BEGIN.search(data[:4096])
    if m:
        label = m.group(1).decode("ascii", errors="ignore").strip()
        if "PKCS7" in label:
            return "PKCS7"
        return "PEM"

    # JKS (magic 0xFEEDFEED)
    if data.startswith(_JKS_MAGIC):
        return "JKS"

    # Indice d’extension pour PKCS12 (aide au dev, pas fiable à 100%)
    if filename and filename.lower().endswith((".p12", ".pfx")):
        return "PKCS12"

    # Binaire ASN.1 (DER/PKCS#12… — indéterminé ici)
    # 0x30 = SEQUENCE ; 0x02 = INTEGER ; c’est trop ambigu pour trancher proprement sans parsing
    if data[:1] in (b"\x30", b"\x02"):
        return "DER"

    return "UNKNOWN"
