from __future__ import annotations
from typing import Dict, Any, List
import hashlib

from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from keyprobe.crypto_utils import x509_cert_to_meta


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "format": "PKCS12",
        "size": len(data),
        "digest_sha256": _sha256_hex(data),
    }
    try:
        key, cert, chain = load_key_and_certificates(data, password=None)
    except Exception:
        out["encrypted"] = True
        return out

    out["encrypted"] = False
    out["has_key"] = key is not None

    certs: List[Dict[str, Any]] = []
    if cert is not None:
        certs.append(x509_cert_to_meta(cert))
    if chain:
        certs.extend(x509_cert_to_meta(c) for c in chain)

    if len(certs) == 1:
        out["x509"] = certs[0]
    elif len(certs) > 1:
        out["x509_chain"] = certs
    return out


def summarize_with_password_bytes(data: bytes, password: str) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "format": "PKCS12",
        "size": len(data),
        "digest_sha256": _sha256_hex(data),
    }
    try:
        key, cert, chain = load_key_and_certificates(data, password=password.encode("utf-8"))
    except Exception:
        return {**base, "encrypted": True, "error": "BadPasswordError"}

    out: Dict[str, Any] = {**base, "encrypted": False, "has_key": key is not None}

    certs: List[Dict[str, Any]] = []
    if cert is not None:
        certs.append(x509_cert_to_meta(cert))
    if chain:
        certs.extend(x509_cert_to_meta(c) for c in chain)

    if len(certs) == 1:
        out["x509"] = certs[0]
    elif len(certs) > 1:
        out["x509_chain"] = certs
    return out
