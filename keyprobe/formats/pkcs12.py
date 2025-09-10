import hashlib
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.serialization.pkcs12 import \
    load_key_and_certificates

from ..x509meta import cert_to_meta, cert_warnings


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _load(data: bytes, password: Optional[str]):
    pwd = None if password is None else password.encode("utf-8")
    return load_key_and_certificates(data, password=pwd)


def _cert_metas(cert, chain) -> List[Dict[str, Any]]:
    metas: List[Dict[str, Any]] = []
    if cert is not None:
        metas.append(cert_to_meta(cert))
    if chain:
        metas.extend(cert_to_meta(c) for c in chain)
    return metas


def _warn_for_chain(metas: List[Dict[str, Any]]) -> List[dict]:
    out: List[dict] = []
    for m in metas:
        out.extend(cert_warnings(m))
    return out


def _summarize_loaded(data: bytes, key, cert, chain) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "format": "PKCS12",
        "size": len(data),
        "digest_sha256": _sha256(data),
    }
    out: Dict[str, Any] = {**base, "encrypted": False, "has_key": key is not None}
    metas = _cert_metas(cert, chain)
    if not metas:
        return out
    if len(metas) == 1:
        out["x509"] = metas[0]
    else:
        out["x509_chain"] = metas
    warns = _warn_for_chain(metas)
    if warns:
        out["warnings"] = warns
    return out


def summarize(data: bytes) -> Dict[str, Any]:
    try:
        key, cert, chain = _load(data, None)
    except Exception:
        return {
            "format": "PKCS12",
            "size": len(data),
            "digest_sha256": _sha256(data),
            "encrypted": True,
        }
    return _summarize_loaded(data, key, cert, chain)


def summarize_with_password_bytes(data: bytes, password: str) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "format": "PKCS12",
        "size": len(data),
        "digest_sha256": _sha256(data),
    }
    try:
        key, cert, chain = _load(data, password)
    except Exception:
        return {**base, "encrypted": True, "error": "BadPasswordError"}
    return _summarize_loaded(data, key, cert, chain)
