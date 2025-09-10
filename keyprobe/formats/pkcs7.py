import warnings
from typing import Dict, Any, List

from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_pem_pkcs7_certificates,
    load_der_pkcs7_certificates,
)

from ..x509meta import cert_to_meta, cert_warnings


def _load_certs(data: bytes):
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            category=UserWarning,
            message=r"PKCS#7 certificates could not be parsed as DER, falling back to parsing as BER\.",
        )
        try:
            return load_pem_pkcs7_certificates(data)
        except Exception:
            try:
                return load_der_pkcs7_certificates(data)
            except Exception:
                return []


def _metas_and_warnings(certs) -> tuple[List[Dict[str, Any]], List[dict]]:
    metas = [cert_to_meta(c) for c in certs]
    warns: List[dict] = []
    for m in metas:
        warns.extend(cert_warnings(m))
    return metas, warns


def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "PKCS7"}
    certs = _load_certs(data)
    if not certs:
        return out
    metas, warns = _metas_and_warnings(certs)
    out["x509_chain"] = metas
    if warns:
        out["warnings"] = warns
    return out
