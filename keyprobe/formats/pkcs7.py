# keyprobe/formats/pkcs7.py
from __future__ import annotations
import warnings
from typing import Dict, Any, List
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_pem_pkcs7_certificates,
    load_der_pkcs7_certificates,
)
from keyprobe.crypto_utils import x509_cert_to_meta

def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "PKCS7"}
    certs: List = []
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            category=UserWarning,
            message=r"PKCS#7 certificates could not be parsed as DER, falling back to parsing as BER\.",
        )
        try:
            certs = load_pem_pkcs7_certificates(data)
        except Exception:
            try:
                certs = load_der_pkcs7_certificates(data)
            except Exception:
                certs = []
    if certs:
        out["x509_chain"] = [x509_cert_to_meta(c) for c in certs]
    return out
