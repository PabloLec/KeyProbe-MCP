# keyprobe/formats/der.py (pour rappel)
from __future__ import annotations
from typing import Dict, Any
from cryptography import x509
from keyprobe.crypto_utils import x509_cert_to_meta

def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "DER"}
    try:
        out["x509"] = x509_cert_to_meta(x509.load_der_x509_certificate(data))
    except Exception:
        pass
    return out
