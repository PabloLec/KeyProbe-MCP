# keyprobe/formats/pkcs12.py
from __future__ import annotations
from typing import Dict, Any, List, Optional
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from keyprobe.crypto_utils import x509_cert_to_meta

def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "PKCS12"}
    try:
        key, cert, chain = load_key_and_certificates(data, password=None)
    except Exception:
        # très probablement protégé par mot de passe ou format inattendu
        out["encrypted"] = True
        return out

    out["encrypted"] = False
    certs: List[Dict[str, Any]] = []
    if cert is not None:
        certs.append(x509_cert_to_meta(cert))
    if chain:
        certs.extend(x509_cert_to_meta(c) for c in chain)
    if certs:
        if len(certs) == 1:
            out["x509"] = certs[0]
        else:
            out["x509_chain"] = certs
    return out