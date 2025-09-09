# keyprobe/formats/pem.py
from __future__ import annotations
from typing import Dict, Any, List
from cryptography import x509
from keyprobe.crypto_utils import x509_cert_to_meta

BEGIN = b"-----BEGIN CERTIFICATE-----"
END = b"-----END CERTIFICATE-----"

def _iter_cert_blocks(data: bytes) -> List[bytes]:
    blocks: List[bytes] = []
    i = 0
    n_begin = len(BEGIN)
    n_end = len(END)
    while True:
        s = data.find(BEGIN, i)
        if s == -1:
            break
        e = data.find(END, s)
        if e == -1:
            break
        e2 = e + n_end
        block = data[s:e2]
        blocks.append(block)
        i = e2
    return blocks

def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "PEM"}
    blocks = _iter_cert_blocks(data)
    certs: List[Dict[str, Any]] = []
    for b in blocks:
        try:
            certs.append(x509_cert_to_meta(x509.load_pem_x509_certificate(b)))
        except Exception:
            continue
    if len(certs) == 1:
        out["x509"] = certs[0]
    elif len(certs) > 1:
        out["x509_chain"] = certs
    return out
