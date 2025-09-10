from __future__ import annotations
from typing import Dict, Any, List
from cryptography import x509
from keyprobe.crypto_utils import x509_cert_to_meta, x509_csr_to_meta

BEGIN_CERT = b"-----BEGIN CERTIFICATE-----"
END_CERT = b"-----END CERTIFICATE-----"
BEGIN_CSR1 = b"-----BEGIN CERTIFICATE REQUEST-----"
END_CSR1 = b"-----END CERTIFICATE REQUEST-----"
BEGIN_CSR2 = b"-----BEGIN NEW CERTIFICATE REQUEST-----"
END_CSR2 = b"-----END NEW CERTIFICATE REQUEST-----"

def _iter_blocks(data: bytes, begin: bytes, end: bytes) -> List[bytes]:
    blocks: List[bytes] = []
    i = 0
    while True:
        s = data.find(begin, i)
        if s == -1: break
        e = data.find(end, s)
        if e == -1: break
        e2 = e + len(end)
        blocks.append(data[s:e2])
        i = e2
    return blocks

def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "PEM"}

    # CERTS
    certs: List[Dict[str, Any]] = []
    for b in _iter_blocks(data, BEGIN_CERT, END_CERT):
        try:
            certs.append(x509_cert_to_meta(x509.load_pem_x509_certificate(b)))
        except Exception:
            continue
    if len(certs) == 1:
        out["x509"] = certs[0]
    elif len(certs) > 1:
        out["x509_chain"] = certs

    # CSR
    csrs_meta: List[Dict[str, Any]] = []
    for begin, end in ((BEGIN_CSR1, END_CSR1), (BEGIN_CSR2, END_CSR2)):
        for b in _iter_blocks(data, begin, end):
            try:
                csrs_meta.append(x509_csr_to_meta(x509.load_pem_x509_csr(b)))
            except Exception:
                continue
    if csrs_meta:
        # s'il n'y en a qu'un, renvoyer un objet ; sinon une liste
        out["csr"] = csrs_meta[0] if len(csrs_meta) == 1 else csrs_meta

    return out
