from typing import Dict, Any, List, Optional
from cryptography import x509

from ..x509meta import cert_to_meta, csr_to_meta, cert_warnings


def _try_cert(data: bytes) -> Optional[Dict[str, Any]]:
    try:
        m = cert_to_meta(x509.load_der_x509_certificate(data))
        warns = cert_warnings(m)
        out: Dict[str, Any] = {"x509": m}
        if warns:
            out["warnings"] = warns
        return out
    except Exception:
        return None


def _try_csr(data: bytes) -> Optional[Dict[str, Any]]:
    try:
        return {"csr": csr_to_meta(x509.load_der_x509_csr(data))}
    except Exception:
        return None


def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "DER"}
    cert_part = _try_cert(data)
    if cert_part:
        out.update(cert_part)
        return out
    csr_part = _try_csr(data)
    if csr_part:
        out.update(csr_part)
    return out
