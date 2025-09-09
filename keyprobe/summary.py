# keyprobe/summary.py
from __future__ import annotations
from typing import Dict, Any, Optional

from .format_identify import guess_format
from .crypto_utils import sha256_hex

from .formats import pem as fmt_pem
from .formats import der as fmt_der
from .formats import pkcs7 as fmt_pkcs7
from .formats import pkcs12 as fmt_pkcs12
from .formats import pkcs8 as fmt_pkcs8
from .formats import openssh as fmt_openssh
from .formats import jks as fmt_jks

def summarize_bytes(data: bytes, filename: Optional[str] = None) -> Dict[str, Any]:
    fmt = guess_format(data, filename=filename)
    base: Dict[str, Any] = {
        "format": fmt,
        "size": len(data),
        "digest_sha256": sha256_hex(data),
    }

    if fmt == "PEM":
        res_pem = fmt_pem.summarize(data)
        base.update(res_pem)
        if not any(k in res_pem for k in ("x509", "x509_chain")):
            res8 = fmt_pkcs8.summarize(data)
            if any(k in res8 for k in ("key", "encrypted")):
                base["format"] = "PKCS8"
                base.update(res8)
            else:
                res7 = fmt_pkcs7.summarize(data)
                if "x509_chain" in res7:
                    base["format"] = "PKCS7"
                    base.update(res7)
        return base

    if fmt == "DER":
        res7 = fmt_pkcs7.summarize(data)
        if "x509_chain" in res7:
            base["format"] = "PKCS7"
            base.update(res7)
            return base
        base.update(fmt_der.summarize(data))
        return base

    if fmt == "PKCS7":
        base.update(fmt_pkcs7.summarize(data))
        return base

    if fmt == "PKCS12":
        base.update(fmt_pkcs12.summarize(data))
        return base

    if fmt == "PKCS8":
        base.update(fmt_pkcs8.summarize(data))
        return base

    if fmt == "OPENSSH":
        base.update(fmt_openssh.summarize(data))
        return base

    if fmt == "JKS":
        base.update(fmt_jks.summarize(data))
        return base

    return base
