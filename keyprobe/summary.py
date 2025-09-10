from typing import Dict, Any, Optional, Callable, List

from .format_identify import guess_format
from .common import sha256_hex

from .formats import pem as fmt_pem
from .formats import der as fmt_der
from .formats import pkcs7 as fmt_pkcs7
from .formats import pkcs12 as fmt_pkcs12
from .formats import pkcs8 as fmt_pkcs8
from .formats import openssh as fmt_openssh
from .formats import jks as fmt_jks


def _merge_warnings(dest: Dict[str, Any], *srcs: Dict[str, Any]) -> None:
    warnings: List[dict] = []
    if "warnings" in dest:
        warnings.extend(dest["warnings"])
    for s in srcs:
        if "warnings" in s:
            warnings.extend(s["warnings"])
    if not warnings:
        return
    seen = set()
    deduped = []
    for w in warnings:
        key = (w.get("code"), w.get("message"), w.get("severity"))
        if key not in seen:
            seen.add(key)
            deduped.append(w)
    dest["warnings"] = deduped


Handler = Callable[[bytes, Optional[str], Optional[str]], Dict[str, Any]]

def _handle_pem(data: bytes, _password: Optional[str], _filename: Optional[str]) -> Dict[str, Any]:
    res = fmt_pem.summarize(data)

    has_cert_or_csr = any(k in res for k in ("x509", "x509_chain", "csr"))
    has_keys_only = ("keys" in res) and not has_cert_or_csr
    if has_keys_only:
        res8 = fmt_pkcs8.summarize(data)
        if any(k in res8 for k in ("key", "encrypted")):
            return {"format": "PKCS8", **res8}
    return res


def _handle_der(data: bytes, _password: Optional[str], _filename: Optional[str]) -> Dict[str, Any]:
    res7 = fmt_pkcs7.summarize(data)
    if "x509_chain" in res7:
        return {"format": "PKCS7", **res7}
    return fmt_der.summarize(data)


def _handle_pkcs7(data: bytes, _password: Optional[str], _filename: Optional[str]) -> Dict[str, Any]:
    return fmt_pkcs7.summarize(data)


def _handle_pkcs12(data: bytes, password: Optional[str], _filename: Optional[str]) -> Dict[str, Any]:
    return (
        fmt_pkcs12.summarize_with_password_bytes(data, password)
        if password
        else fmt_pkcs12.summarize(data)
    )


def _handle_pkcs8(data: bytes, _password: Optional[str], _filename: Optional[str]) -> Dict[str, Any]:
    return fmt_pkcs8.summarize(data)


def _handle_openssh(data: bytes, _password: Optional[str], _filename: Optional[str]) -> Dict[str, Any]:
    return fmt_openssh.summarize(data)


def _handle_jks(data: bytes, password: Optional[str], _filename: Optional[str]) -> Dict[str, Any]:
    return (
        fmt_jks.summarize_with_password_bytes(data, password)
        if password
        else fmt_jks.summarize(data)
    )


_HANDLERS: Dict[str, Handler] = {
    "PEM": _handle_pem,
    "DER": _handle_der,
    "PKCS7": _handle_pkcs7,
    "PKCS12": _handle_pkcs12,
    "PKCS8": _handle_pkcs8,
    "OPENSSH": _handle_openssh,
    "JKS": _handle_jks,
}

def summarize_bytes(
    data: bytes,
    filename: Optional[str] = None,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    fmt = guess_format(data, filename=filename)
    base: Dict[str, Any] = {"format": fmt, "size": len(data), "digest_sha256": sha256_hex(data)}

    handler = _HANDLERS.get(fmt)
    if not handler:
        return base

    res = handler(data, password, filename)
    # Authorize an override of "format" by the handler (e.g., PEM -> PKCS8)
    base.update(res)
    _merge_warnings(base, res)
    return base
