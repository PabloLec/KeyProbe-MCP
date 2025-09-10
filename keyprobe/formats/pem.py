from typing import Dict, Any, List
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    Encoding,
    PublicFormat,
)

from ..x509meta import cert_to_meta, csr_to_meta, cert_warnings


BEGIN_CERT = b"-----BEGIN CERTIFICATE-----"
END_CERT = b"-----END CERTIFICATE-----"
BEGIN_CSR1 = b"-----BEGIN CERTIFICATE REQUEST-----"
END_CSR1 = b"-----END CERTIFICATE REQUEST-----"
BEGIN_CSR2 = b"-----BEGIN NEW CERTIFICATE REQUEST-----"
END_CSR2 = b"-----END NEW CERTIFICATE REQUEST-----"
BEGIN_PRIV_PKCS8 = b"-----BEGIN PRIVATE KEY-----"
END_PRIV_PKCS8 = b"-----END PRIVATE KEY-----"
BEGIN_PRIV_ENC_PKCS8 = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
END_PRIV_ENC_PKCS8 = b"-----END ENCRYPTED PRIVATE KEY-----"
BEGIN_PRIV_RSA = b"-----BEGIN RSA PRIVATE KEY-----"
END_PRIV_RSA = b"-----END RSA PRIVATE KEY-----"
BEGIN_PRIV_EC = b"-----BEGIN EC PRIVATE KEY-----"
END_PRIV_EC = b"-----END EC PRIVATE KEY-----"
BEGIN_PUB_SPKI = b"-----BEGIN PUBLIC KEY-----"
END_PUB_SPKI = b"-----END PUBLIC KEY-----"


def _blocks(data: bytes, begin: bytes, end: bytes) -> List[bytes]:
    out: List[bytes] = []
    i = 0
    while True:
        s = data.find(begin, i)
        if s == -1:
            break
        e = data.find(end, s)
        if e == -1:
            break
        j = e + len(end)
        out.append(data[s:j])
        i = j
    return out


def _spki_sha256(pub) -> str:
    spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    import hashlib as _h
    return _h.sha256(spki).hexdigest()


def _key_meta(key) -> Dict[str, Any]:
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return {"type": "RSA", "size": key.key_size}
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return {"type": "EC", "curve": getattr(key.curve, "name", "EC")}
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return {"type": "Ed25519"}
    if isinstance(key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return {"type": "Ed448"}
    return {"type": key.__class__.__name__}


def _parse_certs(data: bytes) -> tuple[List[Dict[str, Any]], List[dict]]:
    metas: List[Dict[str, Any]] = []
    warns: List[dict] = []
    for b in _blocks(data, BEGIN_CERT, END_CERT):
        try:
            m = cert_to_meta(x509.load_pem_x509_certificate(b))
            metas.append(m)
            warns.extend(cert_warnings(m))
        except Exception:
            continue
    return metas, warns


def _parse_csrs(data: bytes) -> List[Dict[str, Any]]:
    metas: List[Dict[str, Any]] = []
    for begin, end in ((BEGIN_CSR1, END_CSR1), (BEGIN_CSR2, END_CSR2)):
        for b in _blocks(data, begin, end):
            try:
                metas.append(csr_to_meta(x509.load_pem_x509_csr(b)))
            except Exception:
                continue
    return metas


def _parse_private_blocks(data: bytes) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for b in _blocks(data, BEGIN_PRIV_PKCS8, END_PRIV_PKCS8):
        try:
            k = load_pem_private_key(b, password=None)
            meta = _key_meta(k)
            try:
                meta["fingerprint_spki_sha256"] = _spki_sha256(k.public_key())
            except Exception:
                pass
            out.append({"kind": "private", "encrypted": False, "key": meta})
        except TypeError:
            out.append({"kind": "private", "encrypted": True})
        except Exception:
            continue

    for _ in _blocks(data, BEGIN_PRIV_ENC_PKCS8, END_PRIV_ENC_PKCS8):
        out.append({"kind": "private", "encrypted": True})

    for begin, end in ((BEGIN_PRIV_RSA, END_PRIV_RSA), (BEGIN_PRIV_EC, END_PRIV_EC)):
        for b in _blocks(data, begin, end):
            try:
                k = load_pem_private_key(b, password=None)
                meta = _key_meta(k)
                try:
                    meta["fingerprint_spki_sha256"] = _spki_sha256(k.public_key())
                except Exception:
                    pass
                out.append({"kind": "private", "encrypted": False, "key": meta})
            except TypeError:
                out.append({"kind": "private", "encrypted": True})
            except Exception:
                continue

    return out


def _parse_public_blocks(data: bytes) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for b in _blocks(data, BEGIN_PUB_SPKI, END_PUB_SPKI):
        try:
            k = load_pem_public_key(b)
            meta = _key_meta(k)
            try:
                meta["fingerprint_spki_sha256"] = _spki_sha256(k)
            except Exception:
                pass
            out.append({"kind": "public", "key": meta})
        except Exception:
            continue
    return out


def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "PEM"}

    certs, warns = _parse_certs(data)
    if len(certs) == 1:
        out["x509"] = certs[0]
    elif len(certs) > 1:
        out["x509_chain"] = certs

    csrs = _parse_csrs(data)
    if csrs:
        out["csr"] = csrs[0] if len(csrs) == 1 else csrs

    keys = _parse_private_blocks(data) + _parse_public_blocks(data)
    if keys:
        out["keys"] = keys

    if warns:
        out["warnings"] = warns
    return out
