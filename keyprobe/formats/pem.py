from __future__ import annotations
from typing import Dict, Any, List
from cryptography import x509
from keyprobe.crypto_utils import x509_cert_to_meta, x509_csr_to_meta

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    Encoding,
    PublicFormat,
)
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
import hashlib

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

def _iter_blocks(data: bytes, begin: bytes, end: bytes) -> List[bytes]:
    blocks: List[bytes] = []
    i = 0
    while True:
        s = data.find(begin, i)
        if s == -1:
            break
        e = data.find(end, s)
        if e == -1:
            break
        e2 = e + len(end)
        blocks.append(data[s:e2])
        i = e2
    return blocks

def _key_meta_from_obj(key) -> Dict[str, Any]:
    if isinstance(key, rsa.RSAPrivateKey) or isinstance(key, rsa.RSAPublicKey):
        return {"type": "RSA", "size": key.key_size}
    if isinstance(key, ec.EllipticCurvePrivateKey) or isinstance(key, ec.EllipticCurvePublicKey):
        return {"type": "EC", "curve": getattr(key.curve, "name", "EC")}
    if isinstance(key, ed25519.Ed25519PrivateKey) or isinstance(key, ed25519.Ed25519PublicKey):
        return {"type": "Ed25519"}
    if isinstance(key, ed448.Ed448PrivateKey) or isinstance(key, ed448.Ed448PublicKey):
        return {"type": "Ed448"}
    return {"type": key.__class__.__name__}

def _spki_fingerprint_sha256(pub) -> str:
    spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()

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
        out["csr"] = csrs_meta[0] if len(csrs_meta) == 1 else csrs_meta

    # PRIVATE KEYS (PKCS#8 unencrypted)
    keys: List[Dict[str, Any]] = []
    for b in _iter_blocks(data, BEGIN_PRIV_PKCS8, END_PRIV_PKCS8):
        try:
            k = load_pem_private_key(b, password=None)
            meta = _key_meta_from_obj(k)
            try:
                meta["fingerprint_spki_sha256"] = _spki_fingerprint_sha256(k.public_key())
            except Exception:
                pass
            keys.append({"kind": "private", "encrypted": False, "key": meta})
        except TypeError:
            # password required ⇒ shouldn’t happen in this block
            keys.append({"kind": "private", "encrypted": True})
        except Exception:
            continue

    # PRIVATE KEYS (PKCS#8 encrypted)
    for b in _iter_blocks(data, BEGIN_PRIV_ENC_PKCS8, END_PRIV_ENC_PKCS8):
        # pas de tentative de déchiffrement ici
        keys.append({"kind": "private", "encrypted": True})

    # PRIVATE KEYS (traditional RSA/EC) — si non chiffrées, cryptography sait charger ; si chiffrées → TypeError
    for begin, end in ((BEGIN_PRIV_RSA, END_PRIV_RSA), (BEGIN_PRIV_EC, END_PRIV_EC)):
        for b in _iter_blocks(data, begin, end):
            try:
                k = load_pem_private_key(b, password=None)
                meta = _key_meta_from_obj(k)
                try:
                    meta["fingerprint_spki_sha256"] = _spki_fingerprint_sha256(k.public_key())
                except Exception:
                    pass
                keys.append({"kind": "private", "encrypted": False, "key": meta})
            except TypeError:
                keys.append({"kind": "private", "encrypted": True})
            except Exception:
                continue

    # PUBLIC KEYS (SPKI)
    for b in _iter_blocks(data, BEGIN_PUB_SPKI, END_PUB_SPKI):
        try:
            k = load_pem_public_key(b)
            meta = _key_meta_from_obj(k)
            try:
                meta["fingerprint_spki_sha256"] = _spki_fingerprint_sha256(k)
            except Exception:
                pass
            keys.append({"kind": "public", "key": meta})
        except Exception:
            continue

    if keys:
        # si une seule clé, exposer 'key' pour rester proche de PKCS8 ; sinon 'keys'
        if len(keys) == 1:
            out["key"] = keys[0].get("key")
            if "encrypted" in keys[0]:
                out["encrypted"] = keys[0]["encrypted"]
            out["key_kind"] = keys[0]["kind"]
        else:
            out["keys"] = keys

    return out
