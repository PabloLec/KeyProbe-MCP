from __future__ import annotations
from typing import Dict, Any

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_der_private_key,
    load_pem_public_key,
    load_der_public_key,
    Encoding, PublicFormat,
)
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
import hashlib

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

def _spki_fingerprint_sha256_from_public(pub) -> str:
    spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()

def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "PKCS8"}

    # Private PEM
    try:
        k = load_pem_private_key(data, password=None)
        out["key"] = _key_meta_from_obj(k)
        out["encrypted"] = False
        try:
            out["key"]["fingerprint_spki_sha256"] = _spki_fingerprint_sha256_from_public(k.public_key())
        except Exception:
            pass
        return out
    except TypeError:
        out["encrypted"] = True
        return out
    except ValueError:
        pass

    # Private DER
    try:
        k = load_der_private_key(data, password=None)
        out["key"] = _key_meta_from_obj(k)
        out["encrypted"] = False
        try:
            out["key"]["fingerprint_spki_sha256"] = _spki_fingerprint_sha256_from_public(k.public_key())
        except Exception:
            pass
        return out
    except TypeError:
        out["encrypted"] = True
        return out
    except ValueError:
        pass

    # Public PEM
    try:
        k = load_pem_public_key(data)
        out["key"] = _key_meta_from_obj(k)
        try:
            out["key"]["fingerprint_spki_sha256"] = _spki_fingerprint_sha256_from_public(k)
        except Exception:
            pass
        return out
    except Exception:
        pass

    # Public DER
    try:
        k = load_der_public_key(data)
        out["key"] = _key_meta_from_obj(k)
        try:
            out["key"]["fingerprint_spki_sha256"] = _spki_fingerprint_sha256_from_public(k)
        except Exception:
            pass
        return out
    except Exception:
        pass

    return out
