# keyprobe/formats/pkcs8.py
from __future__ import annotations
from typing import Dict, Any, Optional

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_der_private_key,
    load_pem_public_key,
    load_der_public_key,
)
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448

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

def summarize(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "PKCS8"}
    # privé PEM
    try:
        k = load_pem_private_key(data, password=None)
        out["key"] = _key_meta_from_obj(k)
        out["encrypted"] = False
        return out
    except TypeError:
        out["encrypted"] = True  # indique généralement "password required"
        return out
    except ValueError:
        pass
    # privé DER
    try:
        k = load_der_private_key(data, password=None)
        out["key"] = _key_meta_from_obj(k)
        out["encrypted"] = False
        return out
    except TypeError:
        out["encrypted"] = True
        return out
    except ValueError:
        pass
    # public PEM
    try:
        k = load_pem_public_key(data)
        out["key"] = _key_meta_from_obj(k)
        return out
    except Exception:
        pass
    # public DER
    try:
        k = load_der_public_key(data)
        out["key"] = _key_meta_from_obj(k)
        return out
    except Exception:
        pass
    return out
