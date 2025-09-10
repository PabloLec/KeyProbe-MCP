from typing import Dict, Any, Optional, List
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_der_private_key,
    load_pem_public_key,
    load_der_public_key,
    Encoding,
    PublicFormat,
)

from pyasn1.codec.der import decoder as der_decoder
from pyasn1_modules import rfc5208, rfc8018


def _spki_sha256(pub) -> str:
    spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def _key_meta(key) -> Dict[str, Any]:
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        meta: Dict[str, Any] = {"type": "RSA", "size": key.key_size}
        try:
            nums = key.public_key().public_numbers() if hasattr(key, "public_key") else key.public_numbers()
            meta["public_exponent"] = getattr(nums, "e", None)
        except Exception:
            pass
        return meta
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return {"type": "EC", "curve": getattr(key.curve, "name", "EC")}
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return {"type": "Ed25519"}
    if isinstance(key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return {"type": "Ed448"}
    return {"type": key.__class__.__name__}


_PEM_BEGIN_ENC = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
_PEM_END_ENC = b"-----END ENCRYPTED PRIVATE KEY-----"

_PBES1_NAMES = {
    "1.2.840.113549.1.5.3": "pbeWithMD5AndDES-CBC",
    "1.2.840.113549.1.5.6": "pbeWithMD5AndRC2-CBC",
    "1.2.840.113549.1.5.10": "pbeWithSHA1AndDES-CBC",
    "1.2.840.113549.1.5.11": "pbeWithSHA1AndRC2-CBC",
}
_PRF_NAMES = {
    "1.2.840.113549.2.7": "hmacWithSHA1",
    "1.2.840.113549.2.8": "hmacWithSHA224",
    "1.2.840.113549.2.9": "hmacWithSHA256",
    "1.2.840.113549.2.10": "hmacWithSHA384",
    "1.2.840.113549.2.11": "hmacWithSHA512",
}
_CIPHER_NAMES = {
    "1.2.840.113549.3.7": "des-EDE3-CBC",
    "2.16.840.1.101.3.4.1.2": "aes-128-cbc",
    "2.16.840.1.101.3.4.1.22": "aes-192-cbc",
    "2.16.840.1.101.3.4.1.42": "aes-256-cbc",
}
_PBES2_OID = "1.2.840.113549.1.5.13"
_PBKDF2_OID = "1.2.840.113549.1.5.12"


def _extract_epki_der_from_pem(data: bytes) -> Optional[bytes]:
    s = data.find(_PEM_BEGIN_ENC)
    if s == -1:
        return None
    e = data.find(_PEM_END_ENC, s)
    if e == -1:
        return None
    block = data[s:e].splitlines()[1:]
    b64 = b"".join(line.strip() for line in block if not line.startswith(b"-"))
    try:
        return base64.b64decode(b64, validate=True)
    except Exception:
        return None


def _parse_epki_params(der: bytes) -> Optional[Dict[str, Any]]:
    try:
        epki, _ = der_decoder.decode(der, asn1Spec=rfc5208.EncryptedPrivateKeyInfo())
    except Exception:
        return None

    algo_oid = ".".join(str(x) for x in epki["encryptionAlgorithm"]["algorithm"].asTuple())
    info: Dict[str, Any] = {"algorithm_oid": algo_oid}

    if algo_oid == _PBES2_OID:
        try:
            params, _ = der_decoder.decode(epki["encryptionAlgorithm"]["parameters"], asn1Spec=rfc8018.PBES2_params())
            kdf = params["keyDerivationFunc"]
            kdf_oid = ".".join(str(x) for x in kdf["algorithm"].asTuple())
            kdf_info: Dict[str, Any] = {"oid": kdf_oid}
            if kdf_oid == _PBKDF2_OID:
                pbkdf2, _ = der_decoder.decode(kdf["parameters"], asn1Spec=rfc8018.PBKDF2_params())
                salt = bytes(pbkdf2["salt"]["specified"]) if pbkdf2["salt"].getName() == "specified" else b""
                iters = int(pbkdf2["iterationCount"])
                prf_oid = "1.2.840.113549.2.7"
                if pbkdf2["prf"].isValue:
                    prf_oid = ".".join(str(x) for x in pbkdf2["prf"]["algorithm"].asTuple())
                kdf_info.update(
                    {"name": "pbkdf2", "iterations": iters, "salt_b64": base64.b64encode(salt).decode("ascii"),
                     "prf": _PRF_NAMES.get(prf_oid, prf_oid), "prf_oid": prf_oid}
                )
            enc = params["encryptionScheme"]
            enc_oid = ".".join(str(x) for x in enc["algorithm"].asTuple())
            cipher_name = _CIPHER_NAMES.get(enc_oid, enc_oid)
            iv_b64: Optional[str] = None
            try:
                iv_b64 = base64.b64encode(bytes(enc["parameters"])).decode("ascii")
            except Exception:
                pass
            info["kdf"] = kdf_info
            info["cipher"] = {"name": cipher_name, "oid": enc_oid, "iv_b64": iv_b64}
            info["algorithm"] = "pbes2"
            return info
        except Exception:
            info["algorithm"] = "pbes2"
            return info

    info["algorithm"] = _PBES1_NAMES.get(algo_oid, algo_oid)
    return info


def _encryption_warnings(info: Dict[str, Any]) -> List[dict]:
    warns: List[dict] = []
    alg = (info.get("algorithm") or "").lower()
    if "pbe" in alg and "pbes2" not in alg:
        warns.append({"code": "PKCS8_PBES1_WEAK", "message": "PKCS#5 v1 (PBES1) is outdated", "severity": "warn"})
    cipher = (info.get("cipher", {}).get("name") or "").lower()
    if cipher in {"des-ede3-cbc"}:
        warns.append({"code": "PKCS8_3DES", "message": "3DES in use", "severity": "warn"})
    kdf = info.get("kdf") or {}
    if kdf.get("name") == "pbkdf2":
        try:
            iters = int(kdf.get("iterations", 0))
            if iters and iters < 100_000:
                warns.append({"code": "PKCS8_PBKDF2_LOW_ITER", "message": f"PBKDF2 iterations={iters} look low", "severity": "warn"})
            prf = (kdf.get("prf") or "").lower()
            if prf in {"hmacwithsha1", "sha1"}:
                warns.append({"code": "PKCS8_PBKDF2_SHA1", "message": "PBKDF2 PRF is HMAC-SHA1", "severity": "warn"})
        except Exception:
            pass
    return warns


def _analyze_encrypted(data: bytes) -> Optional[Dict[str, Any]]:
    der = _extract_epki_der_from_pem(data) or data
    info = _parse_epki_params(der)
    if not info:
        return None
    out: Dict[str, Any] = {"encrypted": True, "encryption": info}
    warns = _encryption_warnings(info)
    if warns:
        out["warnings"] = warns
    return out


def _summarize_private(key) -> Dict[str, Any]:
    meta = _key_meta(key)
    try:
        meta["fingerprint_spki_sha256"] = _spki_sha256(key.public_key())
    except Exception:
        pass
    out: Dict[str, Any] = {"format": "PKCS8", "key": meta, "encrypted": False}
    if meta.get("type") == "RSA":
        try:
            if int(meta.get("size", 0)) < 2048:
                out["warnings"] = [{"code": "RSA_WEAK_KEY", "message": "RSA key size < 2048", "severity": "warn"}]
        except Exception:
            pass
    return out


def _try_private_pem(data: bytes) -> Optional[Dict[str, Any]]:
    try:
        return _summarize_private(load_pem_private_key(data, password=None))
    except TypeError:
        det = _analyze_encrypted(data)
        return {"format": "PKCS8", **det} if det else {"format": "PKCS8", "encrypted": True}
    except ValueError:
        return None


def _try_private_der(data: bytes) -> Optional[Dict[str, Any]]:
    try:
        return _summarize_private(load_der_private_key(data, password=None))
    except TypeError:
        det = _analyze_encrypted(data)
        return {"format": "PKCS8", **det} if det else {"format": "PKCS8", "encrypted": True}
    except ValueError:
        return None


def _try_public_pem(data: bytes) -> Optional[Dict[str, Any]]:
    try:
        k = load_pem_public_key(data)
        meta = _key_meta(k)
        try:
            meta["fingerprint_spki_sha256"] = _spki_sha256(k)
        except Exception:
            pass
        return {"format": "PKCS8", "key": meta}
    except Exception:
        return None


def _try_public_der(data: bytes) -> Optional[Dict[str, Any]]:
    try:
        k = load_der_public_key(data)
        meta = _key_meta(k)
        try:
            meta["fingerprint_spki_sha256"] = _spki_sha256(k)
        except Exception:
            pass
        return {"format": "PKCS8", "key": meta}
    except Exception:
        return None


def summarize(data: bytes) -> Dict[str, Any]:
    for fn in (_try_private_pem, _try_private_der, _try_public_pem, _try_public_der):
        res = fn(data)
        if res:
            return res
    return {"format": "PKCS8"}
