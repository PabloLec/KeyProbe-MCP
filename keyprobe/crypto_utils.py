# keyprobe/crypto_utils.py
from __future__ import annotations

import datetime as dt
import hashlib
from typing import Any, Dict, List, Optional, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID as EKUOID, NameOID


# ---------------------------
# Common helpers
# ---------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iso_utc(d: dt.datetime) -> str:
    # cryptography renvoie souvent des datetime naïves (UTC) → normalisons en Z
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _name_to_cn(name: x509.Name) -> Optional[str]:
    try:
        return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value  # type: ignore[index]
    except (x509.ExtensionNotFound, Exception):
        return None


def _rfc4514(name: x509.Name) -> str:
    return name.rfc4514_string()


def _public_key_info(cert: x509.Certificate) -> Dict[str, Any]:
    pk = cert.public_key()
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        if isinstance(pk, rsa.RSAPublicKey):
            return {"type": "RSA", "size": pk.key_size}
    except Exception:
        pass

    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        if isinstance(pk, ec.EllipticCurvePublicKey):
            return {"type": "EC", "curve": getattr(pk.curve, "name", "EC")}
    except Exception:
        pass

    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
        if isinstance(pk, ed25519.Ed25519PublicKey):
            return {"type": "Ed25519"}
        if isinstance(pk, ed448.Ed448PublicKey):
            return {"type": "Ed448"}
    except Exception:
        pass

    return {"type": pk.__class__.__name__}


def _san_list(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = cast(x509.SubjectAlternativeName, ext.value)
    except x509.ExtensionNotFound:
        return []

    out: List[str] = []
    for g in san:
        if isinstance(g, x509.DNSName):
            out.append(g.value)
        elif isinstance(g, x509.IPAddress):
            out.append(str(g.value))
    return out


# keyprobe/crypto_utils.py (remplace les fonctions concernées)

def _key_usage(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        ku = cast(x509.KeyUsage, ext.value)
    except x509.ExtensionNotFound:
        return []

    names: List[str] = []
    if ku.digital_signature: names.append("digitalSignature")
    if ku.content_commitment: names.append("contentCommitment")
    if ku.key_encipherment: names.append("keyEncipherment")
    if ku.data_encipherment: names.append("dataEncipherment")
    if ku.key_agreement:
        names.append("keyAgreement")
        if ku.encipher_only: names.append("encipherOnly")
        if ku.decipher_only: names.append("decipherOnly")
    if ku.key_cert_sign: names.append("keyCertSign")
    if ku.crl_sign: names.append("cRLSign")
    return names

def x509_cert_to_meta(cert: x509.Certificate) -> Dict[str, Any]:
    # compat cryptography>=43 (propriétés *_utc)
    if hasattr(cert, "not_valid_before_utc"):
        nb = cert.not_valid_before_utc  # type: ignore[attr-defined]
    else:
        nb = cert.not_valid_before.replace(tzinfo=dt.timezone.utc)

    if hasattr(cert, "not_valid_after_utc"):
        na = cert.not_valid_after_utc  # type: ignore[attr-defined]
    else:
        na = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)

    return {
        "subject_dn": _rfc4514(cert.subject),
        "issuer_dn": _rfc4514(cert.issuer),
        "subject_cn": _name_to_cn(cert.subject),
        "issuer_cn": _name_to_cn(cert.issuer),
        "not_before": _iso_utc(nb),
        "not_after": _iso_utc(na),
        "public_key": _public_key_info(cert),
        "signature_hash": _sig_hash_name(cert),
        "san": _san_list(cert),
        "key_usage": _key_usage(cert),
        "eku": _eku_list(cert),
        "serial_number": str(cert.serial_number),
    }


def _eku_list(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
        eku = cast(x509.ExtendedKeyUsage, ext.value)
    except x509.ExtensionNotFound:
        return []

    # map en s’appuyant sur les OID officiels; fallback = dotted_string
    def _eku_name(oid: x509.ObjectIdentifier) -> str:
        if oid == EKUOID.SERVER_AUTH: return "serverAuth"
        if oid == EKUOID.CLIENT_AUTH: return "clientAuth"
        if oid == EKUOID.CODE_SIGNING: return "codeSigning"
        if oid == EKUOID.EMAIL_PROTECTION: return "emailProtection"
        if oid == EKUOID.TIME_STAMPING: return "timeStamping"
        if oid == EKUOID.OCSP_SIGNING: return "OCSPSigning"
        # autres OID spécifiques (ex: SMARTCARD_LOGON) → conserver l’OID lisible
        return oid.dotted_string

    return [_eku_name(oid) for oid in eku]


def _sig_hash_name(cert: x509.Certificate) -> Optional[str]:
    try:
        algo = cert.signature_hash_algorithm
    except Exception:
        return None
    return algo.name if isinstance(algo, hashes.HashAlgorithm) else None
