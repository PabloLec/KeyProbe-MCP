# keyprobe/x509_utils.py
from __future__ import annotations

import datetime as dt
import ipaddress
import re
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes


_PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\r?\n.*?\r?\n-----END CERTIFICATE-----",
    re.DOTALL,
)

def _iso_utc(d: dt.datetime) -> str:
    # cryptography peut renvoyer des datetimes naïves (UTC). Normalisons en Z.
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _name_to_cn(name: x509.Name) -> Optional[str]:
    for attr in name:
        if attr.oid.dotted_string in ("2.5.4.3",):  # commonName
            return attr.value
    return None


def _name_to_rfc4514(name: x509.Name) -> str:
    # Donne un DN lisible (CN=...,O=...,C=...) sans ordre inversé arbitraire
    return name.rfc4514_string()


def _public_key_info(cert: x509.Certificate) -> Dict[str, Any]:
    pk = cert.public_key()
    try:
        # RSA
        from cryptography.hazmat.primitives.asymmetric import rsa

        if isinstance(pk, rsa.RSAPublicKey):
            return {"type": "RSA", "size": pk.key_size}
    except Exception:
        pass

    try:
        # EC
        from cryptography.hazmat.primitives.asymmetric import ec

        if isinstance(pk, ec.EllipticCurvePublicKey):
            curve_name = getattr(pk.curve, "name", "EC")
            return {"type": "EC", "curve": curve_name}
    except Exception:
        pass

    # EdDSA (Ed25519/Ed448)
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519, ed448

        if isinstance(pk, ed25519.Ed25519PublicKey):
            return {"type": "Ed25519"}
        if isinstance(pk, ed448.Ed448PublicKey):
            return {"type": "Ed448"}
    except Exception:
        pass

    # Fallback
    return {"type": pk.__class__.__name__}


def _san_list(cert: x509.Certificate) -> List[str]:
    out: List[str] = []
    try:
        san = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return out

    # On ne met que les types les plus utiles (DNS, IP)
    for g in san:
        if isinstance(g, x509.DNSName):
            out.append(g.value)
        elif isinstance(g, x509.IPAddress):
            out.append(str(g.value))
    return out


def _sig_hash(cert: x509.Certificate) -> Optional[str]:
    try:
        algo = cert.signature_hash_algorithm
        if isinstance(algo, hashes.HashAlgorithm):
            return algo.name
    except Exception:
        pass
    return None


def _try_load_pem_cert(data: bytes) -> Optional[x509.Certificate]:
    # Cherche le premier bloc CERTIFICATE dans le PEM (chaîne possible).
    m = _PEM_CERT_RE.search(data)
    if not m:
        return None
    block = m.group(0)
    try:
        return x509.load_pem_x509_certificate(block)
    except Exception:
        return None


def _try_load_der_cert(data: bytes) -> Optional[x509.Certificate]:
    try:
        return x509.load_der_x509_certificate(data)
    except Exception:
        return None


def extract_x509_metadata(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Tente d'extraire des métadonnées X.509 (cert unique) depuis des octets PEM/DER.
    Retourne un dict ou None si non applicable.
    """
    cert = _try_load_pem_cert(data) or _try_load_der_cert(data)
    if cert is None:
        return None

    meta: Dict[str, Any] = {
        "subject_dn": _name_to_rfc4514(cert.subject),
        "issuer_dn": _name_to_rfc4514(cert.issuer),
        "subject_cn": _name_to_cn(cert.subject),
        "issuer_cn": _name_to_cn(cert.issuer),
        "not_before": _iso_utc(cert.not_valid_before),
        "not_after": _iso_utc(cert.not_valid_after),
        "public_key": _public_key_info(cert),
        "signature_hash": _sig_hash(cert),
        "san": _san_list(cert),
        "serial_number": str(cert.serial_number),
    }
    return meta
