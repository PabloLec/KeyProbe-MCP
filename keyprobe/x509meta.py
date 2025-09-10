
import datetime as dt
from typing import Any, Dict, List, Optional, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID as EKUOID, NameOID

from .common import iso_utc, days_until, Warn

def _name_to_cn(name: x509.Name) -> Optional[str]:
    try:
        return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value  # type: ignore[index]
    except Exception:
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
        elif isinstance(g, x509.UniformResourceIdentifier):
            out.append(g.value)
        elif isinstance(g, x509.RFC822Name):
            out.append(g.value)
    return out

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

def _eku_list(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
        eku = cast(x509.ExtendedKeyUsage, ext.value)
    except x509.ExtensionNotFound:
        return []
    def _eku_name(oid: x509.ObjectIdentifier) -> str:
        if oid == EKUOID.SERVER_AUTH: return "serverAuth"
        if oid == EKUOID.CLIENT_AUTH: return "clientAuth"
        if oid == EKUOID.CODE_SIGNING: return "codeSigning"
        if oid == EKUOID.EMAIL_PROTECTION: return "emailProtection"
        if oid == EKUOID.TIME_STAMPING: return "timeStamping"
        if oid == EKUOID.OCSP_SIGNING: return "OCSPSigning"
        return oid.dotted_string
    return [_eku_name(oid) for oid in eku]

def _basic_constraints(cert: x509.Certificate) -> Optional[Dict[str, Any]]:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
        bc = cast(x509.BasicConstraints, ext.value)
        return {"ca": bool(bc.ca), "path_len": bc.path_length}
    except x509.ExtensionNotFound:
        return None

def _aia(cert: x509.Certificate) -> Optional[Dict[str, List[str]]]:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        aia = cast(x509.AuthorityInformationAccess, ext.value)
    except x509.ExtensionNotFound:
        return None
    ocsp: List[str] = []
    ca_issuers: List[str] = []
    for ad in aia:
        try:
            if ad.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":  # id-ad-ocsp
                ocsp.append(cast(x509.UniformResourceIdentifier, ad.access_location).value)
            elif ad.access_method.dotted_string == "1.3.6.1.5.5.7.48.2":  # id-ad-caIssuers
                ca_issuers.append(cast(x509.UniformResourceIdentifier, ad.access_location).value)
        except Exception:
            continue
    return {"ocsp_urls": ocsp, "ca_issuers_urls": ca_issuers}

def _crl_dp(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS)
        dps = cast(x509.CRLDistributionPoints, ext.value)
    except x509.ExtensionNotFound:
        return []
    out: List[str] = []
    for dp in dps:
        if dp.full_name:
            for name in dp.full_name:
                if isinstance(name, x509.UniformResourceIdentifier):
                    out.append(name.value)
    return out

def _ski(cert: x509.Certificate) -> Optional[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        ski = cast(x509.SubjectKeyIdentifier, ext.value)
        return ski.digest.hex()
    except x509.ExtensionNotFound:
        return None

def _aki(cert: x509.Certificate) -> Optional[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        aki = cast(x509.AuthorityKeyIdentifier, ext.value)
        return aki.key_identifier.hex() if aki.key_identifier else None
    except x509.ExtensionNotFound:
        return None

def cert_to_meta(cert: x509.Certificate) -> Dict[str, Any]:
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    pub = _public_key_info(cert)
    sig_hash = None
    try:
        algo = cert.signature_hash_algorithm
        if isinstance(algo, hashes.HashAlgorithm):
            sig_hash = algo.name
    except Exception:
        pass

    meta: Dict[str, Any] = {
        "subject_dn": _rfc4514(cert.subject),
        "issuer_dn": _rfc4514(cert.issuer),
        "subject_cn": _name_to_cn(cert.subject),
        "issuer_cn": _name_to_cn(cert.issuer),
        "not_before": iso_utc(nb),
        "not_after": iso_utc(na),
        "days_until_expiry": days_until(na),
        "expired": na < dt.datetime.now(dt.timezone.utc),
        "not_yet_valid": nb > dt.datetime.now(dt.timezone.utc),
        "public_key": pub,
        "signature_hash": sig_hash,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "san": _san_list(cert),
        "key_usage": _key_usage(cert),
        "eku": _eku_list(cert),
        "basic_constraints": _basic_constraints(cert),
        "authority_information_access": _aia(cert),
        "crl_distribution_points": _crl_dp(cert),
        "subject_key_identifier": _ski(cert),
        "authority_key_identifier": _aki(cert),
        "serial_hex": format(cert.serial_number, "x"),
    }
    return meta

def csr_to_meta(csr: x509.CertificateSigningRequest) -> Dict[str, Any]:
    pk = csr.public_key()
    pub: Dict[str, Any]
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
        if isinstance(pk, rsa.RSAPublicKey):
            pub = {"type": "RSA", "size": pk.key_size}
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            pub = {"type": "EC", "curve": getattr(pk.curve, "name", "EC")}
        elif isinstance(pk, ed25519.Ed25519PublicKey):
            pub = {"type": "Ed25519"}
        elif isinstance(pk, ed448.Ed448PublicKey):
            pub = {"type": "Ed448"}
        else:
            pub = {"type": pk.__class__.__name__}
    except Exception:
        pub = {"type": pk.__class__.__name__}

    san: List[str] = []
    try:
        ext = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = [g.value if not isinstance(g, x509.IPAddress) else str(g.value) for g in cast(x509.SubjectAlternativeName, ext.value)]
    except x509.ExtensionNotFound:
        pass

    ku: List[str] = []
    try:
        ext = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        ku_val = cast(x509.KeyUsage, ext.value)
        # reuse logic
        csr_dummy = object()
        csr_dummy  # silence lint
        ku = []
        if ku_val.digital_signature: ku.append("digitalSignature")
        if ku_val.content_commitment: ku.append("contentCommitment")
        if ku_val.key_encipherment: ku.append("keyEncipherment")
        if ku_val.data_encipherment: ku.append("dataEncipherment")
        if ku_val.key_agreement:
            ku.append("keyAgreement")
            if ku_val.encipher_only: ku.append("encipherOnly")
            if ku_val.decipher_only: ku.append("decipherOnly")
        if ku_val.key_cert_sign: ku.append("keyCertSign")
        if ku_val.crl_sign: ku.append("cRLSign")
    except x509.ExtensionNotFound:
        pass

    eku: List[str] = []
    try:
        ext = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
        eku_val = cast(x509.ExtendedKeyUsage, ext.value)
        eku = []
        for oid in eku_val:
            if oid == EKUOID.SERVER_AUTH: eku.append("serverAuth")
            elif oid == EKUOID.CLIENT_AUTH: eku.append("clientAuth")
            elif oid == EKUOID.CODE_SIGNING: eku.append("codeSigning")
            elif oid == EKUOID.EMAIL_PROTECTION: eku.append("emailProtection")
            elif oid == EKUOID.TIME_STAMPING: eku.append("timeStamping")
            elif oid == EKUOID.OCSP_SIGNING: eku.append("OCSPSigning")
            else: eku.append(oid.dotted_string)
    except x509.ExtensionNotFound:
        pass

    sig_hash = None
    try:
        algo = csr.signature_hash_algorithm
        if isinstance(algo, hashes.HashAlgorithm):
            sig_hash = algo.name
    except Exception:
        pass

    return {
        "subject_dn": _rfc4514(csr.subject),
        "subject_cn": _name_to_cn(csr.subject),
        "public_key": pub,
        "san": san,
        "key_usage": ku,
        "eku": eku,
        "signature_hash": sig_hash,
    }

def cert_warnings(meta: Dict[str, Any]) -> List[dict]:
    out: List[dict] = []
    try:
        if meta.get("expired"):
            out.append(Warn("CERT_EXPIRED", "Certificate is expired", "error").as_dict())
        else:
            days = int(meta.get("days_until_expiry", 0))
            if days <= 30:
                out.append(Warn("CERT_SOON_EXPIRES", f"Certificate expires in {days} days", "warn").as_dict())
    except Exception:
        pass

    pk = meta.get("public_key", {})
    if pk.get("type") == "RSA":
        try:
            if int(pk.get("size", 0)) < 2048:
                out.append(Warn("RSA_WEAK_KEY", "RSA key size < 2048", "warn").as_dict())
        except Exception:
            pass

    sig = (meta.get("signature_hash") or "").lower()
    if sig in {"md5", "sha1"}:
        out.append(Warn("WEAK_SIGNATURE_HASH", f"Weak signature hash: {sig}", "warn").as_dict())

    if "serverAuth" in meta.get("eku", []) and not meta.get("san"):
        out.append(Warn("MISSING_SAN", "serverAuth present but SAN is empty", "warn").as_dict())

    bc = meta.get("basic_constraints") or {}
    if bc.get("ca") is True and "keyCertSign" not in meta.get("key_usage", []):
        out.append(Warn("CA_MISSING_KU", "CA certificate without keyCertSign", "warn").as_dict())

    return out
