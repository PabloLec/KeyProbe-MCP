from typing import Any, Dict, List, Optional, Tuple
import hashlib
import logging

log = logging.getLogger(__name__)

def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def summarize(data: bytes) -> Dict[str, Any]:
    return {"format": "JKS", "encrypted": True, "size": len(data), "digest_sha256": _digest(data)}

def _entry_subject_cn(der: bytes) -> Optional[str]:
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        xc = x509.load_der_x509_certificate(der)
        at = xc.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return at[0].value if at else None
    except Exception:
        return None

def _decrypt_jks_epki(encrypted_epki_der: bytes, password: str) -> Tuple[bytes, str]:
    from pyasn1.codec.ber import decoder
    from pyasn1_modules import rfc5208
    from jks import sun_crypto  # type: ignore

    epki = decoder.decode(encrypted_epki_der, asn1Spec=rfc5208.EncryptedPrivateKeyInfo())[0]
    oid_tuple = epki["encryptionAlgorithm"]["algorithm"].asTuple()
    oid_dotted = ".".join(str(i) for i in oid_tuple)
    ciphertext = epki["encryptedData"].asOctets()

    if oid_tuple == sun_crypto.SUN_JKS_ALGO_ID:
        plaintext = sun_crypto.jks_pkey_decrypt(ciphertext, password)
    elif oid_tuple == sun_crypto.SUN_JCE_ALGO_ID:
        raise ValueError("Unexpected JCEKS algorithm in JKS store")
    else:
        raise ValueError(f"Unknown JKS key protection algorithm: {oid_dotted}")

    return plaintext, oid_dotted

def _inventory_keystore(ks) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for alias, e in getattr(ks, "private_keys", {}).items():
        chain_len = len(getattr(e, "cert_chain", []) or [])
        subject_cn = None
        try:
            if chain_len:
                first = e.cert_chain[0]
                der = first[1] if isinstance(first, tuple) else getattr(first, "cert", None)
                if der:
                    subject_cn = _entry_subject_cn(der)
        except Exception:
            pass
        entries.append({"alias": alias, "type": "PrivateKeyEntry", "chain_len": chain_len, "subject_cn": subject_cn})
    for alias, e in getattr(ks, "certs", {}).items():
        subject_cn = _entry_subject_cn(getattr(e, "cert", b"") or b"")
        entries.append({"alias": alias, "type": "TrustedCertEntry", "subject_cn": subject_cn})
    return entries

def summarize_with_password_bytes(data: bytes, password: str) -> Dict[str, Any]:
    base = {"format": "JKS", "size": len(data), "digest_sha256": _digest(data), "magic": data[:4].hex()}

    try:
        import jks  # type: ignore
        from jks.util import KeystoreSignatureException  # type: ignore
    except Exception as e:
        log.debug("pyjks import failed: %s", e)
        return {**base, "error": "DependencyMissing(pyjks)"}

    try:
        ks = jks.KeyStore.loads(data, password, try_decrypt_keys=False)
    except KeystoreSignatureException:
        return {**base, "encrypted": True, "error": "KeystoreSignatureError"}
    except Exception as e:
        log.debug("KeyStore.loads failed: %s", e, exc_info=True)
        return {**base, "error": f"LoadError:{e.__class__.__name__}"}

    entries = _inventory_keystore(ks)
    decrypted_any = False
    probe: List[Dict[str, Any]] = []

    for alias, e in getattr(ks, "private_keys", {}).items():
        try:
            epki_der: bytes = getattr(e, "_encrypted", b"") or b""
            if not epki_der:
                continue
            _, oid = _decrypt_jks_epki(epki_der, password)
            probe.append({"alias": alias, "ok": True, "oid": oid})
            decrypted_any = True
        except Exception as ex:
            probe.append({"alias": alias, "ok": False, "error": f"{ex.__class__.__name__}:{ex}"})

    out: Dict[str, Any] = {
        **base,
        "store_type": getattr(ks, "store_type", "JKS"),
        "entries": entries,
        "decrypt_probe": probe,
        "encrypted": not decrypted_any,
    }

    warns: List[dict] = []
    if any((p.get("ok") and p.get("oid") == "1.3.6.1.4.1.42.2.17.1.1") for p in probe):
        warns.append({"code": "JKS_WEAK_PBE", "message": "Sun PBEWithMD5AndTripleDES in use", "severity": "warn"})
    if warns:
        out["warnings"] = warns
    return out
