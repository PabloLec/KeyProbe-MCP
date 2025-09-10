# keyprobe/formats/jks.py
from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
import hashlib
import logging

log = logging.getLogger(__name__)

def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def summarize(data: bytes) -> Dict[str, Any]:
    # Sans mot de passe, on ne peut pas introspecter
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
    """
    Déchiffre un EncryptedPrivateKeyInfo typique JKS (Sun PBEWithMD5AndTripleDES)
    en s'appuyant sur les primitives internes pyjks.sun_crypto.
    Retourne (pkcs8_private_key_info_der, algo_oid_dotted)
    """
    from pyasn1.codec.ber import decoder
    from pyasn1_modules import rfc5208
    from jks import sun_crypto  # type: ignore

    epki = decoder.decode(encrypted_epki_der, asn1Spec=rfc5208.EncryptedPrivateKeyInfo())[0]
    algo_oid_tuple = epki["encryptionAlgorithm"]["algorithm"].asTuple()
    algo_oid = ".".join(str(i) for i in algo_oid_tuple)
    # IMPORTANT: ne surtout pas accéder à 'parameters' ici (peut être NULL/absent)
    ciphertext = epki["encryptedData"].asOctets()

    if algo_oid_tuple == sun_crypto.SUN_JKS_ALGO_ID:
        plaintext = sun_crypto.jks_pkey_decrypt(ciphertext, password)
    elif algo_oid_tuple == sun_crypto.SUN_JCE_ALGO_ID:
        # Cas JCEKS (PBES1) si jamais on le rencontre côté JKS (peu probable)
        # Ici, il faudrait décoder PBEParameter(salt, iterationCount) depuis parameters.
        # On ne traite pas ce cas tant qu’on n’a pas de keystore JCEKS dans les tests.
        raise ValueError("Unexpected JCEKS algorithm in JKS store")
    else:
        raise ValueError(f"Unknown JKS key protection algorithm: {algo_oid}")

    return plaintext, algo_oid

def _inventory_keystore(ks) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    # PrivateKeyEntry
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

    # TrustedCertEntry
    for alias, e in getattr(ks, "certs", {}).items():
        subject_cn = _entry_subject_cn(getattr(e, "cert", b"") or b"")
        entries.append({"alias": alias, "type": "TrustedCertEntry", "subject_cn": subject_cn})

    return entries

def summarize_with_password_bytes(data: bytes, password: str) -> Dict[str, Any]:
    base = {
        "format": "JKS",
        "size": len(data),
        "digest_sha256": _digest(data),
        "magic": data[:4].hex(),
    }

    try:
        import jks  # type: ignore
        from jks.util import KeystoreSignatureException  # type: ignore
    except Exception as e:
        log.debug("pyjks import failed: %s", e)
        return {**base, "error": "DependencyMissing(pyjks)"}

    # 1) Charger sans déchiffrer (évite le bug parameters.asOctets)
    try:
        ks = jks.KeyStore.loads(data, password, try_decrypt_keys=False)
    except KeystoreSignatureException:
        return {**base, "encrypted": True, "error": "KeystoreSignatureError"}
    except Exception as e:
        log.debug("KeyStore.loads failed: %s", e, exc_info=True)
        return {**base, "error": f"LoadError:{e.__class__.__name__}"}

    # 2) Inventorier, puis tenter un déchiffrement non-intrusif pour marquer encrypted=False si OK
    entries = _inventory_keystore(ks)

    decrypted_any = False
    decrypt_notes: List[Dict[str, Any]] = []

    for alias, e in getattr(ks, "private_keys", {}).items():
        try:
            epki_der: bytes = getattr(e, "_encrypted", b"") or b""
            if not epki_der:
                continue
            pkcs8_der, oid = _decrypt_jks_epki(epki_der, password)
            # On ne persiste PAS la clé — simple preuve de déchiffrage
            decrypt_notes.append({"alias": alias, "ok": True, "oid": oid})
            decrypted_any = True
        except Exception as ex:
            # On n’échoue pas le résumé pour autant ; on loggue seulement
            decrypt_notes.append({"alias": alias, "ok": False, "error": f"{ex.__class__.__name__}:{ex}"})

    result: Dict[str, Any] = {
        **base,
        "store_type": getattr(ks, "store_type", "JKS"),
        "entries": entries,
        "decrypt_probe": decrypt_notes,  # utile pour diagnostiquer en CI
    }
    # Conformément à nos tests: encrypted=False si on a pu déchiffrer au moins une clé
    if decrypted_any:
        result["encrypted"] = False
    else:
        result["encrypted"] = True  # si keystore ne contient que des certs, on reste True, c’est acceptable pour nos tests “clé présente”
    return result
