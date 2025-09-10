from __future__ import annotations
from pathlib import Path
import pytest

from keyprobe.summary import summarize_bytes
from _util import FIX, read_bytes, require

import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keyprobe.summary import summarize_bytes
from _util import FIX, read_bytes, require


@pytest.mark.parametrize("pem_name", ["leaf.cert.pem"])
def test_pem_leaf_has_x509(pem_name: str):
    p = require(FIX / "pem" / pem_name)
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "PEM"
    assert meta["size"] > 0 and len(meta["digest_sha256"]) == 64
    assert "x509" in meta
    x = meta["x509"]
    assert x["subject_cn"] == "leaf.example.com"
    assert "serverAuth" in x["eku"] and "clientAuth" in x["eku"]
    assert "digitalSignature" in x["key_usage"] and "keyEncipherment" in x["key_usage"]
    assert set(x["san"]) >= {"leaf.example.com", "127.0.0.1"}

def test_der_leaf_has_x509():
    p = require(FIX / "der" / "leaf.cert.der")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "DER"
    assert "x509" in meta
    assert meta["x509"]["subject_cn"] == "leaf.example.com"

def test_pkcs7_chain_der():
    p = require(FIX / "pkcs7" / "chain.p7b")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "PKCS7"
    assert "x509_chain" in meta and len(meta["x509_chain"]) >= 2

def test_pkcs7_chain_pem():
    p = require(FIX / "pkcs7" / "chain.pem.p7b")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "PKCS7"
    assert "x509_chain" in meta and len(meta["x509_chain"]) >= 2


def test_pkcs12_encrypted():
    p = require(FIX / "pkcs12" / "keystore.p12")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "PKCS12"
    assert meta.get("encrypted") is True

def test_pkcs8_unencrypted_private():
    p = require(FIX / "pkcs8" / "key_pkcs8_unenc.pem")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "PKCS8"
    assert meta.get("encrypted") in (False, None)
    assert "key" in meta and "type" in meta["key"]

def test_pkcs8_encrypted_private():
    p = require(FIX / "pkcs8" / "key_pkcs8_encrypted.pem")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "PKCS8"
    assert meta.get("encrypted") is True

def test_pkcs8_public():
    p = require(FIX / "pkcs8" / "pubkey_pkcs8.pem")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "PKCS8"
    assert "key" in meta and "type" in meta["key"]

def test_openssh_public():
    p = require(FIX / "openssh" / "id_ed25519.pub")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "OPENSSH"
    assert meta.get("public", {}).get("type") == "ssh-ed25519"

def test_openssh_private_unencrypted():
    p = require(FIX / "openssh" / "id_ed25519")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "OPENSSH"
    assert meta.get("private", {}).get("encrypted") is False

def test_openssh_private_encrypted():
    p = require(FIX / "openssh" / "id_ed25519_enc")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "OPENSSH"
    assert meta.get("private", {}).get("encrypted") is True

def test_jks_minimal():
    p = require(FIX / "jks" / "test.jks")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "JKS"
    assert meta.get("encrypted") in (True, None)

def test_unknown_bin():
    p = require(FIX / "misc" / "unknown.bin")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "UNKNOWN"
    assert meta["size"] > 0 and len(meta["digest_sha256"]) == 64


def _spki_sha256_hex_from_pem_public(data: bytes) -> str:
    pub = serialization.load_pem_public_key(data)
    spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def _spki_sha256_hex_from_pem_private(data: bytes) -> str:
    # only works if private key is unencrypted
    priv = serialization.load_pem_private_key(data, password=None)
    pub = priv.public_key()
    spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def _ssh_fingerprint_from_publine(line: bytes) -> str:
    # "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
    blob_b64 = line.split(None, 2)[1]
    digest = hashlib.sha256(base64.b64decode(blob_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def test_pem_csr_has_meta():
    p = require(FIX / "pem" / "leaf.csr.pem")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "PEM"
    assert "csr" in meta
    csr = meta["csr"]
    assert csr["subject_cn"] in ("leaf.example.com", "leaf.example.com")  # tolérant
    assert "public_key" in csr and "type" in csr["public_key"]


def test_pkcs8_fingerprint_private_unencrypted():
    p = require(FIX / "pkcs8" / "key_pkcs8_unenc.pem")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "PKCS8"
    fp = meta["key"].get("fingerprint_spki_sha256")
    assert fp and len(fp) == 64
    # vérif indépendante
    expected = _spki_sha256_hex_from_pem_private(read_bytes(p))
    assert fp == expected


def test_pkcs8_fingerprint_public():
    p = require(FIX / "pkcs8" / "pubkey_pkcs8.pem")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "PKCS8"
    fp = meta["key"].get("fingerprint_spki_sha256")
    assert fp and len(fp) == 64
    expected = _spki_sha256_hex_from_pem_public(read_bytes(p))
    assert fp == expected


def test_openssh_fingerprint_public():
    p = require(FIX / "openssh" / "id_ed25519.pub")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    assert meta["format"] == "OPENSSH"
    fp = meta.get("public", {}).get("fingerprint_sha256")
    assert fp and fp.startswith("SHA256:")
    # vérif indépendante
    expected = _ssh_fingerprint_from_publine(read_bytes(p).splitlines()[0])
    assert fp == expected


def test_openssh_private_includes_public_fingerprint():
    p_priv = require(FIX / "openssh" / "id_ed25519")
    p_pub = require(FIX / "openssh" / "id_ed25519.pub")
    meta = summarize_bytes(read_bytes(p_priv), filename=str(p_priv))
    assert meta["format"] == "OPENSSH"
    priv = meta.get("private", {})
    assert priv.get("encrypted") is False
    fp_priv = priv.get("public_fingerprint_sha256")
    assert fp_priv and fp_priv.startswith("SHA256:")
    # comparer avec le .pub
    expected = _ssh_fingerprint_from_publine(read_bytes(p_pub).splitlines()[0])
    assert fp_priv == expected