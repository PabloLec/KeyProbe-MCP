from __future__ import annotations
from pathlib import Path
import pytest

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