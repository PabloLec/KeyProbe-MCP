from __future__ import annotations
import base64
import pytest
from fastmcp import Client

from _util import FIX, read_bytes, require


@pytest.mark.asyncio
async def test_p12_summary_ok_password():
    p = require(FIX / "pkcs12" / "keystore.p12")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("p12_summary", {"path": str(p), "password": "changeit"})
        meta = res.data
        assert meta["format"] == "PKCS12"
        assert meta.get("encrypted") is False, f"meta={meta}"
        # on attend au moins 1 cert
        assert ("x509" in meta) or ("x509_chain" in meta)
        assert "has_key" in meta


@pytest.mark.asyncio
async def test_p12_summary_bad_password():
    p = require(FIX / "pkcs12" / "keystore.p12")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("p12_summary", {"path": str(p), "password": "wrongpass"})
        meta = res.data
        assert meta["format"] == "PKCS12"
        assert meta.get("encrypted") is True, f"meta={meta}"
        assert meta.get("error") == "BadPasswordError"


@pytest.mark.asyncio
async def test_p12_summary_from_b64_ok():
    p = require(FIX / "pkcs12" / "keystore.p12")
    b64 = base64.b64encode(read_bytes(p)).decode("ascii")
    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool(
            "p12_summary_from_b64",
            {"filename": p.name, "content_b64": b64, "password": "changeit"},
        )
        meta = res.data
        assert meta["format"] == "PKCS12", f"meta={meta}"
        assert meta.get("encrypted") is False


@pytest.mark.asyncio
async def test_jks_summary_ok_password():
    p = require(FIX / "jks" / "test.jks")
    from keyprobe.server import mcp

    async with Client(mcp) as client:
        res = await client.call_tool("jks_summary", {"path": str(p), "password": "changeit"})
        meta = res.data

        # Format & en-tête JKS
        assert meta["format"] == "JKS"
        assert meta.get("store_type", "").upper() == "JKS"
        assert meta.get("magic", "").upper() == "FEEDFEED"

        # Le déchiffrement a bien réussi (au moins une clé)
        assert meta.get("encrypted") is False, f"meta={meta}"

        # Inventaire cohérent
        entries = meta.get("entries")
        assert isinstance(entries, list) and len(entries) >= 1, f"meta={meta}"
        aliases = {e["alias"] for e in entries}
        assert {"leaf", "root"} <= aliases, f"aliases={aliases}, meta={meta}"

        leaf = next(e for e in entries if e["alias"] == "leaf")
        assert leaf["type"] == "PrivateKeyEntry"
        assert leaf.get("chain_len", 0) >= 1
        assert str(leaf.get("subject_cn", "")).startswith("leaf.example.com")

        root = next(e for e in entries if e["alias"] == "root")
        assert root["type"] == "TrustedCertEntry"
        assert isinstance(root.get("subject_cn"), str) and len(root["subject_cn"]) > 0

        # Vérifie explicitement que la clé 'leaf' a été déchiffrée et l’OID utilisé
        probe = {d["alias"]: d for d in meta.get("decrypt_probe", [])}
        assert "leaf" in probe, f"decrypt_probe={meta.get('decrypt_probe')}"
        assert probe["leaf"].get("ok") is True, f"decrypt_probe={probe['leaf']}"
        assert probe["leaf"].get("oid") == "1.3.6.1.4.1.42.2.17.1.1"  # Sun PBEWithMD5AndTripleDES


@pytest.mark.asyncio
async def test_jks_summary_bad_password():
    p = require(FIX / "jks" / "test.jks")
    from keyprobe.server import mcp

    async with Client(mcp) as client:
        res = await client.call_tool("jks_summary", {"path": str(p), "password": "wrongpass"})
        meta = res.data

        # Toujours un JKS
        assert meta["format"] == "JKS"
        assert meta.get("magic", "").upper() == "FEEDFEED"

        # Mot de passe de store incorrect → vérif d’intégrité échoue dans pyjks
        assert meta.get("encrypted") is True, f"meta={meta}"
        assert meta.get("error") in {"KeystoreSignatureError", "BadPasswordError"}, f"meta={meta}"

        # Pas d’exigence sur entries/decrypt_probe ici (le load a échoué en amont)