from __future__ import annotations
from _util import FIX, read_bytes, require
from keyprobe.summary import summarize_bytes

def test_leaf_keyusage_eku_san_present():
    p = require(FIX / "pem" / "leaf.cert.pem")
    meta = summarize_bytes(read_bytes(p), filename=str(p))
    x = meta["x509"]
    assert "digitalSignature" in x["key_usage"]
    assert "keyEncipherment" in x["key_usage"]
    assert "serverAuth" in x["eku"] and "clientAuth" in x["eku"]
    assert set(x["san"]) >= {"leaf.example.com", "127.0.0.1"}
