# tests/integration/snapshot.py
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List
import json

VOLATILE_TOP = {
    "size", "digest_sha256", "path", "filename", "resolved", "input", "env",
}
VOLATILE_X509 = {
    "fingerprint_sha256", "not_before", "not_after", "serial",
}
VOLATILE_OPENSSH_PRIV = {"public_fingerprint_sha256"}
VOLATILE_PKCS8_KEY = {"fingerprint_spki_sha256"}

def _sorted_list(x: List[Any]) -> List[Any]:
    try:
        return sorted(x)
    except Exception:
        return x

def _sort_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(entries, key=lambda e: (e.get("alias",""), e.get("type","")))

def _sort_chain(chain: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(chain, key=lambda c: (c.get("subject_cn",""), c.get("issuer_cn","")))

def _drop_keys(d: Dict[str, Any], keys: set[str]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if k not in keys}

def _normalize_x509(d: Dict[str, Any]) -> Dict[str, Any]:
    d = _drop_keys(d, VOLATILE_X509)
    if "san" in d and isinstance(d["san"], list):
        d["san"] = _sorted_list(list(dict.fromkeys(d["san"])))
    if "eku" in d and isinstance(d["eku"], list):
        d["eku"] = _sorted_list(d["eku"])
    if "key_usage" in d and isinstance(d["key_usage"], list):
        d["key_usage"] = _sorted_list(d["key_usage"])
    if "public_key" in d and isinstance(d["public_key"], dict):
        d["public_key"] = dict(sorted(d["public_key"].items()))
    return dict(sorted(d.items()))

def _normalize(actual: Dict[str, Any]) -> Dict[str, Any]:
    a = dict(actual)

    # drop volatile on top-level
    a = _drop_keys(a, VOLATILE_TOP)

    # normalize x509
    if "x509" in a and isinstance(a["x509"], dict):
        a["x509"] = _normalize_x509(a["x509"])

    # normalize x509_chain
    if "x509_chain" in a and isinstance(a["x509_chain"], list):
        chain = []
        for c in a["x509_chain"]:
            if isinstance(c, dict):
                chain.append(_normalize_x509(c))
        a["x509_chain"] = _sort_chain(chain)

    # normalize pkcs8 key
    if a.get("format") == "PKCS8" and isinstance(a.get("key"), dict):
        k = dict(a["key"])
        for rm in VOLATILE_PKCS8_KEY:
            k.pop(rm, None)
        a["key"] = dict(sorted(k.items()))

    # normalize openssh private
    if a.get("format") == "OPENSSH" and isinstance(a.get("private"), dict):
        p = dict(a["private"])
        for rm in VOLATILE_OPENSSH_PRIV:
            p.pop(rm, None)
        a["private"] = dict(sorted(p.items()))

    # normalize JKS entries/decrypt_probe
    if a.get("format") == "JKS":
        if isinstance(a.get("entries"), list):
            entries = []
            for e in a["entries"]:
                if isinstance(e, dict):
                    entries.append(dict(sorted(e.items())))
            a["entries"] = _sort_entries(entries)
        if isinstance(a.get("decrypt_probe"), list):
            probe = []
            for e in a["decrypt_probe"]:
                if isinstance(e, dict):
                    # only keep alias/ok/oid for determinism
                    pr = {k: e[k] for k in ("alias", "ok", "oid") if k in e}
                    probe.append(dict(sorted(pr.items())))
            a["decrypt_probe"] = _sort_entries(probe)

    return dict(sorted(a.items()))

def _project(actual: Any, template: Any) -> Any:
    # keep only keys present in template (deep), allows strict compare on chosen fields
    if isinstance(template, dict) and isinstance(actual, dict):
        return {k: _project(actual.get(k), v) for k, v in template.items()}
    if isinstance(template, list) and isinstance(actual, list):
        if not template:
            return []
        # schema-like: apply first element as schema to all items
        tmpl = template[0]
        return [_project(x, tmpl) for x in actual]
    return actual

def load_expected(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def assert_snapshot(actual: Dict[str, Any], expected_path: Path) -> None:
    expected = load_expected(expected_path)
    norm = _normalize(actual)
    proj = _project(norm, expected)
    assert proj == expected, f"\n--- expected: {expected_path}\n--- actual(proj):\n{json.dumps(proj, indent=2, ensure_ascii=False)}\n"
