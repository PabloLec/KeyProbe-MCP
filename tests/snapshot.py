# tests/snapshot.py  (ou tests/integration/snapshot.py)
from pathlib import Path
from typing import Any, Dict, List
import json
import re

# Volatile au top niveau uniquement (chemins, taille, digest)
VOLATILE_TOP = {"path", "filename", "resolved", "input", "size", "digest_sha256"}

# Volatile dans les métadonnées X.509 (dépend du moment de génération)
VOLATILE_X509 = {
    "not_before",
    "not_after",
    "days_until_expiry",
    "expired",
    "not_yet_valid",
    "serial",
    "serial_hex",
}

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _sorted_list(x: List[Any]) -> List[Any]:
    try:
        return sorted(x)
    except Exception:
        return x


def _sort_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(entries, key=lambda e: (e.get("alias", ""), e.get("type", "")))


def _sort_chain(chain: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(chain, key=lambda c: (c.get("subject_cn", ""), c.get("issuer_cn", "")))


def _drop_keys(d: Dict[str, Any], keys: set[str]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if k not in keys}


def _normalize_x509(d: Dict[str, Any]) -> Dict[str, Any]:
    out = _drop_keys(dict(d), VOLATILE_X509)
    if isinstance(out.get("san"), list):
        out["san"] = _sorted_list(list(dict.fromkeys(out["san"])))
    if isinstance(out.get("eku"), list):
        out["eku"] = _sorted_list(out["eku"])
    if isinstance(out.get("key_usage"), list):
        out["key_usage"] = _sorted_list(out["key_usage"])
    if isinstance(out.get("public_key"), dict):
        out["public_key"] = dict(sorted(out["public_key"].items()))
    return dict(sorted(out.items()))


def _normalize(actual: Dict[str, Any]) -> Dict[str, Any]:
    a = _drop_keys(dict(actual), VOLATILE_TOP)

    if isinstance(a.get("x509"), dict):
        a["x509"] = _normalize_x509(a["x509"])

    if isinstance(a.get("x509_chain"), list):
        chain = []
        for c in a["x509_chain"]:
            if isinstance(c, dict):
                chain.append(_normalize_x509(c))
        a["x509_chain"] = _sort_chain(chain)

    if a.get("format") == "PKCS8" and isinstance(a.get("key"), dict):
        a["key"] = dict(sorted(a["key"].items()))

    if a.get("format") == "OPENSSH" and isinstance(a.get("private"), dict):
        a["private"] = dict(sorted(a["private"].items()))
    if a.get("format") == "OPENSSH" and isinstance(a.get("public"), dict):
        a["public"] = dict(sorted(a["public"].items()))

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
                    pr = {k: e[k] for k in ("alias", "ok", "oid") if k in e}
                    probe.append(dict(sorted(pr.items())))
            a["decrypt_probe"] = _sort_entries(probe)

    return dict(sorted(a.items()))


def _presence_invariants(actual: Dict[str, Any]) -> None:
    for k in ("path", "filename", "resolved", "input"):
        if k in actual:
            v = actual[k]
            assert isinstance(v, str) and v.strip(), f"{k} must be a non-empty string"

    if "size" in actual:
        assert isinstance(actual["size"], int) and actual["size"] >= 0, "size must be a non-negative int"

    if "digest_sha256" in actual:
        v = str(actual["digest_sha256"])
        assert HEX64.match(v), "digest_sha256 must be a 64-hex string"

    fmt = actual.get("format")
    if fmt == "PKCS8":
        assert ("key" in actual and isinstance(actual["key"], dict)) or (actual.get("encrypted") is True), \
            "PKCS8 must include key details or encrypted=true"

    if fmt == "OPENSSH":
        assert ("public" in actual) or ("private" in actual), "OPENSSH must include public or private section"

    x = actual.get("x509")
    if isinstance(x, dict):
        for req in ("subject_dn", "issuer_dn", "public_key"):
            assert req in x, f"x509 missing required '{req}'"

    if "warnings" in actual:
        assert isinstance(actual["warnings"], list), "warnings must be a list"


def load_expected(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def assert_snapshot(actual: Dict[str, Any], expected_path: Path) -> None:
    expected = load_expected(expected_path)
    norm = _normalize(actual)

    # Comparaison stricte: l'expected doit être un snapshot complet (hors champs volatils supprimés)
    assert norm == expected, (
        f"\n--- expected: {expected_path}\n"
        f"--- actual(norm):\n{json.dumps(norm, indent=2, ensure_ascii=False)}\n"
    )

    # Invariants de présence sur l'objet brut
    _presence_invariants(actual)
