# keyprobe/server.py
from __future__ import annotations

import hashlib

from fastmcp import FastMCP
from typing import Optional
import os
import json
import pathlib

from keyprobe.format_identify import guess_format
from .settings import Settings
from .logging_conf import setup_logging
from .resource_store import ResourceStore
from .path_utils import resolve_path

mcp = FastMCP(name="KeyProbe")

# -- Bootstrap runtime (idempotent) -------------------------------------------------
_SETTINGS: Optional[Settings] = None
_STORE: Optional[ResourceStore] = None

def _get_settings() -> Settings:
    global _SETTINGS
    if _SETTINGS is None:
        _SETTINGS = Settings.from_env()
        setup_logging(_SETTINGS)
    return _SETTINGS

def _get_store() -> ResourceStore:
    global _STORE
    if _STORE is None:
        s = _get_settings()
        _STORE = ResourceStore(ttl_seconds=s.RESOURCE_TTL_SEC)
    return _STORE

# -- Tool: stocker un résumé éphémère et retourner une URI de resource --------------
@mcp.tool
def put_temp(summary: dict) -> str:
    """
    Enregistre un 'summary' (dict) dans le ResourceStore et renvoie l'URI
    d'une resource lisible par le client (kp://temp/{rid}).
    """
    rid = _get_store().put(summary)
    return f"kp://temp/{rid}"

# -- Resource template: récupérer un summary par ID ---------------------------------
@mcp.resource("kp://temp/{rid}", mime_type="application/json")
def get_temp(rid: str) -> dict:
    """
    Lit un summary éphémère par identifiant et le renvoie (JSON).
    """
    entry = _get_store().get(rid)
    return entry.summary

# -- Resource template: stat de fichier dans une sandbox (allowlist + wildcard) -----
@mcp.resource("kp://fs/{path*}", mime_type="application/json")
def fs_stat(path: str) -> dict:
    """
    Retourne des métadonnées sur un chemin local (dans l'allowlist) :
    - chemin résolu, exists, is_file, is_dir, size (si fichier)
    """
    resolved = resolve_path(path)

    info = {
        "input": path,
        "resolved": str(resolved),
        "exists": resolved.exists(),
        "is_file": resolved.is_file(),
        "is_dir": resolved.is_dir(),
        "size": None,
    }
    if info["exists"] and info["is_file"]:
        info["size"] = resolved.stat().st_size
    return info


@mcp.tool
def file_metadata(path: str) -> dict:
    """
    Lit un fichier (sandboxée par allowlist), calcule taille + SHA-256 et
    renvoie un résumé minimal : { path, format, size, digest_sha256 }.
    """
    resolved = resolve_path(path)

    # Lecture safe (petits fichiers dans nos tests)
    data = resolved.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    fmt = guess_format(data, filename=str(resolved))

    return {
        "path": str(resolved),
        "format": fmt,
        "size": resolved.stat().st_size,
        "digest_sha256": digest,
    }

# -- Smoke tool (déjà présent) ------------------------------------------------------
@mcp.tool
def ping() -> str:
    """Petit outil de fumée pour vérifier que le serveur répond."""
    return "pong"

if __name__ == "__main__":
    # Transport STDIO ; cf. docs FastMCP (run local / quickstart).
    mcp.run()
