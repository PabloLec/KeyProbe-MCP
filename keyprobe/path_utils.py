from __future__ import annotations
import os
import pathlib
from urllib.parse import urlparse, unquote

def _normpath(p: pathlib.Path) -> pathlib.Path:
    return p.expanduser().resolve(strict=False)

def parse_file_uri(uri_or_path: str) -> pathlib.Path:
    """Accepte un chemin local ou une URI file://… ; renvoie Path normalisé."""
    if uri_or_path.startswith("file://"):
        parsed = urlparse(uri_or_path)
        path = parsed.path or ""
        if os.name == "nt":
            import re
            m = re.match(r"^/([A-Za-z]:/.*)$", path)
            if m:
                path = m.group(1)
        return pathlib.Path(unquote(path))
    return pathlib.Path(uri_or_path)

def resolve_path(path_like: str | os.PathLike[str]) -> pathlib.Path:
    """Résout un chemin en absolu (sans vérif sandbox)."""
    return _normpath(parse_file_uri(str(path_like)))
