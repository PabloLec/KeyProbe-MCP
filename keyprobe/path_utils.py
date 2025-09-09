# keyprobe/path_utils.py
from __future__ import annotations
import os
import pathlib
from re import match
from urllib.parse import urlparse, unquote
from typing import Iterable


class PathOutsideSandbox(Exception):
    pass


def _normpath(p: pathlib.Path) -> pathlib.Path:
    # resolve(strict=False) pour ne pas exiger l'existence du fichier
    return p.expanduser().resolve(strict=False)


def _is_subpath(child: pathlib.Path, parents: Iterable[pathlib.Path]) -> bool:
    c = _normpath(child)
    for parent in parents:
        p = _normpath(parent)
        try:
            c.relative_to(p)
            return True
        except ValueError:
            continue
    return False


def parse_file_uri(uri_or_path: str) -> pathlib.Path:
    """Accepte soit un chemin local, soit une URI file://… ; renvoie un Path."""
    if uri_or_path.startswith("file://"):
        parsed = urlparse(uri_or_path)
        path = parsed.path or ""
        # Sur Windows, urlparse('/C:/path') -> '/C:/path'
        re_match = match(r"^/([A-Za-z]:/.*)$", path)
        if os.name == "nt" and re_match:
            path = re_match.group(1)
        return pathlib.Path(unquote(path))
    return pathlib.Path(uri_or_path)


def validate_and_resolve(path_like: str | os.PathLike[str], allowlist_dirs: Iterable[str]) -> pathlib.Path:
    """Résout un chemin et vérifie qu’il est bien dans la sandbox (allowlist)."""
    path = parse_file_uri(str(path_like))
    resolved = _normpath(path)

    allowlist_paths = [_normpath(pathlib.Path(p)) for p in allowlist_dirs]
    if not _is_subpath(resolved, allowlist_paths):
        raise PathOutsideSandbox(f"{resolved} is outside of allowed directories")
    return resolved
