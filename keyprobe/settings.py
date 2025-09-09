# keyprobe/settings.py
from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import List


def _split_allowlist(value: str | None) -> List[str]:
    if not value:
        return []
    # Autoriser séparateurs compatibles (Linux/Mac ":" ; Windows ";")
    seps = [":", ";"]
    parts = [value]
    for sep in seps:
        parts = sum((p.split(sep) for p in parts), [])
    cleaned = [p.strip() for p in parts if p.strip()]
    return cleaned


@dataclass(frozen=True)
class Settings:
    """Runtime settings for KeyProbe."""

    LOG_LEVEL: str = field(default="INFO")
    RESOURCE_TTL_SEC: int = field(default=300)  # TTL par défaut pour resources éphémères
    # Répertoires autorisés (sandbox). Par défaut : CWD uniquement (safe by default)
    ALLOWLIST_DIRS: List[str] = field(default_factory=lambda: [os.getcwd()])

    @staticmethod
    def from_env() -> "Settings":
        log_level = os.getenv("KEYPROBE_LOG_LEVEL", "INFO").upper()
        ttl_raw = os.getenv("KEYPROBE_RESOURCE_TTL_SEC", "300")
        allowlist_raw = os.getenv("KEYPROBE_ALLOWLIST_DIRS", "")
        allowlist = _split_allowlist(allowlist_raw) or [os.getcwd()]

        try:
            ttl = int(ttl_raw)
            if ttl <= 0:
                raise ValueError
        except ValueError:
            ttl = 300  # fallback safe

        return Settings(
            LOG_LEVEL=log_level,
            RESOURCE_TTL_SEC=ttl,
            ALLOWLIST_DIRS=allowlist,
        )
