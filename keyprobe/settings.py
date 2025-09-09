from __future__ import annotations
import os
from dataclasses import dataclass, field

@dataclass(frozen=True)
class Settings:
    """Runtime settings for KeyProbe (sans allowlist)."""
    LOG_LEVEL: str = field(default="INFO")
    RESOURCE_TTL_SEC: int = field(default=300)

    @staticmethod
    def from_env() -> "Settings":
        log_level = os.getenv("KEYPROBE_LOG_LEVEL", "INFO").upper()
        ttl_raw = os.getenv("KEYPROBE_RESOURCE_TTL_SEC", "300")
        try:
            ttl = int(ttl_raw)
            if ttl <= 0:
                raise ValueError
        except ValueError:
            ttl = 300
        return Settings(LOG_LEVEL=log_level, RESOURCE_TTL_SEC=ttl)
