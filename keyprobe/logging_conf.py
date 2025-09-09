# keyprobe/logging_conf.py
from __future__ import annotations
import json
import logging
import os
import re
from typing import Any, Mapping

from .settings import Settings


# Expressions simples pour masquer secrets & blocs sensibles
SECRET_KEYS = re.compile(
    r"(pass(word|phrase)?|token|secret|api[_-]?key)\s*=\s*([^,\s;]+)", re.IGNORECASE
)
PEM_PRIVATE = re.compile(
    r"-----BEGIN (?:RSA |EC |ED25519 )?PRIVATE KEY-----.*?-----END (?:RSA |EC |ED25519 )?PRIVATE KEY-----",
    re.DOTALL | re.IGNORECASE,
)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            # Masquer clés privées PEM
            msg = PEM_PRIVATE.sub("[REDACTED-PRIVATE-KEY]", msg)
            # Masquer k=v de secrets les plus courants
            msg = SECRET_KEYS.sub(lambda m: f"{m.group(1)}=[REDACTED]", msg)
            record.msg = msg
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(settings: Settings, json_mode: bool | None = None) -> None:
    """Configure root logger once, idempotent."""
    root = logging.getLogger()
    if getattr(root, "_keyprobe_configured", False):
        return

    # Déterminer le niveau
    level = getattr(logging, settings.LOG_LEVEL, logging.INFO)
    root.setLevel(level)

    # Formatter (JSON si KEYPROBE_LOG_JSON=true)
    if json_mode is None:
        json_mode = os.getenv("KEYPROBE_LOG_JSON", "false").lower() in ("1", "true", "yes")

    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(JsonFormatter() if json_mode else logging.Formatter("%(levelname)s %(name)s: %(message)s"))

    root.addHandler(handler)
    # Marqueur idempotence
    setattr(root, "_keyprobe_configured", True)
