
import json
import logging
import os
import re
from typing import Any

from .settings import Settings

_SECRET_KV = re.compile(r"(pass(word|phrase)?|token|secret|api[_-]?key)\s*=\s*([^\s,;]+)", re.IGNORECASE)
_PEM_PRIV = re.compile(
    r"-----BEGIN (?:RSA |EC |ED25519 )?PRIVATE KEY-----.*?-----END (?:RSA |EC |ED25519 )?PRIVATE KEY-----",
    re.DOTALL | re.IGNORECASE,
)


class _Redact(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = _PEM_PRIV.sub("[REDACTED-PRIVATE-KEY]", record.msg)
            msg = _SECRET_KV.sub(lambda m: f"{m.group(1)}=[REDACTED]", msg)
            record.msg = msg
        return True


class _JsonFormatter(logging.Formatter):
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
    root = logging.getLogger()
    if getattr(root, "_keyprobe_configured", False):
        return

    level = getattr(logging, settings.LOG_LEVEL, logging.INFO)
    root.setLevel(level)

    if json_mode is None:
        json_mode = os.getenv("KEYPROBE_LOG_JSON", "false").lower() in ("1", "true", "yes")

    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.addFilter(_Redact())
    handler.setFormatter(_JsonFormatter() if json_mode else logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)

    setattr(root, "_keyprobe_configured", True)
