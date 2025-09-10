
import datetime as dt
import hashlib
from dataclasses import dataclass
from typing import Literal

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def iso_utc(d: dt.datetime) -> str:
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")

def days_until(ts: dt.datetime) -> int:
    now = dt.datetime.now(dt.timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    delta = ts - now
    return int(delta.total_seconds() // 86400)

Severity = Literal["info", "warn", "error"]

@dataclass
class Warn:
    code: str
    message: str
    severity: Severity = "warn"

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "severity": self.severity}
