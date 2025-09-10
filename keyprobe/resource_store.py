import time
import uuid
from dataclasses import dataclass
from typing import Callable, Dict, Optional

@dataclass
class ResourceEntry:
    created_at: float
    summary: dict
    tmp_path: Optional[str] = None

class ResourceStore:
    def __init__(self, ttl_seconds: int, now_fn: Callable[[], float] | None = None) -> None:
        self._ttl = ttl_seconds
        self._now = now_fn or time.monotonic
        self._by_id: Dict[str, ResourceEntry] = {}

    def _expired(self, entry: ResourceEntry) -> bool:
        return (self._now() - entry.created_at) > self._ttl

    def purge(self) -> int:
        to_del = [rid for rid, e in self._by_id.items() if self._expired(e)]
        for rid in to_del:
            self._by_id.pop(rid, None)
        return len(to_del)

    def put(self, summary: dict, tmp_path: Optional[str] = None) -> str:
        rid = str(uuid.uuid4())
        self._by_id[rid] = ResourceEntry(created_at=self._now(), summary=summary, tmp_path=tmp_path)
        return rid

    def get(self, rid: str) -> ResourceEntry:
        entry = self._by_id.get(rid)
        if entry is None or self._expired(entry):
            raise KeyError(f"Resource not found or expired: {rid}")
        return entry

    def clear(self) -> None:
        self._by_id.clear()
    def count(self) -> int:
        return len(self._by_id)

    def set_ttl(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
    def get_ttl(self) -> int:
        return self._ttl

    def list_ids(self) -> list[str]:
        return list(self._by_id.keys())

    def list_entries(self) -> dict[str, ResourceEntry]:
        return self._by_id.copy()
