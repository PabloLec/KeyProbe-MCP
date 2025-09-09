# keyprobe/resource_store.py
from __future__ import annotations
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
    """In-memory TTL store for ephemeral resources."""
    def __init__(self, ttl_seconds: int, now_fn: Callable[[], float] | None = None) -> None:
        self._ttl = ttl_seconds
        self._now = now_fn or time.monotonic
        self._by_id: Dict[str, ResourceEntry] = {}

    def _expired(self, entry: ResourceEntry) -> bool:
        return (self._now() - entry.created_at) > self._ttl

    def purge(self) -> int:
        """Remove expired entries; returns count purged."""
        to_del = [rid for rid, e in self._by_id.items() if self._expired(e)]
        for rid in to_del:
            self._by_id.pop(rid, None)
        return len(to_del)

    def put(self, summary: dict, tmp_path: str | None = None) -> str:
        self.purge()
        rid = str(uuid.uuid4())
        self._by_id[rid] = ResourceEntry(created_at=self._now(), summary=summary, tmp_path=tmp_path)
        return rid

    def get(self, rid: str) -> ResourceEntry:
        self.purge()
        entry = self._by_id[rid]
        if self._expired(entry):
            # Si expiré pendant l’accès
            self._by_id.pop(rid, None)
            raise KeyError(rid)
        return entry

    def ttl(self) -> int:
        return self._ttl

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)
