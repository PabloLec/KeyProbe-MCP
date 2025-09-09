from __future__ import annotations
from pathlib import Path
import pytest

FIX = (Path(__file__).resolve().parent / "fixtures").resolve()

def require(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"Fixture missing: {path} – run scripts/make-fixtures.sh")
    return path

def read_bytes(path: Path) -> bytes:
    return require(path).read_bytes()
