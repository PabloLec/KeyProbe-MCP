# tests/test_settings.py
import os
from keyprobe.settings import Settings

def test_settings_defaults(monkeypatch):
    monkeypatch.delenv("KEYPROBE_LOG_LEVEL", raising=False)
    monkeypatch.delenv("KEYPROBE_RESOURCE_TTL_SEC", raising=False)
    monkeypatch.delenv("KEYPROBE_ALLOWLIST_DIRS", raising=False)

    s = Settings.from_env()
    assert s.LOG_LEVEL == "INFO"
    assert s.RESOURCE_TTL_SEC == 300
    # Par défaut : CWD uniquement
    import os as _os
    assert s.ALLOWLIST_DIRS == [_os.getcwd()]

def test_settings_parsing(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYPROBE_LOG_LEVEL", "debug")
    monkeypatch.setenv("KEYPROBE_RESOURCE_TTL_SEC", "42")
    monkeypatch.setenv("KEYPROBE_ALLOWLIST_DIRS", f"{tmp_path}:{tmp_path/'nested'}")

    s = Settings.from_env()
    assert s.LOG_LEVEL == "DEBUG"
    assert s.RESOURCE_TTL_SEC == 42
    assert str(tmp_path) in s.ALLOWLIST_DIRS
