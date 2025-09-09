import os
from keyprobe.settings import Settings

def test_settings_defaults(monkeypatch):
    monkeypatch.delenv("KEYPROBE_LOG_LEVEL", raising=False)
    monkeypatch.delenv("KEYPROBE_RESOURCE_TTL_SEC", raising=False)
    s = Settings.from_env()
    assert s.LOG_LEVEL == "INFO"
    assert s.RESOURCE_TTL_SEC == 300

def test_settings_parsing(monkeypatch):
    monkeypatch.setenv("KEYPROBE_LOG_LEVEL", "debug")
    monkeypatch.setenv("KEYPROBE_RESOURCE_TTL_SEC", "42")
    s = Settings.from_env()
    assert s.LOG_LEVEL == "DEBUG"
    assert s.RESOURCE_TTL_SEC == 42
