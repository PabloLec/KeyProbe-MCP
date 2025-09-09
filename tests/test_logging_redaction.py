# tests/test_logging_redaction.py
import logging
from keyprobe.logging_conf import setup_logging
from keyprobe.settings import Settings

def test_redaction_in_logs(caplog):
    s = Settings(LOG_LEVEL="DEBUG", RESOURCE_TTL_SEC=300)
    setup_logging(s, json_mode=False)

    logger = logging.getLogger("keyprobe.test")
    with caplog.at_level(logging.DEBUG):
        logger.info("password=supersecret token=abc123 foo=bar")
        logger.warning("-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----")

    msgs = [rec.message for rec in caplog.records]
    assert "supersecret" not in "".join(msgs)
    assert "abc123" not in "".join(msgs)
    assert "[REDACTED]" in msgs[0]
    assert "[REDACTED-PRIVATE-KEY]" in msgs[1]
