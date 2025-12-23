"""
Brief: Tests for foghorn.logging_config.init_logging and formatters.

Inputs:
  - None

Outputs:
  - None
"""

import logging
from pathlib import Path

from foghorn.config.logging_config import (
    BracketLevelFormatter,
    SyslogFormatter,
    init_logging,
)


def test_init_logging_adds_stderr_handler(caplog):
    """
    Brief: init_logging configures root logger with stderr handler by default.

    Inputs:
      - cfg: minimal dict with level

    Outputs:
      - None: Asserts StreamHandler present and level applied
    """
    caplog.set_level(logging.DEBUG)
    init_logging({"level": "debug"})
    root = logging.getLogger()
    assert any(isinstance(h, logging.StreamHandler) for h in root.handlers)
    logging.getLogger("x").debug("hello")


def test_init_logging_file_handler_writes(tmp_path):
    """
    Brief: init_logging creates file handler and writes formatted entries.

    Inputs:
      - cfg: file path and level

    Outputs:
      - None: Asserts file created and contains message
    """
    log_path = tmp_path / "foghorn.log"
    init_logging({"level": "info", "file": str(log_path)})
    logging.getLogger("test").info("file message")
    content = Path(log_path).read_text()
    assert "file message" in content
    assert "[info]" in content


def test_init_logging_syslog_success(monkeypatch):
    """
    Brief: init_logging attaches a syslog handler when configured.

    Inputs:
      - syslog: True or dict

    Outputs:
      - None: Asserts dummy handler added without raising
    """
    created = {}

    class DummySysLogHandler:
        LOG_USER = object()

        def __init__(self, address=None, facility=None):
            created["address"] = address
            created["facility"] = facility

        def setFormatter(self, fmt):
            created["formatter"] = fmt

    monkeypatch.setattr(logging.handlers, "SysLogHandler", DummySysLogHandler)
    # Boolean syslog config
    init_logging({"syslog": True})
    assert created["address"] == "/dev/log"
    assert "formatter" in created

    # Dict syslog config (exercise address/facility mapping branch)
    created.clear()
    init_logging({"syslog": {"address": ("localhost", 514), "facility": "LOCAL0"}})
    assert created.get("address") == ("localhost", 514)
    assert "formatter" in created


def test_init_logging_syslog_failure_warns(monkeypatch, caplog):
    """
    Brief: init_logging logs a warning if syslog handler setup fails.

    Inputs:
      - monkeypatch: make SysLogHandler raise OSError

    Outputs:
      - None: Asserts warning emitted
    """
    caplog.set_level(logging.WARNING)

    class FailingSysLogHandler:
        LOG_USER = object()

        def __init__(self, *a, **kw):
            raise OSError("no syslog")

    monkeypatch.setattr(logging.handlers, "SysLogHandler", FailingSysLogHandler)

    # Capture warning call on root logger directly to avoid handler interference
    caught = {"msg": None}
    root = logging.getLogger()

    def fake_warning(msg, *args, **kwargs):
        try:
            caught["msg"] = msg % args if args else str(msg)
        except Exception:
            caught["msg"] = str(msg)

    monkeypatch.setattr(root, "warning", fake_warning)

    init_logging({"syslog": True})
    assert caught["msg"] and "Failed to configure syslog" in caught["msg"]


def test_formatters_produce_expected_tags():
    """
    Brief: BracketLevelFormatter and SyslogFormatter include bracketed tags.

    Inputs:
      - LogRecord instances at different levels

    Outputs:
      - None: Asserts formatted strings contain expected tags
    """
    # BracketLevelFormatter
    fmt = BracketLevelFormatter(fmt="%(asctime)s %(level_tag)s %(name)s: %(message)s")
    rec = logging.LogRecord("n", logging.ERROR, __file__, 1, "m", (), None)
    out = fmt.format(rec)
    assert "[error]" in out and "n:" in out

    # SyslogFormatter
    s = SyslogFormatter()
    rec2 = logging.LogRecord("n2", logging.WARNING, __file__, 2, "m2", (), None)
    out2 = s.format(rec2)
    assert out2.startswith("[warn] n2:")
