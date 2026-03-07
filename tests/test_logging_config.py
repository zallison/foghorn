"""
Brief: Tests for foghorn.logging_config.init_logging and formatters.

Inputs:
  - None

Outputs:
  - None
"""

import logging
import re
from pathlib import Path

from foghorn.config.logging_config import (
    BracketLevelFormatter,
    COLOR_BRIGHT_GREEN,
    COLOR_DARK_GREY,
    COLOR_IP_PORT,
    COLOR_KV_KEY,
    COLOR_KV_SEPARATOR,
    COLOR_KV_VALUE,
    COLOR_LIGHT_GREY,
    COLOR_PLUGIN,
    COLOR_QUOTED,
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


def test_bracket_formatter_color_highlights_tokens():
    """
    Brief: Colored formatter injects ANSI escapes for level, logger, timestamp, and key message tokens.

    Inputs:
      - Formatter configured with color=True
      - Message containing hostname, file path, error code, key/value, and IP:port

    Outputs:
      - None: Asserts ANSI escapes are present in formatted output
    """
    fmt = BracketLevelFormatter(
        fmt="%(asctime)s %(level_tag)s %(name)s: %(message)s", color=True
    )
    rec = logging.LogRecord(
        "foghorn.main",
        logging.ERROR,
        __file__,
        1,
        "failed plugin UpstreamRouter host=api.example.com "
        "upstream=10.10.0.1:5335 file /tmp/a.txt code ERR_TIMEOUT "
        "note='single-quoted' msg=\"double-quoted\" extra(parenthesized) "
        "state: ready "
        "date 2026-03-07 "
        "peer 10.20.30.40:9000 "
        "wrapped (inner_key=10.30.40.50:8053) [inner2=10.9.8.7:53] "
        "bracketed [docker-host] "
        "running setup for plugin filter "
        "meta=a(b)[c] "
        "container_id=e016e8dbb0b7[dd96058298fb79dfb28d55e542941322c0133b5c01a6e5bf3afd]",
        (),
        None,
    )
    out = fmt.format(rec)
    out_without_ansi = re.sub(r"\033\[[0-9;]*m", "", out)
    assert "\033[" in out
    assert "api.example.com" in out
    assert (
        f"{COLOR_KV_KEY}host\033[0m{COLOR_KV_SEPARATOR}=\033[0m"
        f"{COLOR_KV_VALUE}api.example.com\033[0m"
    ) in out
    assert (
        f"{COLOR_KV_KEY}upstream\033[0m{COLOR_KV_SEPARATOR}=\033[0m"
        f"{COLOR_IP_PORT}10.10.0.1\033[0m{COLOR_IP_PORT}:\033[0m{COLOR_IP_PORT}5335\033[0m"
    ) in out
    assert (
        f"{COLOR_IP_PORT}10.20.30.40\033[0m{COLOR_IP_PORT}:\033[0m{COLOR_IP_PORT}9000\033[0m"
    ) in out
    assert (
        "\033[36m(\033[0m"
        f"{COLOR_KV_KEY}inner_key\033[0m{COLOR_KV_SEPARATOR}=\033[0m"
        f"{COLOR_IP_PORT}10.30.40.50\033[0m{COLOR_IP_PORT}:\033[0m{COLOR_IP_PORT}8053\033[0m"
        "\033[36m)\033[0m"
    ) in out
    assert (
        f"{COLOR_DARK_GREY}[\033[0m"
        f"{COLOR_KV_KEY}inner2\033[0m{COLOR_KV_SEPARATOR}=\033[0m"
        f"{COLOR_IP_PORT}10.9.8.7\033[0m{COLOR_IP_PORT}:\033[0m{COLOR_IP_PORT}53\033[0m"
        f"{COLOR_DARK_GREY}]\033[0m"
    ) in out
    assert f"{COLOR_KV_KEY}meta\033[0m{COLOR_KV_SEPARATOR}=\033[0m" in out
    assert "\033[36m(\033[0m" in out
    assert "\033[36m)\033[0m" in out
    assert (
        f"{COLOR_KV_KEY}container_id\033[0m{COLOR_KV_SEPARATOR}=\033[0m"
        f"{COLOR_KV_VALUE}e016e8dbb0b7\033[0m{COLOR_DARK_GREY}[\033[0m"
        f"{COLOR_DARK_GREY}dd96058298fb79dfb28d55e542941322c0133b5c01a6e5bf3afd\033[0m"
        f"{COLOR_DARK_GREY}]\033[0m"
    ) in out
    assert f"{COLOR_DARK_GREY}[\033[0m" in out
    assert f"{COLOR_DARK_GREY}]\033[0m" in out
    assert (
        f"bracketed {COLOR_DARK_GREY}[\033[0mdocker-host{COLOR_DARK_GREY}]\033[0m"
        in out
    )
    assert f"running setup for plugin {COLOR_PLUGIN}filter\033[0m" in out
    assert "host=api.example.com" in out_without_ansi
    assert "state: ready" in out_without_ansi
    assert "upstream=10.10.0.1:5335" in out_without_ansi
    assert "peer 10.20.30.40:9000" in out_without_ansi
    assert (
        "wrapped (inner_key=10.30.40.50:8053) [inner2=10.9.8.7:53]" in out_without_ansi
    )
    assert "bracketed [docker-host]" in out_without_ansi
    assert "running setup for plugin filter" in out_without_ansi
    assert "meta=a(b)[c]" in out_without_ansi
    assert (
        "container_id=e016e8dbb0b7[dd96058298fb79dfb28d55e542941322c0133b5c01a6e5bf3afd]"
    ) in out_without_ansi
    assert "/tmp/a.txt" in out
    assert "ERR_TIMEOUT" in out
    assert "2026-03-07" in out
    assert "UpstreamRouter" in out
    assert f"{COLOR_QUOTED}'single-quoted'\033[0m" in out
    assert f'{COLOR_QUOTED}"double-quoted"\033[0m' in out
    assert "extra(parenthesized)" in out_without_ansi
    assert "\033[34mfoghorn.main\033[0m" in out
    assert f"{COLOR_BRIGHT_GREEN}2026-03-07\033[0m" in out
    assert re.search(
        rf"{re.escape(COLOR_BRIGHT_GREEN)}\d{{4}}-\d{{2}}-\d{{2}}\033\[0m"
        rf"{re.escape(COLOR_LIGHT_GREY)}T\033\[0m"
        rf"{re.escape(COLOR_BRIGHT_GREEN)}\d{{2}}:\d{{2}}:\d{{2}}\033\[0m"
        rf"{re.escape(COLOR_LIGHT_GREY)}Z\033\[0m",
        out,
    )
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z ", out_without_ansi)


def test_init_logging_color_toggle_respects_cfg(monkeypatch):
    """
    Brief: init_logging honors color setting independent of stderr TTY status.

    Inputs:
      - monkeypatch: force sys.stderr.isatty to return False

    Outputs:
      - None: Asserts formatter color mode follows config toggles
    """
    monkeypatch.setattr("sys.stderr.isatty", lambda: False)
    init_logging({"color": False})
    root = logging.getLogger()
    stream_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler)]
    assert stream_handlers
    assert stream_handlers[0].formatter._color is False

    init_logging({"color": True})
    root = logging.getLogger()
    stream_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler)]
    assert stream_handlers
    assert stream_handlers[0].formatter._color is True
