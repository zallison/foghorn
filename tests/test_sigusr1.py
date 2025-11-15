"""
Brief: Unit tests for SIGUSR1 handling logic in foghorn.main.

Inputs:
  - monkeypatch, caplog: to capture installed handler and logs

Outputs:
  - None: asserts that on SIGUSR1, config is reloaded, snapshot is logged, and stats are reset when configured
"""

from unittest.mock import mock_open, patch
import logging
import types

import foghorn.main as main_mod


def test_sigusr1_reload_and_reset(monkeypatch, caplog):
    """
    Brief: Ensure SIGUSR1 reloads config and, when statistics.reset_on_sigusr1 is true, logs a snapshot then resets stats.

    Inputs:
      - monkeypatch/caplog fixtures
    Outputs:
      - None: asserts snapshot log and reset message

    Example:
      Initial config enables stats; SIGUSR1 reload provides reset_on_sigusr1: true.
    """
    # Prepare two configs: initial and after-reload
    initial_yaml = (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n"
        "  - host: 1.1.1.1\n"
        "    port: 53\n"
        "statistics:\n  enabled: true\n  interval_seconds: 1\n"
    )
    reload_yaml = (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n"
        "  - host: 1.1.1.1\n"
        "    port: 53\n"
        "statistics:\n  enabled: true\n  interval_seconds: 1\n  reset_on_sigusr1: true\n"
    )

    # Capture the installed handler
    captured = {"handler": None}

    def fake_signal(sig, handler):
        if sig == getattr(__import__("signal"), "SIGUSR1"):
            captured["handler"] = handler
        # Return a dummy previous handler
        return None

    # Patch DNSServer to simulate a short run and let us invoke the handler before exit
    class DummyServer:
        def __init__(self, *a, **kw):
            pass

        def serve_forever(self):
            # Invoke captured handler (as if a real signal arrived)
            if captured["handler"] is not None:
                captured["handler"](None, None)
            # Now stop the main quickly
            raise KeyboardInterrupt

    # open() should return initial config first, then reload config
    open_calls = {"count": 0}

    def open_side_effect(*args, **kwargs):
        open_calls["count"] += 1
        data = initial_yaml if open_calls["count"] == 1 else reload_yaml
        # Return a mock file handle supporting context manager
        return mock_open(read_data=data)()

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)

    with patch("builtins.open", side_effect=open_side_effect):
        caplog.set_level(logging.INFO)
        rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    # Verify that snapshot was logged by foghorn.stats (single-line JSON expected)
    assert any(
        r.name == "foghorn.stats" and r.levelno == logging.INFO for r in caplog.records
    )
    # Verify reset confirmation in foghorn.main logs
    assert any("statistics reset completed" in r.message for r in caplog.records)
