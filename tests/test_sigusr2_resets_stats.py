"""
Brief: Tests that SIGUSR2 resets statistics when configured and still calls plugin handlers.

Inputs:
  - monkeypatch, caplog

Outputs:
  - None: asserts reset happens and plugin handler invocation count is logged
"""

import logging
from unittest.mock import mock_open, patch

import foghorn.main as main_mod


def test_sigusr2_resets_stats_when_configured(monkeypatch, caplog):
    """
    Brief: Verify SIGUSR2 triggers stats reset when statistics.sigusr2_resets_stats is true.

    Inputs:
      - monkeypatch/caplog
    Outputs:
      - None

    Example:
        >>> # Covered by test body
    """
    yaml_data = (
        "upstreams:\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "    use_asyncio: true\n"
        "stats:\n  enabled: true\n  sigusr2_resets_stats: true\n"
    )

    class DummyServer:
        def __init__(self, *a, **kw):
            pass

        def serve_forever(self):
            # Trigger SIGUSR2 handler then exit
            if captured["handler"] is not None:
                captured["handler"](None, None)
            raise KeyboardInterrupt

    class DummyPlugin:
        def __init__(self, **kw):
            self.called = False

        def handle_sigusr2(self):
            self.called = True

    class FakeCollector:
        def __init__(self, *a, **kw):
            self.reset_called = False

        def snapshot(self, reset=False):
            if reset:
                self.reset_called = True

            # Return minimal object consumed by formatters; not used here
            class S:  # pragma: no cover - not used in this test
                totals = {}

            return S()

    captured = {"handler": None}

    def fake_signal(sig, handler):
        import signal as _signal

        if sig == _signal.SIGUSR2:
            captured["handler"] = handler
        return None

    dummy_plugins = [DummyPlugin(), DummyPlugin()]
    monkeypatch.setattr(main_mod, "load_plugins", lambda specs: dummy_plugins)
    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "StatsCollector", FakeCollector)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        caplog.set_level(logging.INFO)
        rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert all(p.called for p in dummy_plugins)
    # Ensure reset log occurred
    assert any(
        "SIGUSR2: statistics reset completed" in r.message for r in caplog.records
    )
    # Ensure plugin invocation count still logged
    assert any(
        "SIGUSR2: invoked handle_sigusr2 on 2 plugins" in r.message
        for r in caplog.records
    )
