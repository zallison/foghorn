"""
Brief: Unit tests for SIGUSR1 handling logic in foghorn.main.

Inputs:
  - monkeypatch, caplog: to capture installed handler and logs

Outputs:
  - None: asserts that on SIGUSR1, statistics may be reset and plugins are notified
    using the same path as SIGUSR2.
"""

import logging
from unittest.mock import mock_open, patch

import foghorn.main as main_mod


def test_sigusr1_resets_stats_and_notifies_plugins(monkeypatch, caplog):
    """Brief: Ensure SIGUSR1 uses the unified user-signal handler.

    Inputs:
      - monkeypatch/caplog fixtures

    Outputs:
      - None: asserts statistics reset and plugin handler invocation via SIGUSR1.
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
        "stats:\n  enabled: true\n  sigusr1_resets_stats: true\n"
    )

    class DummyCollector:
        def __init__(self, *a, **kw):
            self.reset_called = False

        def snapshot(self, reset=False):
            if reset:
                self.reset_called = True

            # Minimal object for compatibility with other code paths
            class S:  # pragma: no cover - structure only
                totals = {}

            return S()

    class DummyPlugin:
        def __init__(self, **kw):
            self.called = False

        def handle_sigusr2(self):
            self.called = True

    captured = {"handler": None}

    def fake_signal(sig, handler):
        import signal as _signal

        if sig == _signal.SIGUSR1:
            captured["handler"] = handler
        return None

    from foghorn.servers import udp_asyncio_server as udp_asyncio_mod
    import time

    class DummyAliveThread:
        def is_alive(self) -> bool:
            return True

        def join(self, timeout=None) -> None:  # noqa: ARG002
            return None

    class DummyUDPHandle:
        def __init__(self) -> None:
            self.thread = DummyAliveThread()

        def stop(self) -> None:
            return None

    def _sleep_once(_sec: float) -> None:
        assert captured["handler"] is not None
        captured["handler"](None, None)
        raise KeyboardInterrupt

    plugins = [DummyPlugin(), DummyPlugin()]
    monkeypatch.setattr(main_mod, "load_plugins", lambda specs: plugins)
    monkeypatch.setattr(
        udp_asyncio_mod,
        "start_udp_asyncio_threaded",
        lambda *_a, **_kw: DummyUDPHandle(),
    )
    monkeypatch.setattr(main_mod, "StatsCollector", DummyCollector)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(time, "sleep", _sleep_once)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        caplog.set_level(logging.INFO)
        rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    # Ensure statistics were reset via SIGUSR1
    assert any(
        "SIGUSR1: statistics reset completed" in r.message for r in caplog.records
    )
    # Ensure plugins were invoked via SIGUSR1 path
    assert all(p.called for p in plugins)
