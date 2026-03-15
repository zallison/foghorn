"""
Brief: Tests that SIGUSR2 calls handle_sigusr2 on active plugins.

Inputs:
  - monkeypatch, caplog

Outputs:
  - None: asserts plugin handler is called and log reflects invocation count
"""

import logging
from unittest.mock import mock_open, patch

import foghorn.main as main_mod


def test_sigusr2_calls_plugin_handlers(monkeypatch, caplog):
    """
    Brief: Verify that sending SIGUSR2 triggers handle_sigusr2 on each active plugin.

    Inputs:
      - monkeypatch/caplog
    Outputs:
      - None
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
    )

    class DummyPlugin:
        def __init__(self, **kw):
            self.called = False

        def handle_sigusr2(self):
            self.called = True

    captured = {"handler": None}

    def fake_signal(sig, handler):
        import signal as _signal

        if sig == _signal.SIGUSR2:
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

    called = {"sent": False}

    def _sleep_once(_sec: float) -> None:
        assert captured["handler"] is not None
        if not called["sent"]:
            called["sent"] = True
            captured["handler"](None, None)
            return None
        raise KeyboardInterrupt

    # load_plugins returns two plugins
    dummy_plugins = [DummyPlugin(), DummyPlugin()]
    monkeypatch.setattr(main_mod, "load_plugins", lambda specs: dummy_plugins)

    monkeypatch.setattr(
        udp_asyncio_mod,
        "start_udp_asyncio_threaded",
        lambda *_a, **_kw: DummyUDPHandle(),
    )
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(time, "sleep", _sleep_once)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        caplog.set_level(logging.INFO)
        rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert all(p.called for p in dummy_plugins)
    # Ensure log mentions invocation count
    assert any(
        "SIGUSR2: invoked signal handler hook on 2 plugins" in r.message
        for r in caplog.records
    )
