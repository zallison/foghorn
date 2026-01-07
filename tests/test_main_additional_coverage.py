"""
Brief: Additional tests for foghorn.main to cover remaining uncovered branches.

Inputs:
  - None directly; pytest fixtures like monkeypatch/caplog are used per test.

Outputs:
  - None: assertions ensure that previously uncovered lines in foghorn.main are executed.
"""

from __future__ import annotations

import logging
import signal as _signal
from types import SimpleNamespace
from typing import Any, Dict
from unittest.mock import mock_open, patch

import pytest

import foghorn.main as main_mod


class _FakeThreadingModule:
    """Test helper: module-like shim that overrides Thread but proxies others.

    Inputs:
      - real_module: The real threading module.
      - thread_cls: Replacement Thread implementation for tests.

    Outputs:
      - An object suitable for insertion into sys.modules['threading'] that
        exposes Thread as thread_cls while delegating all other attributes to
        real_module.
    """

    def __init__(self, real_module, thread_cls) -> None:  # type: ignore[no-untyped-def]
        self._real = real_module
        self.Thread = thread_cls

    def __getattr__(self, name):  # type: ignore[no-untyped-def]
        return getattr(self._real, name)
from foghorn.plugins.cache.none import NullCache
from foghorn.config.config_parser import normalize_upstream_config
from foghorn.main import _clear_lru_caches, run_setup_plugins
from foghorn.plugins.resolve.base import BasePlugin


def test_clear_lru_caches_none_and_explicit_list():
    """Brief: _clear_lru_caches handles None and explicit wrapper lists.

    Inputs:
      - None: calls _clear_lru_caches(None) and _clear_lru_caches([wrapper]).

    Outputs:
      - None: asserts explicit wrapper.cache_clear() was invoked; no exceptions are raised.
    """

    class DummyWrapper:
        def __init__(self) -> None:
            self.cleared = False

        def cache_clear(self) -> None:
            self.cleared = True

    # Explicit list path exercises the for-loop over provided wrappers.
    w = DummyWrapper()
    _clear_lru_caches([w])
    assert w.cleared is True

    # None path exercises the gc-discovery path and ensures it does not raise.
    # We do not depend on actual gc contents for coverage.
    _clear_lru_caches(None)


def test_normalize_upstream_config_missing_host_and_optional_fields():
    """Brief: normalize_upstream_config enforces host and preserves optional fields.

    Inputs:
      - cfg with an upstream entry missing host.
      - cfg with an upstream entry including transport/tls/pool.

    Outputs:
      - None: asserts ValueError for missing host and presence of optional keys.
    """

    # Missing host should raise and cover the validation branch.
    with pytest.raises(ValueError):
        normalize_upstream_config({"upstreams": [{}]})

    # Optional fields transport/tls/pool should be preserved and timeout_ms is
    # read from the foghorn header section with a default when omitted.
    cfg: Dict[str, Any] = {
        "upstreams": [
            {
                "host": "1.2.3.4",
                "port": 853,
                "transport": "dot",
                "tls": {"verify": True},
                "pool": {"size": 4},
            }
        ],
        "foghorn": {"timeout_ms": 2000},
    }
    ups, timeout_ms = normalize_upstream_config(cfg)
    assert timeout_ms == 2000
    assert ups == [
        {
            "host": "1.2.3.4",
            "port": 853,
            "transport": "dot",
            "tls": {"verify": True},
            "pool": {"size": 4},
        }
    ]


def test_run_setup_plugins_priority_and_fallback(monkeypatch, caplog):
    """Brief: run_setup_plugins sorts by priority and falls back on bad values.

    Inputs:
      - monkeypatch/caplog fixtures; two setup-capable plugins with different
        setup_priority values (one invalid for int()).

    Outputs:
      - None: asserts setup() is called for both plugins and that the invalid
        priority falls back to the default value without raising.
    """

    class POK(BasePlugin):
        def __init__(self) -> None:
            self.config = {"abort_on_failure": True}
            self.calls: list[str] = []

        def setup(self) -> None:  # type: ignore[override]
            self.calls.append("ok")

    class BadPriority:
        def __int__(self) -> int:  # pragma: no cover - exercised via int() call
            raise ValueError("bad priority")

    class PBAD(BasePlugin):
        def __init__(self) -> None:
            # setup_priority that will cause int() to raise, hitting the
            # except branch and defaulting to 50.
            self.setup_priority = BadPriority()
            self.config = {"abort_on_failure": False}
            self.calls: list[str] = []

        def setup(self) -> None:  # type: ignore[override]
            self.calls.append("bad")

    plugins = [POK(), PBAD()]

    caplog.set_level(logging.INFO, logger="foghorn.main.setup")
    run_setup_plugins(plugins)

    # Both plugins must have had setup() invoked despite the bad priority.
    assert plugins[0].calls == ["ok"]
    assert plugins[1].calls == ["bad"]
    # An info log should have been emitted for each plugin.
    messages = [r.message for r in caplog.records]
    assert any("Running setup for plugin" in m for m in messages)


def test_main_returns_one_when_run_setup_plugins_fails(monkeypatch, caplog):
    """Brief: main() returns 1 when run_setup_plugins raises RuntimeError.

    Inputs:
      - monkeypatch/caplog fixtures; run_setup_plugins patched to raise.

    Outputs:
      - None: asserts return code 1 and error log about plugin setup failure.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
        "plugins: []\n"
    )

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:  # pragma: no cover
            raise AssertionError("DNSServer should not be constructed when setup fails")

        def serve_forever(self) -> None:  # pragma: no cover
            raise KeyboardInterrupt

    def boom_run_setup(_plugins: list[Any]) -> None:
        raise RuntimeError("setup failed")

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "run_setup_plugins", boom_run_setup)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.ERROR, logger="foghorn.main"):
            rc = main_mod.main(["--config", "conf.yaml"])

    assert rc == 1
    assert any("Plugin setup failed" in r.message for r in caplog.records)


def test_main_installs_cache_plugin_without_udp_listener(monkeypatch) -> None:
    """Brief: main() installs cache.module even when listen.udp.enabled=false.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts global DNS_CACHE is a NullCache instance.
    """

    yaml_data = (
        "server:\n"
        "  http:\n"
        "    enabled: false\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: false\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "  cache:\n"
        "    module: none\n"
        "    config: {}\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
        "plugins: []\n"
    )

    # Avoid spinning up real webserver components during this unit test.
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **kw: None)

    # Force the keepalive loop to exit promptly when no listeners are enabled.
    import time as _time

    def _boom(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(_time, "sleep", _boom)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "no_udp.yaml"])

    assert rc == 0

    from foghorn.plugins.resolve import base as plugin_base

    assert isinstance(plugin_base.DNS_CACHE, NullCache)


def _capture_sig_handlers() -> Dict[str, Any]:
    """Brief: Helper to capture SIGUSR1/SIGUSR2 handlers when main() registers them.

    Inputs:
      - None directly; used with monkeypatch to override signal.signal.

    Outputs:
      - dict with keys 'sigusr1' and 'sigusr2' for later invocation.
    """

    captured: Dict[str, Any] = {"sigusr1": None, "sigusr2": None}

    def fake_signal(sig, handler):
        if sig == _signal.SIGUSR1:
            captured["sigusr1"] = handler
        elif sig == _signal.SIGUSR2:
            captured["sigusr2"] = handler
        return None

    return {"captured": captured, "fake_signal": fake_signal}

    pytest.skip("SIGUSR1 no longer reloads configuration from disk.")


def test_sigusr1_skip_reset_and_coalescing(monkeypatch, caplog):
    """Brief: SIGUSR1 coalesces multiple signals and can skip statistics reset.

    Inputs:
      - monkeypatch/caplog fixtures; handler closure is inspected to set pending flag.

    Outputs:
      - None: asserts reset is skipped and that when the pending flag is set,
        the handler returns early without invoking reload logic.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
        "stats:\n"
        "  enabled: true\n"
        "  sigusr2_resets_stats: false\n"
    )

    handler_info = _capture_sig_handlers()
    captured = handler_info["captured"]
    fake_signal = handler_info["fake_signal"]

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            # Trigger handler normally once.
            if captured["sigusr1"] is not None:
                captured["sigusr1"](None, None)
            raise KeyboardInterrupt

    # First run: normal SIGUSR1 to exercise skip-reset logging.
    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        caplog.set_level(logging.INFO)
        rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert any("statistics reset skipped" in r.message for r in caplog.records)

    # Second run: ensure coalescing early-exit path is exercised by setting
    # the pending Event in the handler closure before calling it.
    handler_info = _capture_sig_handlers()
    captured = handler_info["captured"]
    fake_signal = handler_info["fake_signal"]

    call_counter = {"count": 0}

    class DummyServer2:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            handler = captured["sigusr1"]
            # Locate the pending Event in the closure and set it.
            pending_event = None
            for cell in handler.__closure__ or ():
                if hasattr(cell.cell_contents, "is_set") and hasattr(
                    cell.cell_contents, "set"
                ):
                    pending_event = cell.cell_contents
                    break
            assert pending_event is not None
            pending_event.set()

            # Monkeypatch internal _process_sigusr1 via attribute on closure
            # cell to count invocations.
            def proxy_process(*_a: Any, **_k: Any) -> None:
                call_counter["count"] += 1

            # Replace _process_sigusr1 in the handler's globals so that if the
            # body executes, our proxy increments the counter.
            handler.__globals__["_process_sigusr1"] = proxy_process

            handler(None, None)
            raise KeyboardInterrupt

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer2)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "cfg2.yaml"])

    assert rc == 0
    # Because the pending flag was set, proxy_process should not have been called.
    assert call_counter["count"] == 0


def test_sigusr1_registration_failure_logs_warning(monkeypatch, caplog):
    """Brief: main() logs a warning if SIGUSR1 handler registration fails.

    Inputs:
      - monkeypatch/caplog fixtures; signal.signal is patched to raise on SIGUSR1.

    Outputs:
      - None: asserts warning log is emitted and main() still returns cleanly.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    def fake_signal(sig, handler):
        if sig == _signal.SIGUSR1:
            raise RuntimeError("no SIGUSR1")
        return None

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.WARNING, logger="foghorn.main"):
            rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert any("Could not install SIGUSR1 handler" in r.message for r in caplog.records)


def test_sigusr2_error_paths_more(monkeypatch, caplog):
    """Brief: SIGUSR2 covers stats reset error, no-collector branch, plugin error, and coalescing.

    Inputs:
      - monkeypatch/caplog fixtures; customized stats collector and plugins.

    Outputs:
      - None: asserts appropriate logs for error/no-collector paths and that
        when the pending Event is set, the handler exits early.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
        "stats:\n"
        "  enabled: true\n"
        "  sigusr2_resets_stats: true\n"
    )

    handler_info = _capture_sig_handlers()
    captured = handler_info["captured"]
    fake_signal = handler_info["fake_signal"]

    class ErrorCollector:
        """Brief: Collector whose snapshot(reset=True) raises to test error branch.

        Inputs:
          - reset flag (ignored).

        Outputs:
          - None: always raises on reset; otherwise returns dummy snapshot.
        """

        def snapshot(self, reset: bool = False):  # type: ignore[override]
            if reset:
                raise RuntimeError("reset failure")
            return SimpleNamespace(totals={})

    class DummyPlugin:
        def __init__(self, **kw: Any) -> None:
            self.called = False

        def handle_sigusr2(self) -> None:
            self.called = True

    class ErrorPlugin(DummyPlugin):
        def handle_sigusr2(self) -> None:  # type: ignore[override]
            raise RuntimeError("plugin boom")

    plugins = [DummyPlugin(), ErrorPlugin()]

    def fake_load_plugins(_specs):
        return plugins

    call_counter = {"count": 0}

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            handler = captured["sigusr2"]
            # First call: normal path with collector and plugins to cover
            # reset error and plugin error branches.
            handler(None, None)
            # Second call: set cfg to a non-dict so statistics inspection
            # path raises when accessing get(), triggering the outer defensive
            # except around configuration handling.
            for cell in handler.__closure__ or ():
                if (
                    isinstance(cell.cell_contents, dict)
                    and "statistics" in cell.cell_contents
                ):
                    cell.cell_contents = None  # type: ignore[assignment]
                    break
            handler(None, None)
            # Third call: set pending flag for coalescing and ensure inner
            # logic does not re-run.
            pending_event = None
            for cell in handler.__closure__ or ():
                if hasattr(cell.cell_contents, "is_set") and hasattr(
                    cell.cell_contents, "set"
                ):
                    pending_event = cell.cell_contents
                    break
            assert pending_event is not None
            pending_event.set()

            def proxy_process_sigusr2():
                call_counter["count"] += 1

            handler.__globals__["_process_sigusr2"] = proxy_process_sigusr2
            handler(None, None)
            raise KeyboardInterrupt

    # Attach ErrorCollector as StatsCollector so SIGUSR2 reset path errors.
    monkeypatch.setattr(main_mod, "StatsCollector", lambda **kw: ErrorCollector())
    monkeypatch.setattr(main_mod, "load_plugins", fake_load_plugins)
    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        caplog.set_level(logging.INFO)
        rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    # Ensure error during statistics reset logged.
    assert any(
        "SIGUSR2: error during statistics reset" in r.message for r in caplog.records
    )
    # Coalescing: proxy_process_sigusr2 should not have been called.
    assert call_counter["count"] == 0


def test_sigusr2_logs_no_collector_active(monkeypatch, caplog):
    """Brief: SIGUSR2 logs a message when no statistics collector is active.

    Inputs:
      - monkeypatch/caplog fixtures; StatsCollector patched to return None.

    Outputs:
      - None: asserts informational log about skipping reset when no collector exists.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
        "stats:\n"
        "  enabled: true\n"
        "  sigusr2_resets_stats: true\n"
    )

    handler_info = _capture_sig_handlers()
    captured = handler_info["captured"]
    fake_signal = handler_info["fake_signal"]

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            handler = captured["sigusr2"]
            handler(None, None)
            raise KeyboardInterrupt

    # StatsCollector returns None so the SIGUSR2 handler sees no active collector.
    monkeypatch.setattr(main_mod, "StatsCollector", lambda **kw: None)
    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.INFO, logger="foghorn.main"):
            rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert any(
        "SIGUSR2: no statistics collector active, skipping reset" in r.message
        for r in caplog.records
    )


def test_sigusr2_registration_failure_logs_warning(monkeypatch, caplog):
    """Brief: main() logs a warning if SIGUSR2 handler registration fails.

    Inputs:
      - monkeypatch/caplog fixtures; signal.signal is patched to raise on SIGUSR2.

    Outputs:
      - None: asserts warning log is emitted and main() still returns cleanly.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    def fake_signal(sig, handler):
        if sig == _signal.SIGUSR2:
            raise RuntimeError("no SIGUSR2")
        return None

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.WARNING, logger="foghorn.main"):
            rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert any("Could not install SIGUSR2 handler" in r.message for r in caplog.records)


def test_sighup_with_udp_enabled_exits_cleanly(monkeypatch, caplog):
    """Brief: SIGHUP triggers coordinated shutdown when UDP is enabled.

    Inputs:
      - monkeypatch/caplog fixtures; we capture the SIGHUP handler via a
        fake signal.signal implementation and invoke it from the UDP
        server's serve_forever method.

    Outputs:
      - None: asserts main() returns 0 and logs the SIGHUP shutdown message.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    captured: Dict[str, Any] = {"sighup": None}

    def fake_signal(sig, handler):
        import signal as _signal

        if sig == _signal.SIGHUP:
            captured["sighup"] = handler
        return None

    class DummyServer:
        """Brief: UDP server stub that invokes SIGHUP handler then exits.

        Inputs:
          - Same signature as DNSServer; extra kwargs are ignored.

        Outputs:
          - serve_forever calls the captured SIGHUP handler once and returns.
        """

        def __init__(self, *a: Any, **kw: Any) -> None:
            self.stop_calls = 0

        def serve_forever(self) -> None:
            handler = captured["sighup"]
            assert handler is not None
            # Invoke the handler to trigger coordinated shutdown; do not
            # raise so that udp_error remains None and exit_code stays 0.
            handler(None, None)

        def stop(self) -> None:
            # Track that stop() was invoked without affecting control flow.
            self.stop_calls += 1

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.INFO, logger="foghorn.main"):
            rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert any(
        "Received SIGHUP, initiating shutdown" in r.message for r in caplog.records
    )


def test_start_without_udp_uses_keepalive_loop(monkeypatch, caplog):
    """Brief: main() logs when starting without UDP listener and enters keepalive loop.

    Inputs:
      - monkeypatch/caplog fixtures; listen.udp.enabled is false and time.sleep
        is patched to raise KeyboardInterrupt.

    Outputs:
      - None: asserts informational log and that keepalive path exits cleanly.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    host: 127.0.0.1\n"
        "    port: 5354\n"
        "    udp:\n"
        "      enabled: false\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    # Ensure DNSServer is never constructed because UDP is disabled.
    def forbidden_dnserver(*a: Any, **kw: Any) -> None:  # pragma: no cover - defensive
        raise AssertionError(
            "DNSServer should not be constructed when udp.enabled=false"
        )

    class DummyHandle:
        def stop(self) -> None:
            pass

    def fake_sleep(_sec: int) -> None:
        raise KeyboardInterrupt

    import sys as _sys

    monkeypatch.setattr(main_mod, "DNSServer", forbidden_dnserver)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **k: DummyHandle())
    # Patch the _time module alias imported inside main for the keepalive loop.
    monkeypatch.setitem(_sys.modules, "time", SimpleNamespace(sleep=fake_sleep))

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.INFO, logger="foghorn.main"):
            rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert any(
        "Starting Foghorn without UDP listener" in r.message for r in caplog.records
    )


def test_tcp_permission_error_falls_back_to_threaded(monkeypatch, caplog):
    """Brief: TCP listener falls back to serve_tcp_threaded when asyncio loop creation fails.

    Inputs:
      - monkeypatch/caplog fixtures; asyncio.new_event_loop raises PermissionError and
        threading.Thread is replaced so runner executes synchronously.

    Outputs:
      - None: asserts serve_tcp_threaded is invoked.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    host: 127.0.0.1\n"
        "    port: 5354\n"
        "    tcp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

    called = {"threaded": 0}

    def fake_serve_tcp_threaded(*a: Any, **kw: Any) -> None:
        called["threaded"] += 1

    def fake_new_event_loop():
        raise PermissionError("blocked")

    class DummyThread:
        def __init__(self, target=None, name=None, daemon=None) -> None:
            self._target = target
            self.name = name
            self.daemon = daemon

        def start(self) -> None:
            # Run the target synchronously to keep the test single-threaded.
            if self._target is not None:
                self._target()

    import asyncio as _asyncio
    import sys as _sys
    import threading as _threading

    fake_threading = _FakeThreadingModule(_threading, DummyThread)

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )
    # Patch the underlying tcp_server module so that when main() imports
    # serve_tcp_threaded, it receives our stub.
    monkeypatch.setattr(
        "foghorn.servers.tcp_server.serve_tcp_threaded", fake_serve_tcp_threaded
    )
    # Patch asyncio's global new_event_loop so that the instance imported in
    # foghorn.main sees the PermissionError, and ensure that the dynamic
    # import inside _start_asyncio_server sees our fake threading module.
    monkeypatch.setattr(_asyncio, "new_event_loop", fake_new_event_loop)
    monkeypatch.setitem(_sys.modules, "threading", fake_threading)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.INFO, logger="foghorn.main"):
            rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert called["threaded"] >= 1


def test_dot_permission_error_logs_without_fallback(monkeypatch, caplog):
    """Brief: DoT listener logs an error when asyncio loop fails and no fallback is provided.

    Inputs:
      - monkeypatch/caplog fixtures; listen.dot.enabled is true, asyncio.new_event_loop
        raises PermissionError, and threading.Thread runs runner synchronously.

    Outputs:
      - None: asserts error log is emitted for DoT PermissionError.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    host: 127.0.0.1\n"
        "    port: 5354\n"
        "    dot:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 8853\n"
        "      cert_file: cert.pem\n"
        "      key_file: key.pem\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

    def fake_new_event_loop():
        raise PermissionError("blocked")

    class DummyThread:
        def __init__(self, target=None, name=None, daemon=None) -> None:
            self._target = target
            self.name = name
            self.daemon = daemon

        def start(self) -> None:
            if self._target is not None:
                self._target()

    import asyncio as _asyncio
    import sys as _sys
    import threading as _threading

    fake_threading = _FakeThreadingModule(_threading, DummyThread)

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )
    # Patch asyncio's global new_event_loop so that the instance imported in
    # foghorn.main sees the PermissionError, and ensure that the dynamic
    # import of threading used by _start_asyncio_server resolves to our
    # fake module.
    monkeypatch.setattr(_asyncio, "new_event_loop", fake_new_event_loop)
    monkeypatch.setitem(_sys.modules, "threading", fake_threading)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.ERROR, logger="foghorn.main"):
            rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert any(
        "Asyncio loop creation failed with PermissionError for foghorn-dot" in r.message
        for r in caplog.records
    )


def test_dot_start_logs_info(monkeypatch, caplog):
    """Brief: main() logs informational message when starting DoT listener.

    Inputs:
      - monkeypatch/caplog fixtures; listen.dot.enabled is true and _start_asyncio_server
        is patched to a no-op.

    Outputs:
      - None: asserts DoT startup info log is emitted.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    host: 127.0.0.1\n"
        "    port: 5354\n"
        "    dot:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 8853\n"
        "      cert_file: cert.pem\n"
        "      key_file: key.pem\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

    # Prevent real background threads by forcing threading.Thread used by
    # _start_asyncio_server to be a dummy implementation whose start() is a no-op.
    class DummyThread:
        def __init__(self, target=None, name=None, daemon=None) -> None:
            self._target = target
            self.name = name
            self.daemon = daemon

        def start(self) -> None:
            return None

    import sys as _sys
    import threading as _threading

    fake_threading = _FakeThreadingModule(_threading, DummyThread)

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )
    monkeypatch.setitem(_sys.modules, "threading", fake_threading)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.INFO, logger="foghorn.main"):
            rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert any("Starting DoT listener on" in r.message for r in caplog.records)


def test_asyncio_server_happy_path_runs_and_closes_loop(monkeypatch):
    """Brief: _start_asyncio_server runs coroutine and closes loop on success.

    Inputs:
      - monkeypatch fixture; asyncio event loop and threading.Thread patched.

    Outputs:
      - None: asserts DummyLoop.run_until_complete and close are both called.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    host: 127.0.0.1\n"
        "    port: 5354\n"
        "    tcp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

    holder: Dict[str, Any] = {}

    class DummyLoop:
        def __init__(self) -> None:
            self.run_called = False
            self.closed = False

        def run_until_complete(self, coro) -> None:  # noqa: ARG002
            self.run_called = True

        def close(self) -> None:
            self.closed = True

    import asyncio as _asyncio
    import sys as _sys
    import threading as _threading

    def fake_new_event_loop() -> DummyLoop:
        loop = DummyLoop()
        holder["loop"] = loop
        return loop

    def fake_set_event_loop(loop: DummyLoop) -> None:
        holder["loop_set"] = loop

    def fake_get_event_loop() -> DummyLoop:
        return holder["loop"]

    async def fake_serve_tcp(host, port, resolver):  # noqa: ARG002
        return None

    class DummyThread:
        def __init__(self, target=None, name=None, daemon=None) -> None:  # noqa: D401
            """Thread stub that runs target synchronously in tests."""

            self._target = target
            self.name = name
            self.daemon = daemon

        def start(self) -> None:
            if self._target is not None:
                self._target()

    fake_threading = _FakeThreadingModule(_threading, DummyThread)

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )
    # Ensure serve_tcp imported inside main() refers to our stub and that
    # _start_asyncio_server uses our DummyThread implementation instead of the
    # real threading.Thread.
    monkeypatch.setattr("foghorn.servers.tcp_server.serve_tcp", fake_serve_tcp)
    monkeypatch.setattr(_asyncio, "new_event_loop", fake_new_event_loop)
    monkeypatch.setattr(_asyncio, "set_event_loop", fake_set_event_loop)
    monkeypatch.setattr(_asyncio, "get_event_loop", fake_get_event_loop)
    monkeypatch.setitem(_sys.modules, "threading", fake_threading)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "cfg_asyncio.yaml"])

    assert rc == 0
    assert holder["loop"].run_called is True
    assert holder["loop"].closed is True


def test_doh_start_failure_returns_one(monkeypatch, caplog):
    """Brief: main() returns 1 when DoH server start throws an exception.

    Inputs:
      - monkeypatch/caplog fixtures; listen.doh.enabled is true and start_doh_server
        is patched to raise RuntimeError.

    Outputs:
      - None: asserts exit code 1 and error log.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    host: 127.0.0.1\n"
        "    port: 5354\n"
        "    doh:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 8053\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

    def boom_start_doh(*a: Any, **kw: Any):
        raise RuntimeError("broken")

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )
    monkeypatch.setattr(main_mod, "start_doh_server", boom_start_doh)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.ERROR, logger="foghorn.main"):
            rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 1
    assert any("Failed to start DoH server" in r.message for r in caplog.records)


def test_webserver_stop_called_on_shutdown(monkeypatch, caplog):
    """Brief: main() stops the webserver handle on shutdown.

    Inputs:
      - monkeypatch/caplog fixtures; webserver.enabled is true and start_webserver
        returns a handle with stop() recording calls.

    Outputs:
      - None: asserts web_handle.stop() is invoked and logged.
    """

    yaml_data = (
        "server:\n"
        "  http:\n    enabled: true\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

    class DummyWebHandle:
        def __init__(self) -> None:
            self.stopped = False

        def stop(self) -> None:
            self.stopped = True

    handle = DummyWebHandle()

    def fake_start_webserver(*a: Any, **k: Any) -> DummyWebHandle:
        return handle

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", fake_start_webserver)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.INFO, logger="foghorn.main"):
            rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert handle.stopped is True
    assert any("Stopping webserver" in r.message for r in caplog.records)


def test_main_returns_one_on_config_validation_error(monkeypatch, capsys):
    """Brief: main() returns 1 and prints the config parsing/validation error.

    Inputs:
      - monkeypatch/capsys fixtures; parse_config_file patched to raise ValueError.

    Outputs:
      - None: asserts exit code 1 and that the error message is printed to stdout.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    def boom_parse_config_file(*_a: Any, **_kw: Any) -> Dict[str, Any]:  # noqa: ANN401
        raise ValueError("bad config value")

    monkeypatch.setattr(main_mod, "parse_config_file", boom_parse_config_file)
    # init_logging should not be called, but keep it harmless if it is.
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "invalid.yaml"])

    assert rc == 1
    out = capsys.readouterr().out
    assert "bad config value" in out


def test_sigterm_sigint_hard_kill_timer_and_early_return(monkeypatch, caplog):
    """Brief: SIGTERM/SIGINT trigger coordinated shutdown, hard-kill timer, and early-return path.

    Inputs:
      - monkeypatch/caplog fixtures; signal.signal and threading.Timer patched.

    Outputs:
      - None: asserts exit code 2, hard-kill error log, and that the shutdown
        request is only processed once when called repeatedly.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    captured: Dict[str, Any] = {"sigterm": None, "sigint": None, "force_exit": None}

    def fake_signal(sig, handler):
        if sig == _signal.SIGTERM:
            captured["sigterm"] = handler
        elif sig == _signal.SIGINT:
            captured["sigint"] = handler
        return None

    class DummyTimer:
        """Brief: Timer stub that captures the _force_exit callback without running it.

        Inputs:
          - interval: float timeout in seconds (ignored).
          - func: callback to invoke on timeout.

        Outputs:
          - None directly; stores callback in captured["force_exit"].
        """

        def __init__(self, interval: float, func, *a, **kw) -> None:  # noqa: ARG002
            captured["force_exit"] = func
            self.daemon = False

        def start(self) -> None:
            # Do not invoke the callback automatically; tests call it explicitly.
            return None

    class DummyServer:
        """Brief: UDP server stub that drives SIGTERM/SIGINT handlers and exits.

        Inputs:
          - Same signature as DNSServer; extra args are ignored.

        Outputs:
          - serve_forever orchestrates signal handlers and then raises KeyboardInterrupt
            so main() can proceed to its shutdown sequence.
        """

        def __init__(self, *a: Any, **kw: Any) -> None:  # noqa: ARG002
            self.server = SimpleNamespace(
                shutdown=lambda: None,
                server_close=lambda: None,
            )

        def serve_forever(self) -> None:
            # First call: normal SIGTERM path to request shutdown and arm timer.
            sigterm = captured["sigterm"]
            assert sigterm is not None
            sigterm(None, None)

            # Second call: exercise early-return path when shutdown already requested.
            sigterm(None, None)

            # Also ensure SIGINT handler delegates correctly to _request_shutdown.
            sigint = captured["sigint"]
            assert sigint is not None
            sigint(None, None)

            # Invoke hard-kill callback while shutdown_complete is still False to
            # exercise the error/logging path inside _force_exit.
            force_exit = captured["force_exit"]
            assert force_exit is not None
            force_exit()

            raise KeyboardInterrupt

    kills: Dict[str, Any] = {"calls": []}
    exits: Dict[str, Any] = {"code": None}

    def fake_kill(pid: int, sig: int) -> None:  # noqa: ARG001
        kills["calls"].append((pid, sig))
        # Simulate failure so _force_exit falls back to os._exit.
        raise RuntimeError("kill failed")

    def fake_os_exit(code: int) -> None:
        exits["code"] = code
        # Do not actually exit the process in tests.
        return None

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(main_mod.threading, "Timer", DummyTimer)
    monkeypatch.setattr(main_mod.os, "kill", fake_kill)
    monkeypatch.setattr(main_mod.os, "_exit", fake_os_exit)
    monkeypatch.setattr(
        main_mod,
        "start_webserver",
        lambda *a, **k: SimpleNamespace(stop=lambda: None),
    )

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.ERROR, logger="foghorn.main"):
            rc = main_mod.main(["--config", "sigterm.yaml"])

    # Exit code 2 corresponds to SIGTERM/SIGINT initiated shutdown.
    assert rc == 2
    assert exits["code"] in (2, None)
    assert kills["calls"]
    assert any(
        "Hard-kill timeout exceeded after SIGTERM" in r.message for r in caplog.records
    )

    # After main() completes, calling the hard-kill callback again should take
    # the fast path where shutdown_complete.is_set() is already True.
    force_exit = captured["force_exit"]
    assert force_exit is not None
    force_exit()


def test_udp_teardown_logs_shutdown_close_and_join_errors(monkeypatch, caplog):
    """Brief: main() logs errors when UDP server shutdown/close/join raise during teardown.

    Inputs:
      - monkeypatch/caplog fixtures; DNSServer and threading.Thread patched.

    Outputs:
      - None: asserts that shutdown, close, and join error messages are logged.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    class FailingSocketServer:
        def shutdown(self) -> None:
            raise RuntimeError("shutdown-fail")

        def server_close(self) -> None:
            raise RuntimeError("close-fail")

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:  # noqa: ARG002
            self.server = FailingSocketServer()

        def serve_forever(self) -> None:
            # UDP loop is never actually started; keepalive loop exits because
            # the thread reports not alive.
            return None

    class DummyThread:
        def __init__(self, target=None, name=None, daemon=None) -> None:  # noqa: D401
            """Thread stub that never starts a real background thread."""

            self._target = target
            self.name = name
            self.daemon = daemon

        def start(self) -> None:
            # Do not invoke target; keepalive loop observes is_alive() == False.
            return None

        def is_alive(self) -> bool:
            return False

        def join(self, timeout: float | None = None) -> None:  # noqa: ARG002
            raise RuntimeError("join-fail")

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.threading, "Thread", DummyThread)
    monkeypatch.setattr(
        main_mod,
        "start_webserver",
        lambda *a, **k: SimpleNamespace(stop=lambda: None),
    )

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.ERROR, logger="foghorn.main"):
            rc = main_mod.main(["--config", "teardown.yaml"])

    assert rc == 0
    messages = [r.message for r in caplog.records]
    assert any("Error while shutting down UDP server" in m for m in messages)
    assert any("Error while closing UDP server socket" in m for m in messages)
    assert any(
        "Error while waiting for UDP server thread to exit" in m for m in messages
    )


def test_udp_teardown_outer_exception_logs_unexpected_error(monkeypatch, caplog):
    """Brief: main() logs an unexpected error when UDP server.server attribute access fails.

    Inputs:
      - monkeypatch/caplog fixtures; DNSServer.server property patched to raise.

    Outputs:
      - None: asserts outer teardown except block logs the unexpected error message.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    class BrokenServerAttr:
        @property
        def server(self):  # type: ignore[override]
            raise RuntimeError("broken-server-attr")

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:  # noqa: ARG002
            self._inner = BrokenServerAttr()

        @property
        def server(self):  # type: ignore[override]
            # Delegate to inner property which raises during getattr in teardown.
            return self._inner.server

        def serve_forever(self) -> None:
            return None

    class DummyThread:
        def __init__(self, target=None, name=None, daemon=None) -> None:  # noqa: D401
            """Thread stub that keeps UDP thread inactive for shutdown tests."""

            self._target = target
            self.name = name
            self.daemon = daemon

        def start(self) -> None:
            return None

        def is_alive(self) -> bool:
            return False

        def join(self, timeout: float | None = None) -> None:  # noqa: ARG002
            return None

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.threading, "Thread", DummyThread)
    monkeypatch.setattr(
        main_mod,
        "start_webserver",
        lambda *a, **k: SimpleNamespace(stop=lambda: None),
    )

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.ERROR, logger="foghorn.main"):
            rc = main_mod.main(["--config", "teardown_outer.yaml"])

    assert rc == 0
    assert any(
        "Unexpected error during UDP server teardown" in r.message
        for r in caplog.records
    )
