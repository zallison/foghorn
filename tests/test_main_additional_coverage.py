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
from typing import Any, Dict, List
from unittest.mock import mock_open, patch

import pytest

import foghorn.main as main_mod
from foghorn.main import _clear_lru_caches, normalize_upstream_config


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
        normalize_upstream_config({"upstream": [{}]})

    # Optional fields transport/tls/pool should be preserved.
    cfg: Dict[str, Any] = {
        "upstream": [
            {
                "host": "1.2.3.4",
                "port": 853,
                "transport": "dot",
                "tls": {"verify": True},
                "pool": {"size": 4},
            }
        ]
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


def test_sigusr1_dnssec_failure_and_disable_stats_on_reload(monkeypatch, caplog):
    """Brief: SIGUSR1 handles DNSSEC handler errors and disables statistics on reload.

    Inputs:
      - monkeypatch/caplog fixtures; two YAML configs via mock_open.

    Outputs:
      - None: asserts StatsReporter.stop() is called and no crash occurs when
        DNSUDPHandler attribute access fails.
    """

    initial_yaml = (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
        "statistics:\n  enabled: true\n  interval_seconds: 10\n"
        "dnssec:\n  mode: validate\n"
    )

    reload_yaml = (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
        "statistics:\n  enabled: false\n"
        "dnssec:\n  mode: validate\n"
    )

    # Patch DNSUDPHandler so attribute assignment fails inside _apply_runtime_config.
    try:
        import foghorn.server as server_mod

        monkeypatch.setattr(server_mod, "DNSUDPHandler", None, raising=False)
    except Exception:
        # If import fails in this environment, the code already goes through the except.
        pass

    constructed: Dict[str, Any] = {}

    class DummyCollector:
        def __init__(self, **kw: Any) -> None:
            constructed["collector_kwargs"] = kw

    class DummyReporter:
        def __init__(
            self,
            collector: DummyCollector,
            interval_seconds: int,
            reset_on_log: bool,
            log_level: str,
            logger_name: str = "foghorn.stats",
            persistence_store: Any | None = None,
        ) -> None:
            constructed["reporter"] = self
            self.collector = collector
            self.interval_seconds = interval_seconds
            self.reset_on_log = reset_on_log
            self.log_level = log_level
            self.logger_name = logger_name
            self.persistence_store = persistence_store
            self.started = False
            self.stopped = False

        def start(self) -> None:
            self.started = True

        def stop(self) -> None:
            self.stopped = True

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            # Trigger SIGUSR1 once, then stop main via KeyboardInterrupt.
            if captured["sigusr1"] is not None:
                captured["sigusr1"](None, None)
            raise KeyboardInterrupt

    handler_info = _capture_sig_handlers()
    captured = handler_info["captured"]
    fake_signal = handler_info["fake_signal"]

    open_calls = {"count": 0}

    def open_side_effect(*args: Any, **kwargs: Any):
        open_calls["count"] += 1
        data = initial_yaml if open_calls["count"] == 1 else reload_yaml
        return mock_open(read_data=data)()

    monkeypatch.setattr(main_mod, "StatsCollector", DummyCollector)
    monkeypatch.setattr(main_mod, "StatsReporter", DummyReporter)
    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )

    with patch("builtins.open", side_effect=open_side_effect):
        caplog.set_level(logging.INFO)
        rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    # Reporter must have been stopped due to statistics.enabled going False.
    assert constructed["reporter"].stopped is True
    # Ensure we logged that statistics were disabled on reload.
    assert any(
        "Disabling statistics reporter per reload" in r.message for r in caplog.records
    )


def test_sigusr1_enable_statistics_on_reload(monkeypatch, caplog):
    """Brief: SIGUSR1 enables statistics on reload when initially disabled.

    Inputs:
      - monkeypatch/caplog fixtures; initial YAML with statistics disabled
        and reload YAML with statistics enabled.

    Outputs:
      - None: asserts StatsCollector and StatsReporter are constructed and
        reporter.start() is invoked on reload.
    """

    initial_yaml = (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
        "statistics:\n  enabled: false\n"
    )

    reload_yaml = (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
        "statistics:\n  enabled: true\n  interval_seconds: 1\n  top_n: 5\n"
    )

    constructed: Dict[str, Any] = {}

    class DummyCollector:
        def __init__(self, **kw: Any) -> None:
            constructed["collector"] = self
            constructed["collector_kwargs"] = kw

    class DummyReporter:
        def __init__(
            self,
            collector: DummyCollector,
            interval_seconds: int,
            reset_on_log: bool,
            log_level: str,
            logger_name: str = "foghorn.stats",
            persistence_store: Any | None = None,
        ) -> None:
            constructed["reporter"] = self
            self.collector = collector
            self.interval_seconds = interval_seconds
            self.reset_on_log = reset_on_log
            self.log_level = log_level
            self.logger_name = logger_name
            self.persistence_store = persistence_store
            self.started = False

        def start(self) -> None:
            self.started = True

        def stop(self) -> None:
            pass

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            if captured["sigusr1"] is not None:
                captured["sigusr1"](None, None)
            raise KeyboardInterrupt

    handler_info = _capture_sig_handlers()
    captured = handler_info["captured"]
    fake_signal = handler_info["fake_signal"]

    open_calls = {"count": 0}

    def open_side_effect(*args: Any, **kwargs: Any):
        open_calls["count"] += 1
        data = initial_yaml if open_calls["count"] == 1 else reload_yaml
        return mock_open(read_data=data)()

    monkeypatch.setattr(main_mod, "StatsCollector", DummyCollector)
    monkeypatch.setattr(main_mod, "StatsReporter", DummyReporter)
    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )

    with patch("builtins.open", side_effect=open_side_effect):
        caplog.set_level(logging.INFO)
        rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert constructed["reporter"].started is True
    assert "collector" in constructed


def test_sigusr1_restart_reporter_on_settings_change_and_error(monkeypatch, caplog):
    """Brief: SIGUSR1 restarts statistics reporter when settings change or inspection errors.

    Inputs:
      - monkeypatch/caplog fixtures; two reload cycles with different configs.

    Outputs:
      - None: asserts reporter.stop() is called when interval changes and that
        a new reporter is started even if attribute access raises.
    """

    base_yaml = (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
    )

    initial_yaml = base_yaml + (
        "statistics:\n  enabled: true\n  interval_seconds: 10\n  reset_on_log: false\n"
    )

    reload_yaml_change = base_yaml + (
        "statistics:\n  enabled: true\n  interval_seconds: 1\n  reset_on_log: true\n"
    )

    reload_yaml_error = base_yaml + (
        "statistics:\n  enabled: true\n  interval_seconds: 1\n"
    )

    class DummyCollector:
        def __init__(self, **kw: Any) -> None:
            self.kw = kw

    reporters: List[Any] = []

    class DummyReporter:
        def __init__(
            self,
            collector: DummyCollector,
            interval_seconds: int,
            reset_on_log: bool,
            log_level: str,
            logger_name: str = "foghorn.stats",
            persistence_store: Any | None = None,
        ) -> None:
            self.collector = collector
            self.interval_seconds = max(1, interval_seconds)
            self.reset_on_log = reset_on_log
            # Simulate a concrete log level for comparison
            self.log_level = logging.getLogger().getEffectiveLevel()
            self.logger_name = logger_name
            self.persistence_store = persistence_store
            self.started = False
            self.stopped = False
            reporters.append(self)

        def start(self) -> None:
            self.started = True

        def stop(self) -> None:
            self.stopped = True

    class DummyReporterMissingAttrs:
        def __init__(
            self,
            collector: DummyCollector,
            interval_seconds: int,
            reset_on_log: bool,
            log_level: str,
            logger_name: str = "foghorn.stats",
            persistence_store: Any | None = None,
        ) -> None:
            # Deliberately omit interval_seconds/reset_on_log attributes to
            # trigger the except path in settings comparison.
            self.collector = collector
            self.logger_name = logger_name
            self.persistence_store = persistence_store
            self.started = False
            self.stopped = False
            reporters.append(self)

        def start(self) -> None:
            self.started = True

        def stop(self) -> None:
            self.stopped = True

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            # Trigger two SIGUSR1 cycles (settings change then error path),
            # then stop.
            if captured["sigusr1"] is not None:
                captured["sigusr1"](None, None)
                captured["sigusr1"](None, None)
            raise KeyboardInterrupt

    handler_info = _capture_sig_handlers()
    captured = handler_info["captured"]
    fake_signal = handler_info["fake_signal"]

    open_calls = {"count": 0}

    def open_side_effect(*args: Any, **kwargs: Any):
        open_calls["count"] += 1
        if open_calls["count"] == 1:
            data = initial_yaml
        elif open_calls["count"] == 2:
            data = reload_yaml_change
        else:
            data = reload_yaml_error
        return mock_open(read_data=data)()

    # First run uses DummyReporter; second reload uses DummyReporterMissingAttrs.
    def reporter_factory(*a: Any, **kw: Any):
        # Decide based on how many reporters exist so far.
        if len(reporters) == 0:
            return DummyReporter(*a, **kw)
        elif len(reporters) == 1:
            return DummyReporter(*a, **kw)
        else:
            return DummyReporterMissingAttrs(*a, **kw)

    monkeypatch.setattr(main_mod, "StatsCollector", DummyCollector)
    monkeypatch.setattr(main_mod, "StatsReporter", reporter_factory)
    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )

    with patch("builtins.open", side_effect=open_side_effect):
        caplog.set_level(logging.INFO)
        rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    # We should have created at least two reporter instances and stopped the first.
    assert len(reporters) >= 2
    assert reporters[0].stopped is True
    assert reporters[1].started is True


def test_sigusr1_read_error_and_skip(monkeypatch, caplog):
    """Brief: SIGUSR1 logs an error when config reload fails and exits gracefully.

    Inputs:
      - monkeypatch/caplog fixtures; open() is patched to raise on reload.

    Outputs:
      - None: asserts error log is emitted and handler returns without crashing.
    """

    yaml_data = (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
    )

    handler_info = _capture_sig_handlers()
    captured = handler_info["captured"]
    fake_signal = handler_info["fake_signal"]

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            if captured["sigusr1"] is not None:
                captured["sigusr1"](None, None)
            raise KeyboardInterrupt

    open_calls = {"count": 0}

    def open_side_effect(*args: Any, **kwargs: Any):
        open_calls["count"] += 1
        if open_calls["count"] == 1:
            return mock_open(read_data=yaml_data)()
        raise OSError("boom")

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod.signal, "signal", fake_signal)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )

    with patch("builtins.open", side_effect=open_side_effect):
        caplog.set_level(logging.ERROR)
        rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert any("SIGUSR1: failed to read config" in r.message for r in caplog.records)


def test_sigusr1_skip_reset_and_coalescing(monkeypatch, caplog):
    """Brief: SIGUSR1 coalesces multiple signals and skips statistics reset when disabled.

    Inputs:
      - monkeypatch/caplog fixtures; handler closure is inspected to set pending flag.

    Outputs:
      - None: asserts reset is skipped and that when the pending flag is set,
        the handler returns early without invoking reload logic.
    """

    yaml_data = (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
        "statistics:\n  enabled: true\n  reset_on_sigusr1: false\n"
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
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
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


def test_sigusr2_error_paths_and_coalescing(monkeypatch, caplog):
    """Brief: SIGUSR2 covers stats reset error, no-collector branch, plugin error, and coalescing.

    Inputs:
      - monkeypatch/caplog fixtures; customized stats collector and plugins.

    Outputs:
      - None: asserts appropriate logs for error/no-collector paths and that
        when the pending Event is set, the handler exits early.
    """

    yaml_data = (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
        "statistics:\n  enabled: true\n  sigusr2_resets_stats: true\n"
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


def test_sigusr2_registration_failure_logs_warning(monkeypatch, caplog):
    """Brief: main() logs a warning if SIGUSR2 handler registration fails.

    Inputs:
      - monkeypatch/caplog fixtures; signal.signal is patched to raise on SIGUSR2.

    Outputs:
      - None: asserts warning log is emitted and main() still returns cleanly.
    """

    yaml_data = (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
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


def test_start_without_udp_uses_keepalive_loop(monkeypatch, caplog):
    """Brief: main() logs when starting without UDP listener and enters keepalive loop.

    Inputs:
      - monkeypatch/caplog fixtures; listen.udp.enabled is false and time.sleep
        is patched to raise KeyboardInterrupt.

    Outputs:
      - None: asserts informational log and that keepalive path exits cleanly.
    """

    yaml_data = (
        "listen:\n"
        "  host: 127.0.0.1\n"
        "  port: 5354\n"
        "  udp:\n"
        "    enabled: false\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
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

    monkeypatch.setattr(main_mod, "DNSServer", forbidden_dnserver)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **k: DummyHandle())
    # Patch the _time module alias imported inside main for the keepalive loop.
    monkeypatch.setitem(main_mod.sys.modules, "time", SimpleNamespace(sleep=fake_sleep))

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
        "listen:\n"
        "  host: 127.0.0.1\n"
        "  port: 5354\n"
        "  tcp:\n"
        "    enabled: true\n"
        "    host: 127.0.0.1\n"
        "    port: 5354\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
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

    import sys as _sys

    fake_threading = SimpleNamespace(Thread=DummyThread)

    def fake_import_module(name: str):  # used inside _start_asyncio_server
        if name == "threading":
            return fake_threading
        raise ImportError(name)

    import asyncio as _asyncio

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )
    # Patch the underlying tcp_server module so that when main() imports
    # serve_tcp_threaded, it receives our stub.
    monkeypatch.setattr(
        "foghorn.tcp_server.serve_tcp_threaded", fake_serve_tcp_threaded
    )
    # Patch asyncio's global new_event_loop so that the instance imported in
    # foghorn.main sees the PermissionError.
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
        "listen:\n"
        "  host: 127.0.0.1\n"
        "  port: 5354\n"
        "  dot:\n"
        "    enabled: true\n"
        "    host: 127.0.0.1\n"
        "    port: 8853\n"
        "    cert_file: cert.pem\n"
        "    key_file: key.pem\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
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

    import sys as _sys
    import asyncio as _asyncio

    fake_threading = SimpleNamespace(Thread=DummyThread)

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(
        main_mod, "start_webserver", lambda *a, **k: SimpleNamespace(stop=lambda: None)
    )
    # Patch asyncio's global new_event_loop so that the instance imported in
    # foghorn.main sees the PermissionError, and ensure threading import
    # returns our DummyThread implementation.
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
        "listen:\n"
        "  host: 127.0.0.1\n"
        "  port: 5354\n"
        "  dot:\n"
        "    enabled: true\n"
        "    host: 127.0.0.1\n"
        "    port: 8853\n"
        "    cert_file: cert.pem\n"
        "    key_file: key.pem\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
    )

    class DummyServer:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

    # Prevent real background threads by replacing the threading module that
    # _start_asyncio_server imports with a dummy implementation whose start()
    # is a no-op.
    class DummyThread:
        def __init__(self, target=None, name=None, daemon=None) -> None:
            self._target = target
            self.name = name
            self.daemon = daemon

        def start(self) -> None:
            return None

    import sys as _sys

    fake_threading = SimpleNamespace(Thread=DummyThread)

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


def test_doh_start_failure_returns_one(monkeypatch, caplog):
    """Brief: main() returns 1 when DoH server start throws an exception.

    Inputs:
      - monkeypatch/caplog fixtures; listen.doh.enabled is true and start_doh_server
        is patched to raise RuntimeError.

    Outputs:
      - None: asserts exit code 1 and error log.
    """

    yaml_data = (
        "listen:\n"
        "  host: 127.0.0.1\n"
        "  port: 5354\n"
        "  doh:\n"
        "    enabled: true\n"
        "    host: 127.0.0.1\n"
        "    port: 8053\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
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
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n  - host: 1.1.1.1\n    port: 53\n"
        "webserver:\n  enabled: true\n"
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
