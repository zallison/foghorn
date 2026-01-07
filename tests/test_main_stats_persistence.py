"""
Brief: Tests for statistics persistence wiring in main().

Inputs:
    - monkeypatch, tmp_path, mock_open
Outputs:
    - None; asserts main() wires a BaseStatsStore into StatsCollector/StatsReporter
      via load_stats_store_backend.
"""

from pathlib import Path
from unittest.mock import mock_open, patch

import foghorn.main as main_mod


def test_main_warm_start_loads_latest_snapshot(monkeypatch, tmp_path: Path) -> None:
    """Brief: When a backend is configured, main() wires a BaseStatsStore into StatsCollector.

    Inputs:
        monkeypatch/tmp_path fixtures
    Outputs:
        None; asserts a stats backend is constructed from logging.backends and
        passed through to StatsCollector/StatsReporter.
    """
    yaml_data = f"""upstreams:
  endpoints:
    - host: 1.1.1.1
      port: 53
  strategy: failover
  max_concurrent: 1
server:
  listen:
    udp:
      enabled: true
      host: 127.0.0.1
      port: 5354
  resolver:
    mode: forward
    timeout_ms: 2000
    use_asyncio: true
logging:
  async: true
  backends:
    - id: warm-store
      backend: sqlite
      config:
        db_path: {tmp_path}/warm.db
stats:
  enabled: true
  interval_seconds: 1
  source_backend: warm-store
"""

    constructed: dict[str, object] = {}

    class DummyCollector:
        def __init__(self, **kw) -> None:
            constructed["collector_kwargs"] = kw
            constructed["collector"] = self

    class DummyStore:
        def __init__(self, **kw) -> None:
            constructed["store_kwargs"] = kw

        def close(self) -> None:
            constructed["store_closed"] = True

    class DummyReporter:
        def __init__(
            self,
            collector,
            interval_seconds,
            reset_on_log,
            log_level,
            logger_name="foghorn.stats",
            persistence_store=None,
        ) -> None:
            constructed["reporter_args"] = {
                "collector": collector,
                "interval_seconds": interval_seconds,
                "reset_on_log": reset_on_log,
                "log_level": log_level,
                "persistence_store": persistence_store,
            }
            self.interval_seconds = interval_seconds

        def start(self) -> None:
            constructed["reporter_started"] = True

        def stop(self) -> None:  # pragma: no cover - not exercised here
            pass

    class DummyServer:
        def __init__(self, *a, **kw) -> None:
            pass

        def serve_forever(self) -> None:
            # Exit main loop quickly
            raise KeyboardInterrupt

    # Patch dependencies in foghorn.main
    monkeypatch.setattr(main_mod, "StatsCollector", DummyCollector)
    monkeypatch.setattr(main_mod, "StatsReporter", DummyReporter)

    def _fake_loader(persistence_cfg: dict[str, object] | None) -> DummyStore | None:
        # Simulate loader returning a single backend when a backend config is provided.
        if not isinstance(persistence_cfg, dict):
            return None
        constructed["store_cfg"] = persistence_cfg
        return DummyStore()

    monkeypatch.setattr(main_mod, "load_stats_store_backend", _fake_loader)
    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "stats_persist.yaml"])

    assert rc == 0
    # Loader should have been called with an effective backend config
    store_cfg = constructed["store_cfg"]
    backends = store_cfg.get("backends") or []
    assert isinstance(backends, list) and len(backends) == 1
    first = backends[0]
    cfg = first.get("config") or {}
    assert cfg.get("db_path") == f"{tmp_path}/warm.db"  # type: ignore[index]
    # Collector should have received the store via stats_store kwarg
    ck = constructed["collector_kwargs"]
    assert isinstance(ck.get("stats_store"), DummyStore)
    # Reporter started and wired with both collector and store
    assert constructed.get("reporter_started") is True
    assert constructed["reporter_args"]["collector"] is constructed["collector"]
    assert isinstance(constructed["reporter_args"]["persistence_store"], DummyStore)


def test_main_persistence_unconfigured_skips_store(monkeypatch, tmp_path: Path) -> None:
    """Brief: When no logging.backends are configured, main() does not create a store.

    Inputs:
        monkeypatch/tmp_path fixtures
    Outputs:
        None; asserts StatsSQLiteStore is never constructed.
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
        "stats:\n"
        "  enabled: true\n"
        "  interval_seconds: 1\n"
    )

    constructed: dict[str, object] = {"store_constructed": False}

    class DummyCollector:
        def __init__(self, **kw) -> None:
            constructed["collector"] = self

    class DummyReporter:
        def __init__(
            self,
            collector,
            interval_seconds,
            reset_on_log,
            log_level,
            logger_name="foghorn.stats",
            persistence_store=None,
        ) -> None:
            constructed["reporter_args"] = {
                "collector": collector,
                "persistence_store": persistence_store,
            }
            self.interval_seconds = interval_seconds

        def start(self) -> None:
            constructed["reporter_started"] = True

        def stop(self) -> None:  # pragma: no cover - not exercised
            pass

    class DummyServer:
        def __init__(self, *a, **kw) -> None:
            pass

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

    def _fake_loader_disabled(persistence_cfg: dict[str, object] | None) -> None:  # pragma: no cover - should not be called when no backends are configured
        # Record that the loader was invoked; in this test config there are no
        # logging.backends, so main() should skip calling the loader entirely.
        constructed["store_constructed"] = True
        return None

    monkeypatch.setattr(main_mod, "StatsCollector", DummyCollector)
    monkeypatch.setattr(main_mod, "StatsReporter", DummyReporter)
    monkeypatch.setattr(main_mod, "load_stats_store_backend", _fake_loader_disabled)
    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "stats_persist_disabled.yaml"])

    assert rc == 0
    assert constructed["store_constructed"] is False
    assert constructed["reporter_started"] is True
    assert constructed["reporter_args"]["persistence_store"] is None
