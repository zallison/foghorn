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

    from foghorn.servers import udp_asyncio_server as udp_asyncio_mod

    class DummyThread:
        def is_alive(self) -> bool:
            return False

        def join(self, timeout: float | None = None) -> None:  # noqa: ARG002
            return None

    class DummyUDPHandle:
        def __init__(self) -> None:
            self.thread = DummyThread()

        def stop(self) -> None:
            return None

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
    monkeypatch.setattr(
        udp_asyncio_mod,
        "start_udp_asyncio_threaded",
        lambda *_a, **_kw: DummyUDPHandle(),
    )
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **k: None)

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

    from foghorn.servers import udp_asyncio_server as udp_asyncio_mod

    class DummyThread:
        def is_alive(self) -> bool:
            return False

        def join(self, timeout: float | None = None) -> None:  # noqa: ARG002
            return None

    class DummyUDPHandle:
        def __init__(self) -> None:
            self.thread = DummyThread()

        def stop(self) -> None:
            return None

    def _fake_loader_disabled(
        persistence_cfg: dict[str, object] | None,
    ) -> (
        None
    ):  # pragma: no cover - should not be called when no backends are configured
        # Record that the loader was invoked; in this test config there are no
        # logging.backends, so main() should skip calling the loader entirely.
        constructed["store_constructed"] = True
        return None

    monkeypatch.setattr(main_mod, "StatsCollector", DummyCollector)
    monkeypatch.setattr(main_mod, "StatsReporter", DummyReporter)
    monkeypatch.setattr(main_mod, "load_stats_store_backend", _fake_loader_disabled)
    monkeypatch.setattr(
        udp_asyncio_mod,
        "start_udp_asyncio_threaded",
        lambda *_a, **_kw: DummyUDPHandle(),
    )
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **k: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "stats_persist_disabled.yaml"])

    assert rc == 0
    assert constructed["store_constructed"] is False
    assert constructed["reporter_started"] is True
    assert constructed["reporter_args"]["persistence_store"] is None


def test_build_effective_persistence_cfg_propagates_global_hardening_defaults() -> None:
    """Brief: Global logging hardening keys are propagated into backend configs.

    Inputs:
        None.

    Outputs:
        None; asserts queue/retention defaults are copied to backend config.
    """

    cfg = {
        "logging": {
            "async": True,
            "max_logging_queue": 2048,
            "query_log_retention": {
                "max_records": 1000,
                "days": 2,
                "max_bytes": 4096,
                "prune_interval_seconds": 30,
                "prune_every_n_inserts": 50,
            },
            "backends": [
                {
                    "id": "store-a",
                    "backend": "sqlite",
                    "config": {"db_path": "./config/var/stats_a.db"},
                }
            ],
        }
    }

    out = main_mod._build_effective_persistence_cfg(cfg=cfg, stats_cfg={})
    backends = out.get("backends")
    assert isinstance(backends, list) and len(backends) == 1
    conf = backends[0]["config"]
    assert conf["async_logging"] is True
    assert conf["max_logging_queue"] == 2048
    assert conf["retention_max_records"] == 1000
    assert conf["retention_days"] == 2
    assert conf["retention_max_bytes"] == 4096
    assert conf["retention_prune_interval_seconds"] == 30
    assert conf["retention_prune_every_n_inserts"] == 50


def test_build_effective_persistence_cfg_respects_per_backend_overrides() -> None:
    """Brief: Per-backend retention fields override propagated global defaults.

    Inputs:
        None.

    Outputs:
        None; asserts explicit backend config values are preserved.
    """

    cfg = {
        "logging": {
            "async": True,
            "query_log_retention_max_records": 1000,
            "query_log_retention_days": 2,
            "query_log_retention_max_bytes": 4096,
            "query_log_retention_prune_interval_seconds": 30,
            "query_log_retention_prune_every_n_inserts": 50,
            "backends": [
                {
                    "id": "store-a",
                    "backend": "sqlite",
                    "config": {
                        "db_path": "./config/var/stats_a.db",
                        "retention_max_records": 25,
                        "retention_days": 1,
                        "retention_max_bytes": 2048,
                        "retention_prune_interval_seconds": 5,
                        "retention_prune_every_n_inserts": 10,
                    },
                }
            ],
        }
    }

    out = main_mod._build_effective_persistence_cfg(cfg=cfg, stats_cfg={})
    backends = out.get("backends")
    assert isinstance(backends, list) and len(backends) == 1
    conf = backends[0]["config"]
    assert conf["retention_max_records"] == 25
    assert conf["retention_days"] == 1
    assert conf["retention_max_bytes"] == 2048
    assert conf["retention_prune_interval_seconds"] == 5
    assert conf["retention_prune_every_n_inserts"] == 10
