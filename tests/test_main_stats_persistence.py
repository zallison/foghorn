"""
Brief: Tests for statistics persistence and warm-start behavior in main().

Inputs:
    - monkeypatch, tmp_path, mock_open
Outputs:
    - None; asserts main() wires StatsSQLiteStore and load_from_snapshot correctly.
"""

from pathlib import Path
from unittest.mock import mock_open, patch

import foghorn.main as main_mod


def test_main_warm_start_loads_latest_snapshot(monkeypatch, tmp_path: Path) -> None:
    """Brief: When persistence is enabled and a snapshot is present, main() loads it.

    Inputs:
        monkeypatch/tmp_path fixtures
    Outputs:
        None; asserts load_latest_snapshot and load_from_snapshot are invoked.
    """
    yaml_data = (
        "listen:\n"
        "  host: 127.0.0.1\n"
        "  port: 5354\n"
        "upstream:\n"
        "  - host: 1.1.1.1\n"
        "    port: 53\n"
        "statistics:\n"
        "  enabled: true\n"
        "  interval_seconds: 1\n"
        "  persistence:\n"
        f"    enabled: true\n"
        f"    db_path: {tmp_path}/warm.db\n"
    )

    constructed: dict[str, object] = {}

    class DummySnapshot:
        """Brief: Minimal snapshot stand-in for warm-start tests.

        Inputs:
            None
        Outputs:
            None
        """

        def __init__(self) -> None:
            self.created_at = 123.0
            self.totals = {"total_queries": 42}
            self.rcodes = {}
            self.qtypes = {}
            self.decisions = {}
            self.upstreams = {}
            self.uniques = None
            self.top_clients = None
            self.top_subdomains = None
            self.top_domains = None
            self.latency_stats = None
            self.latency_recent_stats = None

    class DummyCollector:
        def __init__(self, **kw) -> None:
            constructed["collector_kwargs"] = kw
            constructed["collector"] = self
            self.loaded_snapshot = None

        def load_from_snapshot(self, snapshot) -> None:
            self.loaded_snapshot = snapshot
            constructed["loaded_snapshot"] = snapshot

    class DummyStore:
        def __init__(self, db_path: str, **kw) -> None:
            constructed["store_db_path"] = db_path
            constructed["store_kwargs"] = kw

        def save_snapshot(self, snapshot) -> None:  # pragma: no cover - not used
            pass

        def load_latest_snapshot(self):
            constructed["load_latest_called"] = True
            return DummySnapshot()

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
    monkeypatch.setattr(main_mod, "StatsSQLiteStore", DummyStore)
    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "stats_persist.yaml"])

    assert rc == 0
    # Store should be constructed with configured db_path
    assert str(tmp_path) in str(constructed["store_db_path"])
    # Latest snapshot loaded
    assert constructed.get("load_latest_called") is True
    # Collector should have had load_from_snapshot invoked
    assert constructed.get("loaded_snapshot") is not None
    # Reporter started and wired with both collector and store
    assert constructed.get("reporter_started") is True
    assert constructed["reporter_args"]["collector"] is constructed["collector"]
    assert isinstance(constructed["reporter_args"]["persistence_store"], DummyStore)


def test_main_persistence_disabled_skips_store(monkeypatch, tmp_path: Path) -> None:
    """Brief: When statistics.persistence.enabled=false, main() does not create a store.

    Inputs:
        monkeypatch/tmp_path fixtures
    Outputs:
        None; asserts StatsSQLiteStore is never constructed.
    """
    yaml_data = (
        "listen:\n"
        "  host: 127.0.0.1\n"
        "  port: 5354\n"
        "upstream:\n"
        "  - host: 1.1.1.1\n"
        "    port: 53\n"
        "statistics:\n"
        "  enabled: true\n"
        "  interval_seconds: 1\n"
        "  persistence:\n"
        "    enabled: false\n"
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

    def _store_ctor(*a, **kw):  # pragma: no cover - should not be called
        constructed["store_constructed"] = True
        raise AssertionError("StatsSQLiteStore should not be constructed when disabled")

    monkeypatch.setattr(main_mod, "StatsCollector", DummyCollector)
    monkeypatch.setattr(main_mod, "StatsReporter", DummyReporter)
    monkeypatch.setattr(main_mod, "StatsSQLiteStore", _store_ctor)
    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "stats_persist_disabled.yaml"])

    assert rc == 0
    assert constructed["store_constructed"] is False
    assert constructed["reporter_started"] is True
    assert constructed["reporter_args"]["persistence_store"] is None
