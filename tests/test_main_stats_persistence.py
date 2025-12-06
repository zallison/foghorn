"""
Brief: Tests for statistics persistence wiring in main().

Inputs:
    - monkeypatch, tmp_path, mock_open
Outputs:
    - None; asserts main() wires StatsSQLiteStore into StatsCollector/StatsReporter.
"""

from pathlib import Path
from unittest.mock import mock_open, patch

import foghorn.main as main_mod


def test_main_warm_start_loads_latest_snapshot(monkeypatch, tmp_path: Path) -> None:
    """Brief: When persistence is enabled, main() wires a StatsSQLiteStore into StatsCollector.

    Inputs:
        monkeypatch/tmp_path fixtures
    Outputs:
        None; asserts StatsSQLiteStore is constructed and passed through.
    """
    yaml_data = (
        "listen:\n"
        "  host: 127.0.0.1\n"
        "  port: 5354\n"
        "upstreams:\n"
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

    class DummyCollector:
        def __init__(self, **kw) -> None:
            constructed["collector_kwargs"] = kw
            constructed["collector"] = self

    class DummyStore:
        def __init__(self, db_path: str, **kw) -> None:
            constructed["store_db_path"] = db_path
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
    monkeypatch.setattr(main_mod, "StatsSQLiteStore", DummyStore)
    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "stats_persist.yaml"])

    assert rc == 0
    # Store should be constructed with configured db_path
    assert str(tmp_path) in str(constructed["store_db_path"])
    # Collector should have received the store via stats_store kwarg
    ck = constructed["collector_kwargs"]
    assert isinstance(ck.get("stats_store"), DummyStore)
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
        "upstreams:\n"
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
