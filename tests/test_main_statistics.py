"""
Brief: Tests main() statistics-enabled path initializes collector and reporter.

Inputs:
  - monkeypatch: to patch StatsCollector, StatsReporter, UDP listener start, init_logging.

Outputs:
  - None: asserts reporter.start() called and reporter received the constructed collector.
"""

from unittest.mock import mock_open, patch

import foghorn.main as main_mod


def test_main_statistics_enabled_initializes_and_starts_reporter(monkeypatch):
    """
    Brief: main() with stats.enabled=True creates StatsCollector/Reporter and starts reporter.

    Inputs:
      - YAML config enabling statistics with custom flags and interval.

    Outputs:
      - None: asserts reporter.start called and reporter wired with the constructed collector.

    Example config snippet:
      stats:
        enabled: true
        interval_seconds: 1
        track_uniques: false
        include_qtype_breakdown: false
        include_top_clients: true
        include_top_domains: true
        top_n: 5
        track_latency: true
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
        "logging:\n"
        "  query_log_sampling:\n"
        "    sample_rate: 0.25\n"
        "  query_log_dedupe:\n"
        "    window_seconds: 2\n"
        "    max_entries: 1234\n"
        "stats:\n"
        "  enabled: true\n"
        "  interval_seconds: 1\n"
        "  track_uniques: false\n"
        "  include_qtype_breakdown: false\n"
        "  include_top_clients: true\n"
        "  include_top_domains: true\n"
        "  top_n: 5\n"
        "  track_latency: true\n"
    )

    # Capture constructed objects and parameters
    constructed = {}

    class DummyCollector:
        def __init__(self, **kw):
            constructed["collector_kwargs"] = kw
            constructed["collector"] = self

        def warm_load_from_store(self) -> None:
            """Test stub: emulate real collector's warm_load_from_store()."""
            constructed["collector_warm_loaded"] = True

    class DummyReporter:
        def __init__(
            self,
            collector,
            interval_seconds,
            reset_on_log,
            log_level,
            logger_name="foghorn.stats",
            persistence_store=None,
        ):
            constructed["reporter_args"] = {
                "collector": collector,
                "interval_seconds": interval_seconds,
                "reset_on_log": reset_on_log,
                "log_level": log_level,
                "logger_name": logger_name,
                "persistence_store": persistence_store,
            }
            self.interval_seconds = interval_seconds
            self.started = False

        def start(self):
            self.started = True
            constructed["reporter_started"] = True

        def stop(self):
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
            constructed["udp_stop_called"] = True

    def fake_start_udp_asyncio_threaded(*_a, **_kw):  # type: ignore[no-untyped-def]
        return DummyUDPHandle()

    # Patch dependencies in foghorn.main
    monkeypatch.setattr(main_mod, "StatsCollector", DummyCollector)
    monkeypatch.setattr(main_mod, "StatsReporter", DummyReporter)
    monkeypatch.setattr(
        udp_asyncio_mod, "start_udp_asyncio_threaded", fake_start_udp_asyncio_threaded
    )
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **k: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "stats.yaml"])

    assert rc == 0
    # Reporter should have been started
    assert constructed.get("reporter_started") is True
    # Reporter must receive the same collector instance
    assert constructed["reporter_args"]["collector"] is constructed.get("collector")
    # Validate collector kwargs reflect config
    ck = constructed["collector_kwargs"]
    assert ck["track_uniques"] is False
    assert ck["include_qtype_breakdown"] is False
    assert ck["include_top_clients"] is True
    assert ck["include_top_domains"] is True
    assert ck["top_n"] == 5
    assert ck["track_latency"] is True
    assert ck["query_log_sample_rate"] == 0.25
    assert ck["query_log_dedupe_window_seconds"] == 2
    assert ck["query_log_dedupe_max_entries"] == 1234
