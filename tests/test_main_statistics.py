"""
Brief: Tests main() statistics-enabled path initializes collector and reporter and passes collector to DNSServer.

Inputs:
  - monkeypatch: to patch StatsCollector, StatsReporter, DNSServer, init_logging

Outputs:
  - None: asserts reporter.start() called and DNSServer received stats_collector
"""

from unittest.mock import mock_open, patch

import foghorn.main as main_mod


def test_main_statistics_enabled_initializes_and_starts_reporter(monkeypatch):
    """
    Brief: main() with statistics.enabled=True creates StatsCollector/Reporter, starts reporter, and passes collector to DNSServer.

    Inputs:
      - YAML config enabling statistics with custom flags and interval

    Outputs:
      - None: asserts reporter.start called and DNSServer constructed with provided stats_collector

    Example config snippet:
      statistics:
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

    class DummyServer:
        def __init__(
            self,
            host,
            port,
            upstreams,
            plugins,
            *,
            timeout,
            timeout_ms,
            min_cache_ttl,
            stats_collector=None,
            **_extra,
        ):
            constructed["dnserver_kwargs"] = {
                "stats_collector": stats_collector,
                "timeout_ms": timeout_ms,
                "min_cache_ttl": min_cache_ttl,
            }

        def serve_forever(self):
            # Immediately exit main loop
            raise KeyboardInterrupt

    # Patch dependencies in foghorn.main
    monkeypatch.setattr(main_mod, "StatsCollector", DummyCollector)
    monkeypatch.setattr(main_mod, "StatsReporter", DummyReporter)
    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "stats.yaml"])

    assert rc == 0
    # Reporter should have been started
    assert constructed.get("reporter_started") is True
    # DNSServer must receive the same collector instance
    assert (
        constructed["dnserver_kwargs"]["stats_collector"]
        is constructed["reporter_args"]["collector"]
    )
    # Validate collector kwargs reflect config
    ck = constructed["collector_kwargs"]
    assert ck["track_uniques"] is False
    assert ck["include_qtype_breakdown"] is False
    assert ck["include_top_clients"] is True
    assert ck["include_top_domains"] is True
    assert ck["top_n"] == 5
    assert ck["track_latency"] is True
