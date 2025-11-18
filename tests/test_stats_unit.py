"""
Brief: Unit tests for foghorn.stats covering normalization, histogram, TopK, collector, snapshot formatting, reporter.

Inputs:
  - None

Outputs:
  - None
"""

import time

import pytest

from foghorn.stats import (
    LatencyHistogram,
    StatsCollector,
    StatsReporter,
    TopK,
    _normalize_domain,
    format_snapshot_json,
)


def test_normalize_domain_cases():
    assert _normalize_domain("Example.COM.") == "example.com"
    assert _normalize_domain("foo") == "foo"


def test_latency_histogram_add_and_summarize():
    h = LatencyHistogram()
    # Empty summarize
    s0 = h.summarize()
    assert s0["count"] == 0 and s0["avg_ms"] == 0.0
    # Add samples across bins
    h.add(0.0005)  # 0.5ms
    h.add(0.010)  # 10ms
    h.add(0.250)  # 250ms
    h.add(0.800)  # 800ms
    s = h.summarize()
    assert s["count"] == 4
    assert s["min_ms"] > 0
    assert s["max_ms"] >= s["avg_ms"]


def test_topk_add_export_and_prune():
    k = TopK(capacity=2, prune_factor=2)
    for _ in range(3):
        k.add("a")
    for _ in range(2):
        k.add("b")
    for _ in range(1):
        k.add("c")
    top = k.export(2)
    assert top[0][0] == "a" and top[0][1] == 3
    assert len(k.counts) <= 4  # capacity*prune_factor bound prior to prune
    # Force prune by exceeding bound
    for i in range(10):
        k.add(f"x{i}")
    assert len(k.counts) <= 2 * 2


def test_stats_collector_full_flow_and_reset():
    c = StatsCollector(
        track_uniques=True,
        include_qtype_breakdown=True,
        include_top_clients=True,
        include_top_domains=True,
        top_n=3,
        track_latency=True,
    )
    c.record_query("1.2.3.4", "Example.COM.", "A")
    c.record_cache_hit("example.com")
    c.record_cache_miss("example.com")
    c.record_plugin_decision(
        "Filter", "allow", reason="allowlist", domain="example.com", client_ip="1.2.3.4"
    )
    c.record_plugin_decision(
        "Filter", "block", reason="blocklist", domain="bad.com", client_ip="1.2.3.4"
    )
    c.record_plugin_decision("Modifier", "modify", domain="ex.com")
    c.record_upstream_result("8.8.8.8:53", "success")
    c.record_response_rcode("NOERROR")
    c.record_latency(0.005)

    snap = c.snapshot(reset=False)
    assert snap.totals["total_queries"] == 1
    assert snap.totals["cache_hits"] == 1
    assert snap.totals["cache_misses"] == 1
    assert snap.qtypes.get("A", 0) == 1
    assert snap.decisions["Filter"]["allow"] == 1
    assert snap.decisions["Filter"]["blocked_by"]["blocklist"] == 1
    assert snap.upstreams["8.8.8.8:53"]["success"] == 1
    assert snap.rcodes["NOERROR"] == 1
    assert snap.uniques == {"clients": 1, "domains": 1}
    assert snap.top_clients and len(snap.top_clients) >= 1
    assert snap.top_domains and len(snap.top_domains) >= 1
    assert snap.latency_stats and snap.latency_stats["count"] == 1

    # Reset and verify cleared
    c.snapshot(reset=True)
    snap3 = c.snapshot(reset=False)
    assert snap3.totals == {} and snap3.rcodes == {} and snap3.qtypes == {}


def test_format_snapshot_json_compact_and_fields():
    c = StatsCollector(
        track_uniques=False, include_qtype_breakdown=False, track_latency=False
    )
    c.record_query("1.1.1.1", "ex.com", "A")
    c.record_response_rcode("NOERROR")
    s = c.snapshot()
    js = format_snapshot_json(s)
    assert "\n" not in js
    assert "totals" in js and "rcodes" in js
    assert "qtypes" not in js  # omitted when empty and disabled


@pytest.mark.flaky(reruns=1)
def test_stats_reporter_logs_and_stops(caplog):
    c = StatsCollector()
    rep = StatsReporter(
        c,
        interval_seconds=1,
        reset_on_log=True,
        log_level="info",
        logger_name="foghorn.stats.test",
    )
    rep.daemon = True
    # Use a much smaller interval to avoid long sleeps in tests; the reporter
    # reads interval_seconds on each loop iteration.
    rep.interval_seconds = 0.01

    with caplog.at_level("INFO", logger="foghorn.stats.test"):
        rep.start()
        # Allow at least one cycle with the shorter interval
        time.sleep(0.05)
        rep.stop(timeout=2.0)

    # At least one log record produced
    assert any(r.name == "foghorn.stats.test" for r in caplog.records)
