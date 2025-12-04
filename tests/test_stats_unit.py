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
    # After reset, only baseline pre-plugin cache counters remain at 0.
    assert snap3.totals == {
        "cache_deny_pre": 0,
        "cache_override_pre": 0,
    }
    assert snap3.rcodes == {}
    assert snap3.qtypes == {}


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


def test_format_snapshot_json_includes_extended_sections():
    """Brief: format_snapshot_json emits extended sections when populated.

    Inputs:
      - Synthetic StatsSnapshot with non-empty extended fields.

    Outputs:
      - None; asserts JSON contains plugins, upstream_rcodes/qtypes, qtype_qnames,
        rcode_domains/subdomains, and cache hit/miss sections.
    """

    import json as _json

    from foghorn.stats import StatsSnapshot

    created = time.time()
    snap = StatsSnapshot(
        created_at=created,
        totals={"total_queries": 1},
        rcodes={"NOERROR": 1},
        qtypes={"A": 1},
        decisions={"P": {"allow": 1}},
        upstreams={"up": {"success": 1}},
        uniques={"clients": 1, "domains": 1},
        top_clients=[("1.2.3.4", 2)],
        top_subdomains=[("www.example.com", 3)],
        top_domains=[("example.com", 3)],
        latency_stats={
            "count": 1,
            "min_ms": 1.0,
            "max_ms": 1.0,
            "avg_ms": 1.0,
            "p50_ms": 1.0,
            "p90_ms": 1.0,
            "p99_ms": 1.0,
        },
        latency_recent_stats={
            "count": 1,
            "min_ms": 1.0,
            "max_ms": 1.0,
            "avg_ms": 1.0,
            "p50_ms": 1.0,
            "p90_ms": 1.0,
            "p99_ms": 1.0,
        },
        upstream_rcodes={"up": {"NOERROR": 1}},
        upstream_qtypes={"up": {"A": 1}},
        qtype_qnames={"A": [("example.com", 2)]},
        rcode_domains={"NOERROR": [("example.com", 3)]},
        rcode_subdomains={"NOERROR": [("sub.example.com", 2)]},
        cache_hit_domains=[("example.com", 1)],
        cache_miss_domains=[("other.com", 1)],
        cache_hit_subdomains=[("sub.example.com", 1)],
        cache_miss_subdomains=[("sub.other.com", 1)],
    )

    js = format_snapshot_json(snap)
    parsed = _json.loads(js)

    assert "plugins" in parsed
    assert "upstream_rcodes" in parsed
    assert "upstream_qtypes" in parsed
    assert "qtype_qnames" in parsed
    assert "rcode_domains" in parsed
    assert "rcode_subdomains" in parsed
    assert "cache_hit_domains" in parsed
    assert "cache_miss_domains" in parsed
    assert "cache_hit_subdomains" in parsed
    assert "cache_miss_subdomains" in parsed


class _FakeStore:
    """Brief: Simple in-memory fake StatsSQLiteStore for persistence tests.

    Inputs:
      - None.

    Outputs:
      - Object recording increment_count and insert_query_log calls.
    """

    def __init__(self) -> None:
        self.increment_calls: list[tuple[str, str, int]] = []
        self.query_logs: list[dict[str, object]] = []

    def increment_count(self, scope: str, key: str, delta: int = 1) -> None:
        self.increment_calls.append((scope, key, int(delta)))

    def insert_query_log(
        self,
        ts: float,
        client_ip: str,
        name: str,
        qtype: str,
        upstream_id: str | None,
        rcode: str | None,
        status: str | None,
        error: str | None,
        first: str | None,
        result_json: str,
    ) -> None:
        self.query_logs.append(
            {
                "ts": ts,
                "client_ip": client_ip,
                "name": name,
                "qtype": qtype,
                "upstream_id": upstream_id,
                "rcode": rcode,
                "status": status,
                "error": error,
                "first": first,
                "result_json": result_json,
            }
        )


def test_stats_collector_persists_to_store():
    """Brief: StatsCollector writes core events into the attached store.

    Inputs:
      - None; uses _FakeStore instead of a real SQLite store.

    Outputs:
      - None; asserts expected increment_count and insert_query_log calls.
    """

    store = _FakeStore()
    c = StatsCollector(
        track_uniques=True,
        include_qtype_breakdown=True,
        include_top_clients=False,
        include_top_domains=True,
        top_n=3,
        track_latency=False,
        stats_store=store,
    )

    # Query and caches
    c.record_query("1.2.3.4", "www.example.com", "A")
    c.record_cache_hit("www.example.com")
    c.record_cache_miss("www.example.com")
    c.record_cache_null("www.example.com")

    # Plugin decisions
    c.record_plugin_decision("P", "allow", reason="r1")
    c.record_plugin_decision("P", "block", reason="r2")
    c.record_plugin_decision("P", "modify")

    # Upstream stats
    c.record_upstream_result("up", "success", qtype="A")
    c.record_upstream_rcode("up", "NOERROR")

    # Response rcodes with subdomain so rcode_domains/subdomains are updated.
    c.record_response_rcode("NXDOMAIN", qname="www.example.com")

    # Query-log row
    c.record_query_result(
        client_ip="1.2.3.4",
        qname="www.example.com",
        qtype="A",
        rcode="NOERROR",
        upstream_id="up",
        status="ok",
        error=None,
        first="93.184.216.34",
        result={"answers": ["93.184.216.34"]},
    )

    keys = {(s, k) for (s, k, _d) in store.increment_calls}

    # Core counters
    assert ("totals", "total_queries") in keys
    assert ("totals", "cache_hits") in keys
    assert ("totals", "cache_misses") in keys
    assert ("totals", "cache_null") in keys

    # Cache domain aggregates
    assert ("cache_hit_domains", "example.com") in keys
    assert ("cache_miss_domains", "example.com") in keys
    # Subdomain-only aggregates are keyed by full qname.
    assert ("cache_hit_subdomains", "www.example.com") in keys
    assert ("cache_miss_subdomains", "www.example.com") in keys

    # Plugin decision totals
    assert ("totals", "allowed") in keys
    assert ("totals", "blocked") in keys
    assert ("totals", "modified") in keys

    # Upstream aggregates
    assert any(s == "upstreams" for (s, _k, _d) in store.increment_calls)
    assert any(s == "upstream_qtypes" for (s, _k, _d) in store.increment_calls)

    # Rcode aggregates
    assert ("rcodes", "NXDOMAIN") in keys
    assert ("rcode_domains", "NXDOMAIN|example.com") in keys
    # Subdomain-only rcode aggregates are keyed by full qname.
    assert ("rcode_subdomains", "NXDOMAIN|www.example.com") in keys

    # Query log insert
    assert len(store.query_logs) == 1
    log_row = store.query_logs[0]
    assert log_row["client_ip"] == "1.2.3.4"
    assert log_row["name"] == "www.example.com"
    assert log_row["qtype"] == "A"


def test_record_cache_null_pre_plugin_status_counters() -> None:
    """Brief: record_cache_null tracks per-status pre-plugin totals when requested.

    Inputs:
      - None.

    Outputs:
      - None; asserts cache_deny_pre/cache_override_pre are incremented alongside
        cache_null in both in-memory counters and the attached store.
    """

    # In-memory only: ensure per-status keys are bumped when status is provided.
    c = StatsCollector()
    c.record_cache_null("deny.example", status="deny_pre")
    c.record_cache_null("override.example", status="override_pre")

    snap = c.snapshot(reset=False)
    assert snap.totals["cache_null"] == 2
    assert snap.totals["cache_deny_pre"] == 1
    assert snap.totals["cache_override_pre"] == 1

    # With store attached: verify corresponding totals.* counters are persisted.
    store = _FakeStore()
    c2 = StatsCollector(stats_store=store)
    c2.record_cache_null("deny.example", status="deny_pre")
    c2.record_cache_null("override.example", status="override_pre")

    keys = {(s, k) for (s, k, _d) in store.increment_calls}
    assert ("totals", "cache_null") in keys
    assert ("totals", "cache_deny_pre") in keys
    assert ("totals", "cache_override_pre") in keys


@pytest.mark.flaky(reruns=1)
def test_stats_reporter_logs_and_stops(caplog):
    c = StatsCollector()
    rep = StatsReporter(
        c,
        interval_seconds=1,
        reset_on_log=True,
        log_level="debug",
        logger_name="foghorn.stats.test",
    )
    rep.daemon = True
    # Use a much smaller interval to avoid long sleeps in tests; the reporter
    # reads interval_seconds on each loop iteration.
    rep.interval_seconds = 0.01

    with caplog.at_level("DEBUG", logger="foghorn.stats.test"):
        rep.start()
        # Allow at least one cycle with the shorter interval
        time.sleep(0.05)
        rep.stop(timeout=2.0)

    # At least one log record produced
    assert any(r.name == "foghorn.stats.test" for r in caplog.records)
