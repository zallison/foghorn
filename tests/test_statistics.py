"""Unit tests for statistics collection system."""

import json
import logging
import threading
import time

from foghorn.stats import (
    LatencyHistogram,
    StatsCollector,
    StatsReporter,
    TopK,
    _normalize_domain,
    format_snapshot_json,
)


class TestDomainNormalization:
    """Test domain name normalization."""

    def test_normalize_domain_trailing_dot(self):
        """Domain normalization removes trailing dot."""
        assert _normalize_domain("example.com.") == "example.com"

    def test_normalize_domain_lowercase(self):
        """Domain normalization converts to lowercase."""
        assert _normalize_domain("Example.COM") == "example.com"

    def test_normalize_domain_combined(self):
        """Domain normalization handles mixed case and trailing dot."""
        assert _normalize_domain("EXAMPLE.COM.") == "example.com"


class TestLatencyHistogram:
    """Test latency histogram implementation."""

    def test_empty_histogram(self):
        """Empty histogram returns zero stats."""
        hist = LatencyHistogram()
        stats = hist.summarize()
        assert stats["count"] == 0
        assert stats["min_ms"] == 0.0
        assert stats["max_ms"] == 0.0

    def test_single_sample(self):
        """Single sample tracked correctly."""
        hist = LatencyHistogram()
        hist.add(0.005)  # 5ms
        stats = hist.summarize()
        assert stats["count"] == 1
        assert 4.5 <= stats["min_ms"] <= 5.5
        assert 4.5 <= stats["max_ms"] <= 5.5

    def test_multiple_samples(self):
        """Multiple samples aggregate correctly."""
        hist = LatencyHistogram()
        hist.add(0.001)  # 1ms
        hist.add(0.010)  # 10ms
        hist.add(0.100)  # 100ms
        stats = hist.summarize()
        assert stats["count"] == 3
        assert stats["min_ms"] < stats["max_ms"]

    def test_percentiles(self):
        """Percentile calculation is reasonable."""
        hist = LatencyHistogram()
        for _ in range(100):
            hist.add(0.005)  # 5ms
        stats = hist.summarize()
        # All samples are 5ms, so percentiles should be around 5 (bin midpoint)
        assert 2 <= stats["p50_ms"] <= 10
        assert 2 <= stats["p90_ms"] <= 10

    def test_percentile_overflow_bin(self) -> None:
        """Brief: Percentiles hitting overflow bin return overflow sentinel.

        Inputs:
          - None.

        Outputs:
          - None; asserts _percentile(1.0) for a large sample returns 10000.0.
        """

        hist = LatencyHistogram()
        # Large sample in seconds so that it lands in the overflow bin (>=10s).
        hist.add(12.0)
        assert hist._percentile(1.0) == 10000.0


class TestTopK:
    """Test Top-K heavy hitters tracker."""

    def test_topk_single_item(self):
        """Single item appears in top list."""
        tracker = TopK(capacity=5)
        tracker.add("example.com")
        tracker.add("example.com")
        top = tracker.export(5)
        assert len(top) == 1
        assert top[0] == ("example.com", 2)

    def test_topk_multiple_items(self):
        """Multiple items sorted by frequency."""
        tracker = TopK(capacity=5)
        for _ in range(10):
            tracker.add("a.com")
        for _ in range(5):
            tracker.add("b.com")
        for _ in range(3):
            tracker.add("c.com")

        top = tracker.export(3)
        assert len(top) == 3
        assert top[0][0] == "a.com"
        assert top[0][1] == 10
        assert top[1][0] == "b.com"
        assert top[2][0] == "c.com"

    def test_topk_pruning(self):
        """TopK prunes excess items to bound memory."""
        tracker = TopK(capacity=3, prune_factor=2)
        # Add enough items to trigger pruning
        for i in range(10):
            for _ in range(i + 1):
                tracker.add(f"domain{i}.com")

        # After pruning, should have around capacity items
        assert len(tracker.counts) <= tracker.capacity * tracker.prune_factor


class TestStatsCollector:
    """Test StatsCollector aggregation."""

    def test_record_query(self):
        """Query recording increments counters."""
        collector = StatsCollector()
        collector.record_query("192.0.2.1", "example.com", "A")
        snapshot = collector.snapshot()
        assert snapshot.totals["total_queries"] == 1
        assert snapshot.qtypes["A"] == 1

    def test_cache_hit_miss(self):
        """Cache hits and misses tracked separately."""
        collector = StatsCollector()
        collector.record_cache_hit("example.com")
        collector.record_cache_miss("other.com")
        snapshot = collector.snapshot()
        assert snapshot.totals["cache_hits"] == 1
        assert snapshot.totals["cache_misses"] == 1

    def test_cache_null_counter(self):
        """cache_null responses tracked separately from cache hits/misses."""
        collector = StatsCollector()
        collector.record_cache_null("plugin.example")
        snapshot = collector.snapshot()
        assert snapshot.totals["cache_null"] == 1
        assert snapshot.totals.get("cache_hits", 0) == 0
        assert snapshot.totals.get("cache_misses", 0) == 0

    def test_plugin_decisions(self):
        """Plugin decisions tracked with action and reason."""
        collector = StatsCollector()
        collector.record_plugin_decision(
            "Filter", "block", reason="blocklist", domain="bad.com"
        )
        collector.record_plugin_decision("Filter", "allow", reason="allowlist")
        snapshot = collector.snapshot()
        assert snapshot.totals["blocked"] == 1
        assert snapshot.totals["allowed"] == 1
        assert snapshot.decisions["Filter"]["block"] == 1
        assert snapshot.decisions["Filter"]["allow"] == 1
        assert snapshot.decisions["Filter"]["blocked_by"]["blocklist"] == 1

    def test_upstream_results(self):
        """Upstream results tracked per upstream."""
        collector = StatsCollector()
        collector.record_upstream_result("8.8.8.8:53", "success")
        collector.record_upstream_result("8.8.8.8:53", "success")
        collector.record_upstream_result("1.1.1.1:53", "timeout")
        snapshot = collector.snapshot()
        assert snapshot.upstreams["8.8.8.8:53"]["success"] == 2
        assert snapshot.upstreams["1.1.1.1:53"]["timeout"] == 1

    def test_top_upstreams_and_rcodes(self):
        """Per-upstream rcodes and qtypes are tracked."""
        collector = StatsCollector(include_top_domains=True, top_n=5)
        # Mix of outcomes to drive upstream counters and TopK.
        collector.record_upstream_result("8.8.8.8:53", "success", qtype="A")
        collector.record_upstream_result("8.8.8.8:53", "timeout", qtype="AAAA")
        collector.record_upstream_result("1.1.1.1:53", "success", qtype="A")

        # Attribute a couple of rcodes to the primary upstream.
        collector.record_upstream_rcode("8.8.8.8:53", "NOERROR")
        collector.record_upstream_rcode("8.8.8.8:53", "SERVFAIL")

        snapshot = collector.snapshot()
        assert snapshot.upstream_rcodes is not None
        assert snapshot.upstream_rcodes["8.8.8.8:53"]["NOERROR"] == 1
        assert snapshot.upstream_rcodes["8.8.8.8:53"]["SERVFAIL"] == 1
        # Qtype-by-upstream counts should be tracked.
        assert snapshot.upstream_qtypes is not None
        assert snapshot.upstream_qtypes["8.8.8.8:53"]["A"] == 1
        assert snapshot.upstream_qtypes["8.8.8.8:53"]["AAAA"] == 1

    def test_qtype_qnames_top_domains(self):
        """Per-qtype top domains (qnames) are tracked for multiple qtypes."""
        collector = StatsCollector(include_top_domains=True, top_n=3)
        # A/AAAA/PTR/TXT/SRV should be included (and other qtypes when seen).
        collector.record_query("192.0.2.1", "example.com", "A")
        collector.record_query("192.0.2.2", "example.com", "AAAA")
        collector.record_query("192.0.2.3", "ptr.example.com", "PTR")
        collector.record_query("192.0.2.4", "txt.example.com", "TXT")
        collector.record_query("192.0.2.5", "srv.example.com", "SRV")

        snapshot = collector.snapshot()
        assert snapshot.qtype_qnames is not None
        for qtype in ["A", "AAAA", "PTR", "TXT", "SRV"]:
            assert qtype in snapshot.qtype_qnames
            assert isinstance(snapshot.qtype_qnames[qtype], list)

    def test_response_rcodes(self):
        """Response codes tracked."""
        collector = StatsCollector()
        collector.record_response_rcode("NOERROR")
        collector.record_response_rcode("NOERROR")
        collector.record_response_rcode("NXDOMAIN")
        snapshot = collector.snapshot()
        assert snapshot.rcodes["NOERROR"] == 2
        assert snapshot.rcodes["NXDOMAIN"] == 1

    def test_cache_and_rcode_subdomain_metrics(self):
        """Cache and rcode *_sub metrics count only subdomain queries per subdomain name."""
        collector = StatsCollector(include_top_domains=True, top_n=5)

        # Cache hits/misses: one base-only and one subdomain-only per base.
        collector.record_cache_hit("example.com")
        collector.record_cache_hit("www.example.com")  # subdomain of example.com
        collector.record_cache_miss("other.com")
        collector.record_cache_miss("api.other.com")  # subdomain of other.com

        # RcDoes: mix base and subdomain queries per rcode.
        collector.record_response_rcode("NOERROR", qname="example.com")
        collector.record_response_rcode("NOERROR", qname="www.example.com")
        collector.record_response_rcode("NXDOMAIN", qname="example.com")
        collector.record_response_rcode("NXDOMAIN", qname="nx.example.com")

        snapshot = collector.snapshot(reset=False)

        # Cache hit domains vs cache_hit_subdomains
        assert snapshot.cache_hit_domains is not None
        hit_domains = dict(snapshot.cache_hit_domains)
        # Both base and subdomain queries contribute to the base-domain count.
        assert hit_domains["example.com"] == 2

        assert snapshot.cache_hit_subdomains is not None
        hit_sub = dict(snapshot.cache_hit_subdomains)
        # Only the subdomain query contributes here, keyed by full qname.
        assert hit_sub["www.example.com"] == 1

        # Cache miss domains vs cache_miss_subdomains
        assert snapshot.cache_miss_domains is not None
        miss_domains = dict(snapshot.cache_miss_domains)
        assert miss_domains["other.com"] == 2

        assert snapshot.cache_miss_subdomains is not None
        miss_sub = dict(snapshot.cache_miss_subdomains)
        assert miss_sub["api.other.com"] == 1

        # Rcode domains vs rcode_subdomains
        assert snapshot.rcode_domains is not None
        assert snapshot.rcode_subdomains is not None

        noerror_domains = dict(snapshot.rcode_domains.get("NOERROR", []))
        noerror_sub = dict(snapshot.rcode_subdomains.get("NOERROR", []))
        # Two NOERROR responses for example.com (base + subdomain).
        assert noerror_domains["example.com"] == 2
        # Only the subdomain query shows up in the *_sub view, keyed by full qname.
        assert noerror_sub["www.example.com"] == 1

        nx_domains = dict(snapshot.rcode_domains.get("NXDOMAIN", []))
        nx_sub = dict(snapshot.rcode_subdomains.get("NXDOMAIN", []))
        # Both base and subdomain NXDOMAIN queries count at the base domain.
        assert nx_domains["example.com"] == 2
        # Only the subdomain query contributes to the *_sub view.
        assert nx_sub["nx.example.com"] == 1

    def test_latency_tracking(self):
        """Latency tracking when enabled."""
        collector = StatsCollector(track_latency=True)
        collector.record_latency(0.005)
        collector.record_latency(0.010)
        snapshot = collector.snapshot()
        assert snapshot.latency_stats is not None
        assert snapshot.latency_stats["count"] == 2

    def test_latency_disabled(self):
        """Latency tracking disabled by default."""
        collector = StatsCollector(track_latency=False)
        collector.record_latency(0.005)
        snapshot = collector.snapshot()
        assert snapshot.latency_stats is None

    def test_record_dnssec_status_valid_and_invalid(self) -> None:
        """Brief: record_dnssec_status ignores unknown values and tracks known ones.

        Inputs:
          - None.

        Outputs:
          - None; asserts only supported dnssec_* totals are incremented.
        """

        collector = StatsCollector()
        # Empty/unknown statuses are ignored.
        collector.record_dnssec_status("")
        collector.record_dnssec_status("unknown")
        # Supported statuses map directly to dnssec_* totals keys.
        for status in [
            "dnssec_secure",
            "dnssec_zone_secure",
            "dnssec_unsigned",
            "dnssec_bogus",
            "dnssec_indeterminate",
        ]:
            collector.record_dnssec_status(status)

        snapshot = collector.snapshot()
        assert snapshot.totals["dnssec_secure"] == 1
        assert snapshot.totals["dnssec_zone_secure"] == 1
        assert snapshot.totals["dnssec_unsigned"] == 1
        assert snapshot.totals["dnssec_bogus"] == 1
        assert snapshot.totals["dnssec_indeterminate"] == 1

    def test_unique_tracking(self):
        """Unique clients and domains tracked."""
        collector = StatsCollector(track_uniques=True)
        collector.record_query("192.0.2.1", "example.com", "A")
        collector.record_query("192.0.2.1", "google.com", "A")
        collector.record_query("192.0.2.2", "example.com", "A")
        snapshot = collector.snapshot()
        assert snapshot.uniques["clients"] == 2
        assert snapshot.uniques["domains"] == 2

    def test_unique_tracking_disabled(self):
        """Unique tracking can be disabled."""
        collector = StatsCollector(track_uniques=False)
        collector.record_query("192.0.2.1", "example.com", "A")
        snapshot = collector.snapshot()
        assert snapshot.uniques is None

    def test_record_cache_stat_and_pre_plugin_labels(self) -> None:
        """Brief: cache_stat and cache_pre_plugin labels update totals and stores safely.

        Inputs:
          - None.

        Outputs:
          - None; asserts empty labels are ignored and valid labels touch totals
          - and, when a store is attached, persistent counts.
        """

        from unittest.mock import MagicMock

        # Empty labels are ignored
        collector = StatsCollector()
        collector.record_cache_stat("")
        collector.record_cache_pre_plugin("")
        snap = collector.snapshot(reset=False)
        assert all(not k.startswith("cache_stat_") for k in snap.totals.keys())

        # Defensive path: non-integer existing total should not raise
        collector._totals["cache_stat_bad"] = "oops"  # type: ignore[assignment]
        collector.record_cache_stat("bad")

        # With a backing store, both helpers mirror into SQLite scopes.
        store = MagicMock()
        collector2 = StatsCollector(stats_store=store)
        collector2.record_cache_stat("label")
        collector2.record_cache_pre_plugin("pre_deny_filter")

        store.increment_count.assert_any_call("cache", "label")
        store.increment_count.assert_any_call("totals", "pre_deny_filter")

    def test_top_clients(self):
        """Top clients tracked when enabled."""
        collector = StatsCollector(include_top_clients=True, top_n=2)
        for _ in range(10):
            collector.record_query("192.0.2.1", "example.com", "A")
        for _ in range(5):
            collector.record_query("192.0.2.2", "example.com", "A")
        snapshot = collector.snapshot()
        assert len(snapshot.top_clients) == 2
        assert snapshot.top_clients[0][0] == "192.0.2.1"
        assert snapshot.top_clients[0][1] == 10

    def test_top_domains(self):
        """Top domains tracked when enabled."""
        collector = StatsCollector(include_top_domains=True, top_n=2)
        for _ in range(10):
            collector.record_query("192.0.2.1", "example.com", "A")
        for _ in range(5):
            collector.record_query("192.0.2.1", "google.com", "A")
        snapshot = collector.snapshot()
        assert len(snapshot.top_domains) == 2
        assert snapshot.top_domains[0][0] == "example.com"

    def test_snapshot_without_reset(self):
        """Snapshot without reset preserves counters."""
        collector = StatsCollector()
        collector.record_query("192.0.2.1", "example.com", "A")
        snapshot1 = collector.snapshot(reset=False)
        snapshot2 = collector.snapshot(reset=False)
        assert snapshot1.totals["total_queries"] == 1
        assert snapshot2.totals["total_queries"] == 1

    def test_snapshot_with_reset(self):
        """Snapshot with reset clears counters."""
        collector = StatsCollector()
        collector.record_query("192.0.2.1", "example.com", "A")
        snapshot1 = collector.snapshot(reset=True)
        snapshot2 = collector.snapshot(reset=False)
        assert snapshot1.totals["total_queries"] == 1
        assert snapshot2.totals.get("total_queries", 0) == 0

    def test_rate_limit_summary_handles_non_integer_total(self) -> None:
        """Brief: rate_limit summary falls back safely when cache_stat counter is non-int.

        Inputs:
          - None.

        Outputs:
          - None; asserts rate_limit.denied defaults to 0 on bad totals value.
        """

        collector = StatsCollector()
        # Manually inject a non-integer cache_stat_rate_limit to exercise the
        # defensive conversion path used when deriving rate_limit.
        collector._totals["cache_stat_rate_limit"] = "not-an-int"  # type: ignore[assignment]
        snapshot = collector.snapshot(reset=False)
        assert snapshot.rate_limit == {"denied": 0}

    def test_qtype_breakdown(self):
        """Qtype breakdown tracked when enabled."""
        collector = StatsCollector(include_qtype_breakdown=True)
        collector.record_query("192.0.2.1", "example.com", "A")
        collector.record_query("192.0.2.1", "example.com", "AAAA")
        collector.record_query("192.0.2.1", "example.com", "A")
        snapshot = collector.snapshot()
        assert snapshot.qtypes["A"] == 2
        assert snapshot.qtypes["AAAA"] == 1

    def test_domain_normalization_in_queries(self):
        """Domains are normalized when recording queries."""
        collector = StatsCollector(
            track_uniques=True, include_top_domains=True, top_n=5
        )
        collector.record_query("192.0.2.1", "Example.COM.", "A")
        collector.record_query("192.0.2.1", "example.com", "A")
        snapshot = collector.snapshot()
        # Both should be normalized to "example.com"
        assert snapshot.uniques["domains"] == 1


from foghorn.stats import _is_subdomain


class TestSubdomainMetrics:
    def test_subdomain_lists_only_contain_true_subdomains(self) -> None:
        """Subdomain-oriented metrics must only contain true subdomain names.

        Inputs:
          - StatsCollector configured with include_top_domains=True.

        Outputs:
          - Asserts that top_subdomains, cache_*_subdomains, and rcode_subdomains
            only contain names where _is_subdomain(name) is True.
        """

        collector = StatsCollector(include_top_domains=True, top_n=10)

        # Mix of base and subdomain queries for cache and rcodes.
        collector.record_query("192.0.2.1", "www.example.com", "A")
        collector.record_query("192.0.2.2", "api.other.com", "A")

        collector.record_cache_hit("www.example.com")
        collector.record_cache_miss("api.other.com")

        collector.record_response_rcode("NOERROR", qname="www.example.com")
        collector.record_response_rcode("NXDOMAIN", qname="nx.example.com")

        snapshot = collector.snapshot(reset=False)

        # Top subdomains (full qnames) should all be true subdomains.
        assert snapshot.top_subdomains is not None
        for name, _count in snapshot.top_subdomains:
            assert _is_subdomain(name)

        # Cache hit/miss subdomain lists should also be pure subdomains.
        for sub_list in (snapshot.cache_hit_subdomains, snapshot.cache_miss_subdomains):
            if not sub_list:
                continue
            for name, _count in sub_list:
                assert _is_subdomain(name)

        # Rcode subdomain lists are keyed by full subdomain qnames per rcode.
        if snapshot.rcode_subdomains:
            for entries in snapshot.rcode_subdomains.values():
                for name, _count in entries:
                    assert _is_subdomain(name)

    def test_is_subdomain_empty_and_base(self) -> None:
        """Brief: _is_subdomain returns False for empty and base-domain names.

        Inputs:
          - None.

        Outputs:
          - None; asserts "" and simple base domains are not treated as subdomains.
        """

        assert _is_subdomain("") is False
        assert _is_subdomain("example.com") is False


class TestConcurrency:
    """Test thread-safety of StatsCollector."""

    def test_concurrent_recording(self):
        """Concurrent recording from multiple threads is safe."""
        collector = StatsCollector()
        num_threads = 10
        events_per_thread = 100

        def worker():
            for _ in range(events_per_thread):
                collector.record_query("192.0.2.1", "example.com", "A")
                collector.record_cache_hit("example.com")
                collector.record_response_rcode("NOERROR")

        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snapshot = collector.snapshot()
        expected = num_threads * events_per_thread
        assert snapshot.totals["total_queries"] == expected
        assert snapshot.totals["cache_hits"] == expected
        assert snapshot.rcodes["NOERROR"] == expected


class TestFormatSnapshotJson:
    """Test JSON formatting of snapshots."""

    def test_json_format_basic(self):
        """Basic JSON formatting produces valid JSON."""
        collector = StatsCollector()
        collector.record_query("192.0.2.1", "example.com", "A")
        snapshot = collector.snapshot()
        json_str = format_snapshot_json(snapshot)
        parsed = json.loads(json_str)
        assert "ts" in parsed
        assert "totals" in parsed
        assert parsed["totals"]["total_queries"] == 1

    def test_json_single_line(self):
        """JSON output is a single line."""
        collector = StatsCollector()
        collector.record_query("192.0.2.1", "example.com", "A")
        snapshot = collector.snapshot()
        json_str = format_snapshot_json(snapshot)
        assert "\n" not in json_str

    def test_json_omits_empty_sections(self):
        """Empty sections are omitted from JSON."""
        collector = StatsCollector(
            track_latency=False, include_top_clients=False, include_top_domains=False
        )
        snapshot = collector.snapshot()
        json_str = format_snapshot_json(snapshot)
        parsed = json.loads(json_str)
        assert "latency" not in parsed
        assert "top_clients" not in parsed
        assert "top_domains" not in parsed

    def test_json_includes_enabled_sections(self):
        """Enabled sections appear in JSON."""
        collector = StatsCollector(
            track_latency=True, include_top_clients=True, top_n=5
        )
        collector.record_query("192.0.2.1", "example.com", "A")
        collector.record_latency(0.005)
        snapshot = collector.snapshot()
        json_str = format_snapshot_json(snapshot)
        parsed = json.loads(json_str)
        assert "latency" in parsed
        assert "top_clients" in parsed

    def test_json_includes_rate_limit_summary(self) -> None:
        """Brief: JSON output includes derived rate_limit summary when present.

        Inputs:
          - None.

        Outputs:
          - None; asserts rate_limit.denied reflects cache_stat_rate_limit.
        """

        collector = StatsCollector()
        # Populate the cache_stat_rate_limit counter via the public helper.
        collector.record_cache_stat("rate_limit")
        collector.record_cache_stat("rate_limit")

        snapshot = collector.snapshot(reset=False)
        json_str = format_snapshot_json(snapshot)
        parsed = json.loads(json_str)

        assert "rate_limit" in parsed
        assert parsed["rate_limit"]["denied"] == 2


class TestStatsReporter:
    """Test periodic stats reporter."""

    def test_reporter_starts_and_stops(self):
        """Reporter thread starts and stops cleanly."""
        collector = StatsCollector()
        reporter = StatsReporter(collector, interval_seconds=10)
        # Use a much smaller interval in tests to avoid long sleeps.
        reporter.interval_seconds = 0.01
        reporter.start()
        time.sleep(0.05)
        assert reporter.is_alive()
        reporter.stop(timeout=2.0)
        assert not reporter.is_alive()

    def test_reporter_logs_periodically(self):
        """Reporter logs at specified intervals."""
        collector = StatsCollector()
        collector.record_query("192.0.2.1", "example.com", "A")

        # Use simpler test: verify snapshot is called with reset flag
        reporter = StatsReporter(collector, interval_seconds=0.1, reset_on_log=False)
        # Speed up for tests: shorter interval
        reporter.interval_seconds = 0.01
        reporter.start()
        time.sleep(0.05)  # Wait for at least a couple of intervals
        reporter.stop(timeout=2.0)

        # Verify counter is still there (no reset)
        snapshot = collector.snapshot()
        assert snapshot.totals["total_queries"] == 1

    def test_reporter_reset_on_log(self):
        """Reporter resets counters when configured."""
        collector = StatsCollector()

        # Test reset directly via snapshot to avoid thread timing issues
        collector.record_query("192.0.2.1", "example.com", "A")
        snapshot1 = collector.snapshot(reset=True)
        assert snapshot1.totals["total_queries"] == 1

        snapshot2 = collector.snapshot(reset=False)
        assert snapshot2.totals.get("total_queries", 0) == 0


class MockLogHandler(logging.Handler):
    """Mock log handler for capturing log records."""

    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)
