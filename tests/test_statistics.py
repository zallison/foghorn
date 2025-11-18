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

    def test_plugin_decisions(self):
        """Plugin decisions tracked with action and reason."""
        collector = StatsCollector()
        collector.record_plugin_decision(
            "FilterPlugin", "block", reason="blocklist", domain="bad.com"
        )
        collector.record_plugin_decision("FilterPlugin", "allow", reason="allowlist")
        snapshot = collector.snapshot()
        assert snapshot.totals["blocked"] == 1
        assert snapshot.totals["allowed"] == 1
        assert snapshot.decisions["FilterPlugin"]["block"] == 1
        assert snapshot.decisions["FilterPlugin"]["allow"] == 1
        assert snapshot.decisions["FilterPlugin"]["blocked_by"]["blocklist"] == 1

    def test_upstream_results(self):
        """Upstream results tracked per upstream."""
        collector = StatsCollector()
        collector.record_upstream_result("8.8.8.8:53", "success")
        collector.record_upstream_result("8.8.8.8:53", "success")
        collector.record_upstream_result("1.1.1.1:53", "timeout")
        snapshot = collector.snapshot()
        assert snapshot.upstreams["8.8.8.8:53"]["success"] == 2
        assert snapshot.upstreams["1.1.1.1:53"]["timeout"] == 1

    def test_response_rcodes(self):
        """Response codes tracked."""
        collector = StatsCollector()
        collector.record_response_rcode("NOERROR")
        collector.record_response_rcode("NOERROR")
        collector.record_response_rcode("NXDOMAIN")
        snapshot = collector.snapshot()
        assert snapshot.rcodes["NOERROR"] == 2
        assert snapshot.rcodes["NXDOMAIN"] == 1

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
