"""
Tests for latency_recent statistics feature.

Inputs:
    - StatsCollector with track_latency=True

Outputs:
    - None; assertions verify latency_recent behavior
"""

import json
import threading

from foghorn.stats import StatsCollector, format_snapshot_json


def test_latency_recent_mirrors_latency_shape():
    """
    latency_recent has the same keys as latency.

    Inputs:
        - StatsCollector with track_latency=True
        - Two recorded latency samples

    Outputs:
        - None; asserts latency_recent keys match latency keys
    """
    collector = StatsCollector(track_latency=True)
    collector.record_latency(0.005)
    collector.record_latency(0.010)

    snapshot = collector.snapshot()
    assert snapshot.latency_stats is not None
    assert snapshot.latency_recent_stats is not None

    # Same keys
    assert set(snapshot.latency_stats.keys()) == set(
        snapshot.latency_recent_stats.keys()
    )
    # Both have count = 2
    assert snapshot.latency_stats["count"] == 2
    assert snapshot.latency_recent_stats["count"] == 2


def test_latency_recent_resets_independently():
    """
    latency_recent resets without affecting cumulative latency.

    Inputs:
        - StatsCollector with track_latency=True
        - Samples recorded, then reset_latency_recent called

    Outputs:
        - None; asserts cumulative latency persists, recent resets
    """
    collector = StatsCollector(track_latency=True)
    collector.record_latency(0.005)
    collector.record_latency(0.010)

    snap1 = collector.snapshot()
    assert snap1.latency_stats["count"] == 2
    assert snap1.latency_recent_stats["count"] == 2

    # Reset only recent
    collector.reset_latency_recent()

    snap2 = collector.snapshot()
    # Cumulative unchanged
    assert snap2.latency_stats["count"] == 2
    # Recent cleared
    assert snap2.latency_recent_stats["count"] == 0


def test_latency_recent_interval_behavior():
    """
    latency_recent tracks only samples since last reset.

    Inputs:
        - StatsCollector with track_latency=True
        - Multiple intervals with resets

    Outputs:
        - None; asserts each interval shows only new samples in recent
    """
    collector = StatsCollector(track_latency=True)

    # Interval 1: 2 samples
    collector.record_latency(0.001)
    collector.record_latency(0.002)
    snap1 = collector.snapshot()
    assert snap1.latency_recent_stats["count"] == 2
    assert snap1.latency_stats["count"] == 2

    # Reset recent
    collector.reset_latency_recent()

    # Interval 2: 3 more samples
    collector.record_latency(0.003)
    collector.record_latency(0.004)
    collector.record_latency(0.005)
    snap2 = collector.snapshot()
    assert snap2.latency_recent_stats["count"] == 3
    # Cumulative = 5
    assert snap2.latency_stats["count"] == 5


def test_latency_recent_with_reset_on_log_true():
    """
    With reset=True, both cumulative and recent are cleared.

    Inputs:
        - StatsCollector with track_latency=True
        - snapshot(reset=True) called

    Outputs:
        - None; asserts both latency and latency_recent reset
    """
    collector = StatsCollector(track_latency=True)
    collector.record_latency(0.001)
    collector.record_latency(0.002)

    snap1 = collector.snapshot(reset=True)
    assert snap1.latency_stats["count"] == 2
    assert snap1.latency_recent_stats["count"] == 2

    # Both should be cleared after reset=True
    snap2 = collector.snapshot()
    assert snap2.latency_stats["count"] == 0
    assert snap2.latency_recent_stats["count"] == 0

    # New samples populate both
    collector.record_latency(0.003)
    snap3 = collector.snapshot()
    assert snap3.latency_stats["count"] == 1
    assert snap3.latency_recent_stats["count"] == 1


def test_latency_recent_zero_samples():
    """
    latency_recent with zero samples returns zero-valued stats.

    Inputs:
        - StatsCollector with track_latency=True
        - No latencies recorded

    Outputs:
        - None; asserts count=0 and other fields are 0.0
    """
    collector = StatsCollector(track_latency=True)
    snapshot = collector.snapshot()
    assert snapshot.latency_recent_stats is not None
    assert snapshot.latency_recent_stats["count"] == 0
    assert snapshot.latency_recent_stats["min_ms"] == 0.0
    assert snapshot.latency_recent_stats["max_ms"] == 0.0
    assert snapshot.latency_recent_stats["avg_ms"] == 0.0


def test_latency_recent_json_output():
    """
    JSON output includes latency_recent.

    Inputs:
        - StatsCollector with track_latency=True
        - format_snapshot_json called

    Outputs:
        - None; asserts 'latency_recent' key present in JSON
    """
    collector = StatsCollector(track_latency=True)
    collector.record_latency(0.005)
    snapshot = collector.snapshot()
    json_str = format_snapshot_json(snapshot)
    parsed = json.loads(json_str)

    assert "latency" in parsed
    assert "latency_recent" in parsed
    assert parsed["latency"]["count"] == 1
    assert parsed["latency_recent"]["count"] == 1


def test_latency_recent_thread_safety():
    """
    Concurrent latency recording is thread-safe.

    Inputs:
        - StatsCollector with track_latency=True
        - Multiple threads recording latencies concurrently

    Outputs:
        - None; asserts final counts match expected totals
    """
    collector = StatsCollector(track_latency=True)
    num_threads = 10
    samples_per_thread = 50

    def worker():
        """
        Record samples in a worker thread.

        Inputs:
            None (uses closure)

        Outputs:
            None
        """
        for _ in range(samples_per_thread):
            collector.record_latency(0.001)

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    snapshot = collector.snapshot()
    expected = num_threads * samples_per_thread
    assert snapshot.latency_stats["count"] == expected
    assert snapshot.latency_recent_stats["count"] == expected


def test_latency_recent_disabled_when_track_latency_false():
    """
    latency_recent is None when track_latency=False.

    Inputs:
        - StatsCollector with track_latency=False

    Outputs:
        - None; asserts latency_recent_stats is None
    """
    collector = StatsCollector(track_latency=False)
    collector.record_latency(0.005)  # Should be no-op
    snapshot = collector.snapshot()
    assert snapshot.latency_stats is None
    assert snapshot.latency_recent_stats is None
