"""
Tests for SQLite-backed statistics persistence and warm-load helpers.

Inputs:
    - StatsCollector, StatsSnapshot, StatsSQLiteStore
Outputs:
    - None; assertions verify round-trip persistence and load_from_snapshot.
"""

from pathlib import Path
from typing import Dict

import pytest

from foghorn.stats import StatsCollector, StatsSnapshot, StatsSQLiteStore


def _make_sample_snapshot() -> StatsSnapshot:
    """Brief: Helper to create a StatsSnapshot with non-trivial contents.

    Inputs:
        None
    Outputs:
        StatsSnapshot with populated totals/rcodes/qtypes/decisions/upstreams.
    """
    collector = StatsCollector(
        track_uniques=True,
        include_qtype_breakdown=True,
        include_top_clients=False,
        include_top_domains=False,
        track_latency=False,
    )
    # Populate some metrics
    collector.record_query("192.0.2.1", "example.com", "A")
    collector.record_query("192.0.2.2", "example.com", "AAAA")
    collector.record_cache_hit("example.com")
    collector.record_cache_miss("other.com")
    collector.record_response_rcode("NOERROR")
    collector.record_response_rcode("NXDOMAIN")
    collector.record_plugin_decision(
        "FilterPlugin", "block", reason="blocklist", domain="bad.com"
    )
    collector.record_plugin_decision(
        "FilterPlugin", "allow", reason="allowlist", domain="good.com"
    )
    collector.record_upstream_result("8.8.8.8:53", "success")
    collector.record_upstream_result("1.1.1.1:53", "timeout")

    return collector.snapshot(reset=False)


def test_stats_collector_load_from_snapshot_restores_core_counters() -> None:
    """Brief: load_from_snapshot restores core counters and aggregates.

    Inputs:
        None (uses _make_sample_snapshot)
    Outputs:
        None; asserts totals/rcodes/qtypes/decisions/upstreams restored.
    """
    snap = _make_sample_snapshot()

    # New collector starts empty
    target = StatsCollector(
        track_uniques=True,
        include_qtype_breakdown=True,
        include_top_clients=False,
        include_top_domains=False,
        track_latency=False,
    )
    snap_before = target.snapshot(reset=False)
    assert snap_before.totals == {}
    assert snap_before.rcodes == {}
    assert snap_before.qtypes == {}
    assert snap_before.upstreams == {}
    assert snap_before.decisions == {}

    # Apply snapshot and verify state
    target.load_from_snapshot(snap)
    snap_after = target.snapshot(reset=False)

    assert snap_after.totals == snap.totals
    assert snap_after.rcodes == snap.rcodes
    assert snap_after.qtypes == snap.qtypes
    assert snap_after.upstreams == snap.upstreams
    assert snap_after.decisions == snap.decisions

    # Uniques/top/latency may remain process-local; do not require equality.
    # Just ensure snapshot_after has at least the same totals.
    assert snap_after.totals["total_queries"] == snap.totals["total_queries"]


def test_sqlite_store_load_latest_snapshot_empty_db(tmp_path: Path) -> None:
    """Brief: load_latest_snapshot returns None when no snapshots exist.

    Inputs:
        tmp_path: pytest-provided temporary directory
    Outputs:
        None; asserts no snapshot is returned from an empty DB.
    """
    db_path = tmp_path / "stats.db"
    store = StatsSQLiteStore(db_path=str(db_path))

    try:
        loaded = store.load_latest_snapshot()
    finally:
        store.close()

    assert loaded is None


def test_sqlite_store_roundtrip_snapshot(tmp_path: Path) -> None:
    """Brief: StatsSQLiteStore can persist and reload a snapshot round-trip.

    Inputs:
        tmp_path: pytest-provided temporary directory
    Outputs:
        None; asserts core fields survive save/load.
    """
    db_path = tmp_path / "stats_roundtrip.db"
    original = _make_sample_snapshot()

    store = StatsSQLiteStore(db_path=str(db_path))
    try:
        store.save_snapshot(original)
        loaded = store.load_latest_snapshot()
    finally:
        store.close()

    assert loaded is not None
    assert isinstance(loaded, StatsSnapshot)

    # Compare core aggregates
    assert loaded.totals == original.totals
    assert loaded.rcodes == original.rcodes
    assert loaded.qtypes == original.qtypes
    assert loaded.upstreams == original.upstreams
    assert loaded.decisions == original.decisions

    # Sanity-check created_at ordering
    assert loaded.created_at >= original.created_at
    assert db_path.exists()
