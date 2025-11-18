"""
Tests for SQLite-backed statistics persistence and warm-load helpers.

Inputs:
    - StatsCollector, StatsSnapshot, StatsSQLiteStore
Outputs:
    - None; assertions verify load_from_snapshot and basic SQLite schema.
"""

import sqlite3
from pathlib import Path

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


def test_sqlite_store_counts_increment_and_set(tmp_path: Path) -> None:
    """Brief: StatsSQLiteStore maintains counts via increment_count and set_count.

    Inputs:
        tmp_path: pytest-provided temporary directory
    Outputs:
        None; asserts counts table reflects increment and set operations.
    """
    db_path = tmp_path / "stats_counts.db"
    store = StatsSQLiteStore(db_path=str(db_path))

    try:
        # Increment "totals.total_queries" twice and then override via set.
        store.increment_count("totals", "total_queries")
        store.increment_count("totals", "total_queries", delta=2)
        store.set_count("totals", "total_queries", 10)

        # Verify via a direct sqlite3 query.
        conn = sqlite3.connect(str(db_path))
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT value FROM counts WHERE scope = ? AND key = ?",
                ("totals", "total_queries"),
            )
            row = cur.fetchone()
        finally:
            conn.close()
    finally:
        store.close()

    assert row is not None
    assert row[0] == 10


def test_sqlite_store_query_log_insert(tmp_path: Path) -> None:
    """Brief: StatsSQLiteStore.insert_query_log appends rows to query_log.

    Inputs:
        tmp_path: pytest-provided temporary directory
    Outputs:
        None; asserts a row is present with expected fields.
    """
    db_path = tmp_path / "stats_query_log.db"
    store = StatsSQLiteStore(db_path=str(db_path))

    try:
        store.insert_query_log(
            ts=1763364639.432,
            client_ip="192.0.2.1",
            name="example.com",
            qtype="A",
            upstream_id="8.8.8.8:53",
            rcode="NOERROR",
            status="ok",
            error=None,
            first="93.184.216.34",
            result_json='{"answers": []}',
        )

        conn = sqlite3.connect(str(db_path))
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT client_ip, name, qtype, upstream_id, rcode, status FROM query_log"
            )
            row = cur.fetchone()
        finally:
            conn.close()
    finally:
        store.close()

    assert row is not None
    assert row[0] == "192.0.2.1"
    assert row[1] == "example.com"
    assert row[2] == "A"
    assert row[3] == "8.8.8.8:53"
    assert row[4] == "NOERROR"
    assert row[5] == "ok"


def test_sqlite_store_rebuild_counts_if_needed(tmp_path: Path) -> None:
    """Brief: rebuild_counts_if_needed populates counts from existing query_log rows.

    Inputs:
        tmp_path: pytest-provided temporary directory
    Outputs:
        None; asserts totals.total_queries reflects query_log row count after rebuild.
    """
    db_path = tmp_path / "stats_rebuild.db"
    store = StatsSQLiteStore(db_path=str(db_path))

    try:
        # Insert two log rows with different clients/qtypes to drive aggregation.
        store.insert_query_log(
            ts=1763364639.100,
            client_ip="192.0.2.10",
            name="example.com",
            qtype="A",
            upstream_id="8.8.8.8:53",
            rcode="NOERROR",
            status="ok",
            error=None,
            first="93.184.216.34",
            result_json='{"answers":[{"a":1}]}',
        )
        store.insert_query_log(
            ts=1763364639.200,
            client_ip="192.0.2.11",
            name="example.com",
            qtype="AAAA",
            upstream_id=None,
            rcode="NXDOMAIN",
            status="error",
            error="nx",
            first=None,
            result_json='{"answers":[]}',
        )

        # At this point counts is empty; request rebuild.
        store.rebuild_counts_if_needed(force_rebuild=False)

        conn = sqlite3.connect(str(db_path))
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT value FROM counts WHERE scope = ? AND key = ?",
                ("totals", "total_queries"),
            )
            total_row = cur.fetchone()
        finally:
            conn.close()
    finally:
        store.close()

    assert total_row is not None
    # Two query_log rows should yield total_queries == 2 after rebuild.
    assert total_row[0] == 2


def test_stats_collector_warm_load_from_store_uses_counts(tmp_path: Path) -> None:
    """Brief: StatsCollector.warm_load_from_store hydrates counters from SQLite counts.

    Inputs:
        tmp_path: pytest tmp path for an isolated SQLite DB.
    Outputs:
        None; asserts that totals/qtypes/rcodes/upstreams are restored.
    """
    db_path = tmp_path / "stats_warm_load.db"
    store = StatsSQLiteStore(db_path=str(db_path))

    try:
        # Seed some aggregate counts directly via the store.
        store.increment_count("totals", "total_queries", delta=3)
        store.increment_count("rcodes", "NOERROR", delta=2)
        store.increment_count("qtypes", "A", delta=3)
        store.increment_count("upstreams", "8.8.8.8:53|success", delta=1)

        # Create collector wired to the store and warm-load from counts.
        collector = StatsCollector(
            track_uniques=True,
            include_qtype_breakdown=True,
            include_top_clients=False,
            include_top_domains=False,
            track_latency=False,
            stats_store=store,
        )
        # Collector starts empty.
        snap_empty = collector.snapshot(reset=False)
        assert snap_empty.totals.get("total_queries", 0) == 0
        assert snap_empty.qtypes == {}
        assert snap_empty.rcodes == {}
        assert snap_empty.upstreams == {}

        collector.warm_load_from_store()
        snap = collector.snapshot(reset=False)

        assert snap.totals["total_queries"] == 3
        assert snap.rcodes["NOERROR"] == 2
        assert snap.qtypes["A"] == 3
        # Upstreams use nested mapping upstream_id -> {outcome -> count}.
        assert snap.upstreams["8.8.8.8:53"]["success"] == 1
    finally:
        store.close()


def test_stats_collector_warm_load_populates_top_lists(tmp_path: Path) -> None:
    """Brief: warm_load_from_store reconstructs top clients/domains from counts.

    Inputs:
        tmp_path: pytest tmp path for an isolated SQLite DB.
    Outputs:
        None; asserts top_clients/top_domains/top_subdomains reflect DB aggregates.
    """
    db_path = tmp_path / "stats_warm_load_top.db"
    store = StatsSQLiteStore(db_path=str(db_path))

    try:
        # Seed some per-client and per-domain counts.
        store.increment_count("clients", "192.0.2.1", delta=5)
        store.increment_count("clients", "192.0.2.2", delta=2)

        store.increment_count("sub_domains", "www.example.com", delta=3)
        store.increment_count("sub_domains", "api.example.com", delta=1)

        store.increment_count("domains", "example.com", delta=4)
        store.increment_count("domains", "other.com", delta=2)

        collector = StatsCollector(
            track_uniques=True,
            include_qtype_breakdown=True,
            include_top_clients=True,
            include_top_domains=True,
            top_n=5,
            track_latency=False,
            stats_store=store,
        )

        # Snapshot before warm-load should have no tops/uniques.
        snap_empty = collector.snapshot(reset=False)
        assert snap_empty.top_clients in (None, [])
        assert snap_empty.top_domains in (None, [])
        assert snap_empty.top_subdomains in (None, [])
        if snap_empty.uniques:
            assert snap_empty.uniques["clients"] == 0
            assert snap_empty.uniques["domains"] == 0

        collector.warm_load_from_store()
        snap = collector.snapshot(reset=False)

        # Top clients: 192.0.2.1 should be first with count 5.
        assert snap.top_clients is not None
        assert snap.top_clients[0][0] == "192.0.2.1"
        assert snap.top_clients[0][1] == 5

        # Top subdomains: www.example.com should lead with count 3.
        assert snap.top_subdomains is not None
        assert snap.top_subdomains[0][0] == "www.example.com"
        assert snap.top_subdomains[0][1] == 3

        # Top domains: example.com should lead with count 4.
        assert snap.top_domains is not None
        assert snap.top_domains[0][0] == "example.com"
        assert snap.top_domains[0][1] == 4

        # Unique counts reconstructed from keys.
        assert snap.uniques is not None
        assert snap.uniques["clients"] == 2
        assert snap.uniques["domains"] >= 1
    finally:
        store.close()
