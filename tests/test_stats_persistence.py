"""
Tests for SQLite-backed statistics persistence and warm-load helpers.

Inputs:
    - StatsCollector, StatsSnapshot, StatsSQLiteStore
Outputs:
    - None; assertions verify load_from_snapshot and basic SQLite schema.
"""

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Dict

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
        "Filter", "block", reason="blocklist", domain="bad.com"
    )
    collector.record_plugin_decision(
        "Filter", "allow", reason="allowlist", domain="good.com"
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
    # New snapshots always include baseline pre-plugin cache counters at 0.
    assert snap_before.totals == {
        "cache_deny_pre": 0,
        "cache_override_pre": 0,
    }
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
        with closing(sqlite3.connect(str(db_path))) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT value FROM counts WHERE scope = ? AND key = ?",
                ("totals", "total_queries"),
            )
            row = cur.fetchone()
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

        with closing(sqlite3.connect(str(db_path))) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT client_ip, name, qtype, upstream_id, rcode, status FROM query_log"
            )
            row = cur.fetchone()
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

        with closing(sqlite3.connect(str(db_path))) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT value FROM counts WHERE scope = ? AND key = ?",
                ("totals", "total_queries"),
            )
            total_row = cur.fetchone()

        # Request a forced rebuild when counts already exist to exercise the
        # "force_rebuild" path; this should not raise and will simply
        # recompute aggregates from the same query_log rows.
        store.rebuild_counts_if_needed(force_rebuild=True)
    finally:
        store.close()

    assert total_row is not None
    # Two query_log rows should yield total_queries == 2 after rebuild.
    assert total_row[0] == 2


def test_sqlite_store_rebuild_counts_records_dnssec_status(tmp_path: Path) -> None:
    """Brief: rebuild_counts_from_query_log aggregates dnssec_status from result_json.

    This ensures that rows with a dnssec_status field in result_json increment the
    corresponding totals.dnssec_* counter during rebuild.
    """
    db_path = tmp_path / "stats_rebuild_dnssec.db"
    store = StatsSQLiteStore(db_path=str(db_path))

    try:
        # Insert a single log row with a dnssec_status in result_json.
        store.insert_query_log(
            ts=1763364639.300,
            client_ip="192.0.2.20",
            name="dnssec.example",
            qtype="A",
            upstream_id="8.8.8.8:53",
            rcode="NOERROR",
            status="ok",
            error=None,
            first="203.0.113.10",
            result_json='{"answers":[],"dnssec_status":"dnssec_bogus"}',
        )

        # Rebuild counts directly from query_log.
        store.rebuild_counts_from_query_log()

        counts = store.export_counts()
        totals = counts.get("totals", {})
    finally:
        store.close()

    # One dnssec_status="dnssec_bogus" row should produce dnssec_bogus == 1.
    assert totals.get("dnssec_bogus") == 1


def test_sqlite_store_batched_execute_and_flush(tmp_path: Path) -> None:
    """Brief: Batched SQLite store queues and flushes operations as thresholds are met.

    Inputs:
        tmp_path: pytest tmp path for an isolated SQLite DB.

    Outputs:
        None; asserts that batched increments are visible via export_counts and
        that _maybe_flush_locked is a no-op for non-batched stores.
    """

    db_path = tmp_path / "stats_batch.db"
    store = StatsSQLiteStore(db_path=str(db_path), batch_writes=True, batch_max_size=1)

    try:
        # First increment queues a single operation and triggers an immediate
        # flush because batch_max_size == 1.
        store.increment_count("totals", "batched_queries", delta=1)

        # Non-batched stores should treat _maybe_flush_locked as a no-op; this
        # directly exercises the early-return branch.
        non_batch_db = tmp_path / "stats_nonbatch.db"
        non_batch = StatsSQLiteStore(db_path=str(non_batch_db), batch_writes=False)
        try:
            non_batch._maybe_flush_locked()
        finally:
            non_batch.close()

        counts = store.export_counts()
    finally:
        store.close()

    assert counts.get("totals", {}).get("batched_queries") == 1


def test_export_counts_skips_non_integer_values(tmp_path: Path) -> None:
    """Brief: export_counts skips rows whose value column is not an integer.

    Inputs:
        tmp_path: pytest tmp path for an isolated SQLite DB.

    Outputs:
        None; asserts that rows with non-integer values are omitted.
    """

    db_path = tmp_path / "stats_bad_counts.db"
    store = StatsSQLiteStore(db_path=str(db_path))

    try:
        with closing(sqlite3.connect(str(db_path))) as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO counts(scope, key, value) VALUES(?, ?, ?)",
                ("totals", "good", 5),
            )
            cur.execute(
                "INSERT INTO counts(scope, key, value) VALUES(?, ?, ?)",
                ("totals", "bad", "not-an-int"),
            )
            conn.commit()

        counts = store.export_counts()
        totals = counts.get("totals", {})
    finally:
        store.close()

    assert totals.get("good") == 5
    assert "bad" not in totals


def test_sqlite_store_rebuild_counts_from_query_log_cache_and_upstreams(
    tmp_path: Path,
) -> None:
    """Brief: rebuild_counts_from_query_log populates cache and upstream aggregates.

    Inputs:
        tmp_path: pytest tmp path for an isolated SQLite DB.

    Outputs:
        None; asserts cache_* and upstream-related counters are rebuilt.
    """

    db_path = tmp_path / "stats_rebuild_cache.db"
    # Use non-batched writes here so that query_log rows are immediately
    # visible to the rebuild pipeline. Batched write behavior is covered
    # separately in test_sqlite_store_batched_execute_and_flush.
    store = StatsSQLiteStore(db_path=str(db_path), batch_writes=False)

    try:
        # Cache hit with subdomain and valid dnssec_status in JSON.
        store.insert_query_log(
            ts=1763364639.400,
            client_ip="192.0.2.30",
            name="www.example.com",
            qtype="A",
            upstream_id="8.8.8.8:53",
            rcode="NOERROR",
            status="cache_hit",
            error=None,
            first="93.184.216.34",
            result_json='{"answers":[],"dnssec_status":"dnssec_secure"}',
        )

        # Pre-plugin deny and override treated as cache_null with per-status totals.
        store.insert_query_log(
            ts=1763364639.401,
            client_ip="192.0.2.31",
            name="deny.example.com",
            qtype="AAAA",
            upstream_id=None,
            rcode="NXDOMAIN",
            status="deny_pre",
            error=None,
            first=None,
            result_json='{"answers":[]}',
        )
        store.insert_query_log(
            ts=1763364639.402,
            client_ip="192.0.2.32",
            name="override.example.com",
            qtype="AAAA",
            upstream_id=None,
            rcode="NXDOMAIN",
            status="override_pre",
            error=None,
            first=None,
            result_json='{"answers":[]}',
        )

        # Cache miss with invalid JSON to exercise dnssec_status parsing fallback.
        store.insert_query_log(
            ts=1763364639.403,
            client_ip="192.0.2.33",
            name="api.other.com",
            qtype="AAAA",
            upstream_id="1.1.1.1:53",
            rcode="SERVFAIL",
            status="error",
            error="servfail",
            first=None,
            result_json="{this-is-not-json}",
        )

        store.rebuild_counts_from_query_log()
        counts = store.export_counts()
    finally:
        store.close()

    totals = counts.get("totals", {})
    assert totals.get("total_queries") == 4
    assert totals.get("cache_hits") == 1
    assert totals.get("cache_null") == 2
    assert totals.get("cache_deny_pre") == 1
    assert totals.get("cache_override_pre") == 1
    # One remaining row is treated as a cache miss.
    assert totals.get("cache_misses") == 1

    cache_hit_domains = counts.get("cache_hit_domains", {})
    cache_miss_domains = counts.get("cache_miss_domains", {})
    assert cache_hit_domains.get("example.com") == 1
    assert cache_miss_domains.get("other.com") == 1

    cache_hit_subdomains = counts.get("cache_hit_subdomains", {})
    cache_miss_subdomains = counts.get("cache_miss_subdomains", {})
    assert cache_hit_subdomains.get("www.example.com") == 1
    assert cache_miss_subdomains.get("api.other.com") == 1

    qtypes = counts.get("qtypes", {})
    assert qtypes.get("A") == 1
    assert qtypes.get("AAAA") == 3

    clients = counts.get("clients", {})
    assert set(clients.keys()) >= {
        "192.0.2.30",
        "192.0.2.31",
        "192.0.2.32",
        "192.0.2.33",
    }

    rcode_totals = counts.get("rcodes", {})
    assert rcode_totals.get("NOERROR") == 1
    assert rcode_totals.get("NXDOMAIN") == 2
    assert rcode_totals.get("SERVFAIL") == 1

    rcode_domains = counts.get("rcode_domains", {})
    rcode_subdomains = counts.get("rcode_subdomains", {})
    assert rcode_domains.get("NOERROR|example.com") == 1
    assert rcode_domains.get("NXDOMAIN|example.com") == 2
    assert rcode_domains.get("SERVFAIL|other.com") == 1
    assert rcode_subdomains.get("NOERROR|www.example.com") == 1

    upstream_counts = counts.get("upstreams", {})
    upstream_qtypes = counts.get("upstream_qtypes", {})
    # Success outcome with rcode dimension encoded in the key.
    assert upstream_counts.get("8.8.8.8:53|success|NOERROR") == 1
    # Non-success outcome derives outcome from status string.
    assert upstream_counts.get("1.1.1.1:53|error|SERVFAIL") == 1
    assert upstream_qtypes.get("8.8.8.8:53|A") == 1
    assert upstream_qtypes.get("1.1.1.1:53|AAAA") == 1

    # dnssec_status from the first row should have been aggregated.
    assert totals.get("dnssec_secure") == 1


def test_sqlite_store_rebuild_counts_if_needed_with_empty_log(tmp_path: Path) -> None:
    """Brief: rebuild_counts_if_needed with empty query_log logs and returns.

    Inputs:
        tmp_path: pytest tmp path for an isolated SQLite DB.

    Outputs:
        None; function should be a no-op even when force_rebuild=True.
    """

    db_path = tmp_path / "stats_rebuild_empty.db"
    store = StatsSQLiteStore(db_path=str(db_path))

    try:
        # No rows in query_log; both calls should be no-ops.
        store.rebuild_counts_if_needed(force_rebuild=False)
        store.rebuild_counts_if_needed(force_rebuild=True)
    finally:
        store.close()


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
        store.increment_count("upstream_qtypes", "8.8.8.8:53|A", delta=3)
        store.increment_count("qtype_qnames", "A|example.com", delta=3)
        # Per-rcode and cache-domain aggregates.
        store.increment_count("rcode_domains", "NOERROR|example.com", delta=2)
        store.increment_count("rcode_subdomains", "NOERROR|example.com", delta=1)
        store.increment_count("cache_hit_domains", "example.com", delta=1)
        store.increment_count("cache_miss_domains", "other.com", delta=1)
        store.increment_count("cache_hit_subdomains", "example.com", delta=1)
        store.increment_count("cache_miss_subdomains", "other.com", delta=1)

        # Create collector wired to the store and warm-load from counts.
        collector = StatsCollector(
            track_uniques=True,
            include_qtype_breakdown=True,
            include_top_clients=False,
            include_top_domains=True,
            top_n=5,
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
        # Per-qtype qname counts should warm-load into qtype_qnames.
        assert snap.qtype_qnames is not None
        assert "A" in snap.qtype_qnames
        # Per-rcode base-domain aggregates hydrated into rcode_domains.
        # Subdomain lists now strictly enforce subdomain semantics via
        # _is_subdomain, so warm-loaded base-only entries do not appear in
        # rcode_subdomains.
        assert snap.rcode_domains is not None
        assert "NOERROR" in snap.rcode_domains
        assert snap.rcode_subdomains is None
        # Cache hit/miss domain lists are reconstructed; subdomain lists only
        # surface true subdomains and are therefore empty/None when the store
        # contains base domains only.
        assert snap.cache_hit_domains is not None
        assert snap.cache_miss_domains is not None
        assert snap.cache_hit_subdomains is None
        assert snap.cache_miss_subdomains is None
    finally:
        store.close()


def test_stats_collector_warm_load_aggregates_upstream_rcodes(tmp_path: Path) -> None:
    """Brief: warm_load_from_store aggregates per-rcode upstream counts per outcome.

    Inputs:
        tmp_path: pytest tmp path for an isolated SQLite DB.
    Outputs:
        None; asserts that multiple upstreams.* keys for the same upstream/outcome
        are summed into a single in-memory outcome counter while preserving
        per-rcode tallies.
    """
    db_path = tmp_path / "stats_warm_upstream_rcodes.db"
    store = StatsSQLiteStore(db_path=str(db_path))

    try:
        # Two persisted rows for the same upstream/outcome with different rcodes.
        store.increment_count("upstreams", "8.8.8.8:53|success|NOERROR", delta=3)
        store.increment_count("upstreams", "8.8.8.8:53|success|NXDOMAIN", delta=2)

        collector = StatsCollector(
            track_uniques=True,
            include_qtype_breakdown=True,
            include_top_clients=False,
            include_top_domains=False,
            top_n=5,
            track_latency=False,
            stats_store=store,
        )

        collector.warm_load_from_store()
        snap = collector.snapshot(reset=False)

        # Outcome counter should reflect the sum across rcodes.
        assert snap.upstreams["8.8.8.8:53"]["success"] == 5

        # Per-upstream rcode aggregates should also be restored.
        assert snap.upstream_rcodes is not None
        assert snap.upstream_rcodes["8.8.8.8:53"]["NOERROR"] == 3
        assert snap.upstream_rcodes["8.8.8.8:53"]["NXDOMAIN"] == 2
    finally:
        store.close()


def test_stats_collector_persists_upstream_rcodes_and_warm_loads(
    tmp_path: Path,
) -> None:
    """Brief: record_upstream_rcode persists per-upstream rcodes and warm-load restores them.

    Inputs:
        tmp_path: pytest tmp path for an isolated SQLite DB.
    Outputs:
        None; asserts that upstream/outcome totals and per-upstream rcodes are
        written into counts and hydrated by warm_load_from_store.
    """
    db_path = tmp_path / "stats_upstream_rcodes_persist.db"
    store = StatsSQLiteStore(db_path=str(db_path))

    try:
        # First collector simulates a running process that records upstream
        # outcomes and rcodes with a real SQLite-backed store attached.
        c1 = StatsCollector(
            track_uniques=True,
            include_qtype_breakdown=True,
            include_top_clients=False,
            include_top_domains=False,
            top_n=5,
            track_latency=False,
            stats_store=store,
        )

        # Two successful resolutions for the same upstream and a mix of rcodes.
        c1.record_upstream_result("8.8.8.8:53", "success", qtype="A")
        c1.record_upstream_result("8.8.8.8:53", "success", qtype="A")
        c1.record_upstream_rcode("8.8.8.8:53", "NOERROR")
        c1.record_upstream_rcode("8.8.8.8:53", "NXDOMAIN")

        # Inspect raw counts to ensure persistence used the expected scopes/keys.
        counts = store.export_counts()
        upstream_counts = counts.get("upstreams", {})
        upstream_rcodes = counts.get("upstream_rcodes", {})
        upstream_qtypes = counts.get("upstream_qtypes", {})

        assert upstream_counts.get("8.8.8.8:53|success") == 2
        assert upstream_rcodes.get("8.8.8.8:53|NOERROR") == 1
        assert upstream_rcodes.get("8.8.8.8:53|NXDOMAIN") == 1
        assert upstream_qtypes.get("8.8.8.8:53|A") == 2

        # Second collector simulates a fresh process that warm-loads from the
        # same SQLite store and should see the persisted aggregates.
        c2 = StatsCollector(
            track_uniques=True,
            include_qtype_breakdown=True,
            include_top_clients=False,
            include_top_domains=False,
            top_n=5,
            track_latency=False,
            stats_store=store,
        )

        c2.warm_load_from_store()
        snap = c2.snapshot(reset=False)

        # Upstream outcome totals restored from counts["upstreams"].
        assert snap.upstreams["8.8.8.8:53"]["success"] == 2

        # Per-upstream rcodes restored from counts["upstream_rcodes"].
        assert snap.upstream_rcodes is not None
        assert snap.upstream_rcodes["8.8.8.8:53"]["NOERROR"] == 1
        assert snap.upstream_rcodes["8.8.8.8:53"]["NXDOMAIN"] == 1

        # Per-upstream qtype aggregates restored from counts["upstream_qtypes"].
        assert snap.upstream_qtypes is not None
        assert snap.upstream_qtypes["8.8.8.8:53"]["A"] == 2
    finally:
        store.close()


def test_stats_collector_warm_load_no_store_is_noop() -> None:
    """Brief: warm_load_from_store is a no-op when no store is attached.

    Inputs:
        None.

    Outputs:
        None; asserts calling warm_load_from_store without a store does not
        raise and leaves counters unchanged.
    """

    collector = StatsCollector()
    collector.record_query("192.0.2.1", "example.com", "A")
    snap_before = collector.snapshot(reset=False)
    collector.warm_load_from_store()
    snap_after = collector.snapshot(reset=False)
    assert snap_after.totals == snap_before.totals


def test_stats_collector_warm_load_handles_store_export_error() -> None:
    """Brief: warm_load_from_store handles export_counts failures gracefully.

    Inputs:
        None.

    Outputs:
        None; asserts that an exception from export_counts is swallowed and
        in-memory counters remain unchanged.
    """

    class FailingStore:
        def export_counts(self) -> Dict[str, Dict[str, int]]:  # type: ignore[override]
            raise RuntimeError("boom")

    collector = StatsCollector(stats_store=FailingStore())
    snap_before = collector.snapshot(reset=False)
    collector.warm_load_from_store()
    snap_after = collector.snapshot(reset=False)
    assert snap_after.totals == snap_before.totals


def test_stats_collector_warm_load_handles_malformed_counts() -> None:
    """Brief: warm_load_from_store tolerates malformed counts structures.

    Inputs:
        None (uses an in-memory dummy store returning mixed-type counts).

    Outputs:
        None; asserts that valid entries are applied while malformed ones are
        skipped without raising.
    """

    class DummyStore:
        def export_counts(self) -> Dict[str, Dict[str, object]]:  # type: ignore[override]
            return {
                "totals": {"total_queries": "5", "bad_total": "x"},
                "cache": {"rate_limit": "3", "bad_cache": "y"},
                "rcodes": {"NOERROR": "2", "bad_rcode": "z"},
                "qtypes": {"A": "4", "bad_qtype": "w"},
                "upstreams": {
                    "8.8.8.8:53|success|NOERROR": "1",
                    "1.1.1.1:53|timeout": "2",
                    "malformed-key": "3",
                    "9.9.9.9:53|error|SERVFAIL": "not-int",
                },
                "upstream_qtypes": {
                    "8.8.8.8:53|A": "4",
                    "bad-key": "x",
                },
                "qtype_qnames": {
                    "A|example.com": "2",
                    "malformed-key": "x",
                },
                "rcode_domains": {
                    "NOERROR|example.com": "3",
                    "bad-key": "x",
                },
                "rcode_subdomains": {
                    "NOERROR|www.example.com": "1",
                    "bad-key": "x",
                },
                "clients": {"192.0.2.1": "5"},
                "sub_domains": {"www.example.com": "2"},
                "domains": {"example.com": "3"},
                "cache_hit_domains": {"example.com": "1"},
                "cache_miss_domains": {"other.com": "1"},
                "cache_hit_subdomains": {"www.example.com": "1"},
                "cache_miss_subdomains": {"api.other.com": "1"},
            }

    collector = StatsCollector(
        track_uniques=True,
        include_qtype_breakdown=True,
        include_top_clients=True,
        include_top_domains=True,
        top_n=5,
        track_latency=False,
        stats_store=DummyStore(),
    )

    collector.warm_load_from_store()
    snap = collector.snapshot(reset=False)

    # Core totals/qtypes/rcodes restored from valid entries only.
    assert snap.totals["total_queries"] == 5
    assert snap.totals["cache_stat_rate_limit"] == 3
    assert snap.rcodes["NOERROR"] == 2
    assert snap.qtypes["A"] == 4

    # Upstream outcomes and rcodes reconstructed from composite keys.
    assert snap.upstreams["8.8.8.8:53"]["success"] == 1
    assert snap.upstreams["1.1.1.1:53"]["timeout"] == 2
    assert snap.upstream_rcodes["8.8.8.8:53"]["NOERROR"] == 1

    # Upstream qtypes restored.
    assert snap.upstream_qtypes["8.8.8.8:53"]["A"] == 4

    # Per-qtype qname counts appear under qtype_qnames.
    assert snap.qtype_qnames is not None
    assert "A" in snap.qtype_qnames

    # Per-rcode domain and subdomain aggregates reconstructed.
    assert snap.rcode_domains is not None
    assert snap.rcode_subdomains is not None
    assert dict(snap.rcode_domains["NOERROR"]) == {"example.com": 3}
    assert dict(snap.rcode_subdomains["NOERROR"]) == {"www.example.com": 1}

    # Top clients/domains/subdomains approximated from counts.
    assert snap.top_clients is not None
    assert snap.top_clients[0][0] == "192.0.2.1"
    assert snap.top_domains is not None
    assert any(d == "example.com" for d, _ in snap.top_domains)
    assert snap.top_subdomains is not None
    assert any(d == "www.example.com" for d, _ in snap.top_subdomains)

    # Cache hit/miss domain and subdomain lists rebuilt.
    assert snap.cache_hit_domains is not None
    assert dict(snap.cache_hit_domains)["example.com"] == 1
    assert snap.cache_miss_domains is not None
    assert dict(snap.cache_miss_domains)["other.com"] == 1
    assert snap.cache_hit_subdomains is not None
    assert dict(snap.cache_hit_subdomains)["www.example.com"] == 1
    assert snap.cache_miss_subdomains is not None
    assert dict(snap.cache_miss_subdomains)["api.other.com"] == 1


def test_stats_collector_load_from_snapshot_handles_malformed_mappings() -> None:
    """Brief: load_from_snapshot tolerates mixed-type nested mappings.

    Inputs:
        None (constructs a StatsSnapshot with non-integer nested values).

    Outputs:
        None; asserts that valid parts of the snapshot are restored while
        malformed entries are skipped.
    """

    base_collector = StatsCollector(
        track_uniques=True,
        include_qtype_breakdown=True,
        include_top_clients=False,
        include_top_domains=True,
        track_latency=False,
    )
    base_collector.record_query("192.0.2.1", "example.com", "A")
    base_collector.record_cache_hit("example.com")
    base_collector.record_response_rcode("NOERROR", qname="example.com")
    base_snap = base_collector.snapshot(reset=False)

    decisions = {
        "Filter": {
            "allow": "1",
            "block": "not-int",
            "allowed_by": {"reason-ok": 2},
            "blocked_by": {"reason-bad": "x"},
        }
    }

    upstreams = {"8.8.8.8:53": {"success": "2", "timeout": "bad"}}
    upstream_rcodes = {"8.8.8.8:53": {"NOERROR": "1", "SERVFAIL": "bad"}}
    upstream_qtypes = {"8.8.8.8:53": {"A": "1", "AAAA": "bad"}}
    qtype_qnames = {"A": [("example.com", "2"), ("bad", "x")]}

    snap = StatsSnapshot(
        created_at=base_snap.created_at,
        totals=base_snap.totals,
        rcodes=base_snap.rcodes,
        qtypes=base_snap.qtypes,
        decisions=decisions,
        upstreams=upstreams,
        uniques=None,
        top_clients=None,
        top_subdomains=None,
        top_domains=None,
        latency_stats=None,
        latency_recent_stats=None,
        upstream_rcodes=upstream_rcodes,
        upstream_qtypes=upstream_qtypes,
        qtype_qnames=qtype_qnames,
        rcode_domains=None,
        rcode_subdomains=None,
        cache_hit_domains=None,
        cache_miss_domains=None,
        cache_hit_subdomains=None,
        cache_miss_subdomains=None,
        rate_limit=None,
    )

    target = StatsCollector(
        track_uniques=True,
        include_qtype_breakdown=True,
        include_top_clients=False,
        include_top_domains=True,
        track_latency=False,
    )
    target.load_from_snapshot(snap)
    snap_after = target.snapshot(reset=False)

    # Core counters restored.
    assert snap_after.totals == base_snap.totals
    assert snap_after.rcodes == base_snap.rcodes
    assert snap_after.qtypes == base_snap.qtypes

    # Plugin decisions preserve numeric actions and nested allowed/blocked maps.
    assert snap_after.decisions["Filter"]["allow"] == 1
    assert "block" not in snap_after.decisions["Filter"]
    assert snap_after.decisions["Filter"]["allowed_by"]["reason-ok"] == 2
    assert snap_after.decisions["Filter"]["blocked_by"]["reason-bad"] == "x"

    # Upstream aggregates from snapshots preserve values as-is for the
    # plain upstreams mapping, while malformed numeric data in
    # upstream_rcodes/upstream_qtypes causes those per-upstream maps to be
    # skipped entirely.
    assert snap_after.upstreams["8.8.8.8:53"]["success"] == "2"
    assert snap_after.upstreams["8.8.8.8:53"]["timeout"] == "bad"
    assert "8.8.8.8:53" not in snap_after.upstream_rcodes
    assert "8.8.8.8:53" not in snap_after.upstream_qtypes

    # Per-qtype qname trackers rebuilt with only valid integer counts.
    assert snap_after.qtype_qnames is not None
    domains_for_a = dict(snap_after.qtype_qnames["A"])
    assert domains_for_a["example.com"] == 2
    assert "bad" not in domains_for_a


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
