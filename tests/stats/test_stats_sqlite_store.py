"""Brief: Tests for StatsSQLiteStore query/aggregate helpers and edge cases.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

from typing import Any

from foghorn.plugins.querylog.sqlite import (
    SqliteStatsStore,
    _is_subdomain,
    _normalize_domain,
)
from foghorn.stats import StatsSQLiteStore


def test_health_check_true_and_false(monkeypatch) -> None:
    """Brief: health_check returns True on success and False on failure.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts both True and False paths.
    """

    store = StatsSQLiteStore(":memory:")
    assert store.health_check() is True

    # Force cursor() to raise to hit the False branch.
    class BoomConn:
        def cursor(self) -> Any:  # noqa: D401
            """Always raise to simulate connection failure."""

            raise RuntimeError("boom")

    store._conn = BoomConn()  # type: ignore[assignment]
    assert store.health_check() is False


def test_select_query_log_normalizes_params_and_handles_empty(monkeypatch) -> None:
    """Brief: select_query_log normalizes page/page_size and builds filters.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts parameter normalization and empty result shape.
    """

    store = StatsSQLiteStore(":memory:")

    # No rows yet; call with bogus page/page_size and filters to exercise branches.
    res = store.select_query_log(
        client_ip=" 1.2.3.4 ",
        qtype=" a ",
        qname=" Example.COM.",
        rcode=" noerror ",
        start_ts=0,
        end_ts=1,
        page="not-int",  # triggers page parse except -> default 1
        page_size="also-bad",  # triggers page_size parse except -> default 100
    )

    assert res["total"] == 0
    assert res["page"] == 1
    assert res["page_size"] == 100
    assert res["total_pages"] == 0
    assert res["items"] == []

    # page < 1 should be clamped to 1; page_size < 1 clamped to 1.
    res2 = store.select_query_log(page=-5, page_size=0)
    assert res2["page"] == 1
    assert res2["page_size"] == 1


def test_select_query_log_filters_status_and_source() -> None:
    """Brief: select_query_log filters by status and result source.

    Inputs:
      - None.

    Outputs:
      - None; asserts status/source filters match expected rows.
    """

    store = StatsSQLiteStore(":memory:")
    store.insert_query_log(
        ts=1.0,
        client_ip="192.0.2.1",
        name="cache-hit.example",
        qtype="A",
        upstream_id="up-cache",
        rcode="NOERROR",
        status="cache_hit",
        error=None,
        first="192.0.2.1",
        result_json='{"source":"cache"}',
    )
    store.insert_query_log(
        ts=2.0,
        client_ip="192.0.2.2",
        name="cache-miss.example",
        qtype="A",
        upstream_id="up-upstream",
        rcode="NOERROR",
        status="cache_miss",
        error=None,
        first="192.0.2.2",
        result_json='{"source":"upstream"}',
    )
    store.insert_query_log(
        ts=3.0,
        client_ip="192.0.2.3",
        name="server-error.example",
        qtype="AAAA",
        upstream_id="up-server",
        rcode="SERVFAIL",
        status="error",
        error="boom",
        first="192.0.2.3",
        result_json='{"source": "server"}',
    )

    by_status = store.select_query_log(status=" CACHE_HIT ")
    assert by_status["total"] == 1
    assert by_status["items"][0]["qname"] == "cache-hit.example"

    by_source_compact = store.select_query_log(source=" UpStReAm ")
    assert by_source_compact["total"] == 1
    assert by_source_compact["items"][0]["qname"] == "cache-miss.example"

    by_source_spaced = store.select_query_log(source="server")
    assert by_source_spaced["total"] == 1
    assert by_source_spaced["items"][0]["qname"] == "server-error.example"

    combined = store.select_query_log(status="cache_miss", source="upstream")
    assert combined["total"] == 1
    assert combined["items"][0]["qname"] == "cache-miss.example"

    no_match = store.select_query_log(status="cache_hit", source="upstream")
    assert no_match["total"] == 0
    assert no_match["items"] == []


def test_select_query_log_qname_matches_subdomains() -> None:
    """Brief: qname filtering includes exact domain rows and subdomains.

    Inputs:
      - None.

    Outputs:
      - None; asserts qname=example.com returns both example.com and *.example.com.
    """

    store = StatsSQLiteStore(":memory:")
    store.insert_query_log(
        ts=1.0,
        client_ip="198.51.100.1",
        name="example.com",
        qtype="A",
        upstream_id="up-1",
        rcode="NOERROR",
        status="ok",
        error=None,
        first="198.51.100.10",
        result_json='{"source":"upstream"}',
    )
    store.insert_query_log(
        ts=2.0,
        client_ip="198.51.100.2",
        name="www.example.com",
        qtype="A",
        upstream_id="up-2",
        rcode="NOERROR",
        status="ok",
        error=None,
        first="198.51.100.11",
        result_json='{"source":"upstream"}',
    )
    store.insert_query_log(
        ts=3.0,
        client_ip="198.51.100.3",
        name="api.dev.example.com",
        qtype="A",
        upstream_id="up-3",
        rcode="NOERROR",
        status="ok",
        error=None,
        first="198.51.100.12",
        result_json='{"source":"upstream"}',
    )
    store.insert_query_log(
        ts=4.0,
        client_ip="198.51.100.4",
        name="other.com",
        qtype="A",
        upstream_id="up-4",
        rcode="NOERROR",
        status="ok",
        error=None,
        first="198.51.100.13",
        result_json='{"source":"upstream"}',
    )

    by_root = store.select_query_log(qname="Example.COM.")
    matched = {row["qname"] for row in by_root["items"]}
    assert by_root["total"] == 3
    assert matched == {"example.com", "www.example.com", "api.dev.example.com"}

    by_other = store.select_query_log(qname="other.com")
    assert by_other["total"] == 1
    assert by_other["items"][0]["qname"] == "other.com"


def test_aggregate_query_log_counts_bad_inputs_and_dense_buckets() -> None:
    """Brief: aggregate_query_log_counts normalizes inputs and fills dense buckets.

    Inputs:
      - None.

    Outputs:
      - None; asserts early-return for bad interval and dense zero-filled buckets.
    """

    store = StatsSQLiteStore(":memory:")

    # Non-numeric start/end and interval -> early return with empty items.
    res_bad = store.aggregate_query_log_counts(
        start_ts="x", end_ts="y", interval_seconds="z"
    )
    assert res_bad["interval_seconds"] == 0
    assert res_bad["items"] == []

    # Valid window and interval with no rows -> dense buckets with zero counts.
    res = store.aggregate_query_log_counts(
        start_ts=0.0,
        end_ts=10.0,
        interval_seconds=5,
    )
    assert res["start_ts"] == 0.0
    assert res["end_ts"] == 10.0
    assert res["interval_seconds"] == 5
    items = res["items"]
    # Expect two buckets: [0,5) and [5,10).
    assert len(items) == 2
    assert {i["bucket"] for i in items} == {0, 1}
    assert all(i["count"] == 0 for i in items)


def test_aggregate_query_log_counts_group_by_sparse() -> None:
    """Brief: aggregate_query_log_counts supports sparse grouped results.

    Inputs:
      - None.

    Outputs:
      - None; asserts group_by path executes and returns empty items when no rows.
    """

    store = StatsSQLiteStore(":memory:")

    res = store.aggregate_query_log_counts(
        start_ts=0.0,
        end_ts=10.0,
        interval_seconds=5,
        group_by="qtype",
    )

    assert res["interval_seconds"] == 5
    assert res["items"] == []


def test_sqlite_helpers_normalize_domain_and_is_subdomain() -> None:
    """Brief: _normalize_domain and _is_subdomain mirror stats helper behavior.

    Inputs:
      - None.

    Outputs:
      - None; asserts normalisation and subdomain classification rules.
    """

    assert _normalize_domain("Example.COM.") == "example.com"
    assert _normalize_domain("") == ""

    # Not subdomains: empty/one-label/two-label names.
    assert _is_subdomain("") is False
    assert _is_subdomain("example") is False
    assert _is_subdomain("example.com") is False

    # Generic three-label domain is a subdomain.
    assert _is_subdomain("www.example.com") is True

    # co.uk-style public suffix: need at least four labels.
    assert _is_subdomain("example.co.uk") is False
    assert _is_subdomain("www.example.co.uk") is True


def test_sqlite_backend_health_check_true_and_false() -> None:
    """Brief: SqliteStatsStore.health_check reflects connection state.

    Inputs:
      - None.

    Outputs:
      - None; asserts True for healthy connection and False when cursor fails.
    """

    backend = SqliteStatsStore(":memory:")
    assert backend.health_check() is True

    class BoomConn:
        def cursor(self) -> Any:  # noqa: D401
            """Always raise to simulate connection failure."""

            raise RuntimeError("boom")

    backend._conn = BoomConn()  # type: ignore[assignment]
    assert backend.health_check() is False


def test_sqlite_backend_counts_and_export(tmp_path) -> None:
    """Brief: SqliteStatsStore counts helpers read and write correctly.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - None; asserts increment_count, set_count, has_counts, and export_counts.
    """

    db_path = tmp_path / "stats" / "counts.sqlite"
    backend = SqliteStatsStore(str(db_path))

    # Initially no rows.
    assert backend.has_counts() is False

    backend._increment_count("totals", "a", 2)
    backend._increment_count("totals", "a", 3)
    backend.set_count("totals", "b", 7)

    assert backend.has_counts() is True

    exported = backend.export_counts()
    assert exported["totals"]["a"] == 5
    assert exported["totals"]["b"] == 7


def test_sqlite_backend_insert_and_select_query_log_json_decoding() -> None:
    """Brief: SqliteStatsStore decodes query_log result_json variants.

    Inputs:
      - None.

    Outputs:
      - None; asserts dict, list, and invalid JSON handling.
    """

    backend = SqliteStatsStore(":memory:")

    # Insert three log rows with different JSON payload shapes.
    backend._insert_query_log(
        ts=1.0,
        client_ip="1.2.3.4",
        name="example.com",
        qtype="A",
        upstream_id="up1",
        rcode="NOERROR",
        status="ok",
        error=None,
        first="1.2.3.4",
        result_json='{"dnssec_status": "dnssec_secure"}',
    )
    backend._insert_query_log(
        ts=2.0,
        client_ip="5.6.7.8",
        name="other.example",
        qtype="AAAA",
        upstream_id=None,
        rcode=None,
        status=None,
        error=None,
        first=None,
        result_json="[1, 2, 3]",
    )
    backend._insert_query_log(
        ts=3.0,
        client_ip="9.9.9.9",
        name="bad.json",
        qtype="TXT",
        upstream_id=None,
        rcode=None,
        status=None,
        error=None,
        first=None,
        result_json="not-json",
    )

    res = backend.select_query_log(page=1, page_size=10)
    assert res["total"] == 3
    assert res["page"] == 1
    assert res["page_size"] == 10
    assert res["total_pages"] == 1

    items = res["items"]
    assert len(items) == 3

    by_name = {item["qname"]: item for item in items}

    first = by_name["example.com"]
    assert first["result"]["dnssec_status"] == "dnssec_secure"

    second = by_name["other.example"]
    assert second["result"]["value"] == [1, 2, 3]

    third = by_name["bad.json"]
    assert third["result"] == {}

    # Parameter normalisation for negative page and size mirrors legacy behaviour.
    res2 = backend.select_query_log(page=-5, page_size=0)
    assert res2["page"] == 1
    assert res2["page_size"] == 1


def test_sqlite_backend_select_query_log_filters_status_and_source() -> None:
    """Brief: SqliteStatsStore supports status and source query-log filters.

    Inputs:
      - None.

    Outputs:
      - None; asserts status/source filters match expected rows.
    """

    backend = SqliteStatsStore(":memory:")
    backend._insert_query_log(
        ts=1.0,
        client_ip="192.0.2.1",
        name="cache-hit.example",
        qtype="A",
        upstream_id="up-cache",
        rcode="NOERROR",
        status="cache_hit",
        error=None,
        first="192.0.2.1",
        result_json='{"source":"cache"}',
    )
    backend._insert_query_log(
        ts=2.0,
        client_ip="192.0.2.2",
        name="cache-miss.example",
        qtype="A",
        upstream_id="up-upstream",
        rcode="NOERROR",
        status="cache_miss",
        error=None,
        first="192.0.2.2",
        result_json='{"source":"upstream"}',
    )
    backend._insert_query_log(
        ts=3.0,
        client_ip="192.0.2.3",
        name="server-error.example",
        qtype="AAAA",
        upstream_id="up-server",
        rcode="SERVFAIL",
        status="error",
        error="boom",
        first="192.0.2.3",
        result_json='{"source": "server"}',
    )

    by_status = backend.select_query_log(status=" CACHE_HIT ")
    assert by_status["total"] == 1
    assert by_status["items"][0]["qname"] == "cache-hit.example"

    by_source_compact = backend.select_query_log(source=" UpStReAm ")
    assert by_source_compact["total"] == 1
    assert by_source_compact["items"][0]["qname"] == "cache-miss.example"

    by_source_spaced = backend.select_query_log(source="server")
    assert by_source_spaced["total"] == 1
    assert by_source_spaced["items"][0]["qname"] == "server-error.example"

    combined = backend.select_query_log(status="cache_miss", source="upstream")
    assert combined["total"] == 1
    assert combined["items"][0]["qname"] == "cache-miss.example"

    no_match = backend.select_query_log(status="cache_hit", source="upstream")
    assert no_match["total"] == 0
    assert no_match["items"] == []


def test_sqlite_backend_aggregate_counts_bad_inputs_and_dense() -> None:
    """Brief: SqliteStatsStore aggregates into dense zero-filled buckets.

    Inputs:
      - None.

    Outputs:
      - None; asserts early-return for bad interval and dense buckets with no rows.
    """

    backend = SqliteStatsStore(":memory:")

    res_bad = backend.aggregate_query_log_counts(
        start_ts="x", end_ts="y", interval_seconds="z"
    )
    assert res_bad["interval_seconds"] == 0
    assert res_bad["items"] == []

    res = backend.aggregate_query_log_counts(
        start_ts=0.0,
        end_ts=10.0,
        interval_seconds=5,
    )
    assert res["start_ts"] == 0.0
    assert res["end_ts"] == 10.0
    assert res["interval_seconds"] == 5
    items = res["items"]
    assert len(items) == 2
    assert {i["bucket"] for i in items} == {0, 1}
    assert all(i["count"] == 0 for i in items)


def test_sqlite_backend_aggregate_counts_group_by_sparse() -> None:
    """Brief: SqliteStatsStore returns sparse grouped results.

    Inputs:
      - None.

    Outputs:
      - None; asserts group_by path executes and returns empty items when no rows.
    """

    backend = SqliteStatsStore(":memory:")

    res = backend.aggregate_query_log_counts(
        start_ts=0.0,
        end_ts=10.0,
        interval_seconds=5,
        group_by="qtype",
    )

    assert res["interval_seconds"] == 5
    assert res["items"] == []


def test_sqlite_backend_rebuild_counts_from_query_log() -> None:
    """Brief: rebuild_counts_from_query_log populates derived counters.

    Inputs:
      - None.

    Outputs:
      - None; asserts several key counters are populated from query_log rows.
    """

    backend = SqliteStatsStore(":memory:")

    backend._insert_query_log(
        ts=1.0,
        client_ip="1.2.3.4",
        name="www.example.com",
        qtype="A",
        upstream_id="up1",
        rcode="NOERROR",
        status="cache_hit",
        error=None,
        first="1.2.3.4",
        result_json='{"dnssec_status": "dnssec_secure"}',
    )
    backend._insert_query_log(
        ts=2.0,
        client_ip="5.6.7.8",
        name="block.example.com",
        qtype="A",
        upstream_id=None,
        rcode="NXDOMAIN",
        status="deny_pre",
        error=None,
        first=None,
        result_json="{}",
    )

    backend.rebuild_counts_from_query_log(logger_obj=None)

    # Wait for the async BaseStatsStore worker to drain all queued increment_count
    # operations before asserting on the exported counters.
    backend._op_queue.join()  # type: ignore[attr-defined]

    counts = backend.export_counts()

    # Totals
    assert counts["totals"]["total_queries"] == 2
    assert counts["totals"]["cache_hits"] == 1
    assert counts["totals"]["cache_deny_pre"] == 1
    assert counts["totals"]["cache_null"] == 1
    # Qtypes and clients
    assert counts["qtypes"]["A"] == 2
    assert counts["clients"]["1.2.3.4"] == 1
    assert counts["clients"]["5.6.7.8"] == 1
    # Domains and subdomains
    assert counts["domains"]["example.com"] >= 1
    assert counts["sub_domains"]["www.example.com"] == 1
    # Upstreams (only for the first row with upstream_id)
    assert any(k.startswith("up1|") for k in counts["upstreams"].keys())
    # DNSSEC
    assert counts["totals"]["dnssec_secure"] == 1


def test_sqlite_backend_rebuild_counts_if_needed_branches(monkeypatch) -> None:
    """Brief: rebuild_counts_if_needed respects flags and table state.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts helper calls are gated correctly.
    """

    backend = SqliteStatsStore(":memory:")

    calls = {"rebuild": 0}

    def fake_rebuild(logger_obj=None) -> None:  # type: ignore[no-untyped-def]
        calls["rebuild"] += 1

    monkeypatch.setattr(backend, "rebuild_counts_from_query_log", fake_rebuild)

    # No query_log rows -> no rebuild even when force_rebuild is True.
    monkeypatch.setattr(backend, "has_counts", lambda: False)
    monkeypatch.setattr(backend, "has_query_log", lambda: False)
    backend.rebuild_counts_if_needed(force_rebuild=False, logger_obj=None)
    backend.rebuild_counts_if_needed(force_rebuild=True, logger_obj=None)
    assert calls["rebuild"] == 0

    # Counts present and query_log present, no force -> no rebuild.
    monkeypatch.setattr(backend, "has_counts", lambda: True)
    monkeypatch.setattr(backend, "has_query_log", lambda: True)
    backend.rebuild_counts_if_needed(force_rebuild=False, logger_obj=None)
    assert calls["rebuild"] == 0

    # Counts present and query_log present, force -> rebuild once.
    backend.rebuild_counts_if_needed(force_rebuild=True, logger_obj=None)
    assert calls["rebuild"] == 1

    # Counts empty and query_log present, no force -> rebuild again.
    monkeypatch.setattr(backend, "has_counts", lambda: False)
    backend.rebuild_counts_if_needed(force_rebuild=False, logger_obj=None)
    assert calls["rebuild"] == 2


def test_sqlite_backend_batching_execute_flush_and_close(tmp_path) -> None:
    """Brief: Batched writes are buffered then flushed and closed correctly.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - None; asserts _execute batching, _flush_locked, and close() paths.
    """

    db_path = tmp_path / "stats" / "batched.sqlite"
    backend = SqliteStatsStore(str(db_path), batch_writes=True, batch_time_sec=3600.0)

    # Batched increment should enqueue but not immediately flush due to thresholds.
    backend._increment_count("totals", "queued", 1)
    assert backend._pending_ops  # type: ignore[attr-defined]

    # Manual flush applies operations and clears queue.
    backend._flush_locked()  # type: ignore[attr-defined]
    assert not backend._pending_ops  # type: ignore[attr-defined]
    counts = backend.export_counts()
    assert counts["totals"]["queued"] == 1

    # Close with batch_writes=True should call _flush_locked and then close connection.
    backend.close()


def test_sqlite_backend_batching_flushes_pending_writes_before_read_helpers() -> None:
    """Brief: Batched SQLite reads flush queued writes for parity with other backends.

    Inputs:
      - None.

    Outputs:
      - None; asserts has_counts, export_counts, and has_query_log include pending writes.
    """

    backend = SqliteStatsStore(":memory:", batch_writes=True, batch_time_sec=3600.0)

    backend._increment_count("totals", "queued", 1)
    assert backend._pending_ops  # type: ignore[attr-defined]
    assert backend.has_counts() is True
    assert not backend._pending_ops  # type: ignore[attr-defined]

    backend._increment_count("totals", "from_export", 2)
    assert backend._pending_ops  # type: ignore[attr-defined]
    counts = backend.export_counts()
    assert counts["totals"]["queued"] == 1
    assert counts["totals"]["from_export"] == 2
    assert not backend._pending_ops  # type: ignore[attr-defined]

    backend._insert_query_log(
        ts=1.0,
        client_ip="192.0.2.1",
        name="queued.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    assert backend._pending_ops  # type: ignore[attr-defined]
    assert backend.has_query_log() is True
    assert not backend._pending_ops  # type: ignore[attr-defined]


def test_sqlite_backend_query_log_retention_max_records() -> None:
    """Brief: SQLite backend keeps only newest N records when configured.

    Inputs:
      - None.

    Outputs:
      - None; asserts retention_max_records trims older query_log rows.
    """

    backend = SqliteStatsStore(":memory:", retention_max_records=2)

    backend._insert_query_log(
        ts=1.0,
        client_ip="192.0.2.1",
        name="first.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(
        ts=2.0,
        client_ip="192.0.2.2",
        name="second.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(
        ts=3.0,
        client_ip="192.0.2.3",
        name="third.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )

    res = backend.select_query_log(page=1, page_size=20)
    assert res["total"] == 2
    assert [item["qname"] for item in res["items"]] == [
        "third.example",
        "second.example",
    ]


def test_sqlite_backend_query_log_retention_max_bytes() -> None:
    """Brief: SQLite backend byte-cap retention drops oldest rows.

    Inputs:
      - None.

    Outputs:
      - None; asserts retention_max_bytes keeps only the newest row at cap.
    """

    backend = SqliteStatsStore(":memory:", retention_max_bytes=10_000_000)

    backend._insert_query_log(
        ts=1.0,
        client_ip="192.0.2.1",
        name="alpha.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    row = backend._conn.execute(  # type: ignore[attr-defined]
        """
        SELECT
            LENGTH(client_ip)
            + LENGTH(name)
            + LENGTH(qtype)
            + LENGTH(COALESCE(upstream_id, ''))
            + LENGTH(COALESCE(rcode, ''))
            + LENGTH(COALESCE(status, ''))
            + LENGTH(COALESCE(error, ''))
            + LENGTH(COALESCE(first, ''))
            + LENGTH(result_json)
            + 64
        FROM query_log
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()
    assert row is not None
    backend._query_log_retention_max_bytes = int(row[0])  # type: ignore[attr-defined]

    backend._insert_query_log(
        ts=2.0,
        client_ip="192.0.2.2",
        name="bravo.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )

    res = backend.select_query_log(page=1, page_size=20)
    assert res["total"] == 1
    assert res["items"][0]["qname"] == "bravo.example"


def test_sqlite_backend_query_log_retention_prune_every_n_inserts() -> None:
    """Brief: SQLite retention can be deferred to an insert cadence.

    Inputs:
      - None.

    Outputs:
      - None; asserts max-record pruning runs on the configured cadence.
    """

    backend = SqliteStatsStore(
        ":memory:",
        retention_max_records=1,
        retention_prune_every_n_inserts=3,
    )

    backend._insert_query_log(
        ts=1.0,
        client_ip="192.0.2.1",
        name="first.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(
        ts=2.0,
        client_ip="192.0.2.2",
        name="second.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    mid = backend.select_query_log(page=1, page_size=20)
    assert mid["total"] == 2

    backend._insert_query_log(
        ts=3.0,
        client_ip="192.0.2.3",
        name="third.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    final = backend.select_query_log(page=1, page_size=20)
    assert final["total"] == 1
    assert final["items"][0]["qname"] == "third.example"


def test_sqlite_backend_query_log_retention_days(monkeypatch) -> None:
    """Brief: SQLite backend prunes rows older than retention_days cutoff.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts old query_log rows are removed by days-based retention.
    """

    import foghorn.plugins.querylog.sqlite as sqlite_mod

    now_ts = 10.0 * 86400.0
    monkeypatch.setattr(sqlite_mod.time, "time", lambda: now_ts)

    backend = SqliteStatsStore(":memory:", retention_days=2.0)
    backend._insert_query_log(
        ts=now_ts - (3.0 * 86400.0),
        client_ip="198.51.100.10",
        name="old.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(
        ts=now_ts - 86400.0,
        client_ip="198.51.100.11",
        name="fresh.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )

    res = backend.select_query_log(page=1, page_size=20)
    assert res["total"] == 1
    assert res["items"][0]["qname"] == "fresh.example"


def test_sqlite_backend_query_log_retention_days_and_max_records(monkeypatch) -> None:
    """Brief: SQLite backend applies days and max-record retention together.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts the combined policy keeps only recent newest rows.
    """

    import foghorn.plugins.querylog.sqlite as sqlite_mod

    now_ts = 20.0 * 86400.0
    monkeypatch.setattr(sqlite_mod.time, "time", lambda: now_ts)

    backend = SqliteStatsStore(
        ":memory:",
        retention_days=4.0,
        retention_max_records=2,
    )
    backend._insert_query_log(
        ts=now_ts - (10.0 * 86400.0),
        client_ip="203.0.113.1",
        name="expired.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(
        ts=now_ts - (3.0 * 86400.0),
        client_ip="203.0.113.2",
        name="older.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(
        ts=now_ts - (2.0 * 86400.0),
        client_ip="203.0.113.3",
        name="newer.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(
        ts=now_ts - 86400.0,
        client_ip="203.0.113.4",
        name="newest.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )

    res = backend.select_query_log(page=1, page_size=20)
    assert res["total"] == 2
    assert [item["qname"] for item in res["items"]] == [
        "newest.example",
        "newer.example",
    ]
