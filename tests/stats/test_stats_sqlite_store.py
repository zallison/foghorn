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


def test_select_query_log_filters_ede_code() -> None:
    """Brief: select_query_log filters rows by EDE info-code in result_json.

    Inputs:
      - None.

    Outputs:
      - None; asserts ede_code filter matches numeric and quoted numeric JSON values.
    """

    store = StatsSQLiteStore(":memory:")
    store.insert_query_log(
        ts=1.0,
        client_ip="192.0.2.10",
        name="ede15-numeric.example",
        qtype="A",
        upstream_id="up-a",
        rcode="NXDOMAIN",
        status="deny_pre",
        error=None,
        first=None,
        result_json='{"source":"upstream","ede_code":15}',
    )
    store.insert_query_log(
        ts=2.0,
        client_ip="192.0.2.11",
        name="ede23-numeric.example",
        qtype="A",
        upstream_id="up-b",
        rcode="SERVFAIL",
        status="error",
        error=None,
        first=None,
        result_json='{"source":"upstream","ede_code":23}',
    )
    store.insert_query_log(
        ts=3.0,
        client_ip="192.0.2.12",
        name="ede15-string.example",
        qtype="AAAA",
        upstream_id="up-c",
        rcode="NXDOMAIN",
        status="deny_pre",
        error=None,
        first=None,
        result_json='{"source": "upstream", "ede_code": "15"}',
    )

    by_ede_15 = store.select_query_log(ede_code="15")
    assert by_ede_15["total"] == 2
    assert {row["qname"] for row in by_ede_15["items"]} == {
        "ede15-numeric.example",
        "ede15-string.example",
    }

    by_ede_23 = store.select_query_log(ede_code="023")
    assert by_ede_23["total"] == 1
    assert by_ede_23["items"][0]["qname"] == "ede23-numeric.example"

    invalid = store.select_query_log(ede_code="not-a-number")
    assert invalid["total"] == 0
    assert invalid["items"] == []


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
    row = backend._conn.execute(
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
    ).fetchone()  # type: ignore[attr-defined]
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


def test_sqlite_backend_normalize_auto_vacuum_and_queue_limit_fallback() -> None:
    """Brief: Auto-vacuum normalization and queue-limit fallback handle bad input.

    Inputs:
      - None.

    Outputs:
      - None; asserts mapping/invalid branches and max_logging_queue fallback.
    """

    class BadInt:
        """Helper whose __int__ conversion always fails."""

        def __int__(self) -> int:
            raise TypeError("boom")

    assert SqliteStatsStore._normalize_sqlite_auto_vacuum(None) is None
    assert SqliteStatsStore._normalize_sqlite_auto_vacuum(" full ") == 1
    assert SqliteStatsStore._normalize_sqlite_auto_vacuum("incremental") == 2
    assert SqliteStatsStore._normalize_sqlite_auto_vacuum("bogus") is None
    assert SqliteStatsStore._normalize_sqlite_auto_vacuum(0) == 0
    assert SqliteStatsStore._normalize_sqlite_auto_vacuum(9) is None
    assert SqliteStatsStore._normalize_sqlite_auto_vacuum(BadInt()) is None

    backend = SqliteStatsStore(":memory:", max_logging_queue="bad")
    assert backend._max_logging_queue == 16384


def test_sqlite_backend_init_connection_permission_fallback_and_auto_vacuum(
    monkeypatch,
) -> None:
    """Brief: Default-path permission failures fall back to in-memory SQLite.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts db_path fallback and auto_vacuum PRAGMA application.
    """

    import foghorn.plugins.querylog.sqlite as sqlite_mod

    seen: dict[str, str] = {}
    real_connect = sqlite_mod.sqlite3.connect

    def connect_spy(path: str, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
        seen["path"] = str(path)
        return real_connect(":memory:", *args, **kwargs)

    monkeypatch.setattr(sqlite_mod.os, "access", lambda _path, _mode: False)
    monkeypatch.setattr(sqlite_mod.sqlite3, "connect", connect_spy)

    backend = SqliteStatsStore(
        SqliteStatsStore.default_config["db_path"],
        sqlite_auto_vacuum="full",
    )

    assert seen["path"] == ":memory:"
    mode_row = backend._conn.execute("PRAGMA auto_vacuum").fetchone()  # type: ignore[attr-defined]
    assert mode_row is not None
    assert int(mode_row[0]) == 1


def test_sqlite_backend_maybe_flush_locked_nonbatched_and_threshold_trigger() -> None:
    """Brief: _maybe_flush_locked early-return and threshold flush paths both work.

    Inputs:
      - None.

    Outputs:
      - None; asserts non-batched early return and size-based flush execution.
    """

    non_batched = SqliteStatsStore(":memory:", batch_writes=False)
    non_batched._maybe_flush_locked()

    batched = SqliteStatsStore(
        ":memory:",
        batch_writes=True,
        batch_time_sec=3600.0,
        batch_max_size=1,
    )
    batched._increment_count("totals", "flush_now", 1)
    assert not batched._pending_ops  # type: ignore[attr-defined]
    counts = batched.export_counts()
    assert counts["totals"]["flush_now"] == 1


def test_sqlite_backend_select_query_log_extra_filters_and_ede_guards() -> None:
    """Brief: select_query_log handles extra filter combinations and EDE guards.

    Inputs:
      - None.

    Outputs:
      - None; asserts client/qtype/qname/rcode/time filtering and EDE guards.
    """

    backend = SqliteStatsStore(":memory:", batch_writes=True, batch_time_sec=3600.0)
    backend._insert_query_log(
        ts=1.0,
        client_ip="192.0.2.10",
        name="example.com",
        qtype="A",
        upstream_id="up-a",
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json='{"source":"upstream","ede_code":15}',
    )
    backend._insert_query_log(
        ts=3.0,
        client_ip="192.0.2.11",
        name="www.example.com",
        qtype="AAAA",
        upstream_id="up-b",
        rcode="SERVFAIL",
        status="error",
        error="boom",
        first=None,
        result_json='{"source":"upstream","ede_code":"23"}',
    )

    assert backend._pending_ops  # type: ignore[attr-defined]

    filtered = backend.select_query_log(
        client_ip=" 192.0.2.10 ",
        qtype=" a ",
        qname=" Example.COM. ",
        rcode=" noerror ",
        ede_code="15",
        start_ts=0,
        end_ts=2,
        page="not-int",
        page_size="also-bad",
    )
    assert filtered["page"] == 1
    assert filtered["page_size"] == 100
    assert filtered["total"] == 1
    assert filtered["items"][0]["qname"] == "example.com"

    assert backend.select_query_log(ede_code="-1")["total"] == 0
    assert backend.select_query_log(ede_code="not-a-number")["total"] == 0


def test_sqlite_backend_aggregate_grouped_filters_and_limit_guard(monkeypatch) -> None:
    """Brief: aggregate_query_log_counts supports grouped filters and guard errors.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts grouped filter output and ValueError guard handling path.
    """

    import foghorn.plugins.querylog.sqlite as sqlite_mod

    backend = SqliteStatsStore(":memory:", batch_writes=True, batch_time_sec=3600.0)
    backend._insert_query_log(
        ts=1.0,
        client_ip="198.51.100.10",
        name="example.com",
        qtype="A",
        upstream_id="up-a",
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )

    grouped = backend.aggregate_query_log_counts(
        start_ts=0.0,
        end_ts=10.0,
        interval_seconds=5,
        client_ip=" 198.51.100.10 ",
        qtype=" a ",
        qname=" Example.COM. ",
        rcode=" noerror ",
        group_by="qtype",
    )

    assert grouped["items"]
    assert grouped["items"][0]["group_by"] == "qtype"
    assert grouped["items"][0]["group"] == "A"
    assert grouped["items"][0]["count"] == 1

    def raise_limit(*_args: Any, **_kwargs: Any) -> int:
        raise ValueError("too many buckets")

    monkeypatch.setattr(
        sqlite_mod, "enforce_query_log_aggregate_bucket_limit", raise_limit
    )
    guarded = backend.aggregate_query_log_counts(
        start_ts=0.0,
        end_ts=10.0,
        interval_seconds=5,
    )
    assert guarded["items"] == []


def test_sqlite_backend_retention_vacuum_interval_and_incremental_mode() -> None:
    """Brief: Retention vacuum obeys interval gating and incremental mode path.

    Inputs:
      - None.

    Outputs:
      - None; asserts invalid last-vacuum coercion, run, and interval skip paths.
    """

    backend = SqliteStatsStore(
        ":memory:",
        retention_vacuum_on_prune=True,
        retention_vacuum_interval_seconds=60.0,
        sqlite_auto_vacuum="incremental",
    )
    backend._retention_last_vacuum_ts = "bad-ts"  # type: ignore[assignment]
    backend._maybe_run_retention_vacuum_locked(now_ts=100.0)
    assert backend._retention_last_vacuum_ts == 100.0  # type: ignore[attr-defined]

    backend._maybe_run_retention_vacuum_locked(now_ts=120.0)
    assert backend._retention_last_vacuum_ts == 100.0  # type: ignore[attr-defined]


def test_sqlite_backend_export_counts_skips_non_integer_rows_and_has_query_log() -> (
    None
):
    """Brief: export_counts skips non-int rows and has_query_log tracks presence.

    Inputs:
      - None.

    Outputs:
      - None; asserts non-integer row skip and empty/non-empty query_log states.
    """

    backend = SqliteStatsStore(":memory:")
    assert backend.has_query_log() is False

    with backend._conn:  # type: ignore[attr-defined]
        backend._conn.execute(  # type: ignore[attr-defined]
            "INSERT INTO counts (scope, key, value) VALUES (?, ?, ?)",
            ("totals", "good", 7),
        )
        backend._conn.execute(  # type: ignore[attr-defined]
            "INSERT INTO counts (scope, key, value) VALUES (?, ?, ?)",
            ("totals", "bad", "not-an-int"),
        )

    exported = backend.export_counts()
    assert exported["totals"]["good"] == 7
    assert "bad" not in exported["totals"]

    backend._insert_query_log(
        ts=1.0,
        client_ip="203.0.113.10",
        name="present.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    assert backend.has_query_log() is True


def test_sqlite_backend_rebuild_counts_from_query_log_miss_and_error_paths() -> None:
    """Brief: Rebuild covers cache-miss and upstream-error aggregation branches.

    Inputs:
      - None.

    Outputs:
      - None; asserts miss-domain/subdomain, rcode, and upstream error counters.
    """

    backend = SqliteStatsStore(":memory:")
    backend._insert_query_log(
        ts=1.0,
        client_ip="203.0.113.20",
        name="api.example.com",
        qtype="AAAA",
        upstream_id="up-err",
        rcode="SERVFAIL",
        status="error",
        error="timeout",
        first=None,
        result_json="not-json",
    )

    backend.rebuild_counts_from_query_log(logger_obj=None)
    backend._op_queue.join()  # type: ignore[attr-defined]
    counts = backend.export_counts()

    assert counts["totals"]["cache_misses"] == 1
    assert counts["cache_miss_domains"]["example.com"] == 1
    assert counts["cache_miss_subdomains"]["api.example.com"] == 1
    assert counts["rcode_domains"]["SERVFAIL|example.com"] == 1
    assert counts["rcode_subdomains"]["SERVFAIL|api.example.com"] == 1
    assert counts["upstreams"]["up-err|error|SERVFAIL"] == 1


def test_sqlite_backend_close_tolerates_missing_connection() -> None:
    """Brief: close() tolerates a missing _conn attribute value.

    Inputs:
      - None.

    Outputs:
      - None; asserts close path does not raise when _conn is None.
    """

    backend = SqliteStatsStore(":memory:", batch_writes=True, batch_time_sec=3600.0)
    backend._conn = None  # type: ignore[assignment]
    backend.close()


def test_sqlite_backend_retention_prune_flushes_pending_batch_writes() -> None:
    """Brief: Query-log retention flushes batched writes before pruning decisions.

    Inputs:
      - None.

    Outputs:
      - None; asserts retention path flushes pending batched writes and prunes.
    """

    backend = SqliteStatsStore(
        ":memory:",
        batch_writes=True,
        batch_time_sec=3600.0,
        retention_max_records=1,
    )
    backend._insert_query_log(
        ts=1.0,
        client_ip="198.51.100.20",
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
        client_ip="198.51.100.21",
        name="second.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )

    assert not backend._pending_ops  # type: ignore[attr-defined]
    rows = backend.select_query_log(page=1, page_size=10)
    assert rows["total"] == 1
    assert rows["items"][0]["qname"] == "second.example"


def test_sqlite_backend_retention_vacuum_full_mode_executes_vacuum() -> None:
    """Brief: Retention vacuum uses VACUUM when auto_vacuum is not incremental.

    Inputs:
      - None.

    Outputs:
      - None; asserts VACUUM branch is invoked and timestamp updated.
    """

    class ConnSpy:
        """Collect SQL calls made by _maybe_run_retention_vacuum_locked."""

        def __init__(self) -> None:
            self.calls: list[str] = []

        def execute(self, sql: str) -> None:
            self.calls.append(sql)

    backend = SqliteStatsStore(
        ":memory:",
        retention_vacuum_on_prune=True,
        retention_vacuum_interval_seconds=1.0,
        sqlite_auto_vacuum="full",
    )
    conn_spy = ConnSpy()
    backend._conn = conn_spy  # type: ignore[assignment]
    backend._maybe_run_retention_vacuum_locked(now_ts=42.0)
    assert "VACUUM" in conn_spy.calls
    assert backend._retention_last_vacuum_ts == 42.0  # type: ignore[attr-defined]
