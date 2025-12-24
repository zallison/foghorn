"""Brief: Tests for StatsSQLiteStore query/aggregate helpers and edge cases.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

from typing import Any

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
