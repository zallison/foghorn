"""Brief: Tests for StatsCollector query-log sampling and dedupe controls.

Inputs:
  - None.

Outputs:
  - None; pytest assertions validate pre-persistence flood-suppression logic.
"""

from __future__ import annotations

from typing import Any, Dict, List

from foghorn.stats import StatsCollector


class _CaptureStore:
    """Brief: Minimal persistence stub capturing insert_query_log calls.

    Inputs:
      - None.

    Outputs:
      - In-memory list of inserted query-log rows.
    """

    def __init__(self) -> None:
        self.rows: List[Dict[str, Any]] = []

    def insert_query_log(self, **kwargs: Any) -> None:
        """Brief: Record an inserted query-log row.

        Inputs:
          - **kwargs: Query-log row fields.

        Outputs:
          - None; appends kwargs to ``rows``.
        """

        self.rows.append(dict(kwargs))


def _record_row(
    collector: StatsCollector, *, ts: float, qname: str = "example.com"
) -> None:
    """Brief: Helper to append one query-log row through StatsCollector.

    Inputs:
      - collector: StatsCollector under test.
      - ts: Query timestamp.
      - qname: Query name.

    Outputs:
      - None.
    """

    collector.record_query_result(
        client_ip="192.0.2.10",
        qname=qname,
        qtype="A",
        rcode="NOERROR",
        upstream_id="8.8.8.8:53",
        status="ok",
        error=None,
        first="203.0.113.1",
        result={"source": "test"},
        ts=ts,
    )


def test_query_log_sampling_rate_zero_suppresses_all_rows() -> None:
    """Brief: sample_rate=0 suppresses all persistent query-log writes."""

    store = _CaptureStore()
    collector = StatsCollector(
        stats_store=store,
        query_log_sample_rate=0.0,
    )

    _record_row(collector, ts=1.0)
    _record_row(collector, ts=2.0)
    _record_row(collector, ts=3.0)

    assert store.rows == []


def test_query_log_sampling_rate_half_keeps_deterministic_subset() -> None:
    """Brief: sample_rate=0.5 keeps every other row deterministically."""

    store = _CaptureStore()
    collector = StatsCollector(
        stats_store=store,
        query_log_sample_rate=0.5,
    )

    _record_row(collector, ts=1.0)
    _record_row(collector, ts=2.0)
    _record_row(collector, ts=3.0)
    _record_row(collector, ts=4.0)
    _record_row(collector, ts=5.0)

    assert [row["ts"] for row in store.rows] == [1.0, 3.0, 5.0]


def test_query_log_dedupe_window_suppresses_repeated_rows() -> None:
    """Brief: dedupe window suppresses duplicate rows until the window expires."""

    store = _CaptureStore()
    collector = StatsCollector(
        stats_store=store,
        query_log_sample_rate=1.0,
        query_log_dedupe_window_seconds=5.0,
    )

    _record_row(collector, ts=10.0, qname="dup.example")
    _record_row(collector, ts=12.0, qname="dup.example")
    _record_row(collector, ts=16.0, qname="dup.example")

    assert [row["ts"] for row in store.rows] == [10.0, 16.0]
