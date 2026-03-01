"""Tests for bounded async logging queue behavior in BaseStatsStore.

Inputs:
  - Dummy BaseStatsStore subclass with a blocked worker loop.
  - monkeypatch/caplog pytest fixtures.

Outputs:
  - Verifies put_nowait drop counting when the queue is full.
  - Verifies queue pressure warnings are rate-limited per bucket.
"""

from __future__ import annotations

import logging
import threading
from typing import Any


class _DummyStore:  # pragma: no cover - implementation detail for tests
    """Brief: Minimal BaseStatsStore implementation with a blocked worker loop.

    Inputs:
      - max_logging_queue: Maximum queue size to configure.

    Outputs:
      - Instance exposing increment_count and get_async_queue_metrics.
    """

    def __init__(self, *, max_logging_queue: int) -> None:
        from foghorn.plugins.querylog.base import BaseStatsStore

        class _Impl(BaseStatsStore):
            def __init__(self, *, max_logging_queue: int) -> None:
                self._max_logging_queue = int(max_logging_queue)
                self._block = threading.Event()

            # Blocked worker: never drains the queue.
            def _worker_loop(self) -> None:  # type: ignore[override]
                self._block.wait(timeout=5.0)

            def unblock(self) -> None:
                self._block.set()

            # ---- Required abstract-ish interface methods (unused here) ----
            def health_check(self) -> bool:  # type: ignore[override]
                return True

            def close(self) -> None:  # type: ignore[override]
                try:
                    self._block.set()
                except Exception:
                    pass

            def set_count(self, scope: str, key: str, value: int) -> None:  # type: ignore[override]
                return

            def has_counts(self) -> bool:  # type: ignore[override]
                return False

            def export_counts(self) -> dict[str, dict[str, int]]:  # type: ignore[override]
                return {}

            def rebuild_counts_from_query_log(self, logger_obj=None) -> None:  # type: ignore[override]
                return

            def query(self, *a: Any, **k: Any) -> list[dict[str, Any]]:  # type: ignore[override]
                return []

            def query_count(self, *a: Any, **k: Any) -> int:  # type: ignore[override]
                return 0

            def query_aggregate(self, *a: Any, **k: Any) -> dict[str, Any]:  # type: ignore[override]
                return {}

            def get_config_descriptor(self) -> dict[str, Any]:  # type: ignore[override]
                return {}

            def _increment_count(self, scope: str, key: str, delta: int = 1) -> None:
                return

            def _insert_query_log(self, entry: dict[str, Any]) -> None:
                return

        self._impl = _Impl(max_logging_queue=max_logging_queue)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._impl, name)


def test_base_stats_store_drops_increment_when_queue_full() -> None:
    """Brief: put_nowait drops increment counters when queue is full.

    Inputs:
      - max_logging_queue=1 dummy backend.

    Outputs:
      - None; asserts drop counters increment and queue size stays at capacity.
    """

    store = _DummyStore(max_logging_queue=1)

    store.increment_count("totals", "a", 1)
    store.increment_count("totals", "b", 1)

    metrics = store.get_async_queue_metrics()
    assert metrics["capacity"] == 1
    assert metrics["size"] == 1
    assert metrics["drops_total"] == 1
    assert metrics["drops_by_op"]["increment_count"] == 1

    store.close()


def test_base_stats_store_queue_pressure_warnings_rate_limited(
    monkeypatch, caplog
) -> None:
    """Brief: Queue pressure warnings are rate-limited within a bucket.

    Inputs:
      - monkeypatch: patches time.time used by BaseStatsStore.
      - caplog: captures log messages.

    Outputs:
      - None; asserts only one warning per bucket within reminder interval.
    """

    import foghorn.plugins.querylog.base as base_mod

    t = {"now": 1000.0}

    def _now() -> float:
        return float(t["now"])

    monkeypatch.setattr(base_mod.time, "time", _now)

    store = _DummyStore(max_logging_queue=4)

    with caplog.at_level(logging.WARNING, logger=base_mod.__name__):
        # Fill to 3/4 => 75% bucket.
        store.increment_count("totals", "a", 1)
        store.increment_count("totals", "b", 1)
        store.increment_count("totals", "c", 1)

    # Keep only bucket=75% warnings.
    bucket_75 = [r for r in caplog.records if "bucket=75%" in r.message]
    assert bucket_75

    caplog.clear()

    # Same time: should not emit again.
    with caplog.at_level(logging.WARNING, logger=base_mod.__name__):
        store._maybe_warn_queue_pressure()
    assert not caplog.records

    # Advance less than the 75% reminder interval (600s).
    t["now"] += 120.0
    with caplog.at_level(logging.WARNING, logger=base_mod.__name__):
        store._maybe_warn_queue_pressure()
    assert not caplog.records

    # Advance beyond the reminder interval.
    t["now"] += 600.0
    with caplog.at_level(logging.WARNING, logger=base_mod.__name__):
        store._maybe_warn_queue_pressure()
    assert any("bucket=75%" in r.message for r in caplog.records)

    store.close()
