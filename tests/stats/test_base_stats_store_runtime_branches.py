"""Branch-focused tests for BaseStatsStore runtime helper behavior.

Inputs:
  - pytest fixtures (caplog/monkeypatch).
  - Minimal BaseStatsStore test doubles.

Outputs:
  - Assertions that exercise non-trivial queue, fallback, and metrics branches.
"""

from __future__ import annotations

import logging
import queue
from typing import Any

import pytest

import foghorn.plugins.querylog.base as base_mod
from foghorn.plugins.querylog.base import BaseStatsStore


class _BadInt:
    """Brief: Helper object that always fails integer conversion.

    Inputs:
      - None.

    Outputs:
      - TypeError when int(...) is attempted.
    """

    def __int__(self) -> int:
        raise TypeError("cannot convert to int")


class _ScriptedQueue:
    """Brief: Queue-like object used to deterministically drive _worker_loop.

    Inputs:
      - items: Sequence of (op_name, args, kwargs) tuples returned by get().
      - raise_on_get: When True, get() raises RuntimeError.
      - raise_on_task_done: When True, task_done() raises RuntimeError.

    Outputs:
      - Queue-like object with predictable behavior for branch tests.
    """

    def __init__(
        self,
        items: list[tuple[str, tuple[Any, ...], dict[str, Any]]] | None = None,
        *,
        raise_on_get: bool = False,
        raise_on_task_done: bool = False,
    ) -> None:
        self._items = list(items or [])
        self._raise_on_get = bool(raise_on_get)
        self._raise_on_task_done = bool(raise_on_task_done)
        self.task_done_calls = 0

    def get(self) -> tuple[str, tuple[Any, ...], dict[str, Any]]:
        """Brief: Return the next queued item or raise a scripted error.

        Inputs:
          - None.

        Outputs:
          - Next queue item tuple.
        """

        if self._raise_on_get:
            raise RuntimeError("scripted get failure")
        if not self._items:
            raise RuntimeError("scripted empty queue")
        return self._items.pop(0)

    def task_done(self) -> None:
        """Brief: Record completion and optionally raise scripted errors.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        self.task_done_calls += 1
        if self._raise_on_task_done:
            raise RuntimeError("scripted task_done failure")


class _MetricsBrokenQueue:
    """Brief: Queue-like object whose qsize() fails for error-path coverage.

    Inputs:
      - maxsize: Queue maxsize value to expose.

    Outputs:
      - Queue-like object with failing qsize().
    """

    def __init__(self, *, maxsize: int) -> None:
        self.maxsize = int(maxsize)

    def qsize(self) -> int:
        """Brief: Always raise to exercise defensive exception handling.

        Inputs:
          - None.

        Outputs:
          - RuntimeError.
        """

        raise RuntimeError("qsize failed")


class _RuntimeStore(BaseStatsStore):
    """Brief: Minimal concrete store that records sync fallback operations.

    Inputs:
      - None.

    Outputs:
      - Store with capture lists for _increment_count and _insert_query_log.
    """

    def __init__(self) -> None:
        self.increment_calls: list[tuple[str, str, int]] = []
        self.insert_calls: list[tuple[Any, ...]] = []
        self.worker_loop_calls = 0
        self.handled_values: list[int] = []
        self.raised_ops = 0

    def _worker_loop(self) -> None:
        """Brief: Non-blocking worker used for _ensure_worker initialization tests.

        Inputs:
          - None.

        Outputs:
          - None; increments a call counter and returns immediately.
        """

        self.worker_loop_calls += 1

    def _worker_handler(self, value: int) -> None:
        """Brief: Record handled scripted operation values.

        Inputs:
          - value: Integer marker value.

        Outputs:
          - None.
        """

        self.handled_values.append(int(value))

    def _worker_raises(self) -> None:
        """Brief: Raise a scripted worker operation failure.

        Inputs:
          - None.

        Outputs:
          - RuntimeError.
        """

        self.raised_ops += 1
        raise RuntimeError("scripted worker operation error")

    def _increment_count(self, scope: str, key: str, delta: int = 1) -> None:
        """Brief: Record sync fallback increment_count operations.

        Inputs:
          - scope: Counter scope.
          - key: Counter key.
          - delta: Counter delta.

        Outputs:
          - None.
        """

        self.increment_calls.append((scope, key, int(delta)))

    def _insert_query_log(
        self,
        ts: float,
        client_ip: str,
        name: str,
        qtype: str,
        upstream_id: str | None,
        rcode: str | None,
        status: str | None,
        error: str | None,
        first: str | None,
        result_json: str,
    ) -> None:
        """Brief: Record sync fallback insert_query_log operations.

        Inputs:
          - Query-log fields matching BaseStatsStore.insert_query_log.

        Outputs:
          - None.
        """

        self.insert_calls.append(
            (
                float(ts),
                client_ip,
                name,
                qtype,
                upstream_id,
                rcode,
                status,
                error,
                first,
                result_json,
            )
        )


class _NoFallbackStore(BaseStatsStore):
    """Brief: Minimal store without sync fallback handlers for NotImplemented tests.

    Inputs:
      - None.

    Outputs:
      - Store instance used to validate fallback error branches.
    """

    def __init__(self) -> None:
        return


def _sample_insert_args() -> tuple[
    float,
    str,
    str,
    str,
    str | None,
    str | None,
    str | None,
    str | None,
    str | None,
    str,
]:
    """Brief: Return a canonical insert_query_log argument tuple.

    Inputs:
      - None.

    Outputs:
      - Tuple of values matching insert_query_log positional parameters.
    """

    return (
        1234.5,
        "127.0.0.1",
        "example.com.",
        "A",
        "8.8.8.8:53",
        "NOERROR",
        "ok",
        None,
        "93.184.216.34",
        "{}",
    )


def test_ensure_worker_uses_public_limit_and_is_idempotent() -> None:
    """Brief: _ensure_worker reads max_logging_queue and avoids reinitialization.

    Inputs:
      - None.

    Outputs:
      - None; asserts maxsize from public attribute and idempotent behavior.
    """

    store = _RuntimeStore()
    store.max_logging_queue = 11
    store._ensure_worker()

    assert store._op_queue.maxsize == 11
    existing_queue = store._op_queue

    store._ensure_worker()
    assert store._op_queue is existing_queue


def test_ensure_worker_falls_back_to_default_capacity_on_bad_limit() -> None:
    """Brief: _ensure_worker uses default capacity when limit conversion fails.

    Inputs:
      - None.

    Outputs:
      - None; asserts fallback maxsize is 4096.
    """

    store = _RuntimeStore()
    store.max_logging_queue = object()
    store._ensure_worker()
    assert store._op_queue.maxsize == 65536


def test_ensure_worker_treats_negative_limit_as_unbounded_queue() -> None:
    """Brief: _ensure_worker maps negative queue limits to unbounded maxsize=0.

    Inputs:
      - None.

    Outputs:
      - None; asserts queue maxsize normalization behavior.
    """

    store = _RuntimeStore()
    store._max_logging_queue = -10
    store._ensure_worker()
    assert store._op_queue.maxsize == 0


def test_ensure_worker_uses_default_capacity_when_limit_attrs_missing() -> None:
    """Brief: _ensure_worker defaults to 4096 when no queue-limit attrs are set.

    Inputs:
      - None.

    Outputs:
      - None; asserts default capacity branch behavior.
    """

    store = _RuntimeStore()
    store._ensure_worker()
    assert store._op_queue.maxsize == 65536


def test_worker_loop_returns_when_queue_missing() -> None:
    """Brief: _worker_loop exits early when no operation queue is configured.

    Inputs:
      - None.

    Outputs:
      - None; verifies no exception on missing queue.
    """

    store = _RuntimeStore()
    store._worker_loop = BaseStatsStore._worker_loop.__get__(store, _RuntimeStore)  # type: ignore[assignment]
    store._worker_loop()


def test_worker_loop_handles_callable_unknown_error_and_sentinel(caplog) -> None:
    """Brief: _worker_loop processes known ops, unknown ops, failures, and sentinel.

    Inputs:
      - caplog: Captures worker debug/exception logs.

    Outputs:
      - None; asserts handlers ran and expected logs were emitted.
    """

    store = _RuntimeStore()
    store._worker_loop = BaseStatsStore._worker_loop.__get__(store, _RuntimeStore)  # type: ignore[assignment]
    store._op_queue = _ScriptedQueue(
        items=[
            ("worker_handler", (7,), {}),
            ("not_a_handler", (), {}),
            ("worker_raises", (), {}),
            ("", (), {}),
        ],
        raise_on_task_done=True,
    )

    with caplog.at_level(logging.DEBUG, logger=base_mod.__name__):
        store._worker_loop()

    assert store.handled_values == [7]
    assert store.raised_ops == 1
    assert any("unknown op_name" in rec.message for rec in caplog.records)
    assert any("worker failed while handling" in rec.message for rec in caplog.records)
    assert store._op_queue.task_done_calls == 4


def test_worker_loop_breaks_on_queue_get_error() -> None:
    """Brief: _worker_loop exits when queue.get() raises unexpectedly.

    Inputs:
      - None.

    Outputs:
      - None; verifies defensive break path executes without raising.
    """

    store = _RuntimeStore()
    store._worker_loop = BaseStatsStore._worker_loop.__get__(store, _RuntimeStore)  # type: ignore[assignment]
    store._op_queue = _ScriptedQueue(raise_on_get=True)
    store._worker_loop()


@pytest.mark.parametrize(
    "size,capacity,expected_bucket,expected_interval",
    [
        (100, 100, 100, 60.0),
        (90, 100, 90, 240.0),
        (75, 100, 75, 600.0),
        (50, 100, 50, 900.0),
        (25, 100, 25, 1800.0),
        (24, 100, 0, 3600.0),
        (-5, -20, 0, 3600.0),
    ],
)
def test_queue_pressure_bucket_boundaries(
    size: int, capacity: int, expected_bucket: int, expected_interval: float
) -> None:
    """Brief: _queue_pressure_bucket maps boundary percentages to expected buckets.

    Inputs:
      - size: Current queue size under test.
      - capacity: Queue capacity under test.

    Outputs:
      - None; asserts bucket and reminder interval mapping.
    """

    store = _RuntimeStore()
    bucket, _pct, interval = store._queue_pressure_bucket(size=size, capacity=capacity)
    assert bucket == expected_bucket
    assert interval == expected_interval


def test_maybe_warn_queue_pressure_returns_for_unbounded_small_and_broken_queue(
    caplog,
) -> None:
    """Brief: _maybe_warn_queue_pressure exits quietly for non-actionable states.

    Inputs:
      - caplog: Captures log output.

    Outputs:
      - None; asserts no logs for queue-missing, unbounded, <=5%, and bad qsize.
    """

    store = _RuntimeStore()

    with caplog.at_level(logging.INFO, logger=base_mod.__name__):
        store._maybe_warn_queue_pressure()

        store._op_queue = queue.Queue(maxsize=0)
        store._maybe_warn_queue_pressure()

        store._op_queue = queue.Queue(maxsize=100)
        for i in range(5):
            store._op_queue.put_nowait(("op", (i,), {}))
        store._maybe_warn_queue_pressure()

        store._op_queue = _MetricsBrokenQueue(maxsize=10)
        store._maybe_warn_queue_pressure()

    assert not caplog.records


def test_maybe_warn_queue_pressure_logs_info_and_tolerates_state_errors(
    monkeypatch, caplog
) -> None:
    """Brief: _maybe_warn_queue_pressure logs info-level bucket and swallows state errors.

    Inputs:
      - monkeypatch: Freezes time.time for deterministic due logic.
      - caplog: Captures INFO log output.

    Outputs:
      - None; asserts info log still emits under defensive exception paths.
    """

    monkeypatch.setattr(base_mod.time, "time", lambda: 2000.0)
    store = _RuntimeStore()
    store._op_queue = queue.Queue(maxsize=100)
    for i in range(10):
        store._op_queue.put_nowait(("op", (i,), {}))

    # Trigger the defensive exception branches for last_ts/update-state/drops.
    store._op_queue_warn_last_ts = (1,)
    store._op_queue_drops_total = _BadInt()

    with caplog.at_level(logging.INFO, logger=base_mod.__name__):
        store._maybe_warn_queue_pressure()

    assert any("bucket=0%" in rec.message for rec in caplog.records)
    assert any("drops=0" in rec.message for rec in caplog.records)


def test_maybe_warn_queue_pressure_tolerates_last_bucket_attribute_failure(
    monkeypatch, caplog
) -> None:
    """Brief: _maybe_warn_queue_pressure tolerates exceptions when reading last bucket.

    Inputs:
      - monkeypatch: Freezes time.time for deterministic behavior.
      - caplog: Captures WARNING logs.

    Outputs:
      - None; asserts warning still emits after last-bucket read failure.
    """

    monkeypatch.setattr(base_mod.time, "time", lambda: 2100.0)

    class _BrokenLastBucketStore(_RuntimeStore):
        def __getattribute__(self, name: str) -> Any:
            if name == "_op_queue_warn_last_bucket":
                raise RuntimeError("scripted attribute failure")
            return super().__getattribute__(name)

    store = _BrokenLastBucketStore()
    store._op_queue = queue.Queue(maxsize=100)
    for i in range(30):
        store._op_queue.put_nowait(("op", (i,), {}))
    store._op_queue_warn_last_ts = {}

    with caplog.at_level(logging.WARNING, logger=base_mod.__name__):
        store._maybe_warn_queue_pressure()

    assert any("bucket=25%" in rec.message for rec in caplog.records)


def test_record_queue_drop_handles_non_dict_and_conversion_failures() -> None:
    """Brief: _record_queue_drop handles invalid counters/maps without raising.

    Inputs:
      - None.

    Outputs:
      - None; asserts defensive conversion and mapping branches.
    """

    store = _RuntimeStore()
    store._op_queue_drops_total = 0
    store._op_queue_drops_by_op = []
    store._record_queue_drop("insert_query_log")
    assert store._op_queue_drops_total == 1

    store._op_queue_drops_total = _BadInt()
    store._op_queue_drops_by_op = {}
    store._record_queue_drop("insert_query_log")
    assert isinstance(store._op_queue_drops_total, _BadInt)

    store._op_queue_drops_total = 0
    store._op_queue_drops_by_op = {"insert_query_log": _BadInt()}
    store._record_queue_drop("insert_query_log")
    assert store._op_queue_drops_total == 1
    assert isinstance(store._op_queue_drops_by_op["insert_query_log"], _BadInt)


def test_get_async_queue_metrics_handles_bounded_unbounded_and_bad_inputs() -> None:
    """Brief: get_async_queue_metrics normalizes queue and drop-map edge cases.

    Inputs:
      - None.

    Outputs:
      - None; asserts bounded/unbounded/exceptional queue metric handling.
    """

    store = _RuntimeStore()
    store._op_queue_drops_total = 3
    store._op_queue_drops_by_op = {"": 9, "ok": "2", "bad": _BadInt()}
    metrics = store.get_async_queue_metrics()

    assert metrics["capacity"] is None
    assert metrics["size"] == 0
    assert metrics["pct_full"] is None
    assert metrics["drops_total"] == 3
    assert metrics["drops_by_op"] == {"ok": 2}

    store._op_queue = queue.Queue(maxsize=10)
    for i in range(4):
        store._op_queue.put_nowait(("op", (i,), {}))
    metrics = store.get_async_queue_metrics()
    assert metrics["capacity"] == 10
    assert metrics["size"] == 4
    assert metrics["pct_full"] == 40.0

    store._op_queue = queue.Queue(maxsize=0)
    for i in range(2):
        store._op_queue.put_nowait(("op", (i,), {}))
    metrics = store.get_async_queue_metrics()
    assert metrics["capacity"] is None
    assert metrics["size"] == 2
    assert metrics["pct_full"] is None

    store._op_queue = _MetricsBrokenQueue(maxsize=10)
    metrics = store.get_async_queue_metrics()
    assert metrics["capacity"] is None
    assert metrics["size"] == 0
    assert metrics["pct_full"] is None

    store._op_queue_drops_by_op = ["unexpected"]
    metrics = store.get_async_queue_metrics()
    assert metrics["drops_by_op"] == {}


def test_increment_count_falls_back_to_sync_handler_when_queue_missing() -> None:
    """Brief: increment_count uses _increment_count when queue setup fails.

    Inputs:
      - None.

    Outputs:
      - None; asserts synchronous fallback call parameters.
    """

    store = _RuntimeStore()
    store._ensure_worker = lambda: None  # type: ignore[assignment]
    store.increment_count("totals", "fallback", 5)
    assert store.increment_calls == [("totals", "fallback", 5)]


def test_increment_count_raises_when_sync_handler_missing() -> None:
    """Brief: increment_count raises NotImplementedError when fallback is unavailable.

    Inputs:
      - None.

    Outputs:
      - None; asserts explicit NotImplementedError for missing handler.
    """

    store = _NoFallbackStore()
    store._ensure_worker = lambda: None  # type: ignore[assignment]
    with pytest.raises(NotImplementedError):
        store.increment_count("totals", "missing", 1)


def test_insert_query_log_queue_drop_and_sync_fallback_paths() -> None:
    """Brief: insert_query_log records drop metrics and supports sync fallback.

    Inputs:
      - None.

    Outputs:
      - None; asserts full-queue drop accounting and sync fallback call capture.
    """

    args = _sample_insert_args()

    queued_store = _RuntimeStore()
    queued_store._ensure_worker = lambda: None  # type: ignore[assignment]
    queued_store._op_queue = queue.Queue(maxsize=1)
    queued_store._op_queue_drops_total = 0
    queued_store._op_queue_drops_by_op = {}

    queued_store.insert_query_log(*args)
    queued_store.insert_query_log(*args)

    metrics = queued_store.get_async_queue_metrics()
    assert metrics["size"] == 1
    assert metrics["drops_total"] == 1
    assert metrics["drops_by_op"] == {"insert_query_log": 1}

    fallback_store = _RuntimeStore()
    fallback_store._ensure_worker = lambda: None  # type: ignore[assignment]
    fallback_store.insert_query_log(*args)
    assert fallback_store.insert_calls == [args]


def test_insert_query_log_raises_when_sync_handler_missing() -> None:
    """Brief: insert_query_log raises when neither queue nor fallback handler is usable.

    Inputs:
      - None.

    Outputs:
      - None; asserts NotImplementedError for missing _insert_query_log.
    """

    store = _NoFallbackStore()
    store._ensure_worker = lambda: None  # type: ignore[assignment]
    with pytest.raises(NotImplementedError):
        store.insert_query_log(*_sample_insert_args())
