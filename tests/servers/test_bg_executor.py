"""Brief: Tests for foghorn.servers.bg_executor branch coverage.

Inputs:
  - pytest fixtures (monkeypatch)

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations
import threading

import pytest

from foghorn.servers import bg_executor as be


@pytest.fixture(autouse=True)
def _reset_bg_executor_state() -> None:
    """Brief: Reset shared executor globals for isolated tests.

    Inputs:
      - None

    Outputs:
      - None
    """

    be._BG_EXECUTOR = None
    be._BG_EXECUTOR_MAX_WORKERS = 4
    be._BG_EXECUTOR_MAX_PENDING = None
    be._BG_EXECUTOR_CAPACITY_SEM = None
    yield
    if be._BG_EXECUTOR is not None:
        be._BG_EXECUTOR.shutdown(wait=True, cancel_futures=True)
    be._BG_EXECUTOR = None
    be._BG_EXECUTOR_MAX_WORKERS = 4
    be._BG_EXECUTOR_MAX_PENDING = None
    be._BG_EXECUTOR_CAPACITY_SEM = None


@pytest.mark.parametrize("max_workers", [None, "nope", 0, -1])
def test_configure_ignores_invalid_max_workers(max_workers) -> None:
    """Brief: configure_bg_executor ignores None/invalid/too-small values.

    Inputs:
      - max_workers: parameterized invalid values

    Outputs:
      - None
    """

    be.configure_bg_executor(max_workers=max_workers)
    assert be._BG_EXECUTOR is None
    assert be._BG_EXECUTOR_MAX_WORKERS == 4


def test_configure_sets_max_workers_before_creation() -> None:
    """Brief: configure_bg_executor sets max workers before lazy creation.

    Inputs:
      - None

    Outputs:
      - None
    """

    be.configure_bg_executor(max_workers=2)
    assert be._BG_EXECUTOR is None
    assert be._BG_EXECUTOR_MAX_WORKERS == 2

    executor = be.get_bg_executor()
    assert executor._max_workers == 2


def test_configure_no_effect_after_creation() -> None:
    """Brief: configure_bg_executor is ignored after executor creation.

    Inputs:
      - None

    Outputs:
      - None
    """

    executor = be.get_bg_executor()
    be.configure_bg_executor(max_workers=8)
    assert be._BG_EXECUTOR is executor
    assert executor._max_workers == 4


def test_get_bg_executor_returns_singleton() -> None:
    """Brief: get_bg_executor returns the same instance after creation.

    Inputs:
      - None

    Outputs:
      - None
    """

    first = be.get_bg_executor()
    second = be.get_bg_executor()
    assert first is second


def test_get_bg_executor_default_when_none() -> None:
    """Brief: get_bg_executor falls back to default when configured None.

    Inputs:
      - None

    Outputs:
      - None
    """

    be._BG_EXECUTOR_MAX_WORKERS = None
    executor = be.get_bg_executor()
    assert executor._max_workers == 4


@pytest.mark.parametrize("max_pending", [None, "bad", 0, -2])
def test_configure_ignores_invalid_max_pending(max_pending) -> None:
    """Brief: configure_bg_executor ignores None/invalid/too-small max_pending.

    Inputs:
      - max_pending: parameterized invalid values.

    Outputs:
      - None
    """

    be.configure_bg_executor(max_workers=2, max_pending=max_pending)
    assert be._BG_EXECUTOR is None
    assert be._BG_EXECUTOR_MAX_PENDING is None


def test_configure_sets_max_pending_before_creation() -> None:
    """Brief: configure_bg_executor stores max_pending before lazy creation.

    Inputs:
      - None

    Outputs:
      - None
    """

    be.configure_bg_executor(max_workers=2, max_pending=3)
    assert be._BG_EXECUTOR is None
    assert be._BG_EXECUTOR_MAX_PENDING == 3

    be.get_bg_executor()
    sem = be._BG_EXECUTOR_CAPACITY_SEM
    assert sem is not None

    # The fourth non-blocking acquire should fail when max_pending=3.
    assert sem.acquire(blocking=False) is True
    assert sem.acquire(blocking=False) is True
    assert sem.acquire(blocking=False) is True
    assert sem.acquire(blocking=False) is False
    sem.release()
    sem.release()
    sem.release()


def test_get_bg_executor_uses_instance_created_under_lock() -> None:
    """Brief: get_bg_executor returns executor set by another thread while locked.

    Inputs:
      - None

    Outputs:
      - None
    """

    created = be.ThreadPoolExecutor(max_workers=1, thread_name_prefix="precreated")

    class _LockThatCreates:
        def __enter__(self) -> None:
            be._BG_EXECUTOR = created

        def __exit__(self, *_args) -> None:
            return None

    be._BG_EXECUTOR = None
    old_lock = be._BG_EXECUTOR_LOCK
    be._BG_EXECUTOR_LOCK = _LockThatCreates()
    try:
        assert be.get_bg_executor() is created
    finally:
        be._BG_EXECUTOR_LOCK = old_lock
        be._BG_EXECUTOR = created
        be.shutdown_bg_executor(wait=True)


def test_submit_bg_executor_task_returns_none_when_semaphore_missing() -> None:
    """Brief: submit_bg_executor_task returns None when capacity semaphore is absent.

    Inputs:
      - None

    Outputs:
      - None
    """

    be.get_bg_executor()
    be._BG_EXECUTOR_CAPACITY_SEM = None
    assert be.submit_bg_executor_task(lambda: None) is None


def test_submit_bg_executor_task_handles_acquire_exceptions() -> None:
    """Brief: submit_bg_executor_task treats acquire exceptions as capacity denial.

    Inputs:
      - None

    Outputs:
      - None
    """

    class _BadSemaphore:
        def acquire(self, *, blocking: bool) -> bool:  # noqa: ARG002
            raise RuntimeError("acquire boom")

    be.get_bg_executor()
    be._BG_EXECUTOR_CAPACITY_SEM = _BadSemaphore()
    assert be.submit_bg_executor_task(lambda: None) is None


def test_submit_bg_executor_task_enforces_capacity_and_releases_on_completion() -> None:
    """Brief: submit_bg_executor_task rejects when full and recovers after completion.

    Inputs:
      - None

    Outputs:
      - None
    """

    started = threading.Event()
    finish = threading.Event()

    def _blocking_task() -> str:
        started.set()
        finish.wait(timeout=2.0)
        return "done"

    be.configure_bg_executor(max_workers=1, max_pending=1)
    fut = be.submit_bg_executor_task(_blocking_task)
    assert fut is not None
    assert started.wait(timeout=1.0) is True

    # Capacity is exhausted by one running task when max_pending=1.
    assert be.submit_bg_executor_task(lambda: "second") is None

    finish.set()
    assert fut.result(timeout=1.0) == "done"

    # Completion callback releases capacity for a subsequent submission.
    fut2 = be.submit_bg_executor_task(lambda: "third")
    assert fut2 is not None
    assert fut2.result(timeout=1.0) == "third"


def test_submit_bg_executor_task_releases_permit_when_submit_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: submit_bg_executor_task releases semaphore when executor submit fails.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    class _FakeSemaphore:
        def __init__(self) -> None:
            self.releases = 0

        def acquire(self, *, blocking: bool) -> bool:  # noqa: ARG002
            return True

        def release(self) -> None:
            self.releases += 1

    class _FailingExecutor:
        def submit(self, _fn):
            raise RuntimeError("submit boom")

    sem = _FakeSemaphore()
    be._BG_EXECUTOR_CAPACITY_SEM = sem
    monkeypatch.setattr(be, "get_bg_executor", lambda: _FailingExecutor(), raising=True)

    assert be.submit_bg_executor_task(lambda: None) is None
    assert sem.releases == 1


def test_submit_bg_executor_task_ignores_release_errors_after_submit_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: submit_bg_executor_task swallows rollback release errors after submit failure.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    class _ExplodingRollbackSemaphore:
        def acquire(self, *, blocking: bool) -> bool:  # noqa: ARG002
            return True

        def release(self) -> None:
            raise RuntimeError("rollback release boom")

    class _FailingExecutor:
        def submit(self, _fn):
            raise RuntimeError("submit boom")

    be._BG_EXECUTOR_CAPACITY_SEM = _ExplodingRollbackSemaphore()
    monkeypatch.setattr(be, "get_bg_executor", lambda: _FailingExecutor(), raising=True)

    assert be.submit_bg_executor_task(lambda: None) is None


def test_submit_bg_executor_task_ignores_release_errors_in_done_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: submit_bg_executor_task swallows semaphore release errors in callbacks.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    class _ExplodingReleaseSemaphore:
        def acquire(self, *, blocking: bool) -> bool:  # noqa: ARG002
            return True

        def release(self) -> None:
            raise RuntimeError("release boom")

    class _ImmediateFuture:
        def add_done_callback(self, callback) -> None:
            callback(self)

    class _ImmediateExecutor:
        def submit(self, _fn):
            return _ImmediateFuture()

    be._BG_EXECUTOR_CAPACITY_SEM = _ExplodingReleaseSemaphore()
    monkeypatch.setattr(
        be, "get_bg_executor", lambda: _ImmediateExecutor(), raising=True
    )

    fut = be.submit_bg_executor_task(lambda: None)
    assert fut is not None


def test_shutdown_bg_executor_noop_without_executor() -> None:
    """Brief: shutdown_bg_executor is a no-op when executor is absent.

    Inputs:
      - None

    Outputs:
      - None
    """

    be.shutdown_bg_executor(wait=False)
    assert be._BG_EXECUTOR is None
    assert be._BG_EXECUTOR_CAPACITY_SEM is None


def test_shutdown_bg_executor_passes_wait_and_cancel_flags() -> None:
    """Brief: shutdown_bg_executor forwards wait/cancel_futures semantics correctly.

    Inputs:
      - None

    Outputs:
      - None
    """

    calls: list[tuple[bool, bool]] = []

    class _CapturingExecutor:
        def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
            calls.append((wait, cancel_futures))

    be._BG_EXECUTOR = _CapturingExecutor()
    be._BG_EXECUTOR_CAPACITY_SEM = object()
    be.shutdown_bg_executor(wait=False)
    assert calls == [(False, True)]
    assert be._BG_EXECUTOR is None
    assert be._BG_EXECUTOR_CAPACITY_SEM is None

    be._BG_EXECUTOR = _CapturingExecutor()
    be._BG_EXECUTOR_CAPACITY_SEM = object()
    be.shutdown_bg_executor(wait=True)
    assert calls[-1] == (True, False)


def test_shutdown_bg_executor_ignores_shutdown_exceptions() -> None:
    """Brief: shutdown_bg_executor suppresses executor shutdown exceptions.

    Inputs:
      - None

    Outputs:
      - None
    """

    class _ExplodingExecutor:
        def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:  # noqa: ARG002
            raise RuntimeError("shutdown boom")

    be._BG_EXECUTOR = _ExplodingExecutor()
    be._BG_EXECUTOR_CAPACITY_SEM = object()
    be.shutdown_bg_executor(wait=True)
    assert be._BG_EXECUTOR is None
    assert be._BG_EXECUTOR_CAPACITY_SEM is None
