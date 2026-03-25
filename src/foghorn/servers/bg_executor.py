from __future__ import annotations

"""Shared executor helpers for bounded background tasks.

Brief:
  Foghorn schedules some best-effort background work in response to untrusted
  network events (for example, cache refresh). This needs a bounded executor to
  avoid unbounded thread creation under attack.

Inputs:
  - max_workers configuration value (typically from config under server.limits)

Outputs:
  - A shared ThreadPoolExecutor instance for background tasks
"""

import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Callable, Optional

_BG_EXECUTOR: ThreadPoolExecutor | None = None
_BG_EXECUTOR_LOCK = threading.Lock()
_BG_EXECUTOR_MAX_WORKERS: int | None = 4
_BG_EXECUTOR_MAX_PENDING: int | None = None
_BG_EXECUTOR_CAPACITY_SEM: threading.Semaphore | None = None


def configure_bg_executor(
    *,
    max_workers: Optional[int],
    max_pending: Optional[int] = None,
) -> None:
    """Brief: Configure (or preconfigure) the shared background executor.

    Inputs:
      - max_workers: Desired max worker count. When None or invalid, uses the
        default.
      - max_pending: Optional cap on total in-flight+queued tasks accepted by
        submit_bg_executor_task(). When None or invalid, defaults to
        max_workers * 32 at executor creation time.

    Outputs:
      - None.

    Notes:
      - This is best-effort. If the executor has already been created, this call
        will not resize it (ThreadPoolExecutor cannot be resized safely).
      - Call this during startup (e.g. from main.py) for deterministic sizing.
    """

    global _BG_EXECUTOR_MAX_PENDING, _BG_EXECUTOR_MAX_WORKERS

    try:
        mw = int(max_workers) if max_workers is not None else None
    except Exception:
        mw = None
    try:
        mp = int(max_pending) if max_pending is not None else None
    except Exception:
        mp = None

    if mw is not None and mw < 1:
        mw = None
    if mp is not None and mp < 1:
        mp = None

    with _BG_EXECUTOR_LOCK:
        if _BG_EXECUTOR is not None:
            return
        if mw is not None:
            _BG_EXECUTOR_MAX_WORKERS = mw
        if mp is not None:
            _BG_EXECUTOR_MAX_PENDING = mp


def get_bg_executor() -> ThreadPoolExecutor:
    """Brief: Return the shared ThreadPoolExecutor used for background tasks.

    Inputs:
      - None.

    Outputs:
      - ThreadPoolExecutor: Shared executor.

    Notes:
      - The executor is created lazily on first use.
    """

    global _BG_EXECUTOR, _BG_EXECUTOR_CAPACITY_SEM

    if _BG_EXECUTOR is not None:
        return _BG_EXECUTOR

    with _BG_EXECUTOR_LOCK:
        if _BG_EXECUTOR is not None:
            return _BG_EXECUTOR

        max_workers = _BG_EXECUTOR_MAX_WORKERS
        if max_workers is None:
            max_workers = 4
        max_pending = _BG_EXECUTOR_MAX_PENDING
        if max_pending is None:
            max_pending = max(1, int(max_workers) * 32)

        _BG_EXECUTOR = ThreadPoolExecutor(
            max_workers=int(max_workers),
            thread_name_prefix="foghorn-bg",
        )
        _BG_EXECUTOR_CAPACITY_SEM = threading.Semaphore(int(max_pending))
        return _BG_EXECUTOR


def submit_bg_executor_task(
    fn: Callable[[], Any],
) -> Future[Any] | None:
    """Brief: Submit a background task only when bounded capacity is available.

    Inputs:
      - fn: Zero-argument callable to execute in the shared background
        executor.

    Outputs:
      - Future[Any] | None: Future when accepted, or None when capacity is
        exhausted / submission fails.

    Notes:
      - Capacity is tracked as running + queued tasks via a semaphore.
      - This prevents unbounded memory growth from an unbounded internal queue
        under sustained overload.
    """

    # Ensure lazy initialization of executor + semaphore.
    get_bg_executor()

    sem = _BG_EXECUTOR_CAPACITY_SEM
    if sem is None:
        return None

    try:
        acquired = sem.acquire(blocking=False)
    except Exception:
        acquired = False
    if not acquired:
        return None

    def _done(_fut: Future[Any]) -> None:
        try:
            sem.release()
        except Exception:
            pass

    try:
        fut = get_bg_executor().submit(fn)
        fut.add_done_callback(_done)
        return fut
    except Exception:
        try:
            sem.release()
        except Exception:
            pass
        return None


def shutdown_bg_executor(*, wait: bool = True) -> None:
    """Brief: Shutdown and clear the shared background executor.

    Inputs:
      - wait: When True, wait for running tasks to finish. When False, pending
        tasks are cancelled when supported by the runtime.

    Outputs:
      - None.

    Notes:
      - This is intended for controlled shutdown/reload paths.
      - A subsequent get_bg_executor() call will lazily recreate the executor.
    """

    global _BG_EXECUTOR, _BG_EXECUTOR_CAPACITY_SEM

    with _BG_EXECUTOR_LOCK:
        executor = _BG_EXECUTOR
        _BG_EXECUTOR = None
        _BG_EXECUTOR_CAPACITY_SEM = None

    if executor is None:
        return

    try:
        executor.shutdown(wait=bool(wait), cancel_futures=not bool(wait))
    except Exception:
        pass
