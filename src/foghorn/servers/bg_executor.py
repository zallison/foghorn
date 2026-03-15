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
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

_BG_EXECUTOR: ThreadPoolExecutor | None = None
_BG_EXECUTOR_LOCK = threading.Lock()
_BG_EXECUTOR_MAX_WORKERS: int | None = 4


def configure_bg_executor(*, max_workers: Optional[int]) -> None:
    """Brief: Configure (or preconfigure) the shared background executor.

    Inputs:
      - max_workers: Desired max worker count. When None or invalid, uses the
        default.

    Outputs:
      - None.

    Notes:
      - This is best-effort. If the executor has already been created, this call
        will not resize it (ThreadPoolExecutor cannot be resized safely).
      - Call this during startup (e.g. from main.py) for deterministic sizing.
    """

    global _BG_EXECUTOR_MAX_WORKERS

    try:
        mw = int(max_workers) if max_workers is not None else None
    except Exception:
        mw = None

    if mw is not None and mw < 1:
        mw = None

    with _BG_EXECUTOR_LOCK:
        if _BG_EXECUTOR is not None:
            return
        if mw is not None:
            _BG_EXECUTOR_MAX_WORKERS = mw


def get_bg_executor() -> ThreadPoolExecutor:
    """Brief: Return the shared ThreadPoolExecutor used for background tasks.

    Inputs:
      - None.

    Outputs:
      - ThreadPoolExecutor: Shared executor.

    Notes:
      - The executor is created lazily on first use.
    """

    global _BG_EXECUTOR

    if _BG_EXECUTOR is not None:
        return _BG_EXECUTOR

    with _BG_EXECUTOR_LOCK:
        if _BG_EXECUTOR is not None:
            return _BG_EXECUTOR

        max_workers = _BG_EXECUTOR_MAX_WORKERS
        if max_workers is None:
            max_workers = 4

        _BG_EXECUTOR = ThreadPoolExecutor(
            max_workers=int(max_workers),
            thread_name_prefix="foghorn-bg",
        )
        return _BG_EXECUTOR
