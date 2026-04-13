from __future__ import annotations

"""Shared executor helpers for asyncio-based servers.

Brief:
  Asyncio servers in Foghorn (TCP/DoT and some DoH variants) often need to run the
  synchronous DNS resolution pipeline on a threadpool. Using the event loop's
  default executor makes sizing implicit and harder to harden.

Inputs:
  - max_workers configuration values (typically from config under server.limits)

Outputs:
  - A shared ThreadPoolExecutor instance for resolver work
"""

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

_RESOLVER_EXECUTOR: ThreadPoolExecutor | None = None
_RESOLVER_EXECUTOR_LOCK = threading.Lock()
_RESOLVER_EXECUTOR_MAX_WORKERS: int | None = None


def _default_max_workers() -> int:
    """Brief: Choose a conservative default max worker count.

    Inputs:
      - None.

    Outputs:
      - int: Default max_workers for the resolver executor.

    Notes:
      - We intentionally do not default to the full CPU count. Resolver work can
        be I/O-bound (upstream queries) but also includes CPU parsing/plugin
        logic. A modest fixed default is safer under overload.
    """

    try:
        cpu = int(os.cpu_count() or 1)
    except Exception:
        cpu = 1

    # Conservative default: min(32, max(4, cpu * 4))
    return max(4, min(32, cpu * 4))


def configure_resolver_executor(*, max_workers: Optional[int]) -> None:
    """Brief: Configure (or preconfigure) the shared resolver executor.

    Inputs:
      - max_workers: Desired max worker count. When None or invalid, uses a
        conservative default.

    Outputs:
      - None.

    Notes:
      - This is best-effort. If the executor has already been created, this call
        will not resize it (ThreadPoolExecutor cannot be resized safely).
      - Call this during startup (e.g. from main.py) for deterministic sizing.
    """

    global _RESOLVER_EXECUTOR_MAX_WORKERS

    try:
        mw = int(max_workers) if max_workers is not None else None
    except Exception:
        mw = None

    if mw is not None and mw < 1:
        mw = None

    with _RESOLVER_EXECUTOR_LOCK:
        if _RESOLVER_EXECUTOR is not None:
            return
        _RESOLVER_EXECUTOR_MAX_WORKERS = mw


def get_resolver_executor() -> ThreadPoolExecutor:
    """Brief: Return the shared ThreadPoolExecutor used for DNS resolution.

    Inputs:
      - None.

    Outputs:
      - ThreadPoolExecutor: Shared executor.

    Notes:
      - The executor is created lazily on first use.
    """

    global _RESOLVER_EXECUTOR

    if _RESOLVER_EXECUTOR is not None:
        return _RESOLVER_EXECUTOR

    with _RESOLVER_EXECUTOR_LOCK:
        if _RESOLVER_EXECUTOR is not None:
            return _RESOLVER_EXECUTOR

        max_workers = _RESOLVER_EXECUTOR_MAX_WORKERS
        if max_workers is None:
            max_workers = _default_max_workers()

        _RESOLVER_EXECUTOR = ThreadPoolExecutor(
            max_workers=int(max_workers),
            thread_name_prefix="foghorn-resolver",
        )
        return _RESOLVER_EXECUTOR
