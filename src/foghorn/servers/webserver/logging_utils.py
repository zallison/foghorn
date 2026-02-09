"""Logging and in-memory log buffer helpers for the admin webserver.

This module contains uvicorn access-log suppression logic and a simple
thread-safe RingBuffer used for exposing recent log entries via the
FastAPI admin API.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, List, Optional

from cachetools import TTLCache

from foghorn.utils.register_caches import registered_cached


class _Suppress2xxAccessFilter(logging.Filter):
    """Logging filter that drops uvicorn access records for HTTP 2xx responses.

    Inputs:
      - record: logging.LogRecord instance from uvicorn.access or other loggers.

    Outputs:
      - bool: False for records that clearly correspond to HTTP 2xx status codes,
        True otherwise (including when no status code can be determined).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Fast-path: use explicit status_code attribute if present
        status = getattr(record, "status_code", None)

        # Fallbacks: inspect record.args as used by uvicorn access logger
        if status is None:
            args = getattr(record, "args", None)
            if isinstance(args, dict):
                # Common uvicorn mapping keys: status_code or status
                status = args.get("status_code") or args.get("status")
            elif isinstance(args, (tuple, list)) and args:
                # Heuristic: last positional arg is often the status code
                status = args[-1]

        try:
            code = int(status)
        except Exception:
            # If we cannot confidently determine a numeric status code, keep record
            return True

        # Suppress all 2xx access logs
        return not (200 <= code <= 299)


def install_uvicorn_2xx_suppression() -> None:
    """Attach _Suppress2xxAccessFilter to uvicorn.access logger if not present.

    Inputs:
      - None (operates on the global logging configuration).

    Outputs:
      - None. The uvicorn.access logger will drop 2xx HTTP access records.
    """

    access_logger = logging.getLogger("uvicorn.access")
    # Avoid adding duplicate filters if called multiple times (e.g., reloads)
    for f in getattr(access_logger, "filters", []):
        if isinstance(f, _Suppress2xxAccessFilter):
            return
    access_logger.addFilter(_Suppress2xxAccessFilter())


class RingBuffer:
    """Thread-safe fixed-size ring buffer of arbitrary items.

    Inputs (constructor):
      - capacity: Maximum number of items to retain (int, >= 1)

    Outputs:
      - RingBuffer instance with push() and snapshot() helpers.
    """

    def __init__(self, capacity: int = 500) -> None:
        if capacity <= 0:
            capacity = 1

        self._capacity = int(capacity)
        self._items: List[Any] = []
        self._lock = threading.Lock()

    def push(self, item: Any) -> None:
        """Append an item, evicting the oldest when capacity is exceeded.

        Inputs:
          - item: Any JSON-serializable value.

        Outputs:
          - None.
        """

        with self._lock:
            self._items.append(item)
            if len(self._items) > self._capacity:
                # Drop oldest
                overflow = len(self._items) - self._capacity
                if overflow > 0:
                    self._items = self._items[overflow:]

    @registered_cached(cache=TTLCache(maxsize=1, ttl=10))
    def snapshot(self, limit: Optional[int] = None) -> List[Any]:
        """Return a copy of buffered items, optionally truncated to newest N.

        Inputs:
          - limit: Optional int maximum number of items to return (newest first).

        Outputs:
          - List of items (shallow copy) suitable for JSON serialization.
        """

        with self._lock:
            data = list(self._items)
        if limit is not None and limit >= 0:
            data = data[-limit:]
        return data
