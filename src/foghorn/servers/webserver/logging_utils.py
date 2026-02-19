"""Logging and in-memory log buffer helpers for the admin webserver.

This module contains uvicorn access-log suppression logic and re-exports a
thread-safe RingBuffer (implemented in :mod:`foghorn.servers.runtime_state`) for
exposing recent log entries via the FastAPI admin API.
"""

from __future__ import annotations

import logging

from foghorn.servers.runtime_state import RingBuffer


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
