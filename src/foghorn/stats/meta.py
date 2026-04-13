from __future__ import annotations

import importlib.metadata as importlib_metadata
import time

try:
    FOGHORN_VERSION = importlib_metadata.version("foghorn")
except Exception:  # pragma: no cover - defensive fallback when metadata is missing
    FOGHORN_VERSION = "unknown"


_PROCESS_START_TIME = time.time()


def get_process_uptime_seconds() -> float:
    """Return process uptime in seconds since this module was imported.

    Inputs:
      - None.

    Outputs:
      - float seconds representing elapsed wall-clock time since
        ``_PROCESS_START_TIME``; always >= 0.0.

    Example:
      >>> uptime = get_process_uptime_seconds()
      >>> uptime >= 0.0
      True
    """

    return max(0.0, time.time() - _PROCESS_START_TIME)
