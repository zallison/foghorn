from __future__ import annotations

import os
import sqlite3
import time
from typing import Any, Dict

from .stats_helpers import _find_rate_limit_db_paths_from_config
from .stats_helpers import logger as _stats_logger


# Reuse the existing webserver logger name for consistency
logger = _stats_logger


def _collect_rate_limit_stats(config: Dict[str, Any] | None) -> Dict[str, Any]:
    """Brief: Collect per-key RateLimit statistics from sqlite3 profiles.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - Dict with keys:
          * databases: list of per-db summaries including db_path, total_profiles,
            max_avg_rps, max_max_rps, and a limited list of individual profiles.
    """

    import foghorn.servers.webserver as web_core

    now = time.time()
    with web_core._RATE_LIMIT_CACHE_LOCK:
        if (
            web_core._last_rate_limit_snapshot is not None
            and now - web_core._last_rate_limit_snapshot_ts
            < web_core._RATE_LIMIT_CACHE_TTL_SECONDS
        ):
            return dict(web_core._last_rate_limit_snapshot)

    db_paths = _find_rate_limit_db_paths_from_config(config)
    summaries: list[Dict[str, Any]] = []

    # Heuristic fallback: if no explicit db_path is configured but the default
    # RateLimit db exists, include it.
    default_db = "./config/var/rate_limit.db"
    if not db_paths and os.path.exists(default_db):  # pragma: no cover
        db_paths.append(default_db)

    for path in db_paths:
        try:
            if not os.path.exists(path):
                continue
            with sqlite3.connect(path) as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT key, avg_rps, max_rps, samples, last_update "
                    "FROM rate_profiles ORDER BY avg_rps DESC LIMIT 200"
                )
                rows = cur.fetchall()
        except Exception:  # pragma: no cover - defensive / I/O specific
            logger.debug(
                "webserver: failed to collect rate_limit stats from %s",
                path,
                exc_info=True,
            )
            continue

        if not rows:
            summaries.append(
                {
                    "db_path": path,
                    "total_profiles": 0,
                    "max_avg_rps": 0.0,
                    "max_max_rps": 0.0,
                    "profiles": [],
                }
            )
            continue

        profiles: list[Dict[str, Any]] = []
        max_avg = 0.0
        max_max = 0.0
        for key, avg_rps, max_rps, samples, last_update in rows:
            try:
                avg_val = float(avg_rps)
            except Exception:
                avg_val = 0.0
            try:
                max_val = float(max_rps)
            except Exception:
                max_val = 0.0
            try:
                samples_val = int(samples)
            except Exception:
                samples_val = 0
            try:
                last_val = int(last_update)
            except Exception:
                last_val = 0

            max_avg = max(max_avg, avg_val)
            max_max = max(max_max, max_val)
            profiles.append(
                {
                    "key": str(key),
                    "avg_rps": avg_val,
                    "max_rps": max_val,
                    "samples": samples_val,
                    "last_update": last_val,
                }
            )

        summaries.append(
            {
                "db_path": path,
                "total_profiles": len(profiles),
                "max_avg_rps": max_avg,
                "max_max_rps": max_max,
                "profiles": profiles,
            }
        )

    payload: Dict[str, Any] = {"databases": summaries}
    import foghorn.servers.webserver as web_core

    with web_core._RATE_LIMIT_CACHE_LOCK:
        web_core._last_rate_limit_snapshot = dict(payload)
        web_core._last_rate_limit_snapshot_ts = time.time()
    return payload
