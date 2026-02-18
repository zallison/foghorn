"""Brief: AXFR periodic polling infrastructure.

Inputs/Outputs:
  - Background polling for scheduled AXFR zone refreshes.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)


def start_axfr_polling(plugin: object) -> None:
    """Brief: Start a background thread to periodically refresh AXFR zones.

    Inputs:
      - plugin: ZoneRecords plugin instance with _axfr_zones configuration.

    Outputs:
      - None; when at least one axfr_zones entry has poll_interval_seconds
        > 0, spawns a daemon thread that re-runs AXFR at the minimum
        configured interval.

    Notes:
      - The polling thread waits a full interval before its first reload.
      - Each polling tick clears plugin._axfr_loaded_once and calls
        plugin._load_records(), allowing AXFR-backed zones to transfer again.
    """
    zones = getattr(plugin, "_axfr_zones", None) or []
    min_interval: Optional[int] = None
    for z in zones:
        try:
            raw = z.get("poll_interval_seconds", 0)  # type: ignore[assignment]
        except Exception:  # pragma: no cover - defensive
            raw = 0
        try:
            interval = int(raw or 0)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            interval = 0
        if interval > 0 and (min_interval is None or interval < min_interval):
            min_interval = interval

    if not min_interval:
        return

    try:
        plugin._axfr_poll_interval = float(min_interval)
    except Exception:  # pragma: no cover - defensive
        plugin._axfr_poll_interval = float(min_interval or 0)
    stop_event = threading.Event()
    plugin._axfr_poll_stop = stop_event

    def _loop() -> None:
        """Brief: Background loop that periodically re-runs AXFR transfers.

        Inputs:
          - None (closes over plugin and _axfr_poll_* attributes).

        Outputs:
          - None; exits when the stop event is set.
        """
        interval = float(getattr(plugin, "_axfr_poll_interval", 0.0) or 0.0)
        if interval <= 0.0:
            return
        ev = getattr(plugin, "_axfr_poll_stop", None)
        if ev is None:
            return

        # Initial AXFR has already been performed during setup() via
        # _load_records(); wait for the first full interval before polling
        # again so we do not immediately trigger a second transfer.
        while not ev.wait(interval):
            try:
                logger.info(
                    "ZoneRecords AXFR: polling all configured axfr_zones (interval=%ss)",
                    interval,
                )
                # Allow AXFR-backed zones to run again on the next
                # _load_records() call.
                setattr(plugin, "_axfr_loaded_once", False)
                plugin._load_records()
            except Exception:  # pragma: no cover - defensive logging only
                logger.warning(
                    "ZoneRecords AXFR: error during scheduled AXFR poll",
                    exc_info=True,
                )

    thread = threading.Thread(target=_loop, name="ZoneRecordsAxfrPoller")
    thread.daemon = True
    plugin._axfr_poll_thread = thread
    thread.start()
