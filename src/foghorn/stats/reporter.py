from __future__ import annotations

import logging
import threading
from typing import Any

from .collector import StatsCollector
from .formatters import format_snapshot_json


class StatsReporter(threading.Thread):
    """
    Background daemon thread for periodic statistics logging.

    Inputs (constructor):
        collector: StatsCollector instance to snapshot
        interval_seconds: Seconds between log emissions (default 10)
        reset_on_log: Reset counters after each log (default False)
        log_level: Logging level name ('debug', 'info', 'warning', 'error')
        logger_name: Logger name to use (default 'foghorn.stats')

    Outputs:
        StatsReporter thread instance (call start() to begin)

    The reporter sleeps for interval_seconds, takes a snapshot, formats to JSON,
    and logs. The lock is only held during snapshot creation, not during
    formatting or logging.

    Example:
        >>> collector = StatsCollector()
        >>> reporter = StatsReporter(collector, interval_seconds=10, reset_on_log=True)
        >>> reporter.daemon = True
        >>> reporter.start()
        >>> # reporter logs every 10 seconds until stop() is called
    """

    def __init__(
        self,
        collector: StatsCollector,
        interval_seconds: int = 10,
        reset_on_log: bool = False,
        log_level: str = "info",
        logger_name: str = "foghorn.stats",
        persistence_store: Any | None = None,
    ) -> None:
        """Initialize statistics reporter thread.

        Inputs:
            collector: StatsCollector to snapshot
            interval_seconds: Log interval in seconds
            reset_on_log: Reset counters after each log
            log_level: Log level name
            logger_name: Logger name
            persistence_store: Optional StatsSQLiteStore for persistence.

        Outputs:
            None
        """
        super().__init__(daemon=True, name="StatsReporter")
        self.collector = collector
        self.interval_seconds = max(1, interval_seconds)
        self.reset_on_log = reset_on_log
        self.logger = logging.getLogger(logger_name)
        self.persistence_store = persistence_store

        # Map log level string to logging constant
        level_map = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL,
        }
        self.log_level = level_map.get(log_level.lower(), logging.INFO)

        self._stop_event = threading.Event()

    def run(self) -> None:
        """Reporter main loop (called by start())."""
        while not self._stop_event.wait(self.interval_seconds):
            try:
                snapshot = self.collector.snapshot(reset=self.reset_on_log)
                json_line = format_snapshot_json(snapshot)
                self.logger.debug(json_line)

                # Always reset recent latency window after emission
                self.collector.reset_latency_recent()
            except Exception as e:  # pragma: no cover
                self.logger.error("StatsReporter error: %s", e, exc_info=True)

    def stop(self, timeout: float = 5.0) -> None:
        """Signal reporter to stop and wait for thread to exit."""
        self._stop_event.set()
        self.join(timeout=timeout)
