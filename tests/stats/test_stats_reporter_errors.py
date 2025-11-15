"""
Brief: Additional coverage for foghorn.stats reporter and histogram edge cases.

Inputs:
  - None

Outputs:
  - None
"""

import logging
from unittest.mock import MagicMock

import pytest

from foghorn.stats import StatsCollector, StatsReporter, LatencyHistogram


def test_stats_reporter_logs_error_when_snapshot_raises(caplog):
    c = StatsCollector()
    rep = StatsReporter(
        c, interval_seconds=1, reset_on_log=False, logger_name="foghorn.stats.errtest"
    )
    # Use shorter interval in tests to avoid long waits
    rep.interval_seconds = 0.01

    # Make snapshot raise to hit error handling path
    c.snapshot = MagicMock(side_effect=RuntimeError("boom"))

    with caplog.at_level("ERROR", logger="foghorn.stats.errtest"):
        rep.daemon = True
        rep.start()
        # Wait for at least one cycle with shorter interval
        import time

        time.sleep(0.05)
        rep.stop()

    assert any("StatsReporter error" in r.message for r in caplog.records)


def test_latency_histogram_percentile_empty_and_overflow_bins():
    h = LatencyHistogram()
    # Empty percentile yields 0.0
    assert h._percentile(0.5) == 0.0
    # Add a very large sample to overflow bin (>=10s)
    h.add(12.0)
    s = h.summarize()
    assert s["count"] == 1
    # With a single sample, avg and max reflect the large value (ms ~ 12000)
    assert s["max_ms"] >= 10000 and s["avg_ms"] >= 10000
