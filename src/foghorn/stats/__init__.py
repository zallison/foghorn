"""Thread-safe statistics collection for Foghorn DNS server.

This package provides a statistics subsystem that tracks queries, cache performance,
plugin decisions, upstream results, and response codes with minimal overhead and
guaranteed thread-safety for concurrent request handling.

Public API is preserved for imports such as:
- ``from foghorn.stats import StatsCollector, StatsSQLiteStore, StatsReporter``
"""

from __future__ import annotations

from .collector import StatsCollector
from .domain import _is_subdomain, _normalize_domain
from .formatters import format_snapshot_json
from .histogram import LatencyHistogram
from .meta import FOGHORN_VERSION, get_process_uptime_seconds
from .reporter import StatsReporter
from .snapshot import StatsSnapshot
from .sqlite_store import StatsSQLiteStore
from .topk import TOPK_CAPACITY_FACTOR, TOPK_MIN_CAPACITY, TopK

# Compatibility: preserve historical pickling/introspection module name.
for _cls in (
    LatencyHistogram,
    TopK,
    StatsSnapshot,
    StatsSQLiteStore,
    StatsCollector,
    StatsReporter,
):
    try:
        _cls.__module__ = "foghorn.stats"
    except Exception:
        pass

__all__ = [
    "FOGHORN_VERSION",
    "TOPK_CAPACITY_FACTOR",
    "TOPK_MIN_CAPACITY",
    "LatencyHistogram",
    "StatsCollector",
    "StatsReporter",
    "StatsSQLiteStore",
    "StatsSnapshot",
    "TopK",
    "_is_subdomain",
    "_normalize_domain",
    "format_snapshot_json",
    "get_process_uptime_seconds",
]
