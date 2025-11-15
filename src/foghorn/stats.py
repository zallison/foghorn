"""
Thread-safe statistics collection for Foghorn DNS server.

This module provides a statistics subsystem that tracks queries, cache performance,
plugin decisions, upstream results, and response codes with minimal overhead and
guaranteed thread-safety for concurrent request handling.
"""

from __future__ import annotations
import json
import logging
import functools
import os
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@functools.lru_cache(maxsize=1024)
def _normalize_domain(domain: str) -> str:
    """
    Normalize domain name for statistics tracking.

    Inputs:
        domain: Raw domain name string (may have trailing dot, mixed case)

    Outputs:
        Normalized lowercase domain without trailing dot

    Example:
        >>> _normalize_domain("Example.COM.")
        'example.com'
    """
    return domain.rstrip(".").lower()


class LatencyHistogram:
    """
    Thread-safe histogram for tracking request latencies with logarithmic bins.

    Inputs (constructor):
        None

    Outputs:
        LatencyHistogram instance for adding samples and computing percentiles

    The histogram uses fixed millisecond bins for O(1) insertion and fast
    percentile computation. Bins: [0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100,
    200, 500, 1000, 2000, 5000, 10000+].

    Example:
        >>> hist = LatencyHistogram()
        >>> hist.add(0.0035)  # 3.5ms
        >>> hist.add(0.015)   # 15ms
        >>> stats = hist.summarize()
        >>> stats['count']
        2
    """

    _BINS = [0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000]

    def __init__(self) -> None:
        """Initialize empty histogram with zero counts for all bins."""
        self.bins: List[int] = [0] * (len(self._BINS) + 1)
        self.count = 0
        self.sum_ms = 0.0
        self.min_ms: Optional[float] = None
        self.max_ms: Optional[float] = None

    def add(self, seconds: float) -> None:
        """
        Add a latency sample to the histogram.

        Inputs:
            seconds: Latency in seconds (float)

        Outputs:
            None

        Example:
            >>> hist = LatencyHistogram()
            >>> hist.add(0.004)  # 4 milliseconds
        """
        ms = seconds * 1000.0
        self.count += 1
        self.sum_ms += ms

        if self.min_ms is None or ms < self.min_ms:
            self.min_ms = ms
        if self.max_ms is None or ms > self.max_ms:
            self.max_ms = ms

        # Find appropriate bin
        for i, threshold in enumerate(self._BINS):
            if ms < threshold:
                self.bins[i] += 1
                return
        # Overflow bin (>= 10000ms)
        self.bins[-1] += 1

    def summarize(self) -> Dict[str, float]:
        """
        Compute summary statistics from the histogram.

        Inputs:
            None

        Outputs:
            Dictionary with keys: count, min_ms, max_ms, avg_ms, p50_ms, p90_ms, p99_ms

        Example:
            >>> hist = LatencyHistogram()
            >>> hist.add(0.001)
            >>> summary = hist.summarize()
            >>> summary['count']
            1
        """
        if self.count == 0:
            return {
                "count": 0,
                "min_ms": 0.0,
                "max_ms": 0.0,
                "avg_ms": 0.0,
                "p50_ms": 0.0,
                "p90_ms": 0.0,
                "p99_ms": 0.0,
            }

        avg_ms = self.sum_ms / self.count
        p50_ms = self._percentile(0.50)
        p90_ms = self._percentile(0.90)
        p99_ms = self._percentile(0.99)

        return {
            "count": self.count,
            "min_ms": round(self.min_ms or 0.0, 2),
            "max_ms": round(self.max_ms or 0.0, 2),
            "avg_ms": round(avg_ms, 2),
            "p50_ms": round(p50_ms, 2),
            "p90_ms": round(p90_ms, 2),
            "p99_ms": round(p99_ms, 2),
        }

    def _percentile(self, p: float) -> float:
        """
        Compute percentile from histogram bins.

        Inputs:
            p: Percentile as fraction (0.0 to 1.0)

        Outputs:
            Estimated latency in milliseconds at percentile p
        """
        if self.count == 0:
            return 0.0

        target = int(self.count * p)
        cumulative = 0

        for i, count in enumerate(self.bins):
            cumulative += count
            if cumulative >= target:
                # Return midpoint of bin
                if i == 0:
                    return self._BINS[0] / 2
                elif i < len(self._BINS):
                    return (self._BINS[i - 1] + self._BINS[i]) / 2
                else:
                    return 10000.0  # overflow bin

        return self.max_ms or 0.0


class TopK:
    """
    Approximate top-K heavy hitters tracker with bounded memory.

    Inputs (constructor):
        capacity: Target number of top items to track (K)
        prune_factor: Multiplier for pruning threshold (default 4)

    Outputs:
        TopK instance for adding keys and exporting top N

    Uses a counter dict that is pruned when size exceeds prune_factor * capacity.
    Provides O(1) amortized insertion and bounded memory.

    Example:
        >>> tracker = TopK(capacity=3, prune_factor=2)
        >>> for _ in range(10):
        ...     tracker.add("example.com")
        >>> for _ in range(5):
        ...     tracker.add("google.com")
        >>> top = tracker.export(2)
        >>> top[0][0]
        'example.com'
    """

    def __init__(self, capacity: int = 10, prune_factor: int = 4) -> None:
        """
        Initialize TopK tracker.

        Inputs:
            capacity: Target top-K size
            prune_factor: Pruning multiplier (prune when size > capacity * prune_factor)

        Outputs:
            None
        """
        self.capacity = max(1, capacity)
        self.prune_factor = max(2, prune_factor)
        self.counts: Dict[str, int] = {}

    def add(self, key: str) -> None:
        """
        Increment count for a key.

        Inputs:
            key: String key to track

        Outputs:
            None

        Example:
            >>> tracker = TopK(capacity=5)
            >>> tracker.add("example.com")
            >>> tracker.add("example.com")
        """
        self.counts[key] = self.counts.get(key, 0) + 1

        # Occasional pruning to bound memory
        if len(self.counts) > self.capacity * self.prune_factor:
            self._prune()

    def export(self, n: int) -> List[Tuple[str, int]]:
        """
        Export top N items sorted by count descending.

        Inputs:
            n: Number of top items to return

        Outputs:
            List of (key, count) tuples sorted by count descending

        Example:
            >>> tracker = TopK(capacity=5)
            >>> tracker.add("a")
            >>> tracker.add("a")
            >>> tracker.add("b")
            >>> tracker.export(2)
            [('a', 2), ('b', 1)]
        """
        items = sorted(self.counts.items(), key=lambda x: x[1], reverse=True)
        return items[:n]

    def _prune(self) -> None:
        """
        Prune to top capacity items by count.

        Inputs:
            None

        Outputs:
            None
        """
        if len(self.counts) <= self.capacity:
            return

        items = sorted(self.counts.items(), key=lambda x: x[1], reverse=True)
        self.counts = dict(items[: self.capacity])


@dataclass
class StatsSnapshot:
    """
    Immutable point-in-time snapshot of statistics for logging.

    Inputs (constructor):
        All fields provided by StatsCollector.snapshot()

    Outputs:
        Snapshot instance with read-only view of statistics

    This dataclass is created under lock but logged outside the lock to
    minimize contention. All collections are copied to prevent mutation.
    """

    created_at: float
    totals: Dict[str, int]
    rcodes: Dict[str, int]
    qtypes: Dict[str, int]
    decisions: Dict[str, Dict[str, int]]
    upstreams: Dict[str, Dict[str, int]]
    uniques: Optional[Dict[str, int]]
    top_clients: Optional[List[Tuple[str, int]]]
    top_subdomains: Optional[List[Tuple[str, int]]]
    top_domains: Optional[List[Tuple[str, int]]]
    latency_stats: Optional[Dict[str, float]]
    latency_recent_stats: Optional[Dict[str, float]] = None


class StatsSQLiteStore:
    """SQLite-backed persistence for :class:`StatsSnapshot` objects.

    Inputs (constructor):
        db_path: Filesystem path to the SQLite database file.
        max_snapshots: Optional maximum number of snapshots to retain.
        max_age_seconds: Optional maximum age (in seconds) for snapshots.

    Outputs:
        StatsSQLiteStore instance used to save and load snapshots.

    Example:
        >>> store = StatsSQLiteStore("./var/stats.db")
        >>> collector = StatsCollector()
        >>> collector.record_cache_hit("example.com")
        >>> snap = collector.snapshot()
        >>> store.save_snapshot(snap)
        >>> latest = store.load_latest_snapshot()
        >>> latest.totals["cache_hits"]
        1
    """

    def __init__(
        self,
        db_path: str,
        max_snapshots: Optional[int] = None,
        max_age_seconds: Optional[int] = None,
    ) -> None:
        """Initialize SQLite store and ensure schema exists.

        Inputs:
            db_path: Path to SQLite database file.
            max_snapshots: Optional retention limit by snapshot count.
            max_age_seconds: Optional retention limit by snapshot age.

        Outputs:
            None
        """
        self._db_path = db_path
        self._max_snapshots = max_snapshots
        self._max_age_seconds = max_age_seconds
        self._conn = self._init_connection()

    def _init_connection(self) -> sqlite3.Connection:
        """Create SQLite connection and ensure schema.

        Inputs:
            None

        Outputs:
            sqlite3.Connection instance with schema initialized.
        """
        dir_path = os.path.dirname(self._db_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        conn = sqlite3.connect(self._db_path)
        try:
            # Best-effort journaling tweaks; errors are non-fatal.
            conn.execute("PRAGMA journal_mode=WAL")
        except Exception:  # pragma: no cover - environment specific
            pass

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS stats_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                data_json TEXT NOT NULL
            )
            """
        )
        conn.commit()
        return conn

    def save_snapshot(self, snapshot: StatsSnapshot) -> None:
        """Persist a snapshot to SQLite as a JSON blob.

        Inputs:
            snapshot: StatsSnapshot instance to save.

        Outputs:
            None
        """
        try:
            data = self._snapshot_to_dict(snapshot)
            payload = json.dumps(data, separators=(",", ":"))
            with self._conn:  # type: ignore[attr-defined]
                self._conn.execute(  # type: ignore[attr-defined]
                    "INSERT INTO stats_snapshots (created_at, data_json) VALUES (?, ?)",
                    (snapshot.created_at, payload),
                )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("StatsSQLiteStore save_snapshot error: %s", exc, exc_info=True)

    def load_latest_snapshot(self) -> Optional[StatsSnapshot]:
        """Load the most recent snapshot from SQLite, if any.

        Inputs:
            None

        Outputs:
            Latest StatsSnapshot or None when no snapshots exist or on error.
        """
        try:
            cur = self._conn.cursor()  # type: ignore[attr-defined]
            cur.execute(
                "SELECT created_at, data_json FROM stats_snapshots ORDER BY id DESC LIMIT 1"
            )
            row = cur.fetchone()
            if not row:
                return None
            created_at, data_json = row
            data = json.loads(data_json)
            return self._dict_to_snapshot(data, float(created_at))
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "StatsSQLiteStore load_latest_snapshot error: %s", exc, exc_info=True
            )
            return None

    def close(self) -> None:
        """Close the underlying SQLite connection.

        Inputs:
            None

        Outputs:
            None
        """
        try:
            conn = getattr(self, "_conn", None)
            if conn is not None:
                conn.close()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Error while closing StatsSQLiteStore connection")

    @staticmethod
    def _snapshot_to_dict(snapshot: StatsSnapshot) -> Dict[str, Any]:
        """Convert StatsSnapshot to JSON-serializable dictionary.

        Inputs:
            snapshot: StatsSnapshot instance.

        Outputs:
            Dict[str, Any] suitable for json.dumps.
        """
        return {
            "created_at": snapshot.created_at,
            "totals": snapshot.totals,
            "rcodes": snapshot.rcodes,
            "qtypes": snapshot.qtypes,
            "decisions": snapshot.decisions,
            "upstreams": snapshot.upstreams,
            "uniques": snapshot.uniques,
            "top_clients": snapshot.top_clients,
            "top_subdomains": snapshot.top_subdomains,
            "top_domains": snapshot.top_domains,
            "latency_stats": snapshot.latency_stats,
            "latency_recent_stats": snapshot.latency_recent_stats,
        }

    @staticmethod
    def _dict_to_snapshot(data: Dict[str, Any], created_at: float) -> StatsSnapshot:
        """Rebuild StatsSnapshot from dictionary payload.

        Inputs:
            data: Mapping produced by _snapshot_to_dict.
            created_at: Snapshot creation timestamp.

        Outputs:
            StatsSnapshot instance.
        """
        return StatsSnapshot(
            created_at=created_at,
            totals=data.get("totals", {}) or {},
            rcodes=data.get("rcodes", {}) or {},
            qtypes=data.get("qtypes", {}) or {},
            decisions=data.get("decisions", {}) or {},
            upstreams=data.get("upstreams", {}) or {},
            uniques=data.get("uniques"),
            top_clients=data.get("top_clients"),
            top_subdomains=data.get("top_subdomains"),
            top_domains=data.get("top_domains"),
            latency_stats=data.get("latency_stats"),
            latency_recent_stats=data.get("latency_recent_stats"),
        )


class StatsCollector:
    """
    Thread-safe statistics aggregator for DNS server metrics.

    Inputs (constructor):
        track_uniques: Enable unique client/domain tracking (default True)
        include_qtype_breakdown: Track query type distribution (default True)
        include_top_clients: Track top clients by request count (default False)
        include_top_domains: Track top domains by request count (default False)
        top_n: Number of top items to track (default 10)
        track_latency: Enable latency histogram (default False)

    Outputs:
        StatsCollector instance for recording events and taking snapshots

    All public methods are thread-safe via a single RLock. Critical sections
    are kept minimal (O(1) operations only). The snapshot() method creates a
    deep copy for safe logging without holding the lock.

    Example:
        >>> collector = StatsCollector(track_uniques=True, track_latency=True)
        >>> collector.record_query("192.0.2.1", "example.com", "A")
        >>> collector.record_cache_hit("example.com")
        >>> collector.record_response_rcode("NOERROR")
        >>> snapshot = collector.snapshot(reset=False)
        >>> snapshot.totals['total_queries']
        1
    """

    def __init__(
        self,
        track_uniques: bool = True,
        include_qtype_breakdown: bool = True,
        include_top_clients: bool = False,
        include_top_domains: bool = False,
        top_n: int = 10,
        track_latency: bool = False,
    ) -> None:
        """
        Initialize statistics collector with configuration flags.

        Inputs:
            track_uniques: Enable unique client/domain tracking
            include_qtype_breakdown: Track qtype distribution
            include_top_clients: Enable top-N client tracking
            include_top_domains: Enable top-N domain tracking
            top_n: Size of top-N lists
            track_latency: Enable latency histogram

        Outputs:
            None
        """
        self._lock = threading.RLock()

        # Config flags
        self.track_uniques = track_uniques
        self.include_qtype_breakdown = include_qtype_breakdown
        self.include_top_clients = include_top_clients
        self.include_top_domains = include_top_domains
        self.top_n = max(1, top_n)
        self.track_latency = track_latency

        # Core counters
        self._totals: Dict[str, int] = defaultdict(int)
        self._rcodes: Dict[str, int] = defaultdict(int)
        self._qtypes: Dict[str, int] = defaultdict(int)

        # Plugin decisions: plugin_name -> {action -> count}
        self._plugin_decisions: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )

        # Reasons: plugin_name -> {reason -> count}
        self._allowed_by: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._blocked_by: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )

        # Upstream results: upstream_id -> {outcome -> count}
        self._upstreams: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )

        # Optional: unique tracking
        self._unique_clients: Optional[Set[str]] = set() if track_uniques else None
        self._unique_domains: Optional[Set[str]] = set() if track_uniques else None

        # Optional: top-K trackers
        self._top_clients: Optional[TopK] = (
            TopK(capacity=top_n) if include_top_clients else None
        )
        # Track both subdomains (full qname) and base domains (last two labels)
        self._top_subdomains: Optional[TopK] = (
            TopK(capacity=top_n) if include_top_domains else None
        )
        self._top_domains: Optional[TopK] = (
            TopK(capacity=top_n) if include_top_domains else None
        )

        # Optional: latency histogram
        self._latency: Optional[LatencyHistogram] = (
            LatencyHistogram() if track_latency else None
        )
        self._latency_recent: Optional[LatencyHistogram] = (
            LatencyHistogram() if track_latency else None
        )

    def record_query(self, client_ip: str, qname: str, qtype: str) -> None:
        """
        Record an incoming DNS query.

        Inputs:
            client_ip: Client IP address
            qname: Query domain name
            qtype: Query type (e.g., "A", "AAAA", "CNAME")

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_query("192.0.2.1", "example.com", "A")
        """
        domain = _normalize_domain(qname)

        with self._lock:
            self._totals["total_queries"] += 1

            if self.include_qtype_breakdown:
                self._qtypes[qtype] += 1

            if self._unique_clients is not None:
                self._unique_clients.add(client_ip)

            if self._unique_domains is not None:
                self._unique_domains.add(domain)

            if self._top_clients is not None:
                self._top_clients.add(client_ip)

            if self._top_subdomains is not None:
                self._top_subdomains.add(domain)

            if self._top_domains is not None:
                # Aggregate by base domain (last two labels)
                parts = domain.split(".")
                base = ".".join(parts[-2:]) if len(parts) >= 2 else domain
                self._top_domains.add(base)

    def record_cache_hit(self, qname: str) -> None:
        """
        Record a cache hit.

        Inputs:
            qname: Query domain name

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_cache_hit("example.com")
        """
        with self._lock:
            self._totals["cache_hits"] += 1

    def record_cache_miss(self, qname: str) -> None:
        """
        Record a cache miss.

        Inputs:
            qname: Query domain name

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_cache_miss("example.com")
        """
        with self._lock:
            self._totals["cache_misses"] += 1

    def record_plugin_decision(
        self,
        plugin_name: str,
        action: str,
        reason: Optional[str] = None,
        domain: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> None:
        """
        Record a plugin decision (allow, block, modify, pass).

        Inputs:
            plugin_name: Name of the plugin making the decision
            action: Decision action ("allow", "block", "modify", "pass")
            reason: Optional reason code or description
            domain: Optional domain name affected
            client_ip: Optional client IP

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_plugin_decision(
            ...     "FilterPlugin", "block", reason="blocklist_match", domain="bad.com"
            ... )
        """
        with self._lock:
            self._plugin_decisions[plugin_name][action] += 1

            if action == "allow":
                self._totals["allowed"] += 1
                if reason:
                    self._allowed_by[plugin_name][reason] += 1
            elif action == "block":
                self._totals["blocked"] += 1
                if reason:
                    self._blocked_by[plugin_name][reason] += 1
            elif action == "modify":
                self._totals["modified"] += 1

    def record_upstream_result(
        self,
        upstream_id: str,
        outcome: str,
        bytes_out: Optional[int] = None,
        bytes_in: Optional[int] = None,
    ) -> None:
        """
        Record upstream resolution outcome.

        Inputs:
            upstream_id: Upstream identifier (e.g., "8.8.8.8:53")
            outcome: Outcome classification ("success", "timeout", "error")
            bytes_out: Optional bytes sent to upstream
            bytes_in: Optional bytes received from upstream

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_upstream_result("8.8.8.8:53", "success")
            >>> collector.record_upstream_result("1.1.1.1:53", "timeout")
        """
        with self._lock:
            self._upstreams[upstream_id][outcome] += 1

    def record_response_rcode(self, rcode: str) -> None:
        """
        Record DNS response code.

        Inputs:
            rcode: Response code ("NOERROR", "NXDOMAIN", "SERVFAIL", etc.)

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_response_rcode("NOERROR")
            >>> collector.record_response_rcode("NXDOMAIN")
        """
        with self._lock:
            self._rcodes[rcode] += 1

    def record_latency(self, seconds: float) -> None:
        """
        Record request latency.

        Inputs:
            seconds: Latency duration in seconds

        Outputs:
            None

        Example:
            >>> collector = StatsCollector(track_latency=True)
            >>> collector.record_latency(0.0042)  # 4.2ms
        """
        if self._latency is not None:
            with self._lock:
                self._latency.add(seconds)
                if self._latency_recent is not None:
                    self._latency_recent.add(seconds)

    def snapshot(self, reset: bool = False) -> StatsSnapshot:
        """
        Create immutable snapshot of current statistics.

        Inputs:
            reset: If True, reset all counters after snapshot (default False)

        Outputs:
            StatsSnapshot with deep copies of all statistics

        When reset=True, all counters are zeroed for interval-based reporting.
        The snapshot is created under lock but can be formatted outside the lock.

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_query("1.2.3.4", "example.com", "A")
            >>> snap = collector.snapshot(reset=False)
            >>> snap.totals['total_queries']
            1
        """
        with self._lock:
            # Copy all data structures
            totals = dict(self._totals)
            rcodes = dict(self._rcodes)
            qtypes = dict(self._qtypes)

            # Deep copy nested plugin decisions
            decisions = {}
            for plugin, actions in self._plugin_decisions.items():
                decisions[plugin] = dict(actions)
                if plugin in self._allowed_by:
                    decisions[plugin]["allowed_by"] = dict(self._allowed_by[plugin])
                if plugin in self._blocked_by:
                    decisions[plugin]["blocked_by"] = dict(self._blocked_by[plugin])

            # Deep copy upstream results
            upstreams = {}
            for upstream_id, outcomes in self._upstreams.items():
                upstreams[upstream_id] = dict(outcomes)

            # Unique counts
            uniques = None
            if self._unique_clients is not None and self._unique_domains is not None:
                uniques = {
                    "clients": len(self._unique_clients),
                    "domains": len(self._unique_domains),
                }

            # Top lists
            top_clients = None
            if self._top_clients is not None:
                top_clients = self._top_clients.export(self.top_n)

            top_subdomains = None
            if self._top_subdomains is not None:
                top_subdomains = self._top_subdomains.export(self.top_n)

            top_domains = None
            if self._top_domains is not None:
                top_domains = self._top_domains.export(self.top_n)

            # Latency
            latency_stats = None
            if self._latency is not None:
                latency_stats = self._latency.summarize()

            latency_recent_stats = None
            if self._latency_recent is not None:
                latency_recent_stats = self._latency_recent.summarize()

            snapshot = StatsSnapshot(
                created_at=time.time(),
                totals=totals,
                rcodes=rcodes,
                qtypes=qtypes,
                decisions=decisions,
                upstreams=upstreams,
                uniques=uniques,
                top_clients=top_clients,
                top_subdomains=top_subdomains,
                top_domains=top_domains,
                latency_stats=latency_stats,
                latency_recent_stats=latency_recent_stats,
            )

            # Reset if requested
            if reset:
                self._totals.clear()
                self._rcodes.clear()
                self._qtypes.clear()
                self._plugin_decisions.clear()
                self._allowed_by.clear()
                self._blocked_by.clear()
                self._upstreams.clear()

                if self._unique_clients is not None:
                    self._unique_clients.clear()
                if self._unique_domains is not None:
                    self._unique_domains.clear()

                if self._top_clients is not None:
                    self._top_clients.counts.clear()
                if self._top_subdomains is not None:
                    self._top_subdomains.counts.clear()
                if self._top_domains is not None:
                    self._top_domains.counts.clear()

                if self._latency is not None:
                    self._latency = LatencyHistogram()
                if self._latency_recent is not None:
                    self._latency_recent = LatencyHistogram()

            return snapshot

    def load_from_snapshot(self, snapshot: StatsSnapshot) -> None:
        """Initialize in-memory counters from a prior snapshot.

        Inputs:
            snapshot: StatsSnapshot previously produced by this collector.

        Outputs:
            None

        Notes:
            - Restores core aggregates (totals, rcodes, qtypes, decisions, upstreams).
            - Does not attempt to recreate uniqueness sets, top-K trackers, or
              latency histograms; those remain process-local for the current run.
        """
        with self._lock:
            # Core counters
            self._totals.clear()
            self._totals.update(snapshot.totals or {})

            self._rcodes.clear()
            self._rcodes.update(snapshot.rcodes or {})

            self._qtypes.clear()
            self._qtypes.update(snapshot.qtypes or {})

            # Plugin decisions and reasons
            self._plugin_decisions.clear()
            self._allowed_by.clear()
            self._blocked_by.clear()

            for plugin, actions in (snapshot.decisions or {}).items():
                # Separate action counters from allowed_by/blocked_by mappings
                action_counts: Dict[str, int] = {}
                allowed_by = (
                    actions.get("allowed_by") if isinstance(actions, dict) else None
                )
                blocked_by = (
                    actions.get("blocked_by") if isinstance(actions, dict) else None
                )

                if isinstance(actions, dict):
                    for key, value in actions.items():
                        if key in {"allowed_by", "blocked_by"}:
                            continue
                        try:
                            action_counts[key] = int(value)
                        except (TypeError, ValueError):
                            continue

                self._plugin_decisions[plugin] = defaultdict(int, action_counts)

                if isinstance(allowed_by, dict):
                    self._allowed_by[plugin] = defaultdict(int, allowed_by)
                if isinstance(blocked_by, dict):
                    self._blocked_by[plugin] = defaultdict(int, blocked_by)

            # Upstreams
            self._upstreams.clear()
            for upstream_id, outcomes in (snapshot.upstreams or {}).items():
                if isinstance(outcomes, dict):
                    self._upstreams[upstream_id] = defaultdict(int, outcomes)

    def reset_latency_recent(self) -> None:
        """
        Reset only the recent latency window.

        Inputs:
            None

        Outputs:
            None

        Example:
            >>> collector = StatsCollector(track_latency=True)
            >>> collector.record_latency(0.005)
            >>> snapshot1 = collector.snapshot()
            >>> collector.reset_latency_recent()
            >>> snapshot2 = collector.snapshot()
            >>> snapshot2.latency_recent_stats['count']
            0
        """
        with self._lock:
            if self._latency_recent is not None:
                self._latency_recent = LatencyHistogram()


def format_snapshot_json(snapshot: StatsSnapshot) -> str:
    """
    Format statistics snapshot as single-line JSON.

    Inputs:
        snapshot: StatsSnapshot to serialize

    Outputs:
        JSON string (single line, no trailing newline)

    The output is a compact JSON object suitable for structured logging.
    Empty sections are omitted to minimize log size.

    Example:
        >>> collector = StatsCollector()
        >>> collector.record_query("1.2.3.4", "example.com", "A")
        >>> snap = collector.snapshot()
        >>> json_str = format_snapshot_json(snap)
        >>> "total_queries" in json_str
        True
    """
    ts = datetime.fromtimestamp(snapshot.created_at, tz=timezone.utc).isoformat()

    output: Dict = {
        "ts": ts,
        "totals": snapshot.totals,
    }

    if snapshot.uniques:
        output["uniques"] = snapshot.uniques

    if snapshot.rcodes:
        output["rcodes"] = snapshot.rcodes

    if snapshot.qtypes:
        output["qtypes"] = snapshot.qtypes

    if snapshot.decisions:
        output["plugins"] = snapshot.decisions

    if snapshot.upstreams:
        output["upstreams"] = snapshot.upstreams

    if snapshot.top_clients:
        output["top_clients"] = [
            {"client": c, "count": n} for c, n in snapshot.top_clients
        ]

    if snapshot.top_subdomains:
        output["top_subdomains"] = [
            {"domain": d, "count": n} for d, n in snapshot.top_subdomains
        ]

    if snapshot.top_domains:
        output["top_domains"] = [
            {"domain": d, "count": n} for d, n in snapshot.top_domains
        ]

    if snapshot.latency_stats:
        output["latency"] = snapshot.latency_stats

    if snapshot.latency_recent_stats:
        output["latency_recent"] = snapshot.latency_recent_stats

    return json.dumps(output, separators=(",", ":"))


class StatsReporter(threading.Thread):
    """
    Background daemon thread for periodic statistics logging.

    Inputs (constructor):
        collector: StatsCollector instance to snapshot
        interval_seconds: Seconds between log emissions (default 10)
        reset_on_log: Reset counters after each log (default False)
        log_level: Logging level name ("debug", "info", "warning", "error")
        logger_name: Logger name to use (default "foghorn.stats")

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
        """
        Initialize statistics reporter thread.

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
        """
        Reporter main loop (called by start()).

        Inputs:
            None

        Outputs:
            None

        Sleeps interval_seconds, snapshots stats, formats JSON, and logs.
        Exits when stop() is called.
        """
        while not self._stop_event.wait(self.interval_seconds):
            try:
                snapshot = self.collector.snapshot(reset=self.reset_on_log)
                json_line = format_snapshot_json(snapshot)
                self.logger.log(self.log_level, json_line)

                # Optionally persist snapshot to SQLite
                if self.persistence_store is not None:
                    try:
                        self.persistence_store.save_snapshot(snapshot)
                    except Exception as exc:  # pragma: no cover - defensive
                        self.logger.error(
                            "StatsReporter persistence error: %s", exc, exc_info=True
                        )

                # Always reset recent latency window after emission
                self.collector.reset_latency_recent()
            except Exception as e:  # pragma: no cover
                self.logger.error("StatsReporter error: %s", e, exc_info=True)

    def stop(self, timeout: float = 5.0) -> None:
        """
        Signal reporter to stop and wait for thread to exit.

        Inputs:
            timeout: Maximum seconds to wait for thread join (default 5.0)

        Outputs:
            None

        Example:
            >>> reporter.stop()
        """
        self._stop_event.set()
        self.join(timeout=timeout)
