from __future__ import annotations

import ipaddress
import logging
import math
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Set

from foghorn.plugins.querylog import BaseStatsStore
from foghorn.utils.register_caches import registered_lru_cache
from foghorn.utils import ip_networks

from ..domain import _normalize_domain
from ..histogram import LatencyHistogram
from ..topk import TOPK_CAPACITY_FACTOR, TOPK_MIN_CAPACITY, TopK

logger = logging.getLogger("foghorn.stats")
DEFAULT_MAX_UNIQUE_CLIENTS = 50000
DEFAULT_MAX_UNIQUE_DOMAINS = 50000


@registered_lru_cache(maxsize=4096)
def _parse_client_ip_for_ignore(
    client_ip: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Brief: Parse and cache client IP strings for ignore-filter evaluation.

    Inputs:
      - client_ip: Client IP string.

    Outputs:
      - ipaddress.IPv4Address | ipaddress.IPv6Address: Parsed address object.

    Notes:
      - This is used on the query-recording hot path when ignore_top_clients is
        configured, so caching avoids repeated ipaddress parsing for common
        client IPs.
    """
    parsed = ip_networks.parse_ip(client_ip)
    if parsed is None:
        raise ValueError(f"invalid client ip {client_ip!r}")
    return parsed


class _StatsCollectorInitUtils:
    def __init__(
        self,
        track_uniques: bool = True,
        include_qtype_breakdown: bool = True,
        include_top_clients: bool = False,
        include_top_domains: bool = False,
        top_n: int = 10,
        track_latency: bool = False,
        stats_store: Optional[BaseStatsStore] = None,
        ignore_top_clients: Optional[List[str]] = None,
        ignore_top_domains: Optional[List[str]] = None,
        ignore_top_subdomains: Optional[List[str]] = None,
        ignore_domains_as_suffix: bool = False,
        ignore_subdomains_as_suffix: bool = False,
        ignore_single_host: bool = False,
        include_ignored_in_stats: bool = True,
        logging_only: bool = False,
        query_log_only: bool = False,
        query_log_sample_rate: float = 1.0,
        query_log_dedupe_window_seconds: float = 0.0,
        query_log_dedupe_max_entries: int = 50000,
        max_unique_clients: int = DEFAULT_MAX_UNIQUE_CLIENTS,
        max_unique_domains: int = DEFAULT_MAX_UNIQUE_DOMAINS,
    ) -> None:
        """Initialize statistics collector with configuration flags.

        Inputs:
            track_uniques: Enable unique client/domain tracking
            include_qtype_breakdown: Track qtype distribution
            include_top_clients: Enable top-N client tracking
            include_top_domains: Enable top-N domain tracking
            top_n: Size of top-N lists
            track_latency: Enable latency histogram
            stats_store: Optional SQLite-backed persistence store
            ignore_top_clients: Optional list of client IPs/CIDRs to hide from top_clients
            ignore_top_domains: Optional list of base domains to hide from top_domains
            ignore_top_subdomains: Optional list of full qnames to hide from top_subdomains
            ignore_domains_as_suffix: When True, treat ignore_top_domains entries
                as suffixes for matching both top_domains and (when used as
                fallback) top_subdomains.
            ignore_subdomains_as_suffix: When True, treat ignore_top_subdomains
                entries (or the fallback domain set) as suffixes when matching
                top_subdomains.
            include_ignored_in_stats: When True (default), ignore filters only
                affect display/exported top lists. When False, entries matching
                ignore filters are excluded from aggregation (totals/uniques/topk)
                but are still written to the persistent query_log.
            logging_only: When True, skip background warm-load operations from
                the persistent store so that only insert-style operations
                (query_log appends and counter increments) are performed against
                the attached stats_store.
            query_log_only: When True, only the raw query_log is written to the
                persistent store; aggregate counters are kept in-memory only and
                are not mirrored into the counts table.
            query_log_sample_rate: Fraction of query-log rows to persist from
                record_query_result calls. 1.0 logs all rows, 0.5 logs
                approximately every other row, and 0 disables query-log writes.
            query_log_dedupe_window_seconds: Optional dedupe window. When > 0,
                repeated query-log rows with the same key fields inside this
                window are suppressed.
            query_log_dedupe_max_entries: Maximum dedupe-key entries retained
                in memory for query-log suppression.
            max_unique_clients: Maximum number of unique client IP values
                retained in memory when unique tracking is enabled.
            max_unique_domains: Maximum number of unique domain values retained
                in memory when unique tracking is enabled.

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
        # Display-only flag for hiding single-label hosts from top lists
        self.ignore_single_host = bool(ignore_single_host)

        # Control whether ignore filters exclude entries from aggregation.
        self.include_ignored_in_stats = bool(include_ignored_in_stats)
        # Logging-only mode controls whether background warm-loads use the
        # attached persistent store. Insert-style operations remain enabled.
        self.logging_only = bool(logging_only)
        # When query_log_only is true, only query_log appends are written to
        # the persistent store; aggregate counters remain in-memory only.
        self.query_log_only = bool(query_log_only)
        self.query_log_sample_rate = self._normalize_query_log_sample_rate(
            query_log_sample_rate
        )
        self._query_log_sample_every_n = self._sample_every_n_from_rate(
            self.query_log_sample_rate
        )
        self._query_log_sample_seen = 0
        self._query_log_dedupe_window_seconds = (
            self._normalize_query_log_dedupe_window_seconds(
                query_log_dedupe_window_seconds
            )
        )
        self._query_log_dedupe_max_entries = (
            self._normalize_query_log_dedupe_max_entries(query_log_dedupe_max_entries)
        )
        self._query_log_recent_seen: Dict[str, float] = {}
        self._query_log_dedupe_seen = 0
        try:
            parsed_max_unique_clients = int(max_unique_clients)
        except (TypeError, ValueError):
            parsed_max_unique_clients = DEFAULT_MAX_UNIQUE_CLIENTS
        try:
            parsed_max_unique_domains = int(max_unique_domains)
        except (TypeError, ValueError):
            parsed_max_unique_domains = DEFAULT_MAX_UNIQUE_DOMAINS
        self.max_unique_clients = max(0, parsed_max_unique_clients)
        self.max_unique_domains = max(0, parsed_max_unique_domains)

        # Optional persistent store for long-lived aggregates and query logs.
        # This can be any BaseStatsStore implementation, including
        # MultiStatsStore, which fans writes out to multiple concrete
        # backends (for example, SQLite plus an MQTT logging sink).
        self._store: Optional[BaseStatsStore] = stats_store

        # Core counters
        self._totals: Dict[str, int] = defaultdict(int)
        self._rcodes: Dict[str, int] = defaultdict(int)
        self._qtypes: Dict[str, int] = defaultdict(int)

        # Plugin decisions: plugin_name -> {action -> count}
        self._plugin_decisions = defaultdict(lambda: defaultdict(int))

        # Reasons: plugin_name -> {reason -> count}
        self._allowed_by = defaultdict(lambda: defaultdict(int))
        self._blocked_by = defaultdict(lambda: defaultdict(int))

        # Upstream results: upstream_id -> {outcome -> count}
        self._upstreams = defaultdict(lambda: defaultdict(int))

        # Upstream response codes: upstream_id -> {rcode -> count}
        self._upstream_rcodes = defaultdict(lambda: defaultdict(int))

        # Upstream query types: upstream_id -> {qtype -> count}
        self._upstream_qtypes = defaultdict(lambda: defaultdict(int))

        # Optional: unique tracking
        self._unique_clients = set() if track_uniques else None
        self._unique_domains = set() if track_uniques else None
        self._unique_clients_dropped = 0
        self._unique_domains_dropped = 0
        self._unique_clients_limit_warned = False
        self._unique_domains_limit_warned = False

        # Optional: top-K trackers. Use a larger internal capacity so that
        # display-only filters and downstream consumers (such as prefetching
        # logic) can work with deeper top lists than the default display size.
        # By default we keep up to max(top_n * TOPK_CAPACITY_FACTOR, TOPK_MIN_CAPACITY)
        # entries in memory.
        internal_capacity = max(TOPK_MIN_CAPACITY, self.top_n * TOPK_CAPACITY_FACTOR)
        self._top_capacity = internal_capacity

        self._top_clients = (
            TopK(capacity=internal_capacity) if include_top_clients else None
        )
        # Track both subdomains (full qname) and base domains (last two labels)
        self._top_subdomains = (
            TopK(capacity=internal_capacity) if include_top_domains else None
        )
        self._top_domains = (
            TopK(capacity=internal_capacity) if include_top_domains else None
        )

        # Per-qtype top domains (full qnames).
        self._top_qtype_qnames: Dict[str, TopK] = {}

        # Top base domains split by cache outcome.
        self._top_cache_hit_domains = (
            TopK(capacity=internal_capacity) if include_top_domains else None
        )
        self._top_cache_miss_domains = (
            TopK(capacity=internal_capacity) if include_top_domains else None
        )
        # Top base domains where cache hits/misses were produced by subdomain queries only.
        self._top_cache_hit_subdomains = (
            TopK(capacity=internal_capacity) if include_top_domains else None
        )
        self._top_cache_miss_subdomains = (
            TopK(capacity=internal_capacity) if include_top_domains else None
        )

        # Per-rcode top base domains
        self._top_rcode_domains: Dict[str, TopK] = {}
        # Per-rcode top base domains where only subdomain queries are counted.
        self._top_rcode_subdomains: Dict[str, TopK] = {}

        # Optional: latency histogram
        self._latency = LatencyHistogram() if track_latency else None
        self._latency_recent = LatencyHistogram() if track_latency else None

        # Ignore filters.
        self._ignore_top_client_networks: List[ipaddress._BaseNetwork] = []
        self._ignore_top_domains: Set[str] = set()
        self._ignore_top_subdomains: Set[str] = set()
        self._ignore_domains_as_suffix = bool(ignore_domains_as_suffix)
        self._ignore_subdomains_as_suffix = bool(ignore_subdomains_as_suffix)

        self.set_ignore_filters(
            ignore_top_clients or [],
            ignore_top_domains or [],
            ignore_top_subdomains or [],
        )

    def _track_unique_client_locked(self, client_ip: str) -> None:
        """Brief: Add a unique client IP while enforcing a maximum set size.

        Inputs:
          - client_ip: Client IP value to track.

        Outputs:
          - None. Updates in-memory unique-client tracking state.
        """
        if self._unique_clients is None:
            return
        value = str(client_ip or "")
        if not value:
            return
        if value in self._unique_clients:
            return
        if len(self._unique_clients) >= self.max_unique_clients:
            self._unique_clients_dropped += 1
            if not self._unique_clients_limit_warned:
                logger.warning(
                    "StatsCollector unique client tracking reached max_unique_clients=%d; "
                    "new unseen client values will be dropped",
                    self.max_unique_clients,
                )
                self._unique_clients_limit_warned = True
            return
        self._unique_clients.add(value)

    def _track_unique_domain_locked(self, domain: str) -> None:
        """Brief: Add a unique domain while enforcing a maximum set size.

        Inputs:
          - domain: Normalized domain value to track.

        Outputs:
          - None. Updates in-memory unique-domain tracking state.
        """
        if self._unique_domains is None:
            return
        value = str(domain or "")
        if not value:
            return
        if value in self._unique_domains:
            return
        if len(self._unique_domains) >= self.max_unique_domains:
            self._unique_domains_dropped += 1
            if not self._unique_domains_limit_warned:
                logger.warning(
                    "StatsCollector unique domain tracking reached max_unique_domains=%d; "
                    "new unseen domain values will be dropped",
                    self.max_unique_domains,
                )
                self._unique_domains_limit_warned = True
            return
        self._unique_domains.add(value)

    def _client_is_ignored_locked(self, client_ip: str) -> bool:
        """Brief: Return True if the client IP matches ignore_top_clients.

        Inputs:
          - client_ip: Client IP string.

        Outputs:
          - bool
        """

        if not client_ip or not self._ignore_top_client_networks:
            return False
        try:
            addr = _parse_client_ip_for_ignore(str(client_ip))
        except Exception:
            return False
        return any(addr in net for net in self._ignore_top_client_networks)

    def _base_domain_is_ignored_locked(self, base_domain: str) -> bool:
        """Brief: Return True if base domain matches ignore_top_domains.

        Inputs:
          - base_domain: Normalized base domain (typically last two labels).

        Outputs:
          - bool
        """

        norm = _normalize_domain(str(base_domain or ""))
        if not norm or not self._ignore_top_domains:
            return False
        if self._ignore_domains_as_suffix:
            return any(
                norm == ig or norm.endswith("." + ig) for ig in self._ignore_top_domains
            )
        return norm in self._ignore_top_domains

    def _qname_is_ignored_locked(self, qname: str) -> bool:
        """Brief: Return True if full qname matches ignore_top_subdomains.

        Inputs:
          - qname: Normalized qname.

        Outputs:
          - bool
        """

        norm = _normalize_domain(str(qname or ""))
        if not norm:
            return False

        active: Set[str]
        if self._ignore_top_subdomains:
            active = self._ignore_top_subdomains
        else:
            # Fallback to domain ignore set when subdomain ignore set is empty.
            active = self._ignore_top_domains

        if not active:
            return False

        if self._ignore_subdomains_as_suffix:
            return any(norm == ig or norm.endswith("." + ig) for ig in active)
        return norm in active

    def _should_ignore_query_locked(
        self, client_ip: str, domain: str, base: str
    ) -> bool:
        """Brief: Return True if a query should be excluded from aggregation.

        Inputs:
          - client_ip: Client IP string.
          - domain: Normalized qname.
          - base: Normalized base domain.

        Outputs:
          - bool
        """

        if self._client_is_ignored_locked(client_ip):
            return True
        if base and self._base_domain_is_ignored_locked(base):
            return True
        if domain and self._qname_is_ignored_locked(domain):
            return True
        return False

    def set_ignore_filters(
        self,
        clients: Optional[List[str]] = None,
        domains: Optional[List[str]] = None,
        subdomains: Optional[List[str]] = None,
        domains_as_suffix: Optional[bool] = None,
        subdomains_as_suffix: Optional[bool] = None,
    ) -> None:
        """Update ignore filters for statistics aggregation.

        Inputs:
            clients: Optional list of client IPs or CIDR strings to hide from
                ``top_clients`` (IPv4 and IPv6 supported). When None or empty,
                the client ignore list is cleared.
            domains: Optional list of base domains to hide from
                ``top_domains`` (exact or suffix match after normalization,
                depending on domains_as_suffix). When None or empty, the domain
                ignore list is cleared.
            subdomains: Optional list of full qnames to hide from
                ``top_subdomains`` (exact or suffix match after
                normalization, depending on subdomains_as_suffix). When None or
                empty, the subdomain ignore list is cleared. When the resulting
                ignore set is empty, the domain ignore set is used as a fallback
                for subdomain filtering.
            domains_as_suffix: Optional flag controlling whether domain
                ignores use suffix semantics. When True, a top_domains entry
                is suppressed if its normalized name equals an ignore entry
                or ends with "." + ignore entry. When None, the existing
                setting is preserved.
            subdomains_as_suffix: Optional flag controlling whether
                subdomain ignores use suffix semantics. When True, a
                top_subdomains entry is suppressed if its normalized name
                equals an ignore entry or ends with "." + ignore entry.
                When None, the existing setting is preserved.

        Outputs:
            None (updates internal ignore sets used during aggregation in
            record_query/record_cache_* and when exporting snapshots).

        Example:
            >>> collector = StatsCollector(include_top_clients=True)
            >>> collector.set_ignore_filters(
            ...     ['10.0.0.0/8'],
            ...     ['example.com'],
            ...     ['www.example.com'],
            ...     domains_as_suffix=True,
            ... )
            >>> snap = collector.snapshot(reset=False)
            >>> # Matching entries will not be counted in totals/top lists,
            >>> # but queries are still written to the persistent query_log.
        """
        clients = clients or []
        domains = domains or []
        subdomains = subdomains or []

        client_networks: List[ipaddress._BaseNetwork] = []
        for idx, entry in enumerate(clients):
            if not entry:
                continue
            net = ip_networks.parse_network(entry, strict=False)
            if net is None:  # pragma: no cover
                logger.debug(
                    "StatsCollector: invalid ignore client entry at index %d",
                    idx,
                )
                continue
            client_networks.append(net)

        domain_set: Set[str] = set()
        for raw in domains:
            if not raw:
                continue
            domain_set.add(_normalize_domain(str(raw)))

        subdomain_set: Set[str] = set()
        for raw in subdomains:
            if not raw:
                continue
            subdomain_set.add(_normalize_domain(str(raw)))

        with self._lock:
            self._ignore_top_client_networks = client_networks
            self._ignore_top_domains = domain_set
            self._ignore_top_subdomains = subdomain_set
            if domains_as_suffix is not None:
                self._ignore_domains_as_suffix = bool(domains_as_suffix)
            if subdomains_as_suffix is not None:
                self._ignore_subdomains_as_suffix = bool(subdomains_as_suffix)

    @staticmethod
    def _normalize_query_log_sample_rate(raw: object) -> float:
        """Brief: Normalize query-log sample-rate configuration.

        Inputs:
          - raw: Raw configured sample-rate value.

        Outputs:
          - float: Clamped finite value in [0.0, 1.0].
        """

        try:
            value = float(raw)  # type: ignore[arg-type]
        except Exception:
            return 1.0
        if not math.isfinite(value):
            return 1.0
        if value <= 0.0:
            return 0.0
        if value >= 1.0:
            return 1.0
        return float(value)

    @staticmethod
    def _sample_every_n_from_rate(rate: float) -> int:
        """Brief: Convert sample-rate into a deterministic keep-every-N cadence.

        Inputs:
          - rate: Normalized sample rate in [0.0, 1.0].

        Outputs:
          - int: 0 to disable logging, 1 to keep every row, or N>1 to keep
            every Nth row.
        """

        value = float(rate)
        if value <= 0.0:
            return 0
        if value >= 1.0:
            return 1
        return max(2, int(round(1.0 / value)))

    @staticmethod
    def _normalize_query_log_dedupe_window_seconds(raw: object) -> float:
        """Brief: Normalize query-log dedupe window configuration.

        Inputs:
          - raw: Raw configured dedupe window in seconds.

        Outputs:
          - float: Non-negative finite seconds value.
        """

        try:
            value = float(raw)  # type: ignore[arg-type]
        except Exception:
            return 0.0
        if not math.isfinite(value) or value <= 0.0:
            return 0.0
        return float(value)

    @staticmethod
    def _normalize_query_log_dedupe_max_entries(raw: object) -> int:
        """Brief: Normalize query-log dedupe cache size configuration.

        Inputs:
          - raw: Raw configured maximum number of dedupe entries.

        Outputs:
          - int: Positive maximum entries value.
        """

        try:
            value = int(raw)  # type: ignore[arg-type]
        except Exception:
            return 50000
        if value <= 0:
            return 50000
        return int(value)

    @staticmethod
    def _build_query_log_dedupe_key(
        *,
        client_ip: str,
        qname: str,
        qtype: str,
        upstream_id: Optional[str],
        rcode: Optional[str],
        status: Optional[str],
        error: Optional[str],
        first: Optional[str],
    ) -> str:
        """Brief: Build a stable dedupe key for query-log suppression.

        Inputs:
          - client_ip: Client IP string.
          - qname: Normalized query name.
          - qtype: Query type.
          - upstream_id: Optional upstream identifier.
          - rcode: Optional response code.
          - status: Optional status string.
          - error: Optional error string.
          - first: Optional first-answer string.

        Outputs:
          - str: Composite dedupe key.
        """

        parts = (
            str(client_ip or ""),
            str(qname or ""),
            str(qtype or ""),
            str(upstream_id or ""),
            str(rcode or ""),
            str(status or ""),
            str(error or ""),
            str(first or ""),
        )
        return "\x1f".join(parts)

    def _prune_query_log_dedupe_cache_locked(self, *, now_ts: float) -> None:
        """Brief: Prune stale/overflow dedupe cache entries.

        Inputs:
          - now_ts: Current timestamp used for staleness checks.

        Outputs:
          - None; mutates the internal dedupe cache in place.
        """

        cache = self._query_log_recent_seen
        if not cache:
            return

        window_seconds = float(getattr(self, "_query_log_dedupe_window_seconds", 0.0))
        max_entries = int(getattr(self, "_query_log_dedupe_max_entries", 50000))

        if window_seconds > 0.0:
            cutoff = float(now_ts) - window_seconds
            stale_keys = [k for k, ts_val in cache.items() if float(ts_val) < cutoff]
            for key in stale_keys:
                cache.pop(key, None)

        if len(cache) <= max_entries:
            return

        overflow = len(cache) - max_entries
        oldest = sorted(cache.items(), key=lambda kv: float(kv[1]))[:overflow]
        for key, _ in oldest:
            cache.pop(key, None)

    def _should_persist_query_log_row_locked(
        self,
        *,
        ts: float,
        client_ip: str,
        qname: str,
        qtype: str,
        upstream_id: Optional[str],
        rcode: Optional[str],
        status: Optional[str],
        error: Optional[str],
        first: Optional[str],
    ) -> bool:
        """Brief: Decide whether a query-log row should be persisted.

        Inputs:
          - ts: Query completion timestamp.
          - client_ip: Client IP string.
          - qname: Normalized query name.
          - qtype: Query type.
          - upstream_id: Optional upstream identifier.
          - rcode: Optional response code.
          - status: Optional status string.
          - error: Optional error string.
          - first: Optional first-answer string.

        Outputs:
          - bool: True when this row should be written to the persistent
            query-log store.
        """

        sample_every_n = int(getattr(self, "_query_log_sample_every_n", 1))
        if sample_every_n == 0:
            return False
        self._query_log_sample_seen = (
            int(getattr(self, "_query_log_sample_seen", 0) or 0) + 1
        )
        if sample_every_n > 1 and (self._query_log_sample_seen % sample_every_n) != 1:
            return False

        window_seconds = float(getattr(self, "_query_log_dedupe_window_seconds", 0.0))
        if window_seconds <= 0.0:
            return True

        dedupe_key = self._build_query_log_dedupe_key(
            client_ip=client_ip,
            qname=qname,
            qtype=qtype,
            upstream_id=upstream_id,
            rcode=rcode,
            status=status,
            error=error,
            first=first,
        )
        last_seen = self._query_log_recent_seen.get(dedupe_key)
        ts_f = float(ts)
        if last_seen is not None and (ts_f - float(last_seen)) <= window_seconds:
            return False

        self._query_log_recent_seen[dedupe_key] = ts_f
        self._query_log_dedupe_seen = (
            int(getattr(self, "_query_log_dedupe_seen", 0) or 0) + 1
        )

        prune_due = (self._query_log_dedupe_seen % 128) == 0 or len(
            self._query_log_recent_seen
        ) > int(getattr(self, "_query_log_dedupe_max_entries", 50000))
        if prune_due:
            self._prune_query_log_dedupe_cache_locked(now_ts=ts_f)

        return True
