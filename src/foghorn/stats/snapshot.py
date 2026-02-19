from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class StatsSnapshot:
    """
    Immutable point-in-time snapshot of statistics for logging.

    Inputs (constructor):
        All fields provided by StatsCollector.snapshot().

    Outputs:
        Snapshot instance with read-only view of statistics.

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
    upstream_rcodes: Optional[Dict[str, Dict[str, int]]] = None
    upstream_qtypes: Optional[Dict[str, Dict[str, int]]] = None
    qtype_qnames: Optional[Dict[str, List[Tuple[str, int]]]] = None
    # Mapping of rcode -> list of (base_domain, count) tuples representing the
    # most frequently seen base domains per response code.
    rcode_domains: Optional[Dict[str, List[Tuple[str, int]]]] = None
    # Mapping of rcode -> list of (subdomain, count) tuples representing
    # subdomain names (full qnames) where subdomain queries (qname != base)
    # produced the response code.
    rcode_subdomains: Optional[Dict[str, List[Tuple[str, int]]]] = None
    # Top base domains by cache outcome, derived from cache hit/miss tracking.
    cache_hit_domains: Optional[List[Tuple[str, int]]] = None
    cache_miss_domains: Optional[List[Tuple[str, int]]] = None
    # Top subdomain names (full qnames) where cache hits/misses were produced
    # by subdomain queries only (qname != base).
    cache_hit_subdomains: Optional[List[Tuple[str, int]]] = None
    cache_miss_subdomains: Optional[List[Tuple[str, int]]] = None
    # Optional aggregated view of rate limiting derived from totals and/or
    # persistent counters (for example, cache_stat_rate_limit).
    rate_limit: Optional[Dict[str, Any]] = None
    # Optional DNSSEC status counters (subset of totals where keys start with
    # 'dnssec_'). This is derived from ``totals`` for convenience in APIs and
    # UI rendering; the same keys remain present under ``totals`` for
    # backwards-compatibility.
    dnssec_totals: Optional[Dict[str, int]] = None
    # Optional EDE status counters (subset of totals where keys start with
    # 'ede_'). This mirrors dnssec_totals so that Extended DNS Errors can be
    # surfaced explicitly in snapshot-based APIs without changing the shape of
    # the underlying totals mapping.
    ede_totals: Optional[Dict[str, int]] = None
