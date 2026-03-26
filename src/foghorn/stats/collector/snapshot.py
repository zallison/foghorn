from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from ..domain import _is_subdomain, _normalize_domain
from ..histogram import LatencyHistogram
from ..snapshot import StatsSnapshot

logger = logging.getLogger("foghorn.stats")


class _StatsCollectorSnapshotMixin:
    def snapshot(self, reset: bool = False) -> StatsSnapshot:
        """Create immutable snapshot of current statistics.

        Inputs:
            reset: If True, reset all counters after snapshot (default False)

        Outputs:
            StatsSnapshot with deep copies of all statistics

        When reset=True, all counters are zeroed for interval-based reporting.
        The snapshot is created under lock but can be formatted outside the lock.

        Notes:
            - The ``totals`` mapping in the returned snapshot always contains
              ``cache_deny_pre`` and ``cache_override_pre`` keys. These may be
              zero when no pre-plugin deny/override events have occurred, or
              populated from a warm-loaded SQLite store / rebuild pipeline.

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_query('1.2.3.4', 'example.com', 'A')
            >>> snap = collector.snapshot(reset=False)
            >>> snap.totals['total_queries']
            1
        """
        with self._lock:
            # Copy all data structures
            totals = dict(self._totals)
            # Ensure cache_deny_pre and cache_override_pre are always present
            totals.setdefault("cache_deny_pre", 0)
            totals.setdefault("cache_override_pre", 0)

            # Best-effort: surface async persistence queue pressure + drops.
            store = getattr(self, "_store", None)
            metrics_fn = getattr(store, "get_async_queue_metrics", None)
            if callable(metrics_fn):
                try:
                    metrics = metrics_fn()
                except Exception:  # pragma: no cover
                    metrics = None

                if isinstance(metrics, dict):
                    try:
                        totals["logging_queue_drops"] = int(
                            metrics.get("drops_total", 0) or 0
                        )
                    except Exception:  # pragma: no cover
                        totals["logging_queue_drops"] = 0

                    try:
                        totals["logging_queue_size"] = int(metrics.get("size", 0) or 0)
                    except Exception:  # pragma: no cover
                        totals["logging_queue_size"] = 0

                    cap = metrics.get("capacity")
                    if cap is not None:
                        try:
                            totals["logging_queue_capacity"] = int(cap)
                        except Exception:  # pragma: no cover
                            pass

                    pct = metrics.get("pct_full")
                    if pct is not None:
                        try:
                            totals["logging_queue_pct"] = float(pct)
                        except Exception:  # pragma: no cover
                            pass

            rcodes = dict(self._rcodes)
            qtypes = dict(self._qtypes)

            # Deep copy nested plugin decisions
            decisions: Dict[str, Dict[str, int]] = {}
            for plugin, actions in self._plugin_decisions.items():
                decisions[plugin] = dict(actions)
                if plugin in self._allowed_by:
                    decisions[plugin]["allowed_by"] = dict(self._allowed_by[plugin])
                if plugin in self._blocked_by:
                    decisions[plugin]["blocked_by"] = dict(self._blocked_by[plugin])

            # Deep copy upstream results
            upstreams: Dict[str, Dict[str, int]] = {}
            for upstream_id, outcomes in self._upstreams.items():
                upstreams[upstream_id] = dict(outcomes)

            # Deep copy upstream response codes
            upstream_rcodes: Dict[str, Dict[str, int]] = {}
            for upstream_id, rcodes_map in self._upstream_rcodes.items():
                upstream_rcodes[upstream_id] = dict(rcodes_map)

            # Deep copy upstream query types
            upstream_qtypes: Dict[str, Dict[str, int]] = {}
            for upstream_id, qtypes_map in self._upstream_qtypes.items():
                upstream_qtypes[upstream_id] = dict(qtypes_map)

            # Unique counts
            uniques = None
            if (
                self.track_uniques
                and self._unique_clients is not None
                and self._unique_domains is not None
            ):
                uniques = {
                    "clients": len(self._unique_clients),
                    "domains": len(self._unique_domains),
                }
                if self._unique_clients_dropped > 0:
                    totals["unique_clients_dropped"] = self._unique_clients_dropped
                if self._unique_domains_dropped > 0:
                    totals["unique_domains_dropped"] = self._unique_domains_dropped

            # Top lists
            top_clients = None
            if self._top_clients is not None:
                top_clients = self._top_clients.export(self._top_clients.capacity)

            top_subdomains = None
            if self._top_subdomains is not None:
                top_subdomains = self._top_subdomains.export(
                    self._top_subdomains.capacity
                )

            top_domains = None
            if self._top_domains is not None:
                top_domains = self._top_domains.export(self._top_domains.capacity)

            # Apply display-only ignore filters to top lists.
            if top_clients is not None and self._ignore_top_client_networks:
                import ipaddress

                filtered_clients: List[Tuple[str, int]] = []
                for client, count in top_clients:
                    try:
                        addr = ipaddress.ip_address(str(client))
                    except Exception:  # pragma: no cover
                        filtered_clients.append((client, count))
                        continue
                    if any(addr in net for net in self._ignore_top_client_networks):
                        continue
                    filtered_clients.append((client, count))
                top_clients = filtered_clients

            if top_domains is not None:
                filtered_domains: List[Tuple[str, int]] = []
                for domain, count in top_domains:
                    norm = _normalize_domain(str(domain))
                    if self.ignore_single_host and "." not in norm:
                        continue
                    if self._ignore_top_domains:
                        if self._ignore_domains_as_suffix:
                            if any(
                                norm == ig or norm.endswith("." + ig)
                                for ig in self._ignore_top_domains
                            ):
                                continue
                        else:
                            if norm in self._ignore_top_domains:
                                continue
                    filtered_domains.append((domain, count))
                top_domains = filtered_domains

            if top_subdomains is not None:
                active_subdomain_ignores: Set[str]
                if self._ignore_top_subdomains:
                    active_subdomain_ignores = self._ignore_top_subdomains
                else:
                    active_subdomain_ignores = self._ignore_top_domains

                filtered_subdomains: List[Tuple[str, int]] = []
                for name, count in top_subdomains:
                    norm = _normalize_domain(str(name))
                    if not _is_subdomain(norm):
                        continue  # pragma: no cover
                    if self.ignore_single_host and "." not in norm:
                        continue  # pragma: no cover
                    if active_subdomain_ignores:
                        if self._ignore_subdomains_as_suffix:
                            if any(
                                norm == ig or norm.endswith("." + ig)
                                for ig in active_subdomain_ignores
                            ):
                                continue
                        else:
                            if norm in active_subdomain_ignores:
                                continue
                    filtered_subdomains.append((name, count))
                top_subdomains = filtered_subdomains

            # Per-qtype top domains
            qtype_qnames: Optional[Dict[str, List[Tuple[str, int]]]] = None
            if self._top_qtype_qnames:
                qtype_qnames = {}
                for qtype_name, tracker in self._top_qtype_qnames.items():
                    entries = tracker.export(tracker.capacity)
                    if not entries:
                        continue

                    active_subdomain_ignores: Set[str]
                    if self._ignore_top_subdomains:
                        active_subdomain_ignores = self._ignore_top_subdomains
                    else:
                        active_subdomain_ignores = self._ignore_top_domains

                    if active_subdomain_ignores or self.ignore_single_host:
                        filtered_entries: List[Tuple[str, int]] = []
                        for name, count in entries:
                            norm = _normalize_domain(str(name))
                            if self.ignore_single_host and "." not in norm:
                                continue
                            if active_subdomain_ignores:
                                if self._ignore_domains_as_suffix:
                                    if any(
                                        norm == ig or norm.endswith("." + ig)
                                        for ig in active_subdomain_ignores
                                    ):
                                        continue
                                else:
                                    if norm in active_subdomain_ignores:
                                        continue
                            filtered_entries.append((name, count))
                        entries = filtered_entries

                    if entries:
                        qtype_qnames[qtype_name] = entries

                if not qtype_qnames:
                    qtype_qnames = None

            # Per-rcode top base domains
            rcode_domains: Optional[Dict[str, List[Tuple[str, int]]]] = None
            if self._top_rcode_domains:
                rcode_domains = {}
                for rcode_name, tracker in self._top_rcode_domains.items():
                    entries = tracker.export(tracker.capacity)
                    if not entries:
                        continue

                    filtered_entries: List[Tuple[str, int]] = []
                    for domain, count in entries:
                        norm = _normalize_domain(str(domain))
                        if self.ignore_single_host and "." not in norm:
                            continue  # pragma: no cover
                        if self._ignore_top_domains:
                            if self._ignore_domains_as_suffix:
                                if any(
                                    norm == ig or norm.endswith("." + ig)
                                    for ig in self._ignore_top_domains
                                ):
                                    continue  # pragma: no cover
                            else:
                                if norm in self._ignore_top_domains:
                                    continue  # pragma: no cover
                        filtered_entries.append((domain, count))

                    if not filtered_entries:
                        continue  # pragma: no cover

                    rcode_domains[rcode_name] = filtered_entries

                if not rcode_domains:
                    rcode_domains = None

            # Per-rcode top subdomains
            rcode_subdomains: Optional[Dict[str, List[Tuple[str, int]]]] = None
            if self._top_rcode_subdomains:
                rcode_subdomains = {}
                for rcode_name, tracker in self._top_rcode_subdomains.items():
                    entries = tracker.export(tracker.capacity)
                    if not entries:
                        continue

                    filtered_entries: List[Tuple[str, int]] = []
                    for domain, count in entries:
                        norm = _normalize_domain(str(domain))
                        if not _is_subdomain(norm):
                            continue  # pragma: no cover
                        if self.ignore_single_host and "." not in norm:
                            continue  # pragma: no cover
                        if self._ignore_top_domains:
                            if self._ignore_domains_as_suffix:
                                if any(
                                    norm == ig or norm.endswith("." + ig)
                                    for ig in self._ignore_top_domains
                                ):
                                    continue  # pragma: no cover
                            else:
                                if norm in self._ignore_top_domains:
                                    continue  # pragma: no cover
                        filtered_entries.append((domain, count))

                    if not filtered_entries:
                        continue

                    rcode_subdomains[rcode_name] = filtered_entries

                if not rcode_subdomains:
                    rcode_subdomains = None

            # Cache outcome top lists
            cache_hit_domains: Optional[List[Tuple[str, int]]] = None
            if self._top_cache_hit_domains is not None:
                entries = self._top_cache_hit_domains.export(
                    self._top_cache_hit_domains.capacity
                )
                if entries:
                    filtered_entries = []
                    for domain, count in entries:
                        norm = _normalize_domain(str(domain))
                        if self.ignore_single_host and "." not in norm:
                            continue  # pragma: no cover
                        if self._ignore_top_domains:
                            if self._ignore_domains_as_suffix:
                                if any(
                                    norm == ig or norm.endswith("." + ig)
                                    for ig in self._ignore_top_domains
                                ):
                                    continue  # pragma: no cover
                            else:
                                if norm in self._ignore_top_domains:
                                    continue  # pragma: no cover
                        filtered_entries.append((domain, count))
                    if filtered_entries:
                        cache_hit_domains = filtered_entries

            cache_miss_domains: Optional[List[Tuple[str, int]]] = None
            if self._top_cache_miss_domains is not None:
                entries = self._top_cache_miss_domains.export(
                    self._top_cache_miss_domains.capacity
                )
                if entries:
                    filtered_entries = []
                    for domain, count in entries:
                        norm = _normalize_domain(str(domain))
                        if self.ignore_single_host and "." not in norm:
                            continue  # pragma: no cover
                        if self._ignore_top_domains:
                            if self._ignore_domains_as_suffix:
                                if any(
                                    norm == ig or norm.endswith("." + ig)
                                    for ig in self._ignore_top_domains
                                ):
                                    continue  # pragma: no cover
                            else:
                                if norm in self._ignore_top_domains:
                                    continue  # pragma: no cover
                        filtered_entries.append((domain, count))
                    if filtered_entries:
                        cache_miss_domains = filtered_entries

            cache_hit_subdomains: Optional[List[Tuple[str, int]]] = None
            if self._top_cache_hit_subdomains is not None:
                entries = self._top_cache_hit_subdomains.export(
                    self._top_cache_hit_subdomains.capacity
                )
                if entries:
                    filtered_entries = []
                    for domain, count in entries:
                        norm = _normalize_domain(str(domain))
                        if not _is_subdomain(norm):
                            continue  # pragma: no cover
                        if self.ignore_single_host and "." not in norm:
                            continue  # pragma: no cover
                        if self._ignore_top_domains:
                            if self._ignore_domains_as_suffix:
                                if any(
                                    norm == ig or norm.endswith("." + ig)
                                    for ig in self._ignore_top_domains
                                ):
                                    continue  # pragma: no cover
                            else:
                                if norm in self._ignore_top_domains:
                                    continue  # pragma: no cover
                        filtered_entries.append((domain, count))
                    if filtered_entries:
                        cache_hit_subdomains = filtered_entries

            cache_miss_subdomains: Optional[List[Tuple[str, int]]] = None
            if self._top_cache_miss_subdomains is not None:
                entries = self._top_cache_miss_subdomains.export(
                    self._top_cache_miss_subdomains.capacity
                )
                if entries:
                    filtered_entries = []
                    for domain, count in entries:
                        norm = _normalize_domain(str(domain))
                        if not _is_subdomain(norm):
                            continue  # pragma: no cover
                        if self.ignore_single_host and "." not in norm:
                            continue  # pragma: no cover
                        if self._ignore_top_domains:
                            if self._ignore_domains_as_suffix:
                                if any(
                                    norm == ig or norm.endswith("." + ig)
                                    for ig in self._ignore_top_domains
                                ):
                                    continue  # pragma: no cover
                            else:
                                if norm in self._ignore_top_domains:
                                    continue  # pragma: no cover
                        filtered_entries.append((domain, count))
                    if filtered_entries:
                        cache_miss_subdomains = filtered_entries

            # Latency
            latency_stats = (
                self._latency.summarize() if self._latency is not None else None
            )
            latency_recent_stats = (
                self._latency_recent.summarize()
                if self._latency_recent is not None
                else None
            )

            # Rate limit derived from totals
            rate_limit: Optional[Dict[str, Any]] = None
            rl_key = "cache_stat_rate_limit"
            if rl_key in totals:
                try:
                    denied = int(totals.get(rl_key, 0))
                except (TypeError, ValueError):  # pragma: no cover
                    denied = 0
                rate_limit = {"denied": denied}

            dnssec_totals: Optional[Dict[str, int]] = None
            try:
                dnssec_subset = {
                    k: int(v)
                    for k, v in totals.items()
                    if isinstance(v, (int, float)) and str(k).startswith("dnssec_")
                }
            except Exception:
                dnssec_subset = {}
            if dnssec_subset:
                dnssec_totals = dnssec_subset

            ede_totals: Optional[Dict[str, int]] = None
            try:
                ede_subset = {
                    k: int(v)
                    for k, v in totals.items()
                    if isinstance(v, (int, float)) and str(k).startswith("ede_")
                }
            except Exception:
                ede_subset = {}
            if ede_subset:
                ede_totals = ede_subset

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
                upstream_rcodes=upstream_rcodes,
                upstream_qtypes=upstream_qtypes,
                qtype_qnames=qtype_qnames,
                rcode_domains=rcode_domains,
                rcode_subdomains=rcode_subdomains,
                cache_hit_domains=cache_hit_domains,
                cache_miss_domains=cache_miss_domains,
                cache_hit_subdomains=cache_hit_subdomains,
                cache_miss_subdomains=cache_miss_subdomains,
                rate_limit=rate_limit,
                dnssec_totals=dnssec_totals,
                ede_totals=ede_totals,
            )

            if reset:
                self._totals.clear()
                self._rcodes.clear()
                self._qtypes.clear()
                self._plugin_decisions.clear()
                self._allowed_by.clear()
                self._blocked_by.clear()
                self._upstreams.clear()
                self._upstream_rcodes.clear()
                self._upstream_qtypes.clear()
                self._top_qtype_qnames.clear()

                if self._unique_clients is not None:
                    self._unique_clients.clear()
                if self._unique_domains is not None:
                    self._unique_domains.clear()
                self._unique_clients_dropped = 0
                self._unique_domains_dropped = 0

                if self._top_clients is not None:
                    self._top_clients.counts.clear()
                if self._top_subdomains is not None:
                    self._top_subdomains.counts.clear()
                if self._top_domains is not None:
                    self._top_domains.counts.clear()
                if self._top_cache_hit_domains is not None:
                    self._top_cache_hit_domains.counts.clear()
                if self._top_cache_miss_domains is not None:
                    self._top_cache_miss_domains.counts.clear()
                if self._top_cache_hit_subdomains is not None:
                    self._top_cache_hit_subdomains.counts.clear()
                if self._top_cache_miss_subdomains is not None:
                    self._top_cache_miss_subdomains.counts.clear()
                self._top_rcode_domains.clear()
                self._top_rcode_subdomains.clear()

                if self._latency is not None:
                    self._latency = LatencyHistogram()
                if self._latency_recent is not None:
                    self._latency_recent = LatencyHistogram()

            return snapshot

    def reset_latency_recent(self) -> None:
        """Reset only the recent latency window.

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
