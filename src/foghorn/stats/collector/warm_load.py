from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict

from ..topk import TOPK_CAPACITY_FACTOR, TopK

logger = logging.getLogger("foghorn.stats")


class _StatsCollectorWarmLoadUtils:
    def load_from_snapshot(self, snapshot) -> None:
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

            # Upstream response codes
            self._upstream_rcodes.clear()
            for upstream_id, rcodes_map in (snapshot.upstream_rcodes or {}).items():
                if isinstance(rcodes_map, dict):
                    try:
                        self._upstream_rcodes[upstream_id] = defaultdict(
                            int,
                            {str(k): int(v) for k, v in rcodes_map.items()},
                        )
                    except Exception:
                        continue

            # Upstream query types
            self._upstream_qtypes.clear()
            for upstream_id, qtypes_map in (snapshot.upstream_qtypes or {}).items():
                if isinstance(qtypes_map, dict):
                    try:
                        self._upstream_qtypes[upstream_id] = defaultdict(
                            int,
                            {str(k): int(v) for k, v in qtypes_map.items()},
                        )
                    except Exception:
                        continue

            # Per-qtype top domains (full qnames)
            self._top_qtype_qnames.clear()
            if snapshot.qtype_qnames:
                for qtype_name, entries in snapshot.qtype_qnames.items():
                    if not entries:
                        continue  # pragma: no cover
                    tracker = TopK(capacity=self.top_n * TOPK_CAPACITY_FACTOR)
                    for domain, count in entries:
                        try:
                            tracker.counts[str(domain)] = int(count)
                        except (TypeError, ValueError):
                            continue
                    self._top_qtype_qnames[qtype_name] = tracker

    def warm_load_from_store(self) -> None:
        """Warm-load core counters from the attached SQLite stats store.

        Inputs:
            None (uses self._store when configured).

        Outputs:
            None; mutates in-memory aggregate counters in place.

        Notes:
            - This is a best-effort warm load used on process start. If the
              store is not configured or an error occurs, the collector simply
              starts from empty in-memory counters.
            - Only scopes known to StatsCollector (totals, rcodes, qtypes,
              clients, sub_domains, domains, upstreams, upstream_qtypes,
              upstream_rcodes, qtype_qnames, cache_hit_domains,
              cache_miss_domains, rcode_domains, rcode_subdomains) are applied.
            - Top-N client/domain trackers and unique counts are approximated
              from the aggregated counts when enabled.
            - When logging_only or query_log_only is True, this method is a
              no-op so that the attached stats_store is only exercised via
              insert-style operations (query_log appends, and in logging_only
              mode, counter increments).
        """
        if self._store is None or self.logging_only or self.query_log_only:
            return

        try:
            counts = self._store.export_counts()
        except Exception:  # pragma: no cover
            logger.error(
                "StatsCollector warm_load_from_store: failed to export counts",
                exc_info=True,
            )
            return

        with self._lock:
            # Core totals/qtypes/rcodes
            for key, value in counts.get("totals", {}).items():
                try:
                    self._totals[key] = int(value)
                except (TypeError, ValueError):
                    continue

            # Optional per-label cache statistics persisted under 'cache' scope.
            for label, value in counts.get("cache", {}).items():
                try:
                    int_value = int(value)
                except (TypeError, ValueError):
                    continue
                stat_key = f"cache_stat_{label}"
                self._totals[stat_key] = int_value

            for key, value in counts.get("rcodes", {}).items():
                try:
                    self._rcodes[key] = int(value)
                except (TypeError, ValueError):
                    continue

            for key, value in counts.get("qtypes", {}).items():
                try:
                    self._qtypes[key] = int(value)
                except (TypeError, ValueError):
                    continue

            upstream_rcode_counts = counts.get("upstream_rcodes", {}) or {}
            has_upstream_rcode_scope = bool(upstream_rcode_counts)

            self._upstream_rcodes.clear()

            for key, value in counts.get("upstreams", {}).items():
                parts = str(key).split("|")
                if len(parts) == 3:
                    upstream_id, outcome, rcode_key = parts
                elif len(parts) == 2:
                    upstream_id, outcome = parts
                    rcode_key = None
                else:
                    continue

                try:
                    int_value = int(value)
                except (TypeError, ValueError):
                    continue

                self._upstreams[upstream_id][outcome] += int_value

                if not has_upstream_rcode_scope and rcode_key:
                    self._upstream_rcodes[upstream_id][rcode_key] += int_value

            if has_upstream_rcode_scope:
                self._upstream_rcodes.clear()
                for key, value in upstream_rcode_counts.items():
                    try:
                        upstream_id, rcode_name = str(key).split("|", 1)
                    except ValueError:
                        continue  # pragma: no cover
                    try:
                        int_value = int(value)
                    except (TypeError, ValueError):
                        continue  # pragma: no cover
                    self._upstream_rcodes[upstream_id][rcode_name] += int_value

            for key, value in counts.get("upstream_qtypes", {}).items():
                try:
                    upstream_id, qtype = str(key).split("|", 1)
                except ValueError:
                    continue  # pragma: no cover
                try:
                    int_value = int(value)
                except (TypeError, ValueError):
                    continue  # pragma: no cover
                self._upstream_qtypes[upstream_id][qtype] = int_value

            qtype_qname_counts: Dict[str, Dict[str, int]] = {}
            for key, value in counts.get("qtype_qnames", {}).items():
                try:
                    qtype_name, qname = str(key).split("|", 1)
                except ValueError:
                    continue  # pragma: no cover
                try:
                    int_value = int(value)
                except (TypeError, ValueError):
                    continue  # pragma: no cover
                inner = qtype_qname_counts.setdefault(qtype_name, {})
                inner[str(qname)] = int_value

            rcode_domain_counts: Dict[str, Dict[str, int]] = {}
            for key, value in counts.get("rcode_domains", {}).items():
                try:
                    rcode_name, dname = str(key).split("|", 1)
                except ValueError:
                    continue  # pragma: no cover
                try:
                    int_value = int(value)
                except (TypeError, ValueError):
                    continue  # pragma: no cover
                inner = rcode_domain_counts.setdefault(rcode_name, {})
                inner[str(dname)] = int_value

            rcode_subdomain_counts: Dict[str, Dict[str, int]] = {}
            for key, value in counts.get("rcode_subdomains", {}).items():
                try:
                    rcode_name, dname = str(key).split("|", 1)
                except ValueError:
                    continue  # pragma: no cover
                try:
                    int_value = int(value)
                except (TypeError, ValueError):
                    continue  # pragma: no cover
                inner = rcode_subdomain_counts.setdefault(rcode_name, {})
                inner[str(dname)] = int_value

            client_counts = counts.get("clients", {})
            subdomain_counts = counts.get("sub_domains", {})
            domain_counts = counts.get("domains", {})
            cache_hit_domain_counts = counts.get("cache_hit_domains", {})
            cache_miss_domain_counts = counts.get("cache_miss_domains", {})
            cache_hit_subdomain_counts = counts.get("cache_hit_subdomains", {})
            cache_miss_subdomain_counts = counts.get("cache_miss_subdomains", {})

            if self._unique_clients is not None:
                self._unique_clients.clear()
                dropped_clients = 0
                for raw_client in client_counts.keys():
                    client_key = str(raw_client)
                    if not client_key or client_key in self._unique_clients:
                        continue
                    if len(self._unique_clients) >= self.max_unique_clients:
                        dropped_clients += 1
                        continue
                    self._unique_clients.add(client_key)
                self._unique_clients_dropped = dropped_clients
                if dropped_clients > 0 and not self._unique_clients_limit_warned:
                    logger.warning(
                        "StatsCollector warm-load client uniques exceeded max_unique_clients=%d; "
                        "loaded subset and dropped %d values",
                        self.max_unique_clients,
                        dropped_clients,
                    )
                    self._unique_clients_limit_warned = True

            if self._unique_domains is not None:
                self._unique_domains.clear()
                dropped_domains = 0
                src = subdomain_counts or domain_counts
                for raw_domain in src.keys():
                    domain_key = str(raw_domain)
                    if not domain_key or domain_key in self._unique_domains:
                        continue
                    if len(self._unique_domains) >= self.max_unique_domains:
                        dropped_domains += 1
                        continue
                    self._unique_domains.add(domain_key)
                self._unique_domains_dropped = dropped_domains
                if dropped_domains > 0 and not self._unique_domains_limit_warned:
                    logger.warning(
                        "StatsCollector warm-load domain uniques exceeded max_unique_domains=%d; "
                        "loaded subset and dropped %d values",
                        self.max_unique_domains,
                        dropped_domains,
                    )
                    self._unique_domains_limit_warned = True

            if self._top_clients is not None and client_counts:
                items = sorted(
                    ((str(k), int(v)) for k, v in client_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_clients.capacity])
                self._top_clients.counts = limited

            if self._top_subdomains is not None and subdomain_counts:
                items = sorted(
                    ((str(k), int(v)) for k, v in subdomain_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_subdomains.capacity])
                self._top_subdomains.counts = limited

            if qtype_qname_counts and self.include_top_domains:
                for qtype_name, qmap in qtype_qname_counts.items():
                    items = sorted(
                        ((str(k), int(v)) for k, v in qmap.items()),
                        key=lambda kv: kv[1],
                        reverse=True,
                    )
                    tracker = TopK(capacity=self._top_capacity)
                    tracker.counts = dict(items[: tracker.capacity])
                    self._top_qtype_qnames[qtype_name] = tracker

            if rcode_domain_counts and self.include_top_domains:
                self._top_rcode_domains.clear()
                for rcode_name, dmap in rcode_domain_counts.items():
                    items = sorted(
                        ((str(k), int(v)) for k, v in dmap.items()),
                        key=lambda kv: kv[1],
                        reverse=True,
                    )
                    tracker = TopK(capacity=self._top_capacity)
                    tracker.counts = dict(items[: tracker.capacity])
                    self._top_rcode_domains[rcode_name] = tracker

            if rcode_subdomain_counts and self.include_top_domains:
                self._top_rcode_subdomains.clear()
                for rcode_name, dmap in rcode_subdomain_counts.items():
                    items = sorted(
                        ((str(k), int(v)) for k, v in dmap.items()),
                        key=lambda kv: kv[1],
                        reverse=True,
                    )
                    tracker = TopK(capacity=self._top_capacity)
                    tracker.counts = dict(items[: tracker.capacity])
                    self._top_rcode_subdomains[rcode_name] = tracker

            if self._top_domains is not None and domain_counts:
                items = sorted(
                    ((str(k), int(v)) for k, v in domain_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_domains.capacity])
                self._top_domains.counts = limited

            if self._top_cache_hit_domains is not None and cache_hit_domain_counts:
                items = sorted(
                    ((str(k), int(v)) for k, v in cache_hit_domain_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_cache_hit_domains.capacity])
                self._top_cache_hit_domains.counts = limited

            if self._top_cache_miss_domains is not None and cache_miss_domain_counts:
                items = sorted(
                    ((str(k), int(v)) for k, v in cache_miss_domain_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_cache_miss_domains.capacity])
                self._top_cache_miss_domains.counts = limited

            if (
                self._top_cache_hit_subdomains is not None
                and cache_hit_subdomain_counts
            ):
                items = sorted(
                    ((str(k), int(v)) for k, v in cache_hit_subdomain_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_cache_hit_subdomains.capacity])
                self._top_cache_hit_subdomains.counts = limited

            if (
                self._top_cache_miss_subdomains is not None
                and cache_miss_subdomain_counts
            ):
                items = sorted(
                    ((str(k), int(v)) for k, v in cache_miss_subdomain_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_cache_miss_subdomains.capacity])
                self._top_cache_miss_subdomains.counts = limited
