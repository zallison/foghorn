from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Optional

from ..domain import _base_domain, _is_subdomain, _normalize_domain

logger = logging.getLogger("foghorn.stats")


class _StatsCollectorRecordUtils:
    def _persist_increment_counts(
        self,
        *,
        counts: list[tuple[str, str, int]],
        debug_message: str,
    ) -> None:
        """Persist aggregated increment_count operations outside the collector lock.

        Inputs:
            counts: Sequence of (scope, key, delta) increment operations.
            debug_message: Debug log message emitted when persistence fails.

        Outputs:
            None.
        """
        if not counts:
            return

        store = getattr(self, "_store", None)
        if store is None:
            return

        try:
            for scope, key, delta in counts:
                store.increment_count(scope, key, int(delta))
        except Exception:  # pragma: no cover
            logger.debug(debug_message, exc_info=True)

    def record_query(self, client_ip: str, qname: str, qtype: str) -> None:
        """Record an incoming DNS query.

        Inputs:
            client_ip: Client IP address
            qname: Query domain name
            qtype: Query type (e.g., 'A', 'AAAA', 'CNAME')

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_query('192.0.2.1', 'example.com', 'A')
        """
        domain = _normalize_domain(qname)

        # Compute base domain once so it can be reused for top_domains and persistence.
        # This uses stats.domain._base_domain(), which handles common ccTLD patterns
        # such as example.co.uk (base = example.co.uk).
        base = _base_domain(domain)
        persist_counts: list[tuple[str, str, int]] = []

        with self._lock:
            # When include_ignored_in_stats is False, ignore filters exclude
            # entries from aggregation but do not affect persistent query logging
            # (record_query_result).
            if not self.include_ignored_in_stats and self._should_ignore_query_locked(
                client_ip, domain, base
            ):
                return

            self._totals["total_queries"] += 1

            if self.include_qtype_breakdown:
                self._qtypes[qtype] += 1

            if self._unique_clients is not None:
                self._track_unique_client_locked(client_ip)

            if self._unique_domains is not None:
                self._track_unique_domain_locked(domain)

            if self._top_clients is not None:
                self._top_clients.add(client_ip)

            if self._top_subdomains is not None and _is_subdomain(domain):
                self._top_subdomains.add(domain)

            if self._top_domains is not None:
                # Aggregate by base domain (last two labels)
                self._top_domains.add(base)

            # Per-qtype top domains (full qnames) for all observed qtypes.
            if self.include_top_domains and qtype:
                tracker = self._top_qtype_qnames.get(qtype)
                if tracker is None:
                    from ..topk import TopK

                    tracker = TopK(capacity=self._top_capacity)
                    self._top_qtype_qnames[qtype] = tracker
                tracker.add(domain)

            # Mirror core counters into the persistent store when available.
            if self._store is not None and not self.query_log_only:
                persist_counts.append(("totals", "total_queries", 1))
                if self.include_qtype_breakdown:
                    persist_counts.append(("qtypes", qtype, 1))
                persist_counts.append(("clients", client_ip, 1))
                if _is_subdomain(domain):
                    persist_counts.append(("sub_domains", domain, 1))
                if base:
                    persist_counts.append(("domains", base, 1))
                if qtype and domain:
                    qkey = f"{qtype}|{domain}"
                    persist_counts.append(("qtype_qnames", qkey, 1))

        self._persist_increment_counts(
            counts=persist_counts,
            debug_message="StatsCollector: failed to persist query counters",
        )

    def record_cache_hit(self, qname: str) -> None:
        """Record a cache hit.

        Inputs:
            qname: Query domain name

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_cache_hit('example.com')
        """
        domain = _normalize_domain(qname)
        base = _base_domain(domain)
        persist_counts: list[tuple[str, str, int]] = []

        with self._lock:
            if not self.include_ignored_in_stats:
                if base and self._base_domain_is_ignored_locked(base):
                    return
                if domain and self._qname_is_ignored_locked(domain):
                    return

            self._totals["cache_hits"] += 1

            if self._top_cache_hit_domains is not None and base:
                self._top_cache_hit_domains.add(base)
            if (
                self._top_cache_hit_subdomains is not None
                and domain
                and base
                and domain != base
            ):
                self._top_cache_hit_subdomains.add(domain)

            if self._store is not None and not self.query_log_only:
                persist_counts.append(("totals", "cache_hits", 1))
                if base:
                    persist_counts.append(("cache_hit_domains", base, 1))
                    if domain and domain != base:
                        persist_counts.append(("cache_hit_subdomains", domain, 1))

        self._persist_increment_counts(
            counts=persist_counts,
            debug_message="StatsCollector: failed to persist cache_hit",
        )

    def record_cache_miss(self, qname: str) -> None:
        """Record a cache miss.

        Inputs:
            qname: Query domain name.

        Outputs:
            None.

        Notes:
            - When include_ignored_in_stats is False, cache events for ignored
              domains/qnames are excluded from aggregation.
            - Domain-oriented cache counters are keyed by the derived base domain
              (see stats.domain._base_domain()).
        """
        domain = _normalize_domain(qname)
        base = _base_domain(domain)
        persist_counts: list[tuple[str, str, int]] = []

        with self._lock:
            if not self.include_ignored_in_stats:
                if base and self._base_domain_is_ignored_locked(base):
                    return
                if domain and self._qname_is_ignored_locked(domain):
                    return

            self._totals["cache_misses"] += 1

            if self._top_cache_miss_domains is not None and base:
                self._top_cache_miss_domains.add(base)
            if (
                self._top_cache_miss_subdomains is not None
                and domain
                and base
                and domain != base
            ):
                self._top_cache_miss_subdomains.add(domain)

            if self._store is not None and not self.query_log_only:
                persist_counts.append(("totals", "cache_misses", 1))
                if base:
                    persist_counts.append(("cache_miss_domains", base, 1))
                    if domain and domain != base:
                        persist_counts.append(("cache_miss_subdomains", domain, 1))

        self._persist_increment_counts(
            counts=persist_counts,
            debug_message="StatsCollector: failed to persist cache_miss",
        )

    def record_cache_null(self, qname: str, status: Optional[str] = None) -> None:
        """Record a response served directly by plugins without cache usage.

        Inputs:
            qname: Query domain name associated with the plugin-handled response.
            status: Optional high-level status classification for the cache-null
                event (e.g. 'deny_pre' or 'override_pre').

        Outputs:
            None.

        Notes:
            When status is 'deny_pre' or 'override_pre', an additional
            totals.cache_<status> counter is incremented so that live counters
            can align with rebuild-from-query-log behavior.
        """
        domain = _normalize_domain(qname)
        base = _base_domain(domain)
        persist_counts: list[tuple[str, str, int]] = []

        with self._lock:
            if not self.include_ignored_in_stats:
                if base and self._base_domain_is_ignored_locked(base):
                    return
                if domain and self._qname_is_ignored_locked(domain):
                    return

            self._totals["cache_null"] += 1

            if status in ("deny_pre", "override_pre"):
                key = f"cache_{status}"
                self._totals[key] += 1

            if self._store is not None and not self.query_log_only:
                persist_counts.append(("totals", "cache_null", 1))
                if status in ("deny_pre", "override_pre"):
                    persist_counts.append(("totals", f"cache_{status}", 1))

        self._persist_increment_counts(
            counts=persist_counts,
            debug_message="StatsCollector: failed to persist cache_null",
        )

    def record_dnssec_status(self, status: str) -> None:
        """Record a DNSSEC validation outcome.

        Inputs:
            status: Expected to be a fully-qualified 'dnssec_*' key
                (e.g. 'dnssec_secure').

        Outputs:
            None.

        Notes:
            Unknown/unsupported status strings are ignored.
        """
        if not status:
            return

        totals_key = status if status.startswith("dnssec_") else None
        if not totals_key:
            return

        persist_counts: list[tuple[str, str, int]] = []
        with self._lock:
            self._totals[totals_key] += 1

            if self._store is not None and not self.query_log_only:
                persist_counts.append(("totals", totals_key, 1))

        self._persist_increment_counts(
            counts=persist_counts,
            debug_message="StatsCollector: failed to persist dnssec_status",
        )

    def record_ede_code(self, info_code: int | str) -> None:
        """Record an Extended DNS Error (EDE) info-code.

        Inputs:
            info_code: Integer (or numeric string) EDE info-code.

        Outputs:
            None.

        Notes:
            Non-integer and negative codes are ignored.
        """
        if info_code is None:
            return

        try:
            code_int = int(info_code)
        except (TypeError, ValueError):
            return

        if code_int < 0:
            return

        key = f"ede_{code_int}"
        persist_counts: list[tuple[str, str, int]] = []
        with self._lock:
            self._totals[key] += 1

            if self._store is not None and not self.query_log_only:
                persist_counts.append(("totals", key, 1))

        self._persist_increment_counts(
            counts=persist_counts,
            debug_message="StatsCollector: failed to persist ede_code",
        )

    def record_cache_stat(self, label: str) -> None:
        """Record a cache-related classification label derived from PluginDecision.stat.

        Inputs:
            label: Stat label name.

        Outputs:
            None.

        Notes:
            This increments a totals.cache_stat_<label> counter in-memory.
            When a persistent store is attached, the label is mirrored into the
            'cache' scope so warm-load can restore it.
        """
        if not label:
            return

        key = f"cache_stat_{label}"
        persist_counts: list[tuple[str, str, int]] = []
        with self._lock:
            try:
                self._totals[key] += 1
            except Exception:  # pragma: no cover
                return

            if self._store is not None and not self.query_log_only:
                persist_counts.append(("cache", label, 1))

        self._persist_increment_counts(
            counts=persist_counts,
            debug_message="StatsCollector: failed to persist cache_stat",
        )

    def record_cache_pre_plugin(self, label: str) -> None:
        """Record per-plugin pre_resolve deny/override cache classifications.

        Inputs:
            label: Totals key to increment (e.g. 'cache_deny_pre').

        Outputs:
            None.
        """
        if not label:
            return

        persist_counts: list[tuple[str, str, int]] = []
        with self._lock:
            self._totals[label] += 1

            if self._store is not None and not self.query_log_only:
                persist_counts.append(("totals", label, 1))

        self._persist_increment_counts(
            counts=persist_counts,
            debug_message="StatsCollector: failed to persist cache_pre_plugin",
        )

    def record_latency(self, seconds: float) -> None:
        """Record request latency.

        Inputs:
            seconds: Latency in seconds.

        Outputs:
            None.

        Notes:
            Only records latency when track_latency was enabled at construction.
            Updates both the total and recent latency histograms.
        """
        if self._latency is not None:
            with self._lock:
                self._latency.add(seconds)
                if self._latency_recent is not None:
                    self._latency_recent.add(seconds)

    def record_suppressed_query_log_drop_candidate(
        self,
        *,
        rcode: Optional[str],
        status: Optional[str],
    ) -> None:
        """Record a suppressed query-log candidate for queue-drop accounting.

        Inputs:
            rcode: Optional DNS response code for the suppressed row.
            status: Optional status for the suppressed row.

        Outputs:
            None.

        Notes:
            This does not write a query-log row. It only lets queue metrics
            account for suppressed low-priority rows when queue pressure is high.
        """

        if self._store is None:
            return

        try:
            handler = getattr(self._store, "record_suppressed_query_log_drop_candidate")
        except Exception:
            return
        if not callable(handler):
            return
        try:
            handler(rcode=rcode, status=status)
        except Exception:  # pragma: no cover
            logger.debug(
                "StatsCollector: failed to account for suppressed query_log row",
                exc_info=True,
            )

    def record_query_result(
        self,
        client_ip: str,
        qname: str,
        qtype: str,
        rcode: Optional[str],
        upstream_id: Optional[str],
        status: Optional[str],
        error: Optional[str],
        first: Optional[str],
        result: Optional[Dict[str, Any]],
        ts: Optional[float] = None,
    ) -> None:
        """Record a completed DNS query into the persistent query log.

        Inputs:
            client_ip: Client IP address.
            qname: Query name (normalized for storage).
            qtype: Query type (e.g. 'A').
            rcode: Optional DNS response code (e.g. 'NOERROR').
            upstream_id: Optional upstream identifier.
            status: Optional high-level status (e.g. 'ok', 'timeout', 'cache_hit').
            error: Optional error message summary.
            first: Optional string representation of the first answer.
            result: Optional structured result mapping to be JSON-encoded.
            ts: Optional Unix timestamp. When omitted, current time is used and
                rounded to millisecond precision.

        Outputs:
            None.

        Notes:
            - This method does not modify in-memory counters.
            - JSON encoding is best-effort; invalid payloads are replaced with '{}'.
        """
        if self._store is None:
            return

        if ts is None:
            ts = round(time.time(), 3)

        name = _normalize_domain(qname)
        should_persist = True
        with self._lock:
            should_persist = self._should_persist_query_log_row_locked(
                ts=float(ts),
                client_ip=client_ip,
                qname=name,
                qtype=qtype,
                upstream_id=upstream_id,
                rcode=rcode,
                status=status,
                error=error,
                first=first,
            )
        if not should_persist:
            return
        try:
            payload = json.dumps(result or {}, separators=(",", ":"))
        except Exception:  # pragma: no cover
            payload = "{}"

        try:
            self._store.insert_query_log(
                ts=ts,
                client_ip=client_ip,
                name=name,
                qtype=qtype,
                upstream_id=upstream_id,
                rcode=rcode,
                status=status,
                error=error,
                first=first,
                result_json=payload,
            )
        except Exception:  # pragma: no cover
            logger.debug(
                "StatsCollector: failed to append query_log row", exc_info=True
            )
