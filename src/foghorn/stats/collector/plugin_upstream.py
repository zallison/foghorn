from __future__ import annotations

import logging
from typing import Optional

from ..domain import _base_domain, _normalize_domain
from ..topk import TOPK_CAPACITY_FACTOR, TopK

logger = logging.getLogger("foghorn.stats")


class _StatsCollectorPluginUpstreamMixin:
    def record_plugin_decision(
        self,
        plugin_name: str,
        action: str,
        reason: Optional[str] = None,
        domain: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> None:
        """Record a plugin decision (allow, block, modify, skip).

        Brief:
            Updates in-memory decision counters for a plugin. When a persistent
            stats store is attached, mirrors high-level totals (allowed/blocked/
            modified) into the store.

        Inputs:
            plugin_name: Name of the plugin making the decision.
            action: Decision action (typically 'allow', 'block', 'modify', 'skip').
            reason: Optional reason code or description.
            domain: Optional domain name affected by the decision.
            client_ip: Optional client IP address.

        Outputs:
            None.

        Notes:
            - The domain and client_ip parameters are accepted for compatibility
              and future expansion; they are not currently used for aggregation.

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_plugin_decision(
            ...     'Filter', 'block', reason='blocklist_match', domain='bad.com'
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

            if self._store is not None and not self.query_log_only:
                try:
                    if action == "allow":
                        self._store.increment_count("totals", "allowed")
                    elif action == "block":
                        self._store.increment_count("totals", "blocked")
                    elif action == "modify":
                        self._store.increment_count("totals", "modified")
                except Exception:  # pragma: no cover
                    logger.debug(
                        "StatsCollector: failed to persist plugin decision",
                        exc_info=True,
                    )

    def record_upstream_result(
        self,
        upstream_id: str,
        outcome: str,
        bytes_out: Optional[int] = None,
        bytes_in: Optional[int] = None,
        qtype: Optional[str] = None,
    ) -> None:
        """Record upstream resolution outcome.

        Brief:
            Tracks per-upstream outcomes (success/timeout/error/etc.) and
            optionally a per-upstream qtype breakdown.

        Inputs:
            upstream_id: Upstream identifier (e.g. '8.8.8.8:53').
            outcome: Outcome classification string.
            bytes_out: Optional bytes sent to upstream.
            bytes_in: Optional bytes received from upstream.
            qtype: Optional query type for per-upstream qtype counters.

        Outputs:
            None.

        Notes:
            - bytes_out/bytes_in are accepted for compatibility and future
              expansion; they are not currently used for aggregation.
            - When a persistent store is attached, this mirrors counters using
              composite keys:
                - upstreams scope: '<upstream_id>|<outcome>'
                - upstream_qtypes scope: '<upstream_id>|<qtype>'

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_upstream_result('8.8.8.8:53', 'success')
            >>> collector.record_upstream_result('1.1.1.1:53', 'timeout', qtype='A')
        """
        with self._lock:
            self._upstreams[upstream_id][outcome] += 1
            if qtype:
                self._upstream_qtypes[upstream_id][qtype] += 1
            if self._store is not None and not self.query_log_only:
                try:
                    key = f"{upstream_id}|{outcome}"
                    self._store.increment_count("upstreams", key)
                    if qtype:
                        qt_key = f"{upstream_id}|{qtype}"
                        self._store.increment_count("upstream_qtypes", qt_key)
                except Exception:  # pragma: no cover
                    logger.debug(
                        "StatsCollector: failed to persist upstream result",
                        exc_info=True,
                    )

    def record_upstream_rcode(self, upstream_id: str, rcode: str) -> None:
        """Record DNS response code grouped by upstream identifier.

        Inputs:
            upstream_id: Upstream identifier (e.g. '8.8.8.8:53').
            rcode: Response code ('NOERROR', 'NXDOMAIN', 'SERVFAIL', etc.).

        Outputs:
            None.

        Notes:
            When a persistent store is attached, rcodes are mirrored under the
            upstream_rcodes scope using the composite key:
                '<upstream_id>|<rcode>'
        """
        if not upstream_id or not rcode:
            return

        with self._lock:
            self._upstream_rcodes[upstream_id][rcode] += 1

            if self._store is not None and not self.query_log_only:
                try:
                    key = f"{upstream_id}|{rcode}"
                    self._store.increment_count("upstream_rcodes", key)
                except Exception:  # pragma: no cover
                    logger.debug(
                        "StatsCollector: failed to persist upstream rcode",
                        exc_info=True,
                    )

    def record_response_rcode(self, rcode: str, qname: Optional[str] = None) -> None:
        """Record DNS response code.

        Brief:
            Updates global rcode counters. When qname is provided and domain
            tracking is enabled, also tracks per-rcode top domains and per-rcode
            top subdomains.

        Inputs:
            rcode: Response code ('NOERROR', 'NXDOMAIN', 'SERVFAIL', etc.).
            qname: Optional query name used to attribute rcodes to domains and
                subdomains.

        Outputs:
            None.

        Notes:
            - The base domain is derived via stats.domain._base_domain(), which
              applies a heuristic for common ccTLD patterns like example.co.uk.
            - When include_ignored_in_stats is False, ignore filters can exclude
              rcode attribution from aggregation.
            - When a persistent store is attached, this mirrors counters using
              composite keys:
                - rcode_domains scope: '<rcode>|<base_domain>'
                - rcode_subdomains scope: '<rcode>|<full_qname>'

        Example:
            >>> collector = StatsCollector(include_top_domains=True)
            >>> collector.record_response_rcode('NOERROR', qname='www.example.com')
            >>> collector.record_response_rcode('NXDOMAIN')
        """
        base: Optional[str] = None
        domain: Optional[str] = None
        if qname:
            domain = _normalize_domain(qname)
            base = _base_domain(domain)

        with self._lock:
            if not self.include_ignored_in_stats:
                if base and self._base_domain_is_ignored_locked(base):
                    return
                if domain and self._qname_is_ignored_locked(domain):
                    return

            self._rcodes[rcode] += 1

            if base and self.include_top_domains:
                tracker = self._top_rcode_domains.get(rcode)
                if tracker is None:
                    tracker = TopK(capacity=self.top_n * TOPK_CAPACITY_FACTOR)
                    self._top_rcode_domains[rcode] = tracker
                tracker.add(base)

                if domain and domain != base:
                    sub_tracker = self._top_rcode_subdomains.get(rcode)
                    if sub_tracker is None:
                        sub_tracker = TopK(capacity=self._top_capacity)
                        self._top_rcode_subdomains[rcode] = sub_tracker
                    sub_tracker.add(domain)

            if self._store is not None and not self.query_log_only:
                try:
                    self._store.increment_count("rcodes", rcode)
                    if base:
                        key = f"{rcode}|{base}"
                        self._store.increment_count("rcode_domains", key)
                        if domain and domain != base:
                            sub_key = f"{rcode}|{domain}"
                            self._store.increment_count("rcode_subdomains", sub_key)
                except Exception:  # pragma: no cover
                    logger.debug(
                        "StatsCollector: failed to persist rcode", exc_info=True
                    )
