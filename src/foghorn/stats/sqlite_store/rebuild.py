from __future__ import annotations

import json
import logging
from typing import Any, Optional

from ..domain import _base_domain, _is_subdomain, _normalize_domain

logger = logging.getLogger("foghorn.stats")


class _RebuildMixin:
    def rebuild_counts_from_query_log(
        self, logger_obj: Optional[logging.Logger] = None
    ) -> None:
        """Rebuild counts table by aggregating over all rows in query_log.

        Inputs:
            logger_obj: Optional logger to use for warnings/errors.

        Outputs:
            Noneh

        Notes:
            - Existing counts are cleared before recomputation.
            - Aggregation approximates the live StatsCollector behavior by
              incrementing totals, qtypes, clients, domains/subdomains,
              rcodes, upstreams, and upstream_qtypes based on each
              query_log row.
            - Cache-domain aggregates include both base-domain views
              (cache_*_domains) and subdomain views (cache_*_subdomains)
              where subdomain names are full qnames.
            - Per-rcode aggregates include both base-domain views
              (rcode_domains) and subdomain views (rcode_subdomains).
            - Upstream aggregates include both outcome and rcode in the stored
              key so that rcodes can be associated with upstream outcomes when
              warm-loading from the persistent store.
            - Upstream_qtypes aggregates store 'upstream_id|qtype' keys for
              per-upstream query type breakdowns.
        """
        log = logger_obj or logger
        log.warning(
            "Rebuilding statistics counts from query_log; this may take a while"
        )

        # When batch_writes is enabled, there may be pending INSERTs into
        # query_log that have not yet been flushed to the database. Flush them
        # up front so the rebuild sees a complete view of the log.
        if self._batch_writes:
            with (
                self._lock
            ):  # pragma: no cover - batching lock path exercised indirectly
                self._flush_locked()

        # Clear existing counts so we always rebuild from a clean slate.
        try:
            with self._conn:  # type: ignore[attr-defined]
                self._conn.execute("DELETE FROM counts")  # type: ignore[attr-defined]
        except Exception as exc:  # pragma: no cover
            log.error(
                "Failed to clear counts table before rebuild: %s", exc, exc_info=True
            )
            return

        try:
            cur = self._conn.cursor()  # type: ignore[attr-defined]
            cur.execute(
                "SELECT client_ip, name, qtype, upstream_id, rcode, status, error, result_json FROM query_log"
            )
            for (
                client_ip,
                name,
                qtype,
                upstream_id,
                rcode,
                status,
                error,
                result_json,
            ) in cur:
                domain = _normalize_domain(name or "")
                base = _base_domain(domain)

                # Total queries
                self.increment_count("totals", "total_queries", 1)

                # Cache hits/misses/cache_null (best-effort approximation).
                # These semantics mirror the live StatsCollector behavior:
                # - 'cache_hit' rows are treated as cache hits.
                # - Pre-plugin deny/override rows ('deny_pre'/'override_pre')
                #   are treated as 'cache_null' since no cache lookup occurs.
                # - All other statuses are treated as cache misses.
                if status == "cache_hit":
                    self.increment_count("totals", "cache_hits", 1)
                elif status in ("deny_pre", "override_pre"):
                    self.increment_count("totals", "cache_" + status, 1)
                    self.increment_count("totals", "cache_null", 1)
                else:
                    self.increment_count("totals", "cache_misses", 1)

                # Per-outcome cache-domain aggregates using base domains when
                # available so that warm-loaded top lists align with the
                # in-process StatsCollector tracking. Subdomain-oriented views
                # retain the full qname for *_subdomains scopes.
                if base:
                    if status == "cache_hit":
                        self.increment_count("cache_hit_domains", base, 1)
                    elif status not in ("deny_pre", "override_pre"):
                        # Treat all non-cache_hit, non-cache_null rows as
                        # cache misses for domain-level aggregates.
                        self.increment_count("cache_miss_domains", base, 1)

                # Subdomain-only cache aggregates keyed by full qname.
                if domain and base and _is_subdomain(domain):
                    if status == "cache_hit":
                        self.increment_count("cache_hit_subdomains", domain, 1)
                    elif status not in ("deny_pre", "override_pre"):
                        self.increment_count("cache_miss_subdomains", domain, 1)

                # Qtype breakdown
                if qtype:
                    self.increment_count("qtypes", str(qtype), 1)

                # Clients
                if client_ip:
                    self.increment_count("clients", str(client_ip), 1)

                # Domains and subdomains: only treat names with at least three
                # labels as subdomains for aggregation purposes.
                if domain:
                    if _is_subdomain(domain):
                        self.increment_count("sub_domains", domain, 1)
                    if base:
                        self.increment_count("domains", base, 1)

                # Per-qtype domain counters for all qtypes.
                if domain and qtype:
                    qkey = f"{qtype}|{domain}"
                    self.increment_count("qtype_qnames", qkey, 1)

                # Rcodes
                if rcode:
                    self.increment_count("rcodes", str(rcode), 1)
                    if base:
                        rkey = f"{rcode}|{base}"
                        self.increment_count("rcode_domains", rkey, 1)
                    if domain and base and _is_subdomain(domain):
                        sub_rkey = f"{rcode}|{domain}"
                        self.increment_count("rcode_subdomains", sub_rkey, 1)

                # Upstreams
                if upstream_id:
                    # Approximate outcome classification using status/rcode.
                    outcome = "success"
                    if rcode != "NOERROR" or (
                        status and status not in ("ok", "cache_hit")
                    ):
                        outcome = str(status or "error")

                    # Include rcode in the upstream key so that we can
                    # reconstruct both outcome and rcode aggregates when
                    # warm-loading from the persistent store.
                    rcode_key = str(rcode or "UNKNOWN")
                    key = f"{upstream_id}|{outcome}|{rcode_key}"
                    self.increment_count("upstreams", key, 1)

                    # Track per-upstream qtype breakdowns as 'upstream_id|qtype'.
                    if qtype:
                        qt_key = f"{upstream_id}|{qtype}"
                        self.increment_count("upstream_qtypes", qt_key, 1)

                # DNSSEC outcome (when present in result_json)
                if result_json:
                    dnssec_status = None
                    payload: Any = None
                    try:
                        payload = json.loads(result_json)
                        dnssec_status = (
                            payload.get("dnssec_status")
                            if isinstance(payload, dict)
                            else None
                        )
                    except Exception:
                        dnssec_status = None

                    if dnssec_status in {
                        "dnssec_secure",
                        "dnssec_zone_secure",
                        "dnssec_unsigned",
                        "dnssec_bogus",
                        "dnssec_indeterminate",
                    }:
                        # dnssec_status values are already fully-qualified
                        # keys in the new scheme (for example, 'dnssec_secure').
                        self.increment_count("totals", dnssec_status, 1)

                    # Extended DNS Errors (EDE) derived from result_json, when
                    # present, are aggregated into totals.ede_<code> counters so
                    # warm-loaded statistics expose the same view as the live
                    # StatsCollector record_ede_code() path.
                    ede_val = None
                    if isinstance(payload, dict):
                        try:
                            ede_val = payload.get("ede_code")
                        except Exception:
                            ede_val = None
                    if ede_val is not None:
                        try:
                            ede_code_int = int(ede_val)
                        except (TypeError, ValueError):
                            ede_code_int = None
                        if ede_code_int is not None and ede_code_int >= 0:
                            ede_key = f"ede_{ede_code_int}"
                            self.increment_count("totals", ede_key, 1)

            # Ensure any batched operations are flushed so that export_counts()
            # immediately observes the recomputed aggregates when this method
            # returns.
            if self._batch_writes:
                with (
                    self._lock
                ):  # pragma: no cover - batching lock path exercised indirectly
                    self._flush_locked()
        except Exception as exc:  # pragma: no cover
            log.error(
                "Error while rebuilding counts from query_log: %s", exc, exc_info=True
            )

    def rebuild_counts_if_needed(
        self, force_rebuild: bool = False, logger_obj: Optional[logging.Logger] = None
    ) -> None:
        """Conditionally rebuild counts table based on current DB state and flags.

        Inputs:
            force_rebuild: If True, always rebuild counts when query_log has rows.
            logger_obj: Optional logger to use for warnings/errors.

        Outputs:
            None

        Behavior:
            - If query_log is empty, no rebuild is performed.
            - If counts is empty and query_log is not, a rebuild is performed.
            - If force_rebuild is True and query_log is not empty, a rebuild is
              performed even when counts already has data.
        """
        log = logger_obj or logger
        has_counts = self.has_counts()
        has_log = self.has_query_log()

        if not has_log:
            if force_rebuild:
                log.warning(
                    "Force rebuild requested but query_log is empty; skipping rebuild",
                )
            return

        if has_counts and not force_rebuild:
            # Normal case: counts already present and no override requested.
            return

        if has_counts and force_rebuild:
            log.warning(
                "Force rebuild requested: discarding existing counts and rebuilding from query_log",
            )
        elif not has_counts:
            log.warning(
                "Counts table is empty but query_log has rows; rebuilding counts from query_log",
            )

        self.rebuild_counts_from_query_log(logger_obj=log)
