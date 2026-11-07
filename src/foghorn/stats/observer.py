"""StatsCollectorObserver: map resolve telemetry events to StatsCollector.

Brief:
    Owns the domain-specific policy formerly embedded in resolve pipeline
    stages (pre-plugin deny/override fan-out, cache/upstream/finalize recording).

Inputs:
    - StatsCollector (or duck-typed record_* object).
    - ResolveEvent values from foghorn.servers.resolve_telemetry.

Outputs:
    - Side effects via collector.record_* methods.
"""

from __future__ import annotations

import logging
from typing import Any

from foghorn.servers.resolve_telemetry import (
    ResolveEvent,
    ResolveEventKind,
    latency_since,
)

logger = logging.getLogger("foghorn.stats.observer")


class StatsCollectorObserver:
    """Map ResolveEvent values onto StatsCollector.record_* calls.

    Inputs:
        stats: StatsCollector-like object exposing record_* methods.

    Outputs:
        Observer instance for ResolveTelemetry.
    """

    __slots__ = ("_stats",)

    def __init__(self, stats: object) -> None:
        """Bind to a stats collector.

        Inputs:
            stats: Collector used for all record_* calls.

        Outputs:
            None.
        """
        self._stats = stats

    def on_event(self, event: ResolveEvent) -> None:
        """Dispatch one resolve event to the appropriate record sequence.

        Inputs:
            event: ResolveEvent from the pipeline.

        Outputs:
            None.
        """
        kind = event.kind
        if kind is ResolveEventKind.QUERY_RECEIVED:
            self._on_query_received(event)
        elif kind is ResolveEventKind.GATE_SHORT_CIRCUIT:
            self._on_gate_short_circuit(event)
        elif kind is ResolveEventKind.PRE_PLUGIN_DECISION:
            self._on_pre_plugin_decision(event)
        elif kind is ResolveEventKind.CACHE_LOOKUP:
            self._on_cache_lookup(event)
        elif kind is ResolveEventKind.UPSTREAM_ATTEMPT:
            self._on_upstream_attempt(event)
        elif kind is ResolveEventKind.POST_PLUGIN_DECISION:
            self._on_post_plugin_decision(event)
        elif kind is ResolveEventKind.RESPONSE_FINALIZED:
            self._on_response_finalized(event)

    def _stats_call(self, name: str, *args: Any, **kwargs: Any) -> None:
        """Best-effort call of a collector method by name."""
        stats = self._stats
        try:
            fn = getattr(stats, name, None)
            if callable(fn):
                fn(*args, **kwargs)
        except Exception:
            logger.debug("StatsCollectorObserver.%s failed", name, exc_info=True)

    def _record_latency(self, event: ResolveEvent) -> None:
        elapsed = latency_since(event.t0)
        if elapsed is not None:
            self._stats_call("record_latency", elapsed)

    def _on_query_received(self, event: ResolveEvent) -> None:
        self._stats_call(
            "record_query",
            event.client_ip,
            event.qname,
            event.qtype_label or "UNKNOWN",
        )

    def _on_gate_short_circuit(self, event: ResolveEvent) -> None:
        """Mirror server_resolve_context._finish_early_result stats path."""
        rcode = event.rcode_name or "UNKNOWN"
        if event.record_rcode:
            self._stats_call("record_response_rcode", rcode, event.qname)
        if event.record_query_result:
            result = dict(event.result or {})
            if event.request_result_meta:
                # Prefer explicit result already merged by caller; only fill gaps.
                for k, v in event.request_result_meta.items():
                    result.setdefault(k, v)
            self._stats_call(
                "record_query_result",
                client_ip=event.client_ip,
                qname=event.qname,
                qtype=event.qtype_label or "UNKNOWN",
                rcode=rcode,
                upstream_id=event.upstream_id,
                status=event.status,
                error=event.error,
                first=event.first,
                result=result or None,
            )
        self._record_latency(event)

    def _suppressed_drop(self, *, rcode: str | None, status: str | None) -> None:
        stats = self._stats
        try:
            handler = getattr(stats, "record_suppressed_query_log_drop_candidate", None)
            if callable(handler):
                handler(rcode=rcode, status=status)
        except Exception:
            logger.debug("suppressed query_log drop failed", exc_info=True)

    def _on_pre_plugin_decision(self, event: ResolveEvent) -> None:
        action = str(event.action or "")
        if action == "drop":
            self._suppressed_drop(rcode="DROP", status="drop")
            return

        if action == "deny":
            ede_code = event.ede_code
            if ede_code is not None:
                self._stats_call("record_ede_code", ede_code)
            self._stats_call("record_cache_null", event.qname, status="deny_pre")
            if event.stat_label:
                self._stats_call("record_cache_stat", str(event.stat_label))
            short = str(event.plugin_label or "").strip()
            label = f"pre_deny_{short}" if short else "pre_deny_plugin"
            deny_source = short if short else "pre_plugin"
            self._stats_call("record_cache_pre_plugin", label)
            self._stats_call("record_response_rcode", "NXDOMAIN", event.qname)
            if event.suppress_query_log:
                self._suppressed_drop(rcode="NXDOMAIN", status="deny_pre")
            else:
                result_ctx: dict[str, Any] = {
                    "source": deny_source,
                    "action": "deny",
                }
                if ede_code is not None:
                    result_ctx["ede_code"] = int(ede_code)
                    result_ctx["ede_text"] = str(event.ede_text or "")
                if deny_source != "pre_plugin":
                    result_ctx["plugin"] = deny_source
                if event.request_result_meta:
                    result_ctx.update(event.request_result_meta)
                self._stats_call(
                    "record_query_result",
                    client_ip=event.client_ip,
                    qname=event.qname,
                    qtype=event.qtype_label or "UNKNOWN",
                    rcode="NXDOMAIN",
                    upstream_id=None,
                    status="deny_pre",
                    error=None,
                    first=None,
                    result=result_ctx,
                )
            self._record_latency(event)
            return

        if action == "override":
            if event.dnssec_status is not None:
                self._stats_call("record_dnssec_status", event.dnssec_status)
            rcode_name = event.rcode_name or "UNKNOWN"
            self._stats_call("record_cache_null", event.qname, status="override_pre")
            if event.stat_label:
                self._stats_call("record_cache_stat", str(event.stat_label))
            short = str(event.plugin_label or "").strip()
            if short:
                label = f"pre_override_{short}"
                override_source = short
            else:
                label = "pre_override_plugin"
                override_source = "pre_plugin_override"
            self._stats_call("record_cache_pre_plugin", label)
            self._stats_call("record_response_rcode", rcode_name, event.qname)
            if event.suppress_query_log:
                self._suppressed_drop(rcode=rcode_name, status="override_pre")
            else:
                result_ctx = {
                    "source": override_source,
                    "answers": list(event.answers or []),
                }
                if override_source != "pre_plugin_override":
                    result_ctx["plugin"] = override_source
                if event.request_result_meta:
                    result_ctx.update(event.request_result_meta)
                self._stats_call(
                    "record_query_result",
                    client_ip=event.client_ip,
                    qname=event.qname,
                    qtype=event.qtype_label or "UNKNOWN",
                    rcode=rcode_name,
                    upstream_id=None,
                    status="override_pre",
                    error=None,
                    first=event.first,
                    result=result_ctx,
                )
            self._record_latency(event)

    def _on_cache_lookup(self, event: ResolveEvent) -> None:
        outcome = str(event.cache_outcome or "")
        if outcome == "miss":
            self._stats_call("record_cache_miss", event.qname)
            return
        if outcome != "hit":
            return
        self._stats_call("record_cache_hit", event.qname)
        rcode = event.rcode_name or "UNKNOWN"
        self._stats_call("record_response_rcode", rcode, event.qname)
        result_ctx: dict[str, Any] = {
            "source": "cache",
            "answers": list(event.answers or []),
        }
        if event.request_result_meta:
            result_ctx.update(event.request_result_meta)
        self._stats_call(
            "record_query_result",
            client_ip=event.client_ip,
            qname=event.qname,
            qtype=event.qtype_label or "UNKNOWN",
            rcode=rcode,
            upstream_id=None,
            status="cache_hit",
            error=None,
            first=event.first,
            result=result_ctx,
        )
        self._record_latency(event)

    def _on_upstream_attempt(self, event: ResolveEvent) -> None:
        if event.upstream_id and event.upstream_outcome:
            self._stats_call(
                "record_upstream_result",
                event.upstream_id,
                event.upstream_outcome,
            )
        if not event.total_failure:
            return
        if event.ede_code is not None:
            self._stats_call("record_ede_code", event.ede_code)
        rcode = event.rcode_name or "SERVFAIL"
        self._stats_call("record_response_rcode", rcode, event.qname)
        if event.upstream_id:
            self._stats_call("record_upstream_rcode", event.upstream_id, rcode)
        result_ctx: dict[str, Any] = dict(event.result or {})
        if event.request_result_meta:
            result_ctx.update(event.request_result_meta)
        if event.upstream_id:
            result_ctx.setdefault("upstream", str(event.upstream_id))
        if event.upstream_url:
            result_ctx.setdefault("upstream_url", str(event.upstream_url))
        self._stats_call(
            "record_query_result",
            client_ip=event.client_ip,
            qname=event.qname,
            qtype=event.qtype_label or "UNKNOWN",
            rcode=rcode,
            upstream_id=event.upstream_id,
            status=event.status or str(event.upstream_outcome or "all_failed"),
            error=event.error,
            first=None,
            result=result_ctx or None,
        )
        self._record_latency(event)

    def _on_post_plugin_decision(self, event: ResolveEvent) -> None:
        if str(event.action or "") == "drop":
            self._suppressed_drop(rcode="DROP", status="drop")

    def _on_response_finalized(self, event: ResolveEvent) -> None:
        dnssec_for_totals = event.dnssec_recorded
        if dnssec_for_totals is None:
            dnssec_for_totals = event.dnssec_status
        if dnssec_for_totals is not None:
            self._stats_call("record_dnssec_status", dnssec_for_totals)
        if event.ede_code is not None:
            self._stats_call("record_ede_code", event.ede_code)
        rcode = event.rcode_name or "UNKNOWN"
        self._stats_call("record_response_rcode", rcode, event.qname)
        if event.upstream_id:
            self._stats_call("record_upstream_rcode", event.upstream_id, rcode)
        result_ctx: dict[str, Any] = {
            "source": "upstream",
            "answers": list(event.answers or []),
        }
        if event.upstream_id:
            result_ctx["upstream"] = str(event.upstream_id)
        if event.upstream_url:
            result_ctx["upstream_url"] = str(event.upstream_url)
        if event.dnssec_status is not None:
            result_ctx["dnssec_status"] = event.dnssec_status
        if event.ede_code is not None:
            result_ctx["ede_code"] = int(event.ede_code)
            if event.ede_text is not None:
                result_ctx["ede_text"] = str(event.ede_text)
        if event.request_result_meta:
            result_ctx.update(event.request_result_meta)
        status = event.status
        if status is None:
            status = "ok" if rcode == "NOERROR" else "error"
        self._stats_call(
            "record_query_result",
            client_ip=event.client_ip,
            qname=event.qname,
            qtype=event.qtype_label or "UNKNOWN",
            rcode=rcode,
            upstream_id=event.upstream_id,
            status=status,
            error=event.error,
            first=event.first,
            result=result_ctx,
        )
        self._record_latency(event)
