"""Upstream resolution (recursive/master/forward) for the resolve pipeline."""

from __future__ import annotations

import logging
import random
import time as _time
from typing import Any

from dnslib import RCODE

from foghorn.plugins.resolve import base as plugin_base

from .dns_runtime_state import DNSRuntimeState
from .server_opcode import _ResolveCoreResult
from .server_response_utils import (
    _attach_ede_option,
    _echo_client_edns,
    _set_response_id,
)

logger = logging.getLogger("foghorn.server")


def _resolve_upstream(
    *,
    req: object,
    data: bytes,
    client_ip: str,
    qname: str,
    qtype: object,
    handler: object,
    snap: object | None,
    stats: object | None,
    t0: float | None,
    request_result_meta: dict[str, Any],
    ede_code_for_logs: int | None,
    ede_text_for_logs: str | None,
    send_query_with_failover,
    ensure_edns_request,
    sanitize_upstream_url,
    qtype_label_fn,
) -> tuple[
    bytes | None,
    dict[str, Any] | None,
    str | None,
    str,
    str | None,
    int | None,
    str | None,
    _ResolveCoreResult | None,
]:
    """Brief: Resolve via recursive, master, or forward upstream path.

    Inputs:
      - req/data/client_ip/qname/qtype: Query.
      - handler/snap/stats/t0/request_result_meta: Runtime.
      - ede_code_for_logs/ede_text_for_logs: Optional EDE already set.
      - send_query_with_failover/ensure_edns_request/sanitize_upstream_url/
        qtype_label_fn: Injected helpers.

    Outputs:
      - (reply, used_upstream, reason, upstream_url, upstream_id,
         ede_code_for_logs, ede_text_for_logs, early_result).
        early_result is set on all-upstreams-failed SERVFAIL short-circuit.
    """

    _qtype_label_for_stats = qtype_label_fn
    _sanitize_upstream_url = sanitize_upstream_url

    def _send_query_with_failover(*args, **kwargs):
        return send_query_with_failover(*args, **kwargs)

    def _ensure_edns_request(*args, **kwargs):
        return ensure_edns_request(*args, **kwargs)

    reply: bytes | None = None
    used_upstream: dict | None = None
    reason: str | None = None
    upstream_url = ""
    upstream_id: str | None = None

    # Decide between forwarding, recursion, and authoritative-only (no
    # forwarding) based on resolver_mode.
    resolver_mode = str(getattr(handler, "resolver_mode", "forward")).lower()
    # Backward-compatible alias: "none" historically meant authoritative-only
    # mode (no forwarding), which is now called "master".
    if resolver_mode == "none":
        resolver_mode = "master"

    if resolver_mode == "recursive":
        # Prefer the symbol exported by foghorn.servers.server so tests can
        # monkeypatch RecursiveResolver on that module.
        from foghorn.servers.server import RecursiveResolver

        # In recursive mode we bypass configured upstreams and instead walk
        # from the root using RecursiveResolver. We still honour the
        # dnssec_mode when constructing the query (RD bit and EDNS DO bit
        # are already handled earlier in the pipeline) and we reuse
        # DNSUDPHandler's recursion knobs.
        try:
            max_depth = int(getattr(handler, "recursive_max_depth", 12) or 12)
        except Exception:  # pragma: no cover - defensive
            max_depth = 12
        try:
            recursion_timeout_ms = int(
                getattr(
                    handler,
                    "recursive_timeout_ms",
                    getattr(handler, "timeout_ms", 2000),
                )
                or getattr(handler, "timeout_ms", 2000)
            )
        except Exception:  # pragma: no cover - defensive
            recursion_timeout_ms = int(getattr(handler, "timeout_ms", 2000) or 2000)
        try:
            per_try_ms = int(
                getattr(
                    handler,
                    "recursive_per_try_timeout_ms",
                    recursion_timeout_ms,
                )
                or recursion_timeout_ms
            )
        except Exception:  # pragma: no cover - defensive
            per_try_ms = recursion_timeout_ms

        allow_private_destinations = True
        destination_allowlist: list[str] = []
        try:
            if snap is not None:
                resolver_cfg_snap = (
                    (snap.cfg.get("server") or {}).get("resolver")
                    if isinstance(getattr(snap, "cfg", None), dict)
                    else {}
                )
                if not isinstance(resolver_cfg_snap, dict):
                    resolver_cfg_snap = {}
                allow_private_destinations = bool(
                    resolver_cfg_snap.get("allow_private_destinations", True)
                )
                raw_allow = resolver_cfg_snap.get("destination_allowlist") or []
                if isinstance(raw_allow, list):
                    destination_allowlist = [
                        str(x).strip() for x in raw_allow if str(x).strip()
                    ]
        except Exception:
            allow_private_destinations = True
            destination_allowlist = []

        resolver = RecursiveResolver(
            cache=getattr(plugin_base, "DNS_CACHE", None),
            stats=stats,
            max_depth=max_depth,
            timeout_ms=recursion_timeout_ms,
            per_try_timeout_ms=per_try_ms,
            allow_private_destinations=allow_private_destinations,
            destination_allowlist=destination_allowlist,
        )

        # Perform iterative resolution. RecursiveResolver is responsible for
        # talking to upstream authorities; we only receive the final wire
        # and an optional upstream identifier for stats.
        reply, upstream_id = resolver.resolve(req)
        reason = "ok" if reply is not None else "all_failed"
    elif resolver_mode == "master":
        # Authoritative-only mode: do not forward or recurse. Plugins still
        # run (pre/post), but any cache miss falls through to REFUSED.
        upstream_id = None
        r = req.reply()
        r.header.rcode = RCODE.REFUSED
        # Echo client EDNS(0) OPT and attach an EDE explaining the policy
        # when enabled.
        _echo_client_edns(req, r)
        ede_code_for_logs = 15
        ede_text_for_logs = "forwarding disabled (resolver.mode=master)"
        _attach_ede_option(req, r, ede_code_for_logs, ede_text_for_logs)  # Blocked
        reply = r.pack()
        reason = "no_forwarding"
    else:
        # Classic forwarding: EDNS/DNSSEC adjustments (mirror
        # DNSUDPHandler behaviour) followed by send_query_with_failover.
        # When no upstreams are configured we skip EDNS normalization so that
        # synthesized SERVFAIL responses can echo the client's original OPT
        # record unchanged.
        primary_upstreams = list(getattr(handler, "upstream_addrs", []) or [])
        backup_upstreams = list(getattr(handler, "upstream_backup_addrs", []) or [])
        probe_percent = 1.0
        probe_min_percent = 1.0
        probe_max_percent = 50.0
        probe_increase = 1.0
        probe_decrease = 2.0
        max_recheck = 300.0
        try:
            health_cfg = getattr(handler, "upstream_health", None)
            probe_percent = float(getattr(health_cfg, "probe_percent", 1.0) or 1.0)
            probe_min_percent = float(
                getattr(health_cfg, "probe_min_percent", 1.0) or 1.0
            )
            probe_max_percent = float(
                getattr(health_cfg, "probe_max_percent", 50.0) or 50.0
            )
            probe_increase = float(getattr(health_cfg, "probe_increase", 1.0) or 1.0)
            probe_decrease = float(getattr(health_cfg, "probe_decrease", 2.0) or 2.0)
            max_recheck = float(getattr(health_cfg, "max_recheck", 300.0) or 300.0)
        except Exception:
            probe_percent = 1.0
            probe_min_percent = 1.0
            probe_max_percent = 50.0
            probe_increase = 1.0
            probe_decrease = 2.0
            max_recheck = 300.0
        if probe_min_percent > probe_max_percent:
            probe_min_percent, probe_max_percent = (
                probe_max_percent,
                probe_min_percent,
            )
        probe_min_percent = max(0.0, min(100.0, probe_min_percent))
        probe_max_percent = max(probe_min_percent, min(100.0, probe_max_percent))
        probe_increase = max(0.0, probe_increase)
        probe_decrease = max(0.0, probe_decrease)
        max_recheck = max(0.0, min(86400.0, max_recheck))
        DNSRuntimeState.upstream_max_recheck = max_recheck
        probe_percent = max(probe_min_percent, min(probe_max_percent, probe_percent))
        current_probe_percent = DNSRuntimeState.upstream_probe_percent
        if current_probe_percent is None:
            current_probe_percent = probe_percent
        current_probe_percent = max(
            probe_min_percent,
            min(probe_max_percent, float(current_probe_percent)),
        )

        def _select_upstreams_with_probe(
            candidates: list[dict],
        ) -> tuple[list[dict], int]:
            now = _time.time()
            selected: list[dict] = []
            healthy_count = 0
            for upstream in candidates or []:
                if not isinstance(upstream, dict):
                    continue
                up_id = DNSRuntimeState._upstream_id(upstream)
                if not up_id:
                    selected.append(upstream)
                    healthy_count += 1
                    continue
                entry = DNSRuntimeState.upstream_health.get(up_id)
                down_until = (
                    float(entry.get("down_until", 0.0))
                    if isinstance(entry, dict)
                    else 0.0
                )
                if down_until > now:
                    if current_probe_percent > 0.0:
                        try:
                            if random.random() * 100.0 < current_probe_percent:
                                selected.append(upstream)
                        except Exception:
                            pass
                    continue
                selected.append(upstream)
                healthy_count += 1
            return selected, healthy_count

        def _all_primaries_degraded(candidates: list[dict]) -> bool:
            """Brief: True when all primary upstreams are degraded/down.

            Inputs:
              - candidates: List of primary upstream mappings.

            Outputs:
              - bool: True when no primary is fully healthy.
            """
            now = _time.time()
            saw_primary = False
            for upstream in candidates or []:
                if not isinstance(upstream, dict):
                    continue
                saw_primary = True
                up_id = DNSRuntimeState._upstream_id(upstream)
                if not up_id:
                    return False
                entry = DNSRuntimeState.upstream_health.get(up_id)
                if not isinstance(entry, dict):
                    return False
                try:
                    down_until = float(entry.get("down_until", 0.0) or 0.0)
                except Exception:
                    down_until = 0.0
                if down_until <= now:
                    return False
            return True if saw_primary else True

        primary_selected, primary_healthy_count = _select_upstreams_with_probe(
            primary_upstreams
        )
        backup_selected, _backup_healthy_count = _select_upstreams_with_probe(
            backup_upstreams
        )
        # Backup upstreams are only considered when all primaries are
        # degraded (or none configured). Otherwise failover stays within
        # the primary list order.
        primaries_degraded = _all_primaries_degraded(primary_upstreams)
        if primary_selected and primary_healthy_count > 0 and not primaries_degraded:
            upstreams = primary_selected
        elif backup_selected:
            upstreams = backup_selected
        else:
            upstreams = primary_selected
        try:
            strategy = str(getattr(handler, "upstream_strategy", "failover")).lower()
        except Exception:
            strategy = "failover"
        if strategy == "round_robin" and upstreams:
            try:
                idx = int(getattr(DNSRuntimeState, "_upstream_rr_index", 0) or 0)
            except Exception:
                idx = 0
            offset = idx % len(upstreams)
            upstreams = upstreams[offset:] + upstreams[:offset]
            DNSRuntimeState._upstream_rr_index = (idx + 1) % len(upstreams)
        elif strategy == "random" and len(upstreams) > 1:
            upstreams = list(upstreams)
            try:
                random.shuffle(upstreams)
            except Exception:
                pass
        try:
            mode = str(getattr(handler, "dnssec_mode", "ignore")).lower()
            if mode in ("ignore", "passthrough", "validate") and upstreams:
                edns_helper = type("_H", (), {})()
                edns_helper.dnssec_mode = getattr(handler, "dnssec_mode", "ignore")
                edns_helper.edns_udp_payload = getattr(
                    handler, "edns_udp_payload", 1232
                )
                ensure = getattr(handler, "_ensure_edns", None)
                if callable(ensure):
                    ensure(edns_helper, req)
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably

        # Forward with failover using the same helper as UDP handlers. Tests
        # frequently monkeypatch send_query_with_failover directly, so we call
        # it here rather than DNSUDPHandler._forward_with_failover_helper.
        upstream_id = None
        timeout_ms = getattr(handler, "timeout_ms", 2000)
        try:
            max_concurrent = int(
                getattr(handler, "upstream_max_concurrent", 1) or 1
            )  # pragma: no cover - defensive/metrics path excluded from coverage
        except (
            Exception
        ):  # pragma: no cover - defensive/metrics path excluded from coverage
            max_concurrent = 1
        if (
            max_concurrent < 1
        ):  # pragma: no cover - defensive/metrics path excluded from coverage
            max_concurrent = 1
        reply, used_upstream, reason = send_query_with_failover(
            req,
            upstreams,
            timeout_ms,
            qname,
            qtype,
            max_concurrent=max_concurrent,
        )
        upstream_url = ""
        if isinstance(used_upstream, dict):
            try:
                raw_upstream_url = str(used_upstream.get("url", "")).strip()
            except Exception:
                raw_upstream_url = ""
            if raw_upstream_url:
                upstream_url = _sanitize_upstream_url(raw_upstream_url)
        # Keep upstream health state in sync for admin/status payloads.
        # The UDP handler delegates to this shared resolver path, so health
        # updates must happen here as well.
        if reply is None:
            DNSRuntimeState._mark_upstreams_down(
                upstreams,
                reason,
                max_recheck=max_recheck,
            )
            DNSRuntimeState.upstream_probe_percent = min(
                probe_max_percent,
                max(
                    probe_min_percent,
                    float(current_probe_percent) + float(probe_increase),
                ),
            )
        else:
            DNSRuntimeState._mark_upstream_ok(used_upstream)
            DNSRuntimeState.upstream_probe_percent = min(
                probe_max_percent,
                max(
                    probe_min_percent,
                    float(current_probe_percent) - float(probe_decrease),
                ),
            )

    # Record upstream result, even when all upstreams ultimately fail.
    if stats is not None and used_upstream:
        try:
            host = str(used_upstream.get("host", ""))
            port = int(used_upstream.get("port", 0))
            # For DoH-style upstreams identified by URL, prefer that as the
            # upstream_id so stats can distinguish endpoints consistently.
            url = str(upstream_url or "").strip()
            if url:
                upstream_id = url
            else:
                upstream_id = f"{host}:{port}" if host or port else host or "unknown"
            outcome = "success" if reason == "ok" else str(reason)
            stats.record_upstream_result(upstream_id, outcome)
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass

    if reply is None:
        r = req.reply()
        r.header.rcode = RCODE.SERVFAIL

        # When synthesizing SERVFAIL (for example, when there are no
        # upstreams or all upstreams fail), echo any client EDNS(0) OPT RR
        # into the response so payload size and flags are preserved, and
        # attach an EDE option describing the upstream/network failure when
        # enabled.
        _echo_client_edns(req, r)
        ede_code = 23
        ede_text = "all upstreams failed"
        _attach_ede_option(req, r, ede_code, ede_text)  # Network Error

        wire = _set_response_id(r.pack(), req.header.id)
        if stats is not None:
            try:
                # Record both rcode and EDE info-code for this synthetic
                # SERVFAIL so that metrics and query_log consumers can
                # distinguish upstream/network failures from other errors.
                if hasattr(stats, "record_ede_code"):
                    try:
                        stats.record_ede_code(ede_code)
                    except Exception:  # pragma: no cover - defensive metrics hook
                        pass
                stats.record_response_rcode("SERVFAIL", qname)
                if upstream_id:
                    try:
                        stats.record_upstream_rcode(upstream_id, "SERVFAIL")
                    except (
                        Exception
                    ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                        pass
                qtype_name = _qtype_label_for_stats(qtype)
                status = str(reason or "all_failed")
                result_ctx = {
                    "source": "upstream",
                    "status": status,
                    "error": "all_upstreams_failed",
                    "ede_code": int(ede_code),
                    "ede_text": str(ede_text),
                }
                if upstream_id:
                    result_ctx["upstream"] = str(upstream_id)
                if upstream_url:
                    result_ctx["upstream_url"] = str(upstream_url)
                result_ctx.update(request_result_meta)
                stats.record_query_result(
                    client_ip=client_ip,
                    qname=qname,
                    qtype=qtype_name,
                    rcode="SERVFAIL",
                    upstream_id=upstream_id,
                    status=status,
                    error="all_upstreams_failed",
                    first=None,
                    result=result_ctx,
                )
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass
            # Record latency for the all-upstreams-failed path as well so
            # stats callers see a duration for every resolved query.
            if t0 is not None:
                try:
                    t1 = _time.perf_counter()
                    stats.record_latency(t1 - t0)
                except (
                    Exception
                ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    pass
        early = _ResolveCoreResult(
            wire=wire,
            dnssec_status=None,
            upstream_id=upstream_id,
            rcode_name="SERVFAIL",
        )
        return (
            None,
            used_upstream,
            reason,
            upstream_url,
            upstream_id,
            ede_code_for_logs,
            ede_text_for_logs,
            early,
        )

    return (
        reply,
        used_upstream,
        reason,
        upstream_url,
        upstream_id,
        ede_code_for_logs,
        ede_text_for_logs,
        None,
    )
