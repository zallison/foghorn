"""Resolution setup helpers for the shared DNS resolve pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from .dns_runtime_state import DNSRuntimeState
from .server_opcode import _ResolveCoreResult


def _build_handler_from_snapshot(snap: object) -> object:
    """Brief: Map a runtime snapshot onto a handler-like namespace.

    Inputs:
      - snap: Runtime snapshot from get_runtime_snapshot(), or None.

    Outputs:
      - Handler-like object: SimpleNamespace when snap is set, else DNSRuntimeState.
    """

    if snap is None:
        return DNSRuntimeState

    return SimpleNamespace(
        stats_collector=snap.stats_collector,
        plugins=list(snap.plugins or []),
        upstream_addrs=list(snap.upstream_addrs or []),
        upstream_backup_addrs=list(snap.upstream_backup_addrs or []),
        upstream_health=snap.upstream_health,
        timeout_ms=int(snap.timeout_ms),
        upstream_strategy=str(snap.upstream_strategy or "failover").lower(),
        upstream_max_concurrent=max(1, int(snap.upstream_max_concurrent or 1)),
        resolver_mode=str(snap.resolver_mode or "forward").lower(),
        recursive_max_depth=int(snap.recursive_max_depth),
        recursive_timeout_ms=int(snap.recursive_timeout_ms),
        recursive_per_try_timeout_ms=int(snap.recursive_per_try_timeout_ms),
        dnssec_mode=str(snap.dnssec_mode or "ignore"),
        dnssec_validation=str(snap.dnssec_validation or "upstream_ad"),
        edns_udp_payload=max(512, int(snap.edns_udp_payload)),
        enable_ede=bool(snap.enable_ede),
        forward_local=bool(snap.forward_local),
        refuse_any=bool(getattr(snap, "refuse_any", False)),
        cookies_enabled=bool(getattr(snap, "cookies_enabled", True)),
        cookies_mode=str(getattr(snap, "cookies_mode", "learn") or "learn"),
        cookies_secret=getattr(snap, "cookies_secret", None),
        cookies_secret_old=getattr(snap, "cookies_secret_old", None),
        cookies_lifetime_seconds=int(
            getattr(snap, "cookies_lifetime_seconds", 86400) or 86400
        ),
        tsig_enabled=bool(getattr(snap, "tsig_enabled", False)),
        tsig_mode=str(getattr(snap, "tsig_mode", "optional") or "optional"),
        tsig_keys=list(getattr(snap, "tsig_keys", []) or []),
        tsig_max_fudge_seconds=int(getattr(snap, "tsig_max_fudge_seconds", 300) or 300),
        tsig_allow_clients=list(getattr(snap, "tsig_allow_clients", []) or []),
        tsig_listeners=list(getattr(snap, "tsig_listeners", []) or []),
        ecs_enabled=bool(getattr(snap, "ecs_enabled", False)),
        ecs_forward_inbound=bool(getattr(snap, "ecs_forward_inbound", False)),
        ecs_synthesize_from_client_ip=bool(
            getattr(snap, "ecs_synthesize_from_client_ip", False)
        ),
        ecs_source_prefix_v4=max(
            0, min(32, int(getattr(snap, "ecs_source_prefix_v4", 24)))
        ),
        ecs_source_prefix_v6=max(
            0, min(128, int(getattr(snap, "ecs_source_prefix_v6", 56)))
        ),
        ecs_scope_prefix_v4=max(
            0, min(32, int(getattr(snap, "ecs_scope_prefix_v4", 0)))
        ),
        ecs_scope_prefix_v6=max(
            0, min(128, int(getattr(snap, "ecs_scope_prefix_v6", 0)))
        ),
        ecs_trusted_listeners=list(getattr(snap, "ecs_trusted_listeners", []) or []),
        ecs_trusted_client_cidrs=list(
            getattr(snap, "ecs_trusted_client_cidrs", []) or []
        ),
        ecs_use_for_plugin_targeting=bool(
            getattr(snap, "ecs_use_for_plugin_targeting", False)
        ),
        min_cache_ttl=max(0, int(snap.min_cache_ttl)),
        cache_prefetch_enabled=bool(snap.cache_prefetch_enabled),
        cache_prefetch_min_ttl=max(0, int(snap.cache_prefetch_min_ttl)),
        cache_prefetch_max_ttl=max(0, int(snap.cache_prefetch_max_ttl)),
        cache_prefetch_refresh_before_expiry=max(
            0.0, float(snap.cache_prefetch_refresh_before_expiry)
        ),
        cache_prefetch_allow_stale_after_expiry=max(
            0.0, float(snap.cache_prefetch_allow_stale_after_expiry)
        ),
        _upstream_id=DNSRuntimeState._upstream_id,
        _ensure_edns=getattr(DNSRuntimeState, "_ensure_edns", None),
    )


def _finish_early_result(
    *,
    wire: bytes,
    rcode_name: str,
    stats: object | None,
    t0: float | None,
    client_ip: str,
    qname: str = "",
    qtype_name: str = "UNKNOWN",
    status: str,
    error: object | None = None,
    result: dict[str, Any] | None = None,
    upstream_id: str | None = None,
    dnssec_status: str | None = None,
    record_rcode: bool = True,
    record_query_result: bool = True,
) -> _ResolveCoreResult:
    """Brief: Record stats/latency for an early-return resolve path.

    Inputs:
      - wire: Response wire bytes (ID already fixed when applicable).
      - rcode_name: Textual rcode for the result.
      - stats: Optional stats collector.
      - t0: Optional perf_counter start time.
      - client_ip: Client IP for query_result logging.
      - qname: Best-effort qname for stats.
      - qtype_name: Qtype label for query_result.
      - status: Status string for query_result.
      - error: Optional error payload for query_result.
      - result: Optional result context dict.
      - upstream_id: Optional upstream id.
      - dnssec_status: Optional DNSSEC status on the result.
      - record_rcode: When True, call record_response_rcode.
      - record_query_result: When True, call record_query_result.

    Outputs:
      - _ResolveCoreResult for the early-return path.
    """

    if stats is not None:
        try:
            from foghorn.servers.resolve_telemetry import (
                ResolveEvent,
                ResolveEventKind,
                telemetry_from_stats,
            )

            telemetry_from_stats(stats).emit(
                ResolveEvent(
                    kind=ResolveEventKind.GATE_SHORT_CIRCUIT,
                    client_ip=client_ip,
                    qname=qname,
                    qtype_label=qtype_name,
                    t0=t0,
                    rcode_name=rcode_name,
                    status=status,
                    error=error,
                    result=result,
                    record_rcode=record_rcode,
                    record_query_result=record_query_result,
                    upstream_id=upstream_id,
                    dnssec_status=dnssec_status,
                )
            )
        except Exception:
            pass

    return _ResolveCoreResult(
        wire=wire,
        dnssec_status=dnssec_status,
        upstream_id=upstream_id,
        rcode_name=rcode_name,
    )


@dataclass
class ResolutionContext:
    """Mutable per-query state passed between resolve pipeline stages.

    Inputs:
      - Constructed by _resolve_core with request identity and runtime handles.

    Outputs:
      - Shared fields mutated by stages; early stages may leave optional fields unset.
    """

    data: bytes
    client_ip: str
    listener: str | None
    secure: bool | None
    handler: object
    snap: object | None
    stats: object | None
    t0: float | None
    request_result_meta: dict[str, Any]
    ede_code_for_logs: int | None = None
    ede_text_for_logs: str | None = None
    req: object | None = None
    qname: str = ""
    qtype: object | None = None
    cache_key: tuple | None = None
    tsig_ctx: dict[str, Any] = field(default_factory=dict)
    inbound_ecs: dict[str, Any] | None = None
    inbound_ecs_trusted: bool = False
    trusted_inbound_ecs: dict[str, Any] | None = None
    outbound_ecs: dict[str, Any] | None = None
    effective_target_ip: str = ""
    ecs_cache_bypass: bool = False
    pre_plugins: list[object] = field(default_factory=list)
    post_plugins: list[object] = field(default_factory=list)
    reply: bytes | None = None
    out: bytes | None = None
    used_upstream: dict[str, Any] | None = None
    reason: str | None = None
    upstream_url: str = ""
    upstream_id: str | None = None
    dnssec_status: str | None = None
    rcode_name: str = "UNKNOWN"
