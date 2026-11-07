"""Cache lookup and hit handling for the shared DNS resolve pipeline."""

from __future__ import annotations

from typing import Any

from dnslib import RCODE, DNSRecord

from foghorn.plugins.resolve import base as plugin_base

from .server_opcode import _ResolveCoreResult
from .server_response_utils import (
    _bind_response_cookie_to_request,
    _set_response_id,
)


def _try_cache_hit(
    *,
    data: bytes,
    req: object,
    client_ip: str,
    qname: str,
    qtype: object,
    cache_key: tuple,
    handler: object,
    stats: object | None,
    t0: float | None,
    request_result_meta: dict[str, Any],
    tsig_ctx: dict[str, Any],
    ecs_cache_bypass: bool,
    cache_local: object,
    schedule_cache_refresh,
    qtype_label_fn,
) -> _ResolveCoreResult | None:
    """Brief: Attempt cache lookup with SWR; return hit result or None on miss.

    Inputs:
      - data/req/client_ip/qname/qtype/cache_key: Query identity.
      - handler/stats/t0/request_result_meta/tsig_ctx: Runtime and finish path.
      - ecs_cache_bypass: When True, skip cache.
      - cache_local: Thread-local bypass flag holder.
      - schedule_cache_refresh/qtype_label_fn: Injected helpers.

    Outputs:
      - _ResolveCoreResult on cache hit, else None (and records cache miss).
    """

    _CACHE_LOCAL = cache_local
    _schedule_cache_refresh = schedule_cache_refresh
    _qtype_label_for_stats = qtype_label_fn
    rcode_name = "UNKNOWN"

    # Cache lookup (with optional stale-while-revalidate prefetch).
    cache = getattr(plugin_base, "DNS_CACHE", None)
    cached: bytes | None = None
    seconds_remaining: float | None = None
    ttl_original: int | None = None
    bypass_cache = bool(
        getattr(_CACHE_LOCAL, "bypass_cache", False) or ecs_cache_bypass
    )
    prefetch_enabled = bool(getattr(handler, "cache_prefetch_enabled", False))
    window_after = float(
        getattr(
            handler,
            "cache_prefetch_allow_stale_after_expiry",
            0.0,
        )
        or 0.0
    )

    if cache is not None and not bypass_cache:
        # Prefer get_with_meta() for stale-while-revalidate behavior. Allow a
        # fallback to get() for transitional/custom cache implementations.
        try:
            value, remaining, ttl_val = cache.get_with_meta(cache_key)
            if value is not None:
                cached = value
                seconds_remaining = remaining
                ttl_original = ttl_val  # pragma: no cover - defensive/metrics path excluded from coverage
        except (
            NotImplementedError
        ):  # pragma: no cover - defensive/metrics path excluded from coverage
            try:  # pragma: no cover - defensive/metrics path excluded from coverage
                cached = cache.get(
                    cache_key
                )  # pragma: no cover - defensive/metrics path excluded from coverage
            except (
                NotImplementedError
            ):  # pragma: no cover - defensive/metrics path excluded from coverage
                cached = None
        except Exception:  # pragma: no cover - defensive: cache implementation detail
            cached = None
    if (
        cached is not None
        and seconds_remaining is not None
        and seconds_remaining < 0.0
        and not (
            prefetch_enabled
            and window_after > 0.0
            and (-window_after <= seconds_remaining < 0.0)
        )
    ):
        cached = None

    if cached is not None:
        # Record cache hit statistics
        rcode_name = "UNKNOWN"
        if stats is not None:
            try:
                from foghorn.servers.resolve_telemetry import (
                    ResolveEvent,
                    ResolveEventKind,
                    build_answers_from_parsed,
                    telemetry_from_stats,
                )

                parsed_cached = DNSRecord.parse(cached)
                rcode_name = RCODE.get(
                    parsed_cached.header.rcode,
                    str(parsed_cached.header.rcode),
                )
                answers, first = build_answers_from_parsed(parsed_cached)
                telemetry_from_stats(stats).emit(
                    ResolveEvent(
                        kind=ResolveEventKind.CACHE_LOOKUP,
                        cache_outcome="hit",
                        client_ip=client_ip,
                        qname=qname,
                        qtype_label=_qtype_label_for_stats(qtype),
                        t0=t0,
                        request_result_meta=dict(request_result_meta),
                        rcode_name=rcode_name,
                        answers=answers,
                        first=first,
                    )
                )
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

        # Decide whether to schedule a background refresh for this cache hit
        min_ttl = int(getattr(handler, "cache_prefetch_min_ttl", 0) or 0)
        max_ttl = int(getattr(handler, "cache_prefetch_max_ttl", 0) or 0)
        window_before = float(
            getattr(
                handler,
                "cache_prefetch_refresh_before_expiry",
                0.0,
            )
            or 0.0
        )

        should_refresh = False
        if (
            prefetch_enabled
            and seconds_remaining is not None
            and ttl_original is not None
        ):  # pragma: no cover - defensive/metrics path excluded from coverage
            ttl_ok = (
                True  # pragma: no cover - defensive/metrics path excluded from coverage
            )
            if (
                ttl_original < min_ttl
            ):  # pragma: no cover - defensive/metrics path excluded from coverage
                ttl_ok = False  # pragma: no cover - defensive/metrics path excluded from coverage
            if (
                max_ttl > 0 and ttl_original > max_ttl
            ):  # pragma: no cover - defensive/metrics path excluded from coverage
                ttl_ok = False  # pragma: no cover - defensive/metrics path excluded from coverage
            if (
                ttl_ok
            ):  # pragma: no cover - defensive/metrics path excluded from coverage
                if (
                    0.0 <= seconds_remaining <= window_before
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    should_refresh = True  # pragma: no cover - defensive/metrics path excluded from coverage
                elif (
                    window_after > 0.0 and -window_after <= seconds_remaining < 0.0
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    should_refresh = True

        if (
            should_refresh and not bypass_cache
        ):  # pragma: no cover - defensive/metrics path excluded from coverage
            _schedule_cache_refresh(data, client_ip)

        try:
            from foghorn.servers.tsig_utils import (
                sign_response_tsig,
                strip_tsig_from_wire,
            )

            cached = strip_tsig_from_wire(cached)
            if tsig_ctx.get("ok") and tsig_ctx.get("keyname"):
                cached = sign_response_tsig(
                    cached,
                    key_configs=list(getattr(handler, "tsig_keys", []) or []),
                    keyname=tsig_ctx.get("keyname"),
                    algorithm=tsig_ctx.get("algorithm"),
                    request_msg=tsig_ctx.get("request_msg"),
                )
        except Exception:
            pass
        cached = _bind_response_cookie_to_request(
            req,
            cached,
            client_ip=client_ip,
            cookies_enabled=bool(getattr(handler, "cookies_enabled", True)),
            secret=getattr(handler, "cookies_secret", None),
        )
        wire = _set_response_id(cached, req.header.id)
        # Latency is recorded by CACHE_LOOKUP hit event when stats is active.
        return _ResolveCoreResult(
            wire=wire,
            dnssec_status=None,
            upstream_id=None,
            rcode_name=rcode_name,
        )

    # Cache miss
    if stats is not None:
        try:
            from foghorn.servers.resolve_telemetry import (
                ResolveEvent,
                ResolveEventKind,
                telemetry_from_stats,
            )

            telemetry_from_stats(stats).emit(
                ResolveEvent(
                    kind=ResolveEventKind.CACHE_LOOKUP,
                    cache_outcome="miss",
                    client_ip=client_ip,
                    qname=qname,
                    qtype_label=_qtype_label_for_stats(qtype),
                )
            )
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass

    return None
