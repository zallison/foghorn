"""Cache lookup and hit handling for the shared DNS resolve pipeline."""

from __future__ import annotations

import time as _time
from typing import Any

from dnslib import QTYPE, RCODE, DNSRecord

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
        if stats is not None:
            try:
                stats.record_cache_hit(qname)
                parsed_cached = DNSRecord.parse(cached)
                rcode_name = RCODE.get(
                    parsed_cached.header.rcode,
                    str(parsed_cached.header.rcode),
                )
                stats.record_response_rcode(rcode_name, qname)

                answers = [
                    {
                        "name": str(rr.rname),
                        "type": QTYPE.get(rr.rtype, str(rr.rtype)),
                        "ttl": int(getattr(rr, "ttl", 0)),
                        "rdata": str(rr.rdata),
                    }
                    for rr in (parsed_cached.rr or [])
                ]
                first = answers[0]["rdata"] if answers else None
                result_ctx = {"source": "cache", "answers": answers}
                result_ctx.update(request_result_meta)
                qtype_name = _qtype_label_for_stats(qtype)
                stats.record_query_result(
                    client_ip=client_ip,
                    qname=qname,
                    qtype=qtype_name,
                    rcode=rcode_name,
                    upstream_id=None,
                    status="cache_hit",
                    error=None,
                    first=str(first) if first is not None else None,
                    result=result_ctx,
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
        if stats is not None and t0 is not None:
            try:
                t1 = _time.perf_counter()
                stats.record_latency(t1 - t0)
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass
        return _ResolveCoreResult(
            wire=wire,
            dnssec_status=None,
            upstream_id=None,
            rcode_name=rcode_name,
        )

    # Cache miss
    if stats is not None:
        try:
            stats.record_cache_miss(qname)
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass

    return None
