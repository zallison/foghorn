"""Post-upstream finalize: DNSSEC, cache store, TSIG/cookie bind, stats."""

from __future__ import annotations

from typing import Any

from dnslib import QTYPE, RCODE, DNSRecord

from foghorn.plugins.resolve import base as plugin_base

from .server_opcode import _ResolveCoreResult
from .server_response_utils import (
    _attach_ede_option,
    _bind_response_cookie_to_request,
    _compute_negative_ttl,
    _set_response_id,
    _strip_response_cookie_options,
)


def _finalize_resolved_response(
    *,
    out: bytes,
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
    upstream_id: str | None,
    upstream_url: str,
    ede_code_for_logs: int | None,
    ede_text_for_logs: str | None,
    classify_dnssec_status_for_response,
    apply_dnssec_ad_bit,
    is_signed_authoritative_response,
    qtype_label_fn,
) -> _ResolveCoreResult:
    """Brief: DNSSEC classify, cache store, sign/bind cookies, record stats.

    Inputs:
      - out/req/client_ip/qname/qtype/cache_key: Response and question.
      - handler/stats/t0/request_result_meta/tsig_ctx: Runtime finish path.
      - ecs_cache_bypass: Skip cache store when True.
      - upstream_id/upstream_url: Upstream identity for logs.
      - ede_code_for_logs/ede_text_for_logs: Optional EDE already chosen.
      - classify_dnssec_status_for_response/apply_dnssec_ad_bit/
        is_signed_authoritative_response/qtype_label_fn: Injected helpers.

    Outputs:
      - Final _ResolveCoreResult for the query.
    """

    _classify_dnssec_status_for_response = classify_dnssec_status_for_response
    _apply_dnssec_ad_bit = apply_dnssec_ad_bit
    _is_signed_authoritative_response = is_signed_authoritative_response
    _qtype_label_for_stats = qtype_label_fn

    # Cache store positive answers, negative responses (NXDOMAIN/NODATA), and
    # delegations/referrals using TTLs derived from SOA/NS records where
    # possible, following RFC 2308 guidance.

    # DNSSEC classification for non-UDP transports (TCP/DoT/DoH) shares the
    # same helper as UDP handlers so stats/query_log carry consistent status.
    dnssec_status = _classify_dnssec_status_for_response(
        handler=handler,
        qname=qname,
        qtype=qtype,
        response_wire=out,
    )
    dnssec_recorded = dnssec_status
    # When DNSSEC validation classifies a response as bogus under
    # dnssec_mode='validate', attach an RFC 8914 EDE code 6 (DNSSEC Bogus)
    # so clients and metrics can distinguish these failures.
    if dnssec_status == "dnssec_bogus":
        ede_code_for_logs = 6
        ede_text_for_logs = "DNSSEC validation failed (bogus)"
    try:
        dnssec_mode = str(getattr(handler, "dnssec_mode", "ignore")).lower()
    except Exception:
        dnssec_mode = "ignore"
    if (
        dnssec_mode == "validate"
        and upstream_id is None
        and dnssec_status in (None, "dnssec_unsigned", "dnssec_bogus")
        and _is_signed_authoritative_response(out)
    ):
        dnssec_status = "dnssec_zone_secure"
    out = _apply_dnssec_ad_bit(
        handler=handler,
        dnssec_status=dnssec_status,
        response_wire=out,
    )

    try:
        r = DNSRecord.parse(out)
        rcode = r.header.rcode
        ttl: int | None = None

        # Positive answers: cache when we have an answer RRset.
        if rcode == RCODE.NOERROR and r.rr:
            ttls = [
                int(getattr(rr, "ttl", 0))
                for rr in r.rr
                if isinstance(getattr(rr, "ttl", None), (int, float))
            ]
            ttl = min(ttls) if ttls else 300

            # Apply cache TTL floor and cap.
            min_cache_ttl = max(0, int(getattr(handler, "min_cache_ttl", 0) or 0))
            ttl = max(int(ttl), int(min_cache_ttl))
            try:
                cache_obj = getattr(plugin_base, "DNS_CACHE", None)
                raw_max = getattr(cache_obj, "max_cache_ttl", None)
                max_cache_ttl = int(raw_max) if raw_max is not None else 86400
            except Exception:
                max_cache_ttl = 86400
            if int(max_cache_ttl) > 0:
                ttl = min(int(ttl), int(max_cache_ttl))
        else:
            auth_rrs = getattr(r, "auth", None) or []
            has_soa = any(rr.rtype == QTYPE.SOA for rr in auth_rrs)
            has_ns = any(rr.rtype == QTYPE.NS for rr in auth_rrs)

            # Negative caching per RFC 2308: NXDOMAIN or NODATA responses
            # with an SOA in the authority section.
            if (
                has_soa
                and (rcode == RCODE.NXDOMAIN or (rcode == RCODE.NOERROR and not r.rr))
                or has_ns
                and rcode == RCODE.NOERROR
                and not r.rr
            ):
                ttl = _compute_negative_ttl(r, getattr(handler, "min_cache_ttl", 0))

        if ttl is not None and ttl > 0 and not ecs_cache_bypass:
            cache = getattr(plugin_base, "DNS_CACHE", None)
            if cache is not None:
                cache_payload = _strip_response_cookie_options(out)
                try:
                    from foghorn.servers.tsig_utils import strip_tsig_from_wire

                    cache_payload = strip_tsig_from_wire(cache_payload)
                except Exception:
                    pass
                cache.set(cache_key, int(ttl), cache_payload)

        # Attach a DNSSEC-related EDE only for explicitly bogus
        # classifications. This is done after caching decisions so TTL
        # handling remains unchanged.
        if dnssec_status == "dnssec_bogus" and ede_code_for_logs is not None:
            try:
                _attach_ede_option(
                    req,
                    r,
                    int(ede_code_for_logs),
                    str(ede_text_for_logs or "DNSSEC validation failed (bogus)"),
                )
                out = r.pack()
            except Exception:  # pragma: no cover - defensive: best-effort only
                pass
    except (
        Exception
    ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably

    try:
        from foghorn.servers.tsig_utils import (
            sign_response_tsig,
            strip_tsig_from_wire,
        )

        out = strip_tsig_from_wire(out)
        if tsig_ctx.get("ok") and tsig_ctx.get("keyname"):
            out = sign_response_tsig(
                out,
                key_configs=list(getattr(handler, "tsig_keys", []) or []),
                keyname=tsig_ctx.get("keyname"),
                algorithm=tsig_ctx.get("algorithm"),
                request_msg=tsig_ctx.get("request_msg"),
            )
    except Exception:
        pass
    out = _bind_response_cookie_to_request(
        req,
        out,
        client_ip=client_ip,
        cookies_enabled=bool(getattr(handler, "cookies_enabled", True)),
        secret=getattr(handler, "cookies_secret", None),
    )
    wire = _set_response_id(out, req.header.id)

    # Record response rcode and append to persistent query_log when enabled.
    rcode_name = "UNKNOWN"
    if stats is not None:
        try:
            from foghorn.servers.resolve_telemetry import (
                ResolveEvent,
                ResolveEventKind,
                build_answers_from_parsed,
                telemetry_from_stats,
            )

            parsed = DNSRecord.parse(wire)
            rcode_name = RCODE.get(parsed.header.rcode, str(parsed.header.rcode))
            answers, first = build_answers_from_parsed(parsed)
            status = "ok" if rcode_name == "NOERROR" else "error"
            telemetry_from_stats(stats).emit(
                ResolveEvent(
                    kind=ResolveEventKind.RESPONSE_FINALIZED,
                    client_ip=client_ip,
                    qname=qname,
                    qtype_label=_qtype_label_for_stats(qtype),
                    t0=t0,
                    request_result_meta=dict(request_result_meta),
                    rcode_name=rcode_name,
                    status=status,
                    upstream_id=upstream_id,
                    upstream_url=upstream_url,
                    dnssec_status=dnssec_status,
                    dnssec_recorded=dnssec_recorded,
                    ede_code=ede_code_for_logs,
                    ede_text=ede_text_for_logs,
                    answers=answers,
                    first=first,
                )
            )
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass

    return _ResolveCoreResult(
        wire=wire,
        dnssec_status=dnssec_status,
        upstream_id=upstream_id,
        rcode_name=rcode_name,
    )
