"""Early-path gatekeepers for the shared DNS resolve pipeline."""

from __future__ import annotations

from typing import Any

from dnslib import QTYPE, RCODE

from .server_opcode import _ResolveCoreResult
from .server_resolve_context import _finish_early_result
from .server_response_utils import (
    _attach_ede_option,
    _build_badcookie_response,
    _classify_request_cookie,
    _echo_client_edns,
    _set_response_id,
)


def _qname_from_req(req: object) -> str:
    """Brief: Best-effort qname from a parsed request for gate stats.

    Inputs:
      - req: Parsed DNSRecord-like request.

    Outputs:
      - str: qname without trailing dot, or empty string.
    """

    try:
        return str(req.questions[0].qname).rstrip(".")
    except Exception:
        return ""


def _handle_dns_cookies(
    *,
    req: object,
    handler: object,
    client_ip: str,
    listener: str | None,
    stats: object | None,
    t0: float | None,
) -> _ResolveCoreResult | None:
    """Brief: Enforce DNS COOKIE require_udp short-circuit when configured.

    Inputs:
      - req: Parsed DNS request.
      - handler: Runtime handler-like object.
      - client_ip: Client IP string.
      - listener: Optional listener label.
      - stats: Optional stats collector.
      - t0: Optional latency start time.

    Outputs:
      - _ResolveCoreResult on BADCOOKIE short-circuit, else None.
    """

    try:
        cookies_enabled = bool(getattr(handler, "cookies_enabled", True))
    except Exception:
        cookies_enabled = True
    try:
        cookies_mode = str(getattr(handler, "cookies_mode", "learn") or "learn").lower()
    except Exception:
        cookies_mode = "learn"
    cookies_secret = getattr(handler, "cookies_secret", None)
    cookies_secret_old = getattr(handler, "cookies_secret_old", None)
    try:
        cookies_lifetime_seconds = int(
            getattr(handler, "cookies_lifetime_seconds", 86400) or 86400
        )
    except Exception:
        cookies_lifetime_seconds = 86400
    if not isinstance(cookies_secret, (bytes, bytearray)):
        cookies_secret = None
    else:
        cookies_secret = bytes(cookies_secret)
    if not isinstance(cookies_secret_old, (bytes, bytearray)):
        cookies_secret_old = None
    else:
        cookies_secret_old = bytes(cookies_secret_old)

    if not (
        cookies_enabled
        and cookies_mode == "require_udp"
        and str(listener or "").lower() == "udp"
    ):
        return None

    cookie_status = _classify_request_cookie(
        req,
        client_ip=client_ip,
        secret=cookies_secret,
        secret_old=cookies_secret_old,
        lifetime_seconds=cookies_lifetime_seconds,
    )
    if cookie_status == "valid":
        return None

    wire = _build_badcookie_response(
        req,
        client_ip=client_ip,
        secret=cookies_secret or b"",
    )
    wire = _set_response_id(wire, req.header.id)
    qn = _qname_from_req(req)
    return _finish_early_result(
        wire=wire,
        rcode_name="BADCOOKIE",
        stats=stats,
        t0=t0,
        client_ip=client_ip,
        qname=qn,
        qtype_name="UNKNOWN",
        status="cookie_required",
        error=None,
        result={
            "source": "cookies",
            "action": "badcookie",
            "cookie_status": str(cookie_status),
        },
    )


def _handle_tsig(
    *,
    data: bytes,
    req: object,
    handler: object,
    client_ip: str,
    listener: str | None,
    stats: object | None,
    t0: float | None,
    request_result_meta: dict[str, Any],
) -> tuple[dict[str, Any], _ResolveCoreResult | None]:
    """Brief: Verify downstream QUERY TSIG and short-circuit on failure.

    Inputs:
      - data: Original query wire bytes.
      - req: Parsed DNS request.
      - handler: Runtime handler-like object.
      - client_ip: Client IP string.
      - listener: Optional listener label.
      - stats: Optional stats collector.
      - t0: Optional latency start time.
      - request_result_meta: Mutable per-query metadata dict.

    Outputs:
      - (tsig_ctx, optional early _ResolveCoreResult).
    """

    tsig_ctx: dict[str, Any] = {
        "ok": False,
        "keyname": None,
        "algorithm": None,
        "had_tsig": False,
        "request_msg": None,
    }
    try:
        tsig_enabled = bool(getattr(handler, "tsig_enabled", False))
    except Exception:
        tsig_enabled = False
    tsig_keys = list(getattr(handler, "tsig_keys", []) or [])
    try:
        tsig_mode = str(getattr(handler, "tsig_mode", "optional") or "optional").lower()
    except Exception:
        tsig_mode = "optional"
    if tsig_mode not in {"optional", "require"}:
        tsig_mode = "optional"
    try:
        tsig_max_fudge = int(getattr(handler, "tsig_max_fudge_seconds", 300) or 300)
    except Exception:
        tsig_max_fudge = 300
    tsig_allow_clients = list(getattr(handler, "tsig_allow_clients", []) or [])
    tsig_listeners = list(getattr(handler, "tsig_listeners", []) or [])
    listener_l = str(listener or "").lower()
    tsig_applies = True
    if tsig_listeners:
        tsig_applies = listener_l in {str(x).lower() for x in tsig_listeners}

    if not (tsig_enabled and tsig_applies):
        return tsig_ctx, None

    from foghorn.servers import tsig_utils as _tsig
    from foghorn.utils import ip_networks as _ipn

    data_bytes = data if isinstance(data, (bytes, bytearray)) else b""
    may_tsig = _tsig.wire_may_contain_tsig(data_bytes)
    need_check = bool(may_tsig) or tsig_mode == "require"
    if need_check:
        if tsig_allow_clients:
            if not _ipn.ip_string_in_cidrs(
                str(client_ip or "").strip(), tsig_allow_clients
            ):
                # Outside allowlist: ignore TSIG feature for this client.
                need_check = False
                tsig_enabled = False
    if not need_check:
        return tsig_ctx, None

    def _tsig_fail(
        *,
        wire: bytes,
        status: str,
        error: object | None,
        result: dict[str, Any],
    ) -> _ResolveCoreResult:
        wire = _set_response_id(wire, req.header.id)
        qn = _qname_from_req(req)
        return _finish_early_result(
            wire=wire,
            rcode_name="NOTAUTH",
            stats=stats,
            t0=t0,
            client_ip=client_ip,
            qname=qn,
            qtype_name="UNKNOWN",
            status=status,
            error=error,
            result=result,
        )

    if not may_tsig:
        # require + no additional section => missing TSIG
        if tsig_mode == "require":
            wire = _tsig.build_tsig_error_response(
                bytes(data_bytes),
                key_configs=tsig_keys,
                sign=False,
            )
            return tsig_ctx, _tsig_fail(
                wire=wire,
                status="tsig_required",
                error=None,
                result={
                    "source": "tsig",
                    "action": "missing",
                    "tsig_mode": tsig_mode,
                },
            )
        return tsig_ctx, None

    vr = _tsig.verify_request_tsig(
        bytes(data_bytes),
        tsig_keys,
        max_fudge_seconds=tsig_max_fudge,
    )
    tsig_ctx["had_tsig"] = bool(vr.had_tsig)
    if vr.ok:
        tsig_ctx["ok"] = True
        tsig_ctx["keyname"] = vr.keyname
        tsig_ctx["algorithm"] = vr.algorithm
        tsig_ctx["request_msg"] = vr.request_msg
        request_result_meta["tsig_ok"] = True
        request_result_meta["tsig_key_name"] = vr.keyname
        return tsig_ctx, None

    # optional + no_tsig is fine (ARCOUNT may be EDNS-only)
    if vr.error_code == "no_tsig" and tsig_mode == "optional":
        return tsig_ctx, None
    if vr.error_code == "no_tsig" and tsig_mode == "require":
        wire = _tsig.build_tsig_error_response(
            bytes(data_bytes),
            key_configs=tsig_keys,
            sign=False,
        )
        return tsig_ctx, _tsig_fail(
            wire=wire,
            status="tsig_required",
            error=vr.error_text,
            result={
                "source": "tsig",
                "action": "missing",
                "tsig_error": vr.error_code,
            },
        )

    # bad sig/key/time/etc or optional with present bad TSIG
    if vr.had_tsig or tsig_mode == "require":
        wire = _tsig.build_tsig_error_response(
            bytes(data_bytes),
            key_configs=tsig_keys,
            keyname=vr.keyname,
            algorithm=vr.algorithm,
            sign=bool(vr.keyname and tsig_keys),
        )
        return tsig_ctx, _tsig_fail(
            wire=wire,
            status="tsig_failed",
            error=vr.error_text,
            result={
                "source": "tsig",
                "action": "reject",
                "tsig_error": vr.error_code,
            },
        )
    return tsig_ctx, None


def _handle_refuse_any(
    *,
    req: object,
    handler: object,
    client_ip: str,
    qname: str,
    qtype: object,
    qtype_label_fn,
    stats: object | None,
    t0: float | None,
    request_result_meta: dict[str, Any],
) -> _ResolveCoreResult | None:
    """Brief: Refuse QTYPE ANY when amplification mitigation is enabled.

    Inputs:
      - req: Parsed DNS request.
      - handler: Runtime handler-like object.
      - client_ip: Client IP string.
      - qname: Normalized query name.
      - qtype: Query type value.
      - qtype_label_fn: Callable mapping qtype -> stats label.
      - stats: Optional stats collector.
      - t0: Optional latency start time.
      - request_result_meta: Per-query metadata for result context.

    Outputs:
      - _ResolveCoreResult when refused, else None.
    """

    try:
        refuse_any = bool(getattr(handler, "refuse_any", False))
    except Exception:
        refuse_any = False
    if not refuse_any:
        return None

    try:
        qtype_num = int(qtype)
    except Exception:
        qtype_num = int(qtype or 0)
    if qtype_num != int(getattr(QTYPE, "ANY", 255)):
        return None

    r = req.reply()
    r.header.rcode = RCODE.REFUSED
    _echo_client_edns(req, r)
    _attach_ede_option(
        req,
        r,
        21,
        "QTYPE ANY refused",
    )
    wire = _set_response_id(r.pack(), req.header.id)
    qtype_name = qtype_label_fn(qtype)
    result_ctx = {"source": "refuse_any", "action": "refuse"}
    result_ctx.update(request_result_meta)
    return _finish_early_result(
        wire=wire,
        rcode_name="REFUSED",
        stats=stats,
        t0=t0,
        client_ip=client_ip,
        qname=qname,
        qtype_name=qtype_name,
        status="refuse_any",
        error=None,
        result=result_ctx,
    )


def _handle_local_blocked(
    *,
    req: object,
    handler: object,
    client_ip: str,
    qname: str,
    qtype: object,
    qtype_label_fn,
    is_forward_local_blocked_query,
    is_rfc1918_ptr_query_name,
    stats: object | None,
    t0: float | None,
    request_result_meta: dict[str, Any],
) -> _ResolveCoreResult | None:
    """Brief: Block .local / RFC1918 PTR forwarding when forward_local is false.

    Inputs:
      - req: Parsed DNS request.
      - handler: Runtime handler-like object.
      - client_ip: Client IP string.
      - qname: Normalized query name.
      - qtype: Query type value.
      - qtype_label_fn: Callable mapping qtype -> stats label.
      - is_forward_local_blocked_query: Predicate for blocked local queries.
      - is_rfc1918_ptr_query_name: Predicate for RFC1918 PTR owners.
      - stats: Optional stats collector.
      - t0: Optional latency start time.
      - request_result_meta: Per-query metadata for result context.

    Outputs:
      - _ResolveCoreResult when blocked, else None.
    """

    forward_local = bool(getattr(handler, "forward_local", False))
    qname_lower = qname.lower()
    is_rfc1918_ptr_query = qtype == QTYPE.PTR and is_rfc1918_ptr_query_name(qname_lower)
    if forward_local or not is_forward_local_blocked_query(qname_lower, qtype):
        return None

    r = req.reply()
    r.header.rcode = RCODE.NXDOMAIN
    _echo_client_edns(req, r)
    ede_text = ".local not forwarded (RFC 6762)"
    if is_rfc1918_ptr_query:
        ede_text = "RFC1918 PTR not forwarded"
    _attach_ede_option(req, r, 21, ede_text)  # Not Authoritative
    wire = _set_response_id(r.pack(), req.header.id)
    qtype_name = qtype_label_fn(qtype)
    result_ctx = {"source": "local_blocked"}
    result_ctx.update(request_result_meta)
    return _finish_early_result(
        wire=wire,
        rcode_name="NXDOMAIN",
        stats=stats,
        t0=t0,
        client_ip=client_ip,
        qname=qname,
        qtype_name=qtype_name,
        status="local_blocked",
        error=None,
        result=result_ctx,
    )
