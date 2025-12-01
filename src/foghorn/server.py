import functools
import logging
import socketserver
from typing import Dict, List, Optional, Tuple

from dnslib import EDNS0, QTYPE, RCODE, RR, DNSRecord

from .plugins.base import BasePlugin, PluginContext, PluginDecision
from .transports.dot import DoTError, get_dot_pool
from .transports.tcp import TCPError, get_tcp_pool, tcp_query
from .udp_server import DNSUDPHandler, _edns_flags_for_mode

logger = logging.getLogger("foghorn.server")


def compute_effective_ttl(resp: DNSRecord, min_cache_ttl: int) -> int:
    """
    Computes cache TTL with min floor applied for any DNS response.

    Inputs:
      - resp: dnslib.DNSRecord, the parsed DNS response to cache
      - min_cache_ttl: int (seconds), minimum TTL floor

    Outputs:
      - int: effective TTL in seconds to use for cache expiry

    For NOERROR + answers: max(min(answer.ttl), min_cache_ttl)
    For all other cases: min_cache_ttl

    Example:
      >>> # Mock resp with NOERROR and answer RRs with TTL 30, min_cache_ttl=60
      >>> ttl = compute_effective_ttl(resp_with_low_ttl, 60)
      >>> ttl
      60
    """
    try:
        rcode = resp.header.rcode
        has_answers = bool(resp.rr)
        if rcode == RCODE.NOERROR and has_answers:
            answer_min_ttl = min(rr.ttl for rr in resp.rr)
            return max(int(answer_min_ttl), int(min_cache_ttl))
        return max(0, int(min_cache_ttl))
    except Exception:
        # Defensive: on parsing error, fall back to min_cache_ttl
        return max(0, int(min_cache_ttl))


def _compute_negative_ttl(resp: DNSRecord, fallback_ttl: int) -> int:
    """Compute TTL for negative or referral caching using SOA/NS where possible.

    Inputs:
      - resp: Parsed DNSRecord from upstream.
      - fallback_ttl: Fallback TTL (seconds) when no suitable SOA/NS TTL exists.

    Outputs:
      - int TTL in seconds (>= 0) to use for negative/referral cache entries.

    Notes:
      - For NXDOMAIN/NODATA with an SOA in the authority section, we use the
        minimum of the SOA RR TTL and the SOA minimum TTL field when present.
      - For delegation/referral responses without SOA but with NS records, we
        fall back to the minimum NS TTL.
      - If neither SOA nor NS TTLs are available, fallback_ttl is used.
    """
    try:
        auth_rrs = getattr(resp, "auth", None) or []
        soa_ttls = []
        ns_ttls = []
        for rr in auth_rrs:
            if rr.rtype == QTYPE.SOA:
                try:
                    ttl_val = getattr(rr, "ttl", None)
                    if isinstance(ttl_val, (int, float)):
                        soa_ttls.append(int(ttl_val))
                    rdata = getattr(rr, "rdata", None)
                    minimum = getattr(rdata, "minttl", None) or getattr(
                        rdata, "minimum", None
                    )
                    if isinstance(minimum, (int, float)):
                        soa_ttls.append(int(minimum))
                except Exception:
                    continue
            elif rr.rtype == QTYPE.NS:
                try:
                    ttl_val = getattr(rr, "ttl", None)
                    if isinstance(ttl_val, (int, float)):
                        ns_ttls.append(int(ttl_val))
                except Exception:
                    continue

        # Prefer SOA-derived TTLs for true negative caching per RFC 2308.
        candidates = [t for t in soa_ttls if t >= 0]
        if candidates:
            return max(0, min(candidates))

        # Fall back to NS TTLs for delegation / referral caching.
        candidates = [t for t in ns_ttls if t >= 0]
        if candidates:
            return max(0, min(candidates))

        return max(0, int(fallback_ttl))
    except Exception:
        return max(0, int(fallback_ttl))


def _set_response_id(wire: bytes, req_id: int) -> bytes:
    """Ensure the response DNS ID matches the request ID.

    Inputs:
      - wire: bytes-like DNS response (bytes, bytearray, or memoryview).
      - req_id: int request ID to set in the first two bytes.

    Outputs:
      - bytes: response with corrected ID.

    Fast path: DNS ID is the first 2 bytes (big-endian). We rewrite them
    without parsing to avoid any packing differences.

    Note: We normalize to bytes before delegating to a cached helper so that
    unhashable types (e.g., bytearray) do not break caching.
    """
    try:
        # Normalize to bytes to ensure hashability and immutability
        try:
            bwire = bytes(wire)
        except Exception:
            bwire = wire  # fallback; will likely still be bytes
        return _set_response_id_cached(bwire, int(req_id))
    except Exception as e:  # pragma: no cover - defensive
        logger.error("Failed to set response id: %s", e)
        return (
            bytes(wire)
            if not isinstance(wire, (bytes, bytearray))
            else (bytes(wire) if isinstance(wire, bytearray) else wire)
        )


@functools.lru_cache(maxsize=1024)
def _set_response_id_cached(wire: bytes, req_id: int) -> bytes:
    """Cached helper for setting DNS ID on an immutable bytes payload.

    Inputs:
      - wire: Immutable bytes payload containing DNS message.
      - req_id: int request ID to embed in the first two bytes.

    Outputs:
      - bytes: DNS message with first two bytes rewritten when possible.
    """
    try:
        if len(wire) >= 2:
            hi = (req_id >> 8) & 0xFF
            lo = req_id & 0xFF
            return bytes([hi, lo]) + wire[2:]
        return wire
    except Exception as e:  # pragma: no cover
        logger.error("Failed to set response id (cached): %s", e)
        return wire


def send_query_with_failover(
    query: DNSRecord,
    upstreams: List[Dict],
    timeout_ms: int,
    qname: str,
    qtype: int,
) -> Tuple[Optional[bytes], Optional[Dict], str]:
    """
    Sends a DNS query to a list of upstream servers, with failover.

    Args:
        query: The DNSRecord to send.
        upstreams: A list of upstream server dicts to try.
        timeout_ms: The timeout in milliseconds for each attempt.
        qname: The query name (for logging).
        qtype: The query type (for logging).

    Returns:
        A tuple of (response_wire_bytes, used_upstream, reason).
        reason is 'ok', 'servfail', 'timeout', or 'all_failed'.
    """
    if not upstreams:
        return None, None, "no_upstreams"

    timeout_sec = timeout_ms / 1000.0
    last_exception = None

    for upstream in upstreams:
        # For DoH we may not have host/port; use safe defaults for logging
        host = str(upstream.get("host", ""))
        try:
            port = int(upstream.get("port", 0))
        except Exception:  # pragma: no cover
            port = 0
        transport = str(upstream.get("transport", "udp")).lower()
        try:
            logger.debug(
                "Forwarding %s type %s via %s to %s:%d",
                qname,
                qtype,
                transport,
                host,
                port,
            )
            # Send based on transport
            if transport == "dot":
                tls = (
                    upstream.get("tls", {})
                    if isinstance(upstream.get("tls"), dict)
                    else {}
                )
                server_name = tls.get("server_name")
                verify = bool(tls.get("verify", True))
                ca_file = tls.get("ca_file")
                pool_cfg = (
                    upstream.get("pool", {})
                    if isinstance(upstream.get("pool"), dict)
                    else {}
                )
                pool = get_dot_pool(host, int(port), server_name, verify, ca_file)
                try:
                    pool.set_limits(
                        max_connections=pool_cfg.get("max_connections"),
                        idle_timeout_s=(
                            (int(pool_cfg.get("idle_timeout_ms")) // 1000)
                            if pool_cfg.get("idle_timeout_ms")
                            else None
                        ),
                    )
                except Exception:  # pragma: no cover
                    pass  # pragma: no cover
                response_wire = pool.send(query.pack(), timeout_ms, timeout_ms)
            elif transport == "tcp":
                pool_cfg = (
                    upstream.get("pool", {})
                    if isinstance(upstream.get("pool"), dict)
                    else {}
                )
                pool = get_tcp_pool(host, int(port))
                try:
                    pool.set_limits(
                        max_connections=pool_cfg.get("max_connections"),
                        idle_timeout_s=(
                            (int(pool_cfg.get("idle_timeout_ms")) // 1000)
                            if pool_cfg.get("idle_timeout_ms")
                            else None
                        ),
                    )
                except Exception:  # pragma: no cover
                    pass  # pragma: no cover
                response_wire = pool.send(query.pack(), timeout_ms, timeout_ms)
            elif transport == "doh":
                doh_url = str(
                    upstream.get("url") or upstream.get("endpoint") or ""
                ).strip()
                if not doh_url:
                    raise Exception("missing DoH url in upstream config")
                doh_method = str(upstream.get("method", "POST"))
                doh_headers = (
                    upstream.get("headers")
                    if isinstance(upstream.get("headers"), dict)
                    else {}
                )
                tls_cfg = (
                    upstream.get("tls", {})
                    if isinstance(upstream.get("tls"), dict)
                    else {}
                )
                verify = bool(tls_cfg.get("verify", True))
                ca_file = tls_cfg.get("ca_file")
                from .transports.doh import doh_query  # local import to avoid overhead

                body, resp_headers = doh_query(
                    doh_url,
                    query.pack(),
                    method=doh_method,
                    headers=doh_headers,
                    timeout_ms=timeout_ms,
                    verify=verify,
                    ca_file=ca_file,
                )
                response_wire = body
            else:  # udp (default)
                # Use transport impl for consistency, but preserve legacy path for tests/mocks
                try:
                    pack = getattr(query, "pack")
                except Exception:
                    pack = None
                if callable(pack):
                    from .transports.udp import udp_query

                    response_wire = udp_query(
                        host, int(port), query.pack(), timeout_ms=timeout_ms
                    )
                else:
                    # Fallback to dnslib's convenience API (used in unit tests)
                    response_wire = query.send(host, int(port), timeout=timeout_sec)

            # Check for SERVFAIL or truncation to trigger fallback
            try:
                parsed_response = DNSRecord.parse(response_wire)
                if parsed_response.header.rcode == RCODE.SERVFAIL:
                    logger.warning(
                        "Upstream %s:%d returned SERVFAIL for %s, trying next",
                        host,
                        port,
                        qname,
                    )
                    last_exception = Exception(f"SERVFAIL from {host}:{port}")
                    continue  # Try next upstream
                # If UDP and TC=1, fallback to TCP for full response
                tc_flag = getattr(parsed_response.header, "tc", 0)
                if transport == "udp" and tc_flag == 1:
                    logger.debug(
                        "Truncated UDP response for %s; retrying over TCP", qname
                    )
                    try:
                        response_wire = tcp_query(
                            host,
                            int(port),
                            query.pack(),
                            connect_timeout_ms=timeout_ms,
                            read_timeout_ms=timeout_ms,
                        )
                        return response_wire, {**upstream, "transport": "tcp"}, "ok"
                    except Exception as e2:  # pragma: no cover
                        last_exception = e2
                        continue
            except Exception as e:  # pragma: no cover
                # If parsing fails, treat as a server failure
                logger.warning(
                    "Failed to parse response from %s:%d for %s: %s",
                    host,
                    port,
                    qname,
                    e,
                )
                last_exception = e
                continue  # Try next upstream

            # Success (NOERROR, NXDOMAIN, etc.)
            return response_wire, upstream, "ok"

        except (DoTError, TCPError, Exception) as e:  # pragma: no cover
            logger.debug(
                "Upstream %s:%d via %s failed for %s: %s",
                host,
                port,
                transport,
                qname,
                str(e),
            )
            last_exception = e
            continue  # Try next upstream

    logger.warning(
        "All upstreams failed for %s %s. Last error: %s", qname, qtype, last_exception
    )
    return None, None, "all_failed"


# DNSUDPHandler and DNSServer now live in foghorn.udp_server; they are re-exported
# at the bottom of this module for backward compatibility.


def resolve_query_bytes(data: bytes, client_ip: str) -> bytes:
    """Resolve a single DNS wire query and return wire response.

    Inputs:
      - data: Wire-format DNS query bytes.
      - client_ip: String client IP for plugin context, logging, and statistics.
    Outputs:
      - bytes: Wire-format DNS response.

    This helper reuses DNSUDPHandler's class-level configuration (cache,
    plugins, upstreams, DNSSEC knobs, and optional StatsCollector) so that
    TCP/DoT/DoH and other non-UDP callers share the same behavior and
    statistics pipeline.

    Example:
      >>> resp = resolve_query_bytes(query_bytes, '127.0.0.1')
    """
    import time as _time  # Local import to avoid impacting module import time

    stats = getattr(DNSUDPHandler, "stats_collector", None)
    t0 = _time.perf_counter() if stats is not None else None

    try:
        req = DNSRecord.parse(data)
        q = req.questions[0]
        qname = str(q.qname).rstrip(".")
        qtype = q.qtype
        cache_key = (qname.lower(), qtype)

        # Record query stats (mirrors DNSUDPHandler.handle)
        if stats is not None:
            try:
                qtype_name = QTYPE.get(qtype, str(qtype))
                stats.record_query(client_ip, qname, qtype_name)
            except Exception:  # pragma: no cover
                pass

        # Pre plugins
        ctx = PluginContext(client_ip=client_ip)
        for p in sorted(
            DNSUDPHandler.plugins, key=lambda p: getattr(p, "pre_priority", 50)
        ):
            decision = p.pre_resolve(qname, qtype, data, ctx)
            if isinstance(decision, PluginDecision):
                if decision.action == "deny":
                    # NXDOMAIN deny path
                    r = req.reply()
                    r.header.rcode = RCODE.NXDOMAIN
                    wire = _set_response_id(r.pack(), req.header.id)
                    if stats is not None:
                        try:
                            qtype_name = QTYPE.get(qtype, str(qtype))
                            try:
                                # Pre-plugin deny bypasses cache; count it as
                                # a cache_null response.
                                stats.record_cache_null(qname)
                            except Exception:  # pragma: no cover
                                pass
                            stats.record_response_rcode("NXDOMAIN", qname)
                            stats.record_query_result(
                                client_ip=client_ip,
                                qname=qname,
                                qtype=qtype_name,
                                rcode="NXDOMAIN",
                                upstream_id=None,
                                status="deny_pre",
                                error=None,
                                first=None,
                                result={"source": "pre_plugin", "action": "deny"},
                            )
                        except Exception:  # pragma: no cover
                            pass
                    return wire
                if decision.action == "override" and decision.response is not None:
                    wire = _set_response_id(decision.response, req.header.id)
                    if stats is not None:
                        try:
                            parsed = DNSRecord.parse(wire)
                            rcode_name = RCODE.get(
                                parsed.header.rcode, str(parsed.header.rcode)
                            )
                            try:
                                # Pre-plugin override also bypasses cache; count
                                # it as a cache_null response.
                                stats.record_cache_null(qname)
                            except Exception:  # pragma: no cover
                                pass
                            stats.record_response_rcode(rcode_name, qname)

                            answers = [
                                {
                                    "name": str(rr.rname),
                                    "type": QTYPE.get(rr.rtype, str(rr.rtype)),
                                    "ttl": int(getattr(rr, "ttl", 0)),
                                    "rdata": str(rr.rdata),
                                }
                                for rr in (parsed.rr or [])
                            ]
                            first = answers[0]["rdata"] if answers else None
                            result = {
                                "source": "pre_plugin_override",
                                "answers": answers,
                            }
                            qtype_name = QTYPE.get(qtype, str(qtype))
                            stats.record_query_result(
                                client_ip=client_ip,
                                qname=qname,
                                qtype=qtype_name,
                                rcode=rcode_name,
                                upstream_id=None,
                                status="override_pre",
                                error=None,
                                first=str(first) if first is not None else None,
                                result=result,
                            )
                        except Exception:  # pragma: no cover
                            pass
                    return wire
                if decision.action == "allow":
                    # Explicit allow: stop evaluating further pre plugins but
                    # continue normal resolution (cache/upstream).
                    break

        # Cache lookup
        cached = DNSUDPHandler.cache.get(cache_key)
        if cached is not None:
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
                    result = {"source": "cache", "answers": answers}
                    qtype_name = QTYPE.get(qtype, str(qtype))
                    stats.record_query_result(
                        client_ip=client_ip,
                        qname=qname,
                        qtype=qtype_name,
                        rcode=rcode_name,
                        upstream_id=None,
                        status="cache_hit",
                        error=None,
                        first=str(first) if first is not None else None,
                        result=result,
                    )
                except Exception:  # pragma: no cover
                    pass
            return _set_response_id(cached, req.header.id)

        # Cache miss
        if stats is not None:
            try:
                stats.record_cache_miss(qname)
            except Exception:  # pragma: no cover
                pass

        # Upstreams
        upstreams = ctx.upstream_candidates or DNSUDPHandler.upstream_addrs
        if not upstreams:
            r = req.reply()
            r.header.rcode = RCODE.SERVFAIL
            wire = _set_response_id(r.pack(), req.header.id)
            if stats is not None:
                try:
                    stats.record_response_rcode("SERVFAIL", qname)
                    qtype_name = QTYPE.get(qtype, str(qtype))
                    stats.record_query_result(
                        client_ip=client_ip,
                        qname=qname,
                        qtype=qtype_name,
                        rcode="SERVFAIL",
                        upstream_id=None,
                        status="no_upstreams",
                        error="no upstreams configured",
                        first=None,
                        result={"source": "server", "error": "no_upstreams"},
                    )
                except Exception:  # pragma: no cover
                    pass
            return wire

        # EDNS/DNSSEC adjustments (mirror DNSUDPHandler behavior)
        try:
            mode = str(DNSUDPHandler.dnssec_mode).lower()
            if mode in ("ignore", "passthrough", "validate"):
                # Use instance-like helper by constructing a temp handler
                dummy = type("_H", (), {})()
                dummy.dnssec_mode = DNSUDPHandler.dnssec_mode
                dummy.edns_udp_payload = DNSUDPHandler.edns_udp_payload

                def _ensure(req):
                    # Inline simplified ensure to avoid method binding
                    opt_idx = None
                    for idx, rr in enumerate(getattr(req, "ar", []) or []):
                        if rr.rtype == QTYPE.OPT:
                            opt_idx = idx
                            break
                    flags = _edns_flags_for_mode(dummy.dnssec_mode)
                    opt_rr = RR(
                        rname=".",
                        rtype=QTYPE.OPT,
                        rclass=int(dummy.edns_udp_payload),
                        ttl=0,
                        rdata=EDNS0(flags=flags),
                    )
                    if opt_idx is None:
                        req.add_ar(opt_rr)
                    else:
                        req.ar[opt_idx] = opt_rr

                _ensure(req)
        except Exception:  # pragma: no cover
            pass  # pragma: no cover

        # Forward with failover
        upstream_id: Optional[str] = None
        reply, used_upstream, reason = send_query_with_failover(
            req, upstreams, DNSUDPHandler.timeout_ms, qname, qtype
        )

        # Record upstream result
        if stats is not None and used_upstream:
            try:
                host = str(used_upstream.get("host", ""))
                port = int(used_upstream.get("port", 0))
                upstream_id = f"{host}:{port}" if host or port else host or "unknown"
                outcome = "success" if reason == "ok" else str(reason)
                stats.record_upstream_result(upstream_id, outcome)
            except Exception:  # pragma: no cover
                pass

        if reply is None:
            r = req.reply()
            r.header.rcode = RCODE.SERVFAIL
            wire = _set_response_id(r.pack(), req.header.id)
            if stats is not None:
                try:
                    stats.record_response_rcode("SERVFAIL", qname)
                    if upstream_id:
                        try:
                            stats.record_upstream_rcode(upstream_id, "SERVFAIL")
                        except Exception:  # pragma: no cover
                            pass
                    qtype_name = QTYPE.get(qtype, str(qtype))
                    status = str(reason or "all_failed")
                    stats.record_query_result(
                        client_ip=client_ip,
                        qname=qname,
                        qtype=qtype_name,
                        rcode="SERVFAIL",
                        upstream_id=upstream_id,
                        status=status,
                        error="all_upstreams_failed",
                        first=None,
                        result={
                            "source": "upstream",
                            "status": status,
                            "error": "all_upstreams_failed",
                        },
                    )
                except Exception:  # pragma: no cover
                    pass
            return wire

        # Post plugins
        ctx2 = PluginContext(client_ip=client_ip)
        out = reply
        for p in sorted(
            DNSUDPHandler.plugins, key=lambda p: getattr(p, "post_priority", 50)
        ):
            decision = p.post_resolve(qname, qtype, out, ctx2)
            if isinstance(decision, PluginDecision):
                if decision.action == "deny":
                    r = req.reply()
                    r.header.rcode = RCODE.NXDOMAIN
                    out = r.pack()
                    break
                if decision.action == "override" and decision.response is not None:
                    out = decision.response
                    break
                if decision.action == "allow":
                    # Explicit allow: stop evaluating further post plugins but
                    # leave the upstream response unchanged.
                    break

        # Cache store positive answers, negative responses (NXDOMAIN/NODATA), and
        # delegations/referrals using TTLs derived from SOA/NS records where
        # possible, following RFC 2308 guidance.
        try:
            r = DNSRecord.parse(out)
            rcode = r.header.rcode
            ttl: Optional[int] = None

            # Positive answers: cache when we have an answer RRset.
            if rcode == RCODE.NOERROR and r.rr:
                ttls = [
                    int(getattr(rr, "ttl", 0))
                    for rr in r.rr
                    if isinstance(getattr(rr, "ttl", None), (int, float))
                ]
                ttl = min(ttls) if ttls else 300
            else:
                auth_rrs = getattr(r, "auth", None) or []
                has_soa = any(rr.rtype == QTYPE.SOA for rr in auth_rrs)
                has_ns = any(rr.rtype == QTYPE.NS for rr in auth_rrs)

                # Negative caching per RFC 2308: NXDOMAIN or NODATA responses
                # with an SOA in the authority section.
                if has_soa and (
                    rcode == RCODE.NXDOMAIN or (rcode == RCODE.NOERROR and not r.rr)
                ):
                    ttl = _compute_negative_ttl(
                        r, getattr(DNSUDPHandler, "min_cache_ttl", 0)
                    )
                # Delegation / referral caching: NOERROR with no answers but NS
                # in the authority section.
                elif has_ns and rcode == RCODE.NOERROR and not r.rr:
                    ttl = _compute_negative_ttl(
                        r, getattr(DNSUDPHandler, "min_cache_ttl", 0)
                    )

            if ttl is not None and ttl > 0:
                DNSUDPHandler.cache.set(cache_key, int(ttl), out)
        except Exception:  # pragma: no cover
            pass  # pragma: no cover

        wire = _set_response_id(out, req.header.id)

        # Record response rcode and append to persistent query_log when enabled.
        if stats is not None:
            try:
                parsed = DNSRecord.parse(wire)
                rcode_name = RCODE.get(parsed.header.rcode, str(parsed.header.rcode))
                stats.record_response_rcode(rcode_name, qname)
                if upstream_id:
                    try:
                        stats.record_upstream_rcode(upstream_id, rcode_name)
                    except Exception:  # pragma: no cover
                        pass

                answers = [
                    {
                        "name": str(rr.rname),
                        "type": QTYPE.get(rr.rtype, str(rr.rtype)),
                        "ttl": int(getattr(rr, "ttl", 0)),
                        "rdata": str(rr.rdata),
                    }
                    for rr in (parsed.rr or [])
                ]
                first = answers[0]["rdata"] if answers else None
                result = {"source": "upstream", "answers": answers}
                qtype_name = QTYPE.get(qtype, str(qtype))
                status = "ok" if rcode_name == "NOERROR" else "error"
                stats.record_query_result(
                    client_ip=client_ip,
                    qname=qname,
                    qtype=qtype_name,
                    rcode=rcode_name,
                    upstream_id=upstream_id,
                    status=status,
                    error=None,
                    first=str(first) if first is not None else None,
                    result=result,
                )
            except Exception:  # pragma: no cover
                pass

        return wire
    except Exception as e:
        try:
            req = DNSRecord.parse(data)
            r = req.reply()
            r.header.rcode = RCODE.SERVFAIL
            wire = _set_response_id(r.pack(), req.header.id)
            if stats is not None:
                try:
                    stats.record_response_rcode("SERVFAIL")
                    # Attempt to recover qname/qtype for logging
                    q = req.questions[0]
                    qname = str(q.qname).rstrip(".")
                    qtype = q.qtype
                    qtype_name = QTYPE.get(qtype, str(qtype))
                    stats.record_query_result(
                        client_ip=client_ip,
                        qname=qname,
                        qtype=qtype_name,
                        rcode="SERVFAIL",
                        upstream_id=None,
                        status="error",
                        error=str(e),
                        first=None,
                        result={"source": "server", "error": "unhandled_exception"},
                    )
                except Exception:  # pragma: no cover
                    pass
            return wire
        except Exception:
            return data  # fallback worst-case
    finally:
        # Latency tracking shared across all transports
        if stats is not None and t0 is not None:
            try:
                t1 = _time.perf_counter()
                stats.record_latency(t1 - t0)
            except Exception:  # pragma: no cover
                pass


class DNSServer:
    """
    A basic DNS server.

    Example use:
        >>> from foghorn.server import DNSServer
        >>> import threading
        >>> import time
        >>> # Start server in a background thread
        >>> server = DNSServer("127.0.0.1", 5355, ("8.8.8.8", 53), [], timeout=1.0)
        >>> server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        >>> server_thread.start()
        >>> # The server is now running in the background
        >>> time.sleep(0.1)
        >>> server.server.shutdown()
    """

    def __init__(
        self,
        host: str,
        port: int,
        upstreams: List[Dict],
        plugins: List[BasePlugin],
        timeout: float = 2.0,
        timeout_ms: int = 2000,
        min_cache_ttl: int = 60,
        stats_collector=None,
        *,
        dnssec_mode: str = "ignore",
        edns_udp_payload: int = 1232,
    ) -> None:
        """
        Initializes the DNSServer.

        Inputs:
            host: The host to listen on.
            port: The port to listen on.
            upstreams: A list of upstream DNS server configurations.
            plugins: A list of initialized plugins.
            timeout: The timeout for upstream queries (seconds, legacy).
            timeout_ms: The timeout for upstream queries (milliseconds).
            min_cache_ttl: Minimum cache TTL in seconds applied to all cached responses.
            stats_collector: Optional StatsCollector for recording metrics.

        Outputs:
            None

        Uses socketserver.ThreadingUDPServer for concurrent request handling.

        Example:
            >>> from foghorn.server import DNSServer
            >>> upstreams = [{'host': '8.8.8.8', 'port': 53}]
            >>> server = DNSServer("127.0.0.1", 5353, upstreams, [], 2.0, 2000, 60)
            >>> server.server.server_address
            ('127.0.0.1', 5353)
        """
        DNSUDPHandler.upstream_addrs = upstreams  # pragma: no cover
        DNSUDPHandler.plugins = plugins  # pragma: no cover
        DNSUDPHandler.timeout = timeout  # pragma: no cover
        DNSUDPHandler.timeout_ms = timeout_ms  # pragma: no cover
        DNSUDPHandler.min_cache_ttl = max(0, int(min_cache_ttl))  # pragma: no cover
        DNSUDPHandler.stats_collector = stats_collector  # pragma: no cover
        DNSUDPHandler.dnssec_mode = str(dnssec_mode)
        try:
            DNSUDPHandler.edns_udp_payload = max(512, int(edns_udp_payload))
        except Exception:
            DNSUDPHandler.edns_udp_payload = 1232
        self.server = socketserver.ThreadingUDPServer(
            (host, port), DNSUDPHandler
        )  # pragma: no cover

        # Ensure request handler threads do not block shutdown
        self.server.daemon_threads = True  # pragma: no cover
        logger.debug("DNS UDP server bound to %s:%d", host, port)  # pragma: no cover

    def serve_forever(self):
        """
        Starts the server and listens for requests.

        Example use:
            This method is typically run in a separate thread for testing.
            See the DNSServer class docstring for an example.
        """
        try:  # pragma: no cover
            self.server.serve_forever()  # pragma: no cover
        except KeyboardInterrupt:  # pragma: no cover
            pass  # pragma: no cover
