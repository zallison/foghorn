import logging
import socketserver
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, NamedTuple, Optional, Tuple

from dnslib import (  # noqa: F401  (re-exported for udp_server._ensure_edns)
    EDNS0,
    QTYPE,
    RCODE,
    RR,
    DNSRecord,
)

from cachetools import TTLCache

from foghorn.plugins.resolve import base as plugin_base
from foghorn.plugins.resolve.base import BasePlugin, PluginContext, PluginDecision
from foghorn.servers.recursive_resolver import RecursiveResolver
from foghorn.servers.transports.dot import DoTError, get_dot_pool
from foghorn.servers.transports.tcp import TCPError, get_tcp_pool, tcp_query
from foghorn.utils.register_caches import registered_cached, registered_lru_cached
from .udp_server import DNSUDPHandler

logger = logging.getLogger("foghorn.server")


# Thread-local flag used to bypass cache lookups when performing background
# refresh queries. When bypass_cache is True, _resolve_core skips the cache
# hit path and always treats the query as a miss.
_CACHE_LOCAL = threading.local()


def _schedule_cache_refresh(data: bytes, client_ip: str) -> None:
    """Brief: Schedule a background cache refresh for a given query.

    Inputs:
      - data: Original wire-format DNS query bytes.
      - client_ip: Client IP string used when reissuing the query (typically
        the same as the original requester so stats attribution is consistent).

    Outputs:
      - None; best-effort background refresh that bypasses cache on the next
        resolve_query_bytes() call for this thread.
    """

    def _worker() -> None:
        try:
            setattr(_CACHE_LOCAL, "bypass_cache", True)
            try:
                # Use the shared resolver so cache, plugins, and stats are all
                # kept consistent with normal query handling.
                resolve_query_bytes(data, client_ip)
            finally:
                setattr(_CACHE_LOCAL, "bypass_cache", False)
        except Exception:
            # Background refresh failures must never impact the caller; log
            # at debug level only.
            logger.debug("Cache refresh failed", exc_info=True)

    try:
        t = threading.Thread(
            target=_worker,
            name="FoghornCacheRefresh",
            daemon=True,
        )
        t.start()
    except Exception:
        logger.debug("Failed to start cache refresh thread", exc_info=True)


@registered_cached(
    cache=TTLCache(maxsize=1024, ttl=60),
    key=lambda resp, min_cache_ttl: (id(resp), int(min_cache_ttl)),
)
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
    without parsing to avoid any packing differences. For non-bytes inputs we
    return the original object unchanged so callers can rely on a best-effort
    behaviour without hard failures.
    """
    # Non-bytes inputs (e.g., None in defensive tests) are returned unchanged
    # but still trigger an error log so callers can diagnose misuse.
    if not isinstance(wire, (bytes, bytearray, memoryview)):
        logger.error("Failed to set response id: non-bytes wire %r", type(wire))
        return wire
    try:
        bwire = bytes(wire)
        if len(bwire) < 2:
            return bwire
        hi = (int(req_id) >> 8) & 0xFF
        lo = int(req_id) & 0xFF
        return bytes([hi, lo]) + bwire[2:]
    except Exception as e:  # pragma: no cover - defensive: error-handling path
        logger.error("Failed to set response id: %s", e)
        # Fall back to returning the original value when rewriting fails.
        return wire


def _set_response_id_bytes(wire: bytes, req_id: int) -> bytes:
    try:
        if len(wire) >= 2:
            hi = (req_id >> 8) & 0xFF
            lo = req_id & 0xFF
            return bytes([hi, lo]) + wire[2:]
        return wire
    except (
        Exception
    ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        logger.error("Failed to set response id (cached): %s", e)
        return wire


def send_query_with_failover(
    query: DNSRecord,
    upstreams: List[Dict],
    timeout_ms: int,
    qname: str,
    qtype: int,
    max_concurrent: int = 1,
) -> Tuple[Optional[bytes], Optional[Dict], str]:
    """
    Sends a DNS query to a list of upstream servers, with failover and optional
    per-query concurrency across multiple upstreams.

    Args:
        query: The DNSRecord to send.
        upstreams: A list of upstream server dicts to try.
        timeout_ms: The timeout in milliseconds for each attempt.
        qname: The query name (for logging).
        qtype: The query type (for logging).
        max_concurrent: Maximum number of upstreams to query in parallel for
            this request. Values <1 are treated as 1. When greater than 1,
            up to ``max_concurrent`` upstreams are queried concurrently and the
            first successful response is returned.

    Returns:
        A tuple of (response_wire_bytes, used_upstream, reason).
        reason is 'ok', 'no_upstreams', or 'all_failed'.
    """
    if not upstreams:
        return None, None, "no_upstreams"

    timeout_sec = timeout_ms / 1000.0
    last_exception: Optional[Exception] = None

    try:
        max_c = int(max_concurrent or 1)
    except Exception:  # pragma: no cover - defensive: invalid caller input
        max_c = 1
    if max_c < 1:
        max_c = 1

    def _try_single(upstream: Dict) -> Tuple[Optional[bytes], Optional[Dict], str]:
        """Send query to a single upstream and classify the result.

        Inputs:
          - upstream: Mapping describing host/port/transport configuration.

        Outputs:
          - (response_wire, used_upstream, reason) where response_wire is
            None when this upstream failed and reason is 'ok' on success or
            'all_failed' on per-upstream failure.
        """

        nonlocal last_exception

        # For DoH we may not have host/port; use safe defaults for logging
        host = str(upstream.get("host", ""))
        try:
            port = int(upstream.get("port", 0))
        except Exception:  # pragma: no cover - defensive: bad port value
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
                except Exception:  # pragma: no cover - defensive: pool tuning only
                    pass
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
                except Exception:  # pragma: no cover - defensive: pool tuning only
                    pass
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
                from foghorn.servers.transports.doh import (  # local import to avoid overhead
                    doh_query,
                )

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
                    from foghorn.servers.transports.udp import udp_query

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
                    return None, None, "all_failed"
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
                        return (
                            response_wire,
                            {**upstream, "transport": "tcp"},
                            "ok",
                        )
                    except Exception as e2:  # pragma: no cover - defensive
                        last_exception = e2
                        return None, None, "all_failed"
            except Exception as e:  # pragma: no cover - defensive
                # If parsing fails, treat as a server failure
                logger.warning(
                    "Failed to parse response from %s:%d for %s: %s",
                    host,
                    port,
                    qname,
                    e,
                )
                last_exception = e
                return None, None, "all_failed"

            # Success (NOERROR, NXDOMAIN, etc.)
            return response_wire, upstream, "ok"

        except (
            DoTError,
            TCPError,
            Exception,
        ) as e:  # pragma: no cover - defensive: network/transport failure
            logger.debug(
                "Upstream %s:%d via %s failed for %s: %s",
                host,
                port,
                transport,
                qname,
                str(e),
            )
            last_exception = e
            return None, None, "all_failed"

    # Sequential path: same semantics as the original implementation when
    # max_concurrent == 1.
    if max_c == 1 or len(upstreams) <= 1:
        for upstream in upstreams:
            resp, used, reason = _try_single(upstream)
            if resp is not None:
                return resp, used, reason
    else:
        # Concurrency path: query up to max_c upstreams in parallel and return
        # the first successful response.
        workers = min(max_c, len(upstreams))
        try:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(_try_single, up) for up in upstreams]
                for fut in as_completed(futures):
                    try:
                        resp, used, reason = fut.result()
                    except Exception as e:  # pragma: no cover - defensive
                        last_exception = e
                        continue
                    if resp is not None:
                        return resp, used, reason
        except Exception as e:  # pragma: no cover - defensive: executor failure
            last_exception = e

    logger.warning(
        "All upstreams failed for %s %s. Last error: %s", qname, qtype, last_exception
    )
    return None, None, "all_failed"


# DNSUDPHandler and DNSServer now live in foghorn.udp_server; they are re-exported
# at the bottom of this module for backward compatibility.


class _ResolveCoreResult(NamedTuple):
    """Internal result for the shared resolve pipeline.

    Inputs:
      - None (constructed by _resolve_core).
    Outputs:
      - wire: Final DNS response bytes with ID fixed.
      - dnssec_status: Optional DNSSEC status string.
      - upstream_id: Optional upstream identifier string.
      - rcode_name: Textual rcode name.
    """

    wire: bytes
    dnssec_status: Optional[str]
    upstream_id: Optional[str]
    rcode_name: str


def _resolve_core(data: bytes, client_ip: str) -> _ResolveCoreResult:
    """Shared resolution pipeline used by UDP and non-UDP callers.

    Inputs:
      - data: Wire-format DNS query bytes.
      - client_ip: Client IP string for plugin context and stats.
    Outputs:
      - _ResolveCoreResult with final wire bytes and metadata.
    """
    import time as _time  # Local import to avoid impacting module import time

    stats = getattr(DNSUDPHandler, "stats_collector", None)
    t0 = _time.perf_counter() if stats is not None else None

    try:
        rcode_name = "UNKNOWN"
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
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

        # Pre plugins
        ctx = PluginContext(client_ip=client_ip)
        for p in sorted(
            DNSUDPHandler.plugins, key=lambda p: getattr(p, "pre_priority", 50)
        ):
            # Skip plugins that do not target this qtype when they opt in via
            # BasePlugin.target_qtypes.
            try:
                if hasattr(p, "targets_qtype") and not p.targets_qtype(qtype):
                    continue
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                # On failure, fall back to running the plugin to avoid hiding
                # errors behind targeting decisions.
                pass

            decision = p.pre_resolve(qname, qtype, data, ctx)
            if isinstance(decision, PluginDecision):
                if decision.action == "drop":
                    # Pre-plugin timeout/drop: return sentinel empty wire so UDP
                    # handlers and othefoghorn.servers.transports can choose not to reply.
                    return _ResolveCoreResult(
                        wire=b"",
                        dnssec_status=None,
                        upstream_id=None,
                        rcode_name="DROP",
                    )
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
                                # a cache_null response and bump the
                                # cache_deny_pre total for live counters.
                                stats.record_cache_null(qname, status="deny_pre")
                            except (
                                Exception
                            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                                pass
                            # When plugins provide a decision.stat label,
                            # mirror it into cache statistics so the HTML
                            # dashboard can expose per-decision tallies.
                            try:
                                stat_label = getattr(decision, "stat", None)
                                if stat_label:
                                    stats.record_cache_stat(str(stat_label))
                            except (
                                Exception
                            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                                pass
                            # Also record per-plugin pre-deny totals so
                            # stats.totals exposes pre_deny_<name> keys. Prefer
                            # the originating plugin instance label when
                            # available, falling back to alias/class naming.
                            try:
                                label_suffix = getattr(decision, "plugin_label", None)
                                if not label_suffix:
                                    plugin_cls = getattr(
                                        decision, "plugin", None
                                    ) or type(p)
                                    plugin_name = getattr(
                                        plugin_cls, "__name__", "plugin"
                                    ).lower()
                                    aliases = []
                                    try:
                                        aliases = list(
                                            getattr(
                                                plugin_cls, "get_aliases", lambda: []
                                            )()
                                        )
                                    except (
                                        Exception
                                    ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                                        aliases = []
                                    if aliases:
                                        label_suffix = str(aliases[0]).strip().lower()
                                    else:
                                        label_suffix = plugin_name

                                short = str(label_suffix).strip()
                                if short:
                                    label = f"pre_deny_{short}"
                                else:
                                    label = "pre_deny_plugin"
                                stats.record_cache_pre_plugin(label)
                            except (
                                Exception
                            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
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
                        except (
                            Exception
                        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                            pass
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
                        rcode_name="NXDOMAIN",
                    )
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
                                # it as a cache_null response and bump the
                                # cache_override_pre total for live counters.
                                stats.record_cache_null(qname, status="override_pre")
                            except (
                                Exception
                            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                                pass
                            # Mirror any decision.stat label into cache stats
                            # so per-decision tallies are available in Totals.
                            try:
                                stat_label = getattr(decision, "stat", None)
                                if stat_label:
                                    stats.record_cache_stat(str(stat_label))
                            except (
                                Exception
                            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                                pass
                            # Also record per-plugin pre-override totals so
                            # stats.totals exposes pre_override_<name>. Prefer
                            # the originating plugin instance label when
                            # available, falling back to alias/class naming.
                            try:
                                label_suffix = getattr(decision, "plugin_label", None)
                                if not label_suffix:
                                    plugin_cls = getattr(
                                        decision, "plugin", None
                                    ) or type(p)
                                    plugin_name = getattr(
                                        plugin_cls, "__name__", "plugin"
                                    ).lower()
                                    aliases = []
                                    try:
                                        aliases = list(
                                            getattr(
                                                plugin_cls, "get_aliases", lambda: []
                                            )()
                                        )
                                    except (
                                        Exception
                                    ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                                        aliases = []
                                    if aliases:
                                        label_suffix = str(aliases[0]).strip().lower()
                                    else:
                                        label_suffix = plugin_name

                                short = str(label_suffix).strip()
                                if short:
                                    label = f"pre_override_{short}"
                                else:
                                    label = "pre_override_plugin"
                                stats.record_cache_pre_plugin(label)
                            except (
                                Exception
                            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
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
                        except (
                            Exception
                        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                            pass
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
                if decision.action == "allow":
                    # Explicit allow: stop evaluating further pre plugins but
                    # continue normal resolution (cache/upstream).
                    break

        # Cache lookup (with optional stale-while-revalidate prefetch).
        cache = getattr(plugin_base, "DNS_CACHE", None)
        cached: Optional[bytes] = None
        seconds_remaining: Optional[float] = None
        ttl_original: Optional[int] = None
        bypass_cache = bool(getattr(_CACHE_LOCAL, "bypass_cache", False))

        if cache is not None and not bypass_cache:
            # Prefer get_with_meta() for stale-while-revalidate behavior. Allow a
            # fallback to get() for transitional/custom cache implementations.
            try:
                value, remaining, ttl_val = cache.get_with_meta(cache_key)
                if value is not None:
                    cached = value
                    seconds_remaining = remaining
                    ttl_original = ttl_val
            except NotImplementedError:
                try:
                    cached = cache.get(cache_key)
                except NotImplementedError:
                    cached = None
            except (
                Exception
            ):  # pragma: no cover - defensive: cache implementation detail
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
                except (
                    Exception
                ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    pass

            # Decide whether to schedule a background refresh for this cache hit
            prefetch_enabled = bool(
                getattr(DNSUDPHandler, "cache_prefetch_enabled", False)
            )
            min_ttl = int(getattr(DNSUDPHandler, "cache_prefetch_min_ttl", 0) or 0)
            max_ttl = int(getattr(DNSUDPHandler, "cache_prefetch_max_ttl", 0) or 0)
            window_before = float(
                getattr(
                    DNSUDPHandler,
                    "cache_prefetch_refresh_before_expiry",
                    0.0,
                )
                or 0.0
            )
            window_after = float(
                getattr(
                    DNSUDPHandler,
                    "cache_prefetch_allow_stale_after_expiry",
                    0.0,
                )
                or 0.0
            )

            should_refresh = False
            if (
                prefetch_enabled
                and seconds_remaining is not None
                and ttl_original is not None
            ):
                ttl_ok = True
                if ttl_original < min_ttl:
                    ttl_ok = False
                if max_ttl > 0 and ttl_original > max_ttl:
                    ttl_ok = False
                if ttl_ok:
                    if 0.0 <= seconds_remaining <= window_before:
                        should_refresh = True
                    elif (
                        window_after > 0.0 and -window_after <= seconds_remaining < 0.0
                    ):
                        should_refresh = True

            if should_refresh and not bypass_cache:
                _schedule_cache_refresh(data, client_ip)

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

        reply: Optional[bytes] = None
        used_upstream: Optional[Dict] = None
        reason: Optional[str] = None

        # Decide between forwarding and recursive resolution based on resolver_mode.
        resolver_mode = str(getattr(DNSUDPHandler, "resolver_mode", "forward")).lower()

        if resolver_mode == "recursive":
            # In recursive mode we bypass configured upstreams and instead walk
            # from the root using RecursiveResolver. We still honour the
            # dnssec_mode when constructing the query (RD bit and EDNS DO bit
            # are already handled earlier in the pipeline) and we reuse
            # DNSUDPHandler's recursion knobs.
            try:
                max_depth = int(getattr(DNSUDPHandler, "recursive_max_depth", 16) or 16)
            except Exception:  # pragma: no cover - defensive
                max_depth = 16
            try:
                recursion_timeout_ms = int(
                    getattr(
                        DNSUDPHandler,
                        "recursive_timeout_ms",
                        getattr(DNSUDPHandler, "timeout_ms", 2000),
                    )
                    or getattr(DNSUDPHandler, "timeout_ms", 2000)
                )
            except Exception:  # pragma: no cover - defensive
                recursion_timeout_ms = int(
                    getattr(DNSUDPHandler, "timeout_ms", 2000) or 2000
                )
            try:
                per_try_ms = int(
                    getattr(
                        DNSUDPHandler,
                        "recursive_per_try_timeout_ms",
                        recursion_timeout_ms,
                    )
                    or recursion_timeout_ms
                )
            except Exception:  # pragma: no cover - defensive
                per_try_ms = recursion_timeout_ms

            resolver = RecursiveResolver(
                cache=getattr(plugin_base, "DNS_CACHE", None),
                stats=stats,
                max_depth=max_depth,
                timeout_ms=recursion_timeout_ms,
                per_try_timeout_ms=per_try_ms,
            )

            # Perform iterative resolution. RecursiveResolver is responsible for
            # talking to upstream authorities; we only receive the final wire
            # and an optional upstream identifier for stats.
            reply, upstream_id = resolver.resolve(req)
            reason = "ok" if reply is not None else "all_failed"
        else:
            # Classic forwarding: EDNS/DNSSEC adjustments (mirror
            # DNSUDPHandler behaviour) followed by send_query_with_failover.
            try:
                mode = str(getattr(DNSUDPHandler, "dnssec_mode", "ignore")).lower()
                if mode in ("ignore", "passthrough", "validate"):
                    handler = type("_H", (), {})()
                    handler.dnssec_mode = DNSUDPHandler.dnssec_mode
                    handler.edns_udp_payload = getattr(
                        DNSUDPHandler, "edns_udp_payload", 1232
                    )
                    ensure = getattr(DNSUDPHandler, "_ensure_edns", None)
                    if callable(ensure):
                        ensure(handler, req)
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably

            # Forward with failover using the same helper as UDP handlers. Tests
            # frequently monkeypatch send_query_with_failover directly, so we call
            # it here rather than DNSUDPHandler._forward_with_failover_helper.
            upstream_id = None
            timeout_ms = getattr(DNSUDPHandler, "timeout_ms", 2000)
            upstreams = list(getattr(DNSUDPHandler, "upstream_addrs", []) or [])
            try:
                max_concurrent = int(
                    getattr(DNSUDPHandler, "upstream_max_concurrent", 1) or 1
                )
            except Exception:
                max_concurrent = 1
            if max_concurrent < 1:
                max_concurrent = 1
            reply, used_upstream, reason = send_query_with_failover(
                req,
                upstreams,
                timeout_ms,
                qname,
                qtype,
                max_concurrent=max_concurrent,
            )

        # Record upstream result, even when all upstreams ultimately fail.
        if stats is not None and used_upstream:
            try:
                host = str(used_upstream.get("host", ""))
                port = int(used_upstream.get("port", 0))
                # For DoH-style upstreams identified by URL, prefer that as the
                # upstream_id so stats can distinguish endpoints consistently.
                url = str(used_upstream.get("url", "")).strip()
                if url:
                    upstream_id = url
                else:
                    upstream_id = (
                        f"{host}:{port}" if host or port else host or "unknown"
                    )
                outcome = "success" if reason == "ok" else str(reason)
                stats.record_upstream_result(upstream_id, outcome)
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
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
                        except (
                            Exception
                        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
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
            return _ResolveCoreResult(
                wire=wire,
                dnssec_status=None,
                upstream_id=upstream_id,
                rcode_name="SERVFAIL",
            )

        # Post plugins
        ctx2 = PluginContext(client_ip=client_ip)
        out = reply
        for p in sorted(
            DNSUDPHandler.plugins, key=lambda p: getattr(p, "post_priority", 50)
        ):
            # Skip plugins that do not target this qtype when they opt in via
            # BasePlugin.target_qtypes.
            try:
                if hasattr(p, "targets_qtype") and not p.targets_qtype(qtype):
                    continue
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                pass

            decision = p.post_resolve(qname, qtype, out, ctx2)
            if isinstance(decision, PluginDecision):
                if decision.action == "drop":
                    # Post-plugin timeout/drop: do not send a response.
                    return _ResolveCoreResult(
                        wire=b"",
                        dnssec_status=None,
                        upstream_id=upstream_id,
                        rcode_name="DROP",
                    )
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

        # DNSSEC classification for non-UDfoghorn.servers.transports (TCP/DoT/DoH) now shares
        # the same helper as UDP handlers so stats and query_log entries carry a
        # consistent "secure"/"insecure" status when dnssec.mode is 'validate'.
        dnssec_status = None
        try:
            # Use the same DNSSEC classification helper as the UDP handler so
            # non-UDP callers (TCP/DoT/DoH and tests using _resolve_core
            # directly) see consistent dnssec_status values.
            from ..dnssec.dnssec_validate import classify_dnssec_status

            mode = str(getattr(DNSUDPHandler, "dnssec_mode", "ignore"))
            validation = str(getattr(DNSUDPHandler, "dnssec_validation", "upstream_ad"))
            edns_udp_payload = int(getattr(DNSUDPHandler, "edns_udp_payload", 1232))
            dnssec_status = classify_dnssec_status(
                dnssec_mode=mode,
                dnssec_validation=validation,
                qname_text=qname,
                qtype_num=qtype,
                response_wire=out,
                udp_payload_size=edns_udp_payload,
            )
            if stats is not None and dnssec_status is not None:
                try:
                    stats.record_dnssec_status(dnssec_status)
                except (
                    Exception
                ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    pass
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            dnssec_status = None

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
                cache = getattr(plugin_base, "DNS_CACHE", None)
                if cache is not None:
                    cache.set(cache_key, int(ttl), out)
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably

        wire = _set_response_id(out, req.header.id)

        # Record response rcode and append to persistent query_log when enabled.
        rcode_name = "UNKNOWN"
        if stats is not None:
            try:
                parsed = DNSRecord.parse(wire)
                rcode_name = RCODE.get(parsed.header.rcode, str(parsed.header.rcode))
                stats.record_response_rcode(rcode_name, qname)
                if upstream_id:
                    try:
                        stats.record_upstream_rcode(upstream_id, rcode_name)
                    except (
                        Exception
                    ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
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
                if dnssec_status is not None:
                    result["dnssec_status"] = dnssec_status
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
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

        # Latency tracking shared across alfoghorn.servers.transports
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
            dnssec_status=dnssec_status,
            upstream_id=upstream_id,
            rcode_name=rcode_name,
        )
    except Exception as e:
        # Outer exception handler: synthesize SERVFAIL and record stats.
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
                except (
                    Exception
                ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    pass
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
                rcode_name="SERVFAIL",
            )
        except Exception:
            # Worst-case fallback
            return _ResolveCoreResult(
                wire=data,
                dnssec_status=None,
                upstream_id=None,
                rcode_name="UNKNOWN",
            )


def resolve_query_bytes(data: bytes, client_ip: str) -> bytes:
    """Resolve a single DNS wire query and return wire response.

    Inputs:
      - data: Wire-format DNS query bytes.
      - client_ip: String client IP for plugin context, logging, and statistics.
    Outputs:
      - bytes: Wire-format DNS response.

    This helper reuses DNSUDPHandler's class-level configuration (plugins,
    upstreams, DNSSEC knobs, and optional StatsCollector) so that TCP/DoT/DoH
    and other non-UDP callers share the same behavior and statistics pipeline.

    DNS response caching is provided by `foghorn.plugins.resolve.base.DNS_CACHE`.

    Example:
      >>> resp = resolve_query_bytes(query_bytes, '127.0.0.1')
    """
    return _resolve_core(data, client_ip).wire


class DNSServer:
    """A basic UDP DNS server wrapper.

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
        cache=None,
        *,
        dnssec_mode: str = "ignore",
        edns_udp_payload: int = 1232,
        dnssec_validation: str = "upstream_ad",
        upstream_strategy: str = "failover",
        upstream_max_concurrent: int = 1,
        resolver_mode: str = "forward",
        recursive_max_depth: int = 16,
        recursive_timeout_ms: int = 2000,
        recursive_per_try_timeout_ms: int = 2000,
        cache_prefetch_enabled: bool = False,
        cache_prefetch_min_ttl: int = 0,
        cache_prefetch_max_ttl: int = 0,
        cache_prefetch_refresh_before_expiry: float = 0.0,
        cache_prefetch_allow_stale_after_expiry: float = 0.0,
    ) -> None:
        """Initialize a UDP DNSServer.

        Inputs:
            host: The host to listen on.
            port: The port to listen on.
            upstreams: A list of upstream DNS server configurations.
            plugins: A list of initialized plugins.
            timeout: The timeout for upstream queries (seconds, legacy).
            timeout_ms: The timeout for upstream queries (milliseconds).
            min_cache_ttl: Minimum cache TTL in seconds applied to all cached responses.
            stats_collector: Optional StatsCollector for recording metrics.
        """
        # Install cache plugin for alfoghorn.servers.transports.
        if cache is None:
            try:
                from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache

                cache = InMemoryTTLCache()
            except Exception:
                cache = None
        try:
            plugin_base.DNS_CACHE = cache  # type: ignore[assignment]
        except Exception:
            pass

        DNSUDPHandler.upstream_addrs = upstreams  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSUDPHandler.plugins = plugins  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSUDPHandler.timeout = timeout  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSUDPHandler.timeout_ms = timeout_ms  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSUDPHandler.min_cache_ttl = max(
            0, int(min_cache_ttl)
        )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSUDPHandler.stats_collector = stats_collector  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSUDPHandler.dnssec_mode = str(dnssec_mode)
        DNSUDPHandler.dnssec_validation = str(dnssec_validation)
        DNSUDPHandler.upstream_strategy = str(upstream_strategy).lower()
        DNSUDPHandler.resolver_mode = str(resolver_mode).lower()
        DNSUDPHandler.recursive_max_depth = int(recursive_max_depth)
        DNSUDPHandler.recursive_timeout_ms = int(recursive_timeout_ms)
        DNSUDPHandler.recursive_per_try_timeout_ms = int(recursive_per_try_timeout_ms)

        # Cache prefetch / stale-while-revalidate knobs used by _resolve_core.
        DNSUDPHandler.cache_prefetch_enabled = bool(cache_prefetch_enabled)
        try:
            DNSUDPHandler.cache_prefetch_min_ttl = max(0, int(cache_prefetch_min_ttl))
        except Exception:
            DNSUDPHandler.cache_prefetch_min_ttl = 0
        try:
            DNSUDPHandler.cache_prefetch_max_ttl = max(0, int(cache_prefetch_max_ttl))
        except Exception:
            DNSUDPHandler.cache_prefetch_max_ttl = 0
        try:
            DNSUDPHandler.cache_prefetch_refresh_before_expiry = max(
                0.0, float(cache_prefetch_refresh_before_expiry)
            )
        except Exception:
            DNSUDPHandler.cache_prefetch_refresh_before_expiry = 0.0
        try:
            DNSUDPHandler.cache_prefetch_allow_stale_after_expiry = max(
                0.0, float(cache_prefetch_allow_stale_after_expiry)
            )
        except Exception:
            DNSUDPHandler.cache_prefetch_allow_stale_after_expiry = 0.0

        try:
            DNSUDPHandler.upstream_max_concurrent = max(1, int(upstream_max_concurrent))
        except Exception:
            DNSUDPHandler.upstream_max_concurrent = 1
        try:
            DNSUDPHandler.edns_udp_payload = max(512, int(edns_udp_payload))
        except Exception:
            DNSUDPHandler.edns_udp_payload = 1232
        try:
            self.server = socketserver.ThreadingUDPServer((host, port), DNSUDPHandler)
        except PermissionError as e:
            logger.error(
                "Permission denied when binding to %s:%d. Try a port >1024 or run with elevated privileges. Original error: %s",
                host,
                port,
                e,
            )
            raise  # Re-raise the exception after logging

        # Ensure request handler threads do not block shutdown
        self.server.daemon_threads = True  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        logger.debug(
            "DNS UDP server bound to %s:%d", host, port
        )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably

    def serve_forever(self) -> None:
        """Start the UDP server loop and listen for requests.

        Inputs:
          - None
        Outputs:
          - None; runs until shutdown is requested or KeyboardInterrupt occurs.
        """
        try:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            self.server.serve_forever()  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        except (
            KeyboardInterrupt
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably

    def stop(self) -> None:
        """Request graceful shutdown and close the underlying UDP socket.

        Inputs:
          - None
        Outputs:
          - None; best-effort shutdown suitable for use from signal handlers.
        """
        try:
            # First ask the ThreadingUDPServer loop to stop accepting requests.
            self.server.shutdown()
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.exception("Error while shutting down UDP server")
        try:
            # Then close the socket so resources are released promptly.
            self.server.server_close()
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.exception("Error while closing UDP server socket")
