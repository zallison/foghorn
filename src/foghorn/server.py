import logging
import socketserver
from typing import List, Tuple, Dict, Optional
from dnslib import DNSRecord, QTYPE, RCODE, RR, EDNS0

from .cache import TTLCache
from .plugins.base import BasePlugin, PluginDecision, PluginContext
from .transports.dot import dot_query, DoTError, get_dot_pool
from .transports.tcp import tcp_query, TCPError, get_tcp_pool

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


def _set_response_id(wire: bytes, req_id: int) -> bytes:
    """Ensure the response DNS ID matches the request ID.

    Fast path: DNS ID is the first 2 bytes (big-endian). We rewrite them
    without parsing to avoid any packing differences.
    """
    try:
        if len(wire) >= 2:
            hi = (req_id >> 8) & 0xFF
            lo = req_id & 0xFF
            return bytes([hi, lo]) + wire[2:]
        return wire
    except Exception as e:
        logger.error("Failed to set response id: %s", e)
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
        except Exception:
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
                except Exception:
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
                except Exception:
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
                from .transports.doh import (
                    doh_query,
                    DoHError,
                )  # local import to avoid overhead

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
                    except Exception as e2:
                        last_exception = e2
                        continue
            except Exception as e:
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

        except (DoTError, TCPError, Exception) as e:
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


class DNSUDPHandler(socketserver.BaseRequestHandler):
    """
    Handles UDP DNS requests.
    This class is instantiated for each incoming DNS query.

    Example use:
        This handler is used internally by the DNSServer and is not
        typically instantiated directly by users.
    """

    cache = TTLCache()
    upstream_addrs: List[Dict] = []
    plugins: List[BasePlugin] = []
    timeout = 2.0
    timeout_ms = 2000
    min_cache_ttl = 60
    stats_collector = None  # Optional StatsCollector instance
    dnssec_mode = "ignore"  # ignore | passthrough | validate
    dnssec_validation = "upstream_ad"  # upstream_ad | local
    edns_udp_payload = 1232

    def _cache_and_send_response(
        self,
        response_wire: bytes,
        req: DNSRecord,
        qname: str,
        qtype: int,
        sock,
        client_address,
        cache_key,
    ):
        """
        Caches response using TTL floor and sends to client.

        Inputs:
          - response_wire: bytes, the DNS response to cache and send
          - req: DNSRecord, original request for ID matching
          - qname: str, query name for logging
          - qtype: int, query type for logging
          - sock: socket to send response through
          - client_address: client address to send response to
          - cache_key: tuple, cache key for storing response

        Outputs:
          - None

        Caches all response types using min_cache_ttl floor and sends response.
        """
        try:
            r = DNSRecord.parse(response_wire)
            effective_ttl = compute_effective_ttl(r, self.min_cache_ttl)
            if effective_ttl > 0:
                rcode_name = RCODE.get(r.header.rcode, f"rcode{r.header.rcode}")
                logger.debug(
                    "Caching %s %s (%s) with TTL %ds",
                    qname,
                    qtype,
                    rcode_name,
                    effective_ttl,
                )
                self.cache.set(cache_key, effective_ttl, response_wire)
            else:
                logger.debug(
                    "Not caching %s %s (effective TTL=%d)", qname, qtype, effective_ttl
                )  # pragma: no cover
        except Exception as e:
            logger.debug("Failed to parse response for caching: %s", str(e))

        # Ensure the response ID matches the request ID before sending
        response_wire = _set_response_id(response_wire, req.header.id)
        sock.sendto(response_wire, client_address)

    def _parse_query(self, data: bytes):
        """
        Parse the incoming DNS query from raw UDP payload bytes.

        Inputs:
            - data (bytes): Raw UDP payload bytes containing a DNS query.

        Outputs:
            - request (DNSRecord): Parsed DNS request record.
            - qname (str): Query name (FQDN) with trailing dot removed.
            - qtype (int): DNS RR type (e.g., 1 for A, 28 for AAAA).
            - ctx (PluginContext): Plugin context with client IP.

        Example:
            request, qname, qtype, ctx = self._parse_query(data)
        """
        client_ip = self.client_address[0]
        req = DNSRecord.parse(data)
        q = req.questions[0]
        qname = str(q.qname).rstrip(".")
        qtype = q.qtype

        logger.debug("Query from %s: %s type: %s", client_ip, qname, qtype)

        ctx = PluginContext(client_ip=client_ip)
        return req, qname, qtype, ctx

    def _apply_pre_plugins(
        self, request: DNSRecord, qname: str, qtype: int, data: bytes, ctx
    ):
        """
        Apply pre-resolve plugins in ascending pre_priority order.

        Inputs:
            - request (DNSRecord): Parsed DNS request record.
            - qname (str): Query name.
            - qtype (int): DNS RR type.
            - data (bytes): Original query wire data.
            - ctx (PluginContext): Plugin context.

        Outputs:
            - decision (PluginDecision or None): Plugin decision if deny/override.

        Plugins execute in ascending pre_priority order (lower values first, default 50).
        Stable sort preserves registration order for equal priorities.

        Example:
            decision = self._apply_pre_plugins(request, qname, qtype, data, ctx)
        """
        # Pre-resolve plugin checks in priority order
        for p in sorted(self.plugins, key=lambda p: getattr(p, "pre_priority", 50)):
            decision = p.pre_resolve(qname, qtype, data, ctx)
            if isinstance(decision, PluginDecision):
                if decision.action == "deny":
                    logger.warning(
                        "Denied %s %s by %s", qname, qtype, p.__class__.__name__
                    )
                    return decision
                elif decision.action == "override" and decision.response is not None:
                    logger.info(
                        "Override %s type %s by %s", qname, qtype, p.__class__.__name__
                    )
                    return decision
                else:
                    pass

                logger.debug("Plugin %s: %s", p.__class__.__name__, decision.action)
        return None

    def _cache_lookup(self, qname: str, qtype: int):
        """
        Look up cached response for the query.

        Inputs:
            - qname (str): Query name.
            - qtype (int): DNS RR type.

        Outputs:
            - cached (bytes or None): Cached wire response or None if not found.

        Example:
            cached = self._cache_lookup(qname, qtype)
        """
        # Check cache for a response.
        cache_key = (qname.lower(), qtype)
        cached = self.cache.get(cache_key)
        if cached is not None:
            logger.debug("Cache hit: %s type %s (%d bytes)", qname, qtype, len(cached))
            return cached
        else:
            logger.debug("Cache miss: %s type %s", qname, qtype)
            return None

    def _choose_upstreams(self, qname: str, qtype: int, ctx):
        """
        Determine upstream servers to use for the query.

        Inputs:
            - qname (str): Query name.
            - qtype (int): DNS RR type.
            - ctx (PluginContext): Plugin context with possible upstream_candidates.

        Outputs:
            - upstreams (List[Dict]): List of upstream server configs to try.

        Notes:
            Respects plugin routing decisions and falls back to global upstreams.

        Example:
            upstreams = self._choose_upstreams(qname, qtype, ctx)
        """
        # Determine upstream candidates to try
        upstreams_to_try = ctx.upstream_candidates or self.upstream_addrs
        if upstreams_to_try:
            logger.debug(
                "Using %d upstreams for %s %s", len(upstreams_to_try), qname, qtype
            )  # pragma: no cover
        else:
            logger.warning("No upstreams configured for %s type %s", qname, qtype)
        return upstreams_to_try

    def _forward_with_failover_helper(
        self, request: DNSRecord, upstreams, qname: str, qtype: int
    ):
        """
        Forward query to upstream servers with failover support.

        Inputs:
            - request (DNSRecord): DNS request to forward.
            - upstreams (List[Dict]): Upstream servers to try.
            - qname (str): Query name for logging.
            - qtype (int): DNS RR type for logging.

        Outputs:
            - reply (bytes or None): Response wire data or None if all failed.
            - used_upstream (Dict or None): Upstream that succeeded or None.
            - reason (str): Result reason ('ok', 'all_failed', etc.).

        Notes:
            Uses existing send_query_with_failover function with timeout handling.

        Example:
            reply, upstream, reason = self._forward_with_failover_helper(req, upstreams, qname, qtype)
        """
        # Try upstreams with failover
        reply, used_upstream, reason = send_query_with_failover(
            request, upstreams, self.timeout_ms, qname, qtype
        )
        return reply, used_upstream, reason

    def _apply_post_plugins(
        self, request: DNSRecord, qname: str, qtype: int, response_wire: bytes, ctx
    ):
        """
        Apply post-resolve plugins in ascending post_priority order.

        Inputs:
            - request (DNSRecord): Original DNS request record.
            - qname (str): Query name.
            - qtype (int): DNS RR type.
            - response_wire (bytes): Response wire data.
            - ctx (PluginContext): Plugin context.

        Outputs:
            - final_response (bytes): Modified or original response wire data.

        Plugins execute in ascending post_priority order (lower values first, default 50).
        Stable sort preserves registration order for equal priorities.

        Example:
            response = self._apply_post_plugins(request, qname, qtype, response_wire, ctx)
        """
        reply = response_wire
        # Post-resolve plugin hooks in priority order
        for p in sorted(self.plugins, key=lambda p: getattr(p, "post_priority", 50)):
            decision = p.post_resolve(qname, qtype, reply, ctx)
            if isinstance(decision, PluginDecision):
                if decision.action == "deny":
                    logger.warning(
                        "Post-resolve denied %s type %s by %s",
                        qname,
                        qtype,
                        p.__class__.__name__,
                    )
                    r = request.reply()
                    r.header.rcode = RCODE.NXDOMAIN
                    reply = r.pack()
                    break
                if (
                    decision.action == "override" and decision.response is not None
                ):  # pragma: no cover
                    logger.info(
                        "Post-resolve override %s type %s by %s",
                        qname,
                        qtype,
                        p.__class__.__name__,
                    )  # pragma: no cover
                    reply = decision.response  # pragma: no cover
                    break  # pragma: no cover
        return reply

    def _cache_store_if_applicable(self, qname: str, qtype: int, response_wire: bytes):
        """
        Cache the response if it meets caching criteria.

        Inputs:
            - qname (str): Query name.
            - qtype (int): DNS RR type.
            - response_wire (bytes): Response wire data to potentially cache.

        Outputs:
            - None

        Notes:
            Only caches NOERROR responses with answer RRs using minimum TTL.
            Never caches SERVFAIL responses.

        Example:
            self._cache_store_if_applicable(qname, qtype, response_wire)
        """
        # Cache the response based on the minimum TTL in the answer records.
        # Only cache NOERROR responses with answer RRs; never cache SERVFAIL
        try:
            r = DNSRecord.parse(response_wire)
            cache_key = (qname.lower(), qtype)
            if r.header.rcode == RCODE.NOERROR and r.rr:
                ttls = [rr.ttl for rr in r.rr]
                ttl = min(ttls) if ttls else 300
                if ttl > 0:
                    logger.debug("Caching %s %s with TTL %ds", qname, qtype, ttl)
                    self.cache.set(cache_key, ttl, response_wire)
                else:
                    logger.debug("Not caching %s type %s (TTL=%d)", qname, qtype, ttl)
            elif r.header.rcode == RCODE.SERVFAIL:
                logger.debug(
                    "Not caching %s type: %s (SERVFAIL never cached)", qname, qtype
                )
            else:
                logger.debug(
                    "Not caching %s %s (rcode=%s, no answer RRs)",
                    qname,
                    qtype,
                    RCODE.get(r.header.rcode, r.header.rcode),
                )  # pragma: no cover
        except Exception as e:
            logger.debug("Failed to parse response for caching: %s", str(e))

    def _make_nxdomain_response(self, request: DNSRecord):
        """
        Create NXDOMAIN response for the given request.

        Inputs:
            - request (DNSRecord): Original DNS request.

        Outputs:
            - response_wire (bytes): NXDOMAIN response wire data.

        Example:
            nxdomain_wire = self._make_nxdomain_response(request)
        """
        reply = request.reply()
        reply.header.rcode = RCODE.NXDOMAIN
        return _set_response_id(reply.pack(), request.header.id)

    def _make_servfail_response(self, request: DNSRecord):
        """
        Create SERVFAIL response for the given request.

        Inputs:
            - request (DNSRecord): Original DNS request.

        Outputs:
            - response_wire (bytes): SERVFAIL response wire data.

        Example:
            servfail_wire = self._make_servfail_response(request)
        """
        r = request.reply()
        r.header.rcode = RCODE.SERVFAIL
        return _set_response_id(r.pack(), request.header.id)

    def _ensure_edns(self, req: DNSRecord) -> None:
        """
        Ensure the request carries an EDNS(0) OPT record with configured payload size and DO bit per dnssec_mode.

        Inputs:
          - req: DNSRecord to mutate.
        Outputs:
          - None

        Example:
          >>> self._ensure_edns(req)
        """
        # Find existing OPT
        opt_idx = None
        for idx, rr in enumerate(getattr(req, "ar", []) or []):
            if rr.rtype == QTYPE.OPT:
                opt_idx = idx
                break
        flags = 0
        if str(self.dnssec_mode).lower() == "passthrough":
            # Preserve DO if present, otherwise set it to advertise support
            flags |= 0x8000  # DO bit
        # rclass of OPT holds payload size
        opt_rr = RR(
            rname=".",
            rtype=QTYPE.OPT,
            rclass=int(self.edns_udp_payload),
            ttl=0,
            rdata=EDNS0(flags=flags),
        )
        if opt_idx is None:
            req.add_ar(opt_rr)
        else:
            req.ar[opt_idx] = opt_rr

    def handle(self):
        """
        Processes an incoming DNS query.
        The method follows these steps:
        1. Parses the query.
        2. Runs pre-resolve plugins.
        3. Checks the cache.
        4. Forwards to an upstream server if needed.
        5. Runs post-resolve plugins.
        6. Caches the response.
        7. Sends the final response to the client.
        """
        import time as time_module
        from dnslib import QTYPE

        t0 = time_module.perf_counter() if self.stats_collector else None
        data, sock = self.request
        client_ip = self.client_address[0]
        qname_for_stats = None
        qtype_for_stats = None

        try:
            # 1. Parse the query
            req, qname, qtype, ctx = self._parse_query(data)
            cache_key = (qname.lower(), qtype)

            # Record query stats
            qname_for_stats = qname
            qtype_for_stats = qtype
            if self.stats_collector:
                qtype_name = QTYPE.get(qtype, str(qtype))
                self.stats_collector.record_query(client_ip, qname, qtype_name)

            # 2. Apply pre-resolve plugins
            pre_decision = self._apply_pre_plugins(req, qname, qtype, data, ctx)
            if pre_decision is not None:
                if pre_decision.action == "deny":
                    if self.stats_collector:
                        self.stats_collector.record_response_rcode("NXDOMAIN")
                    wire = self._make_nxdomain_response(req)
                    sock.sendto(wire, self.client_address)
                    return
                if (
                    pre_decision.action == "override"
                    and pre_decision.response is not None
                ):
                    resp = _set_response_id(pre_decision.response, req.header.id)
                    sock.sendto(resp, self.client_address)
                    return

            # 3. Check cache
            cached = self._cache_lookup(qname, qtype)

            if cached is not None:
                if self.stats_collector:
                    self.stats_collector.record_cache_hit(qname)
                    # Parse to get rcode for stats
                    try:
                        parsed_cached = DNSRecord.parse(cached)
                        rcode_name = RCODE.get(
                            parsed_cached.header.rcode, str(parsed_cached.header.rcode)
                        )
                        self.stats_collector.record_response_rcode(rcode_name)
                    except Exception:
                        pass
                resp = _set_response_id(cached, req.header.id)
                sock.sendto(resp, self.client_address)
                return

            # Record cache miss
            if self.stats_collector:
                self.stats_collector.record_cache_miss(qname)

            # 4. Choose upstreams and forward with failover
            upstreams = self._choose_upstreams(qname, qtype, ctx)
            if not upstreams:
                if self.stats_collector:
                    self.stats_collector.record_response_rcode("SERVFAIL")
                wire = self._make_servfail_response(req)
                sock.sendto(wire, self.client_address)
                return

            # Adjust EDNS/DO based on dnssec.mode before forwarding
            try:
                mode = str(self.dnssec_mode).lower()
                if mode in ("ignore", "passthrough", "validate"):
                    self._ensure_edns(req)
            except Exception:
                pass

            reply, used_upstream, reason = self._forward_with_failover_helper(
                req, upstreams, qname, qtype
            )

            # Record upstream result
            if self.stats_collector and used_upstream:
                upstream_id = f"{used_upstream['host']}:{used_upstream['port']}"
                outcome = "success" if reason == "ok" else reason
                self.stats_collector.record_upstream_result(upstream_id, outcome)

            if reply is None:
                if self.stats_collector:
                    self.stats_collector.record_response_rcode("SERVFAIL")
                wire = self._make_servfail_response(req)
                sock.sendto(wire, self.client_address)

                logger.warning(
                    "All upstreams failed for %s %s, returning SERVFAIL", qname, qtype
                )
                r = req.reply()
                r.header.rcode = RCODE.SERVFAIL
                self._cache_and_send_response(
                    r.pack(), req, qname, qtype, sock, self.client_address, cache_key
                )
                return

            # 5. Apply post-resolve plugins
            reply = self._apply_post_plugins(req, qname, qtype, reply, ctx)

            # Validate DNSSEC if requested
            try:
                if str(self.dnssec_mode).lower() == "validate":
                    parsed = DNSRecord.parse(reply)
                    valid = False
                    if (
                        str(getattr(self, "dnssec_validation", "upstream_ad")).lower()
                        == "local"
                    ):
                        try:
                            from .dnssec_validate import validate_response_local

                            valid = bool(
                                validate_response_local(
                                    qname,
                                    qtype,
                                    reply,
                                    udp_payload_size=self.edns_udp_payload,
                                )
                            )
                        except Exception as e:
                            logger.debug("Local DNSSEC validation error: %s", e)
                            valid = False
                    else:
                        # Require AD bit from upstream to consider validated
                        valid = getattr(parsed.header, "ad", 0) == 1
                    if not valid:
                        logger.warning(
                            "DNSSEC validate mode: validation failed for %s; returning SERVFAIL",
                            qname,
                        )
                        r = req.reply()
                        r.header.rcode = RCODE.SERVFAIL
                        reply = r.pack()
            except Exception:
                logger.debug("DNSSEC validate check failed; returning SERVFAIL")
                r = req.reply()
                r.header.rcode = RCODE.SERVFAIL
                reply = r.pack()

            # 6. Cache the response
            self._cache_store_if_applicable(qname, qtype, reply)

            # Record response rcode
            if self.stats_collector:
                try:
                    parsed_reply = DNSRecord.parse(reply)
                    rcode_name = RCODE.get(
                        parsed_reply.header.rcode, str(parsed_reply.header.rcode)
                    )
                    self.stats_collector.record_response_rcode(rcode_name)
                except Exception:
                    pass

            # 7. Send final response
            reply = _set_response_id(reply, req.header.id)
            sock.sendto(reply, self.client_address)

            # Cache and send the final response
            self._cache_and_send_response(
                reply, req, qname, qtype, sock, self.client_address, cache_key
            )

        except Exception as e:
            logger.exception(
                "Unhandled error during request handling from %s", client_ip
            )
            if self.stats_collector:
                self.stats_collector.record_response_rcode("SERVFAIL")
            try:
                # On parse or other errors, return SERVFAIL
                req = DNSRecord.parse(data)
                q = req.questions[0]
                qname = str(q.qname).rstrip(".")
                qtype = q.qtype
                cache_key = (qname.lower(), qtype)
                r = req.reply()
                r.header.rcode = RCODE.SERVFAIL
                self._cache_and_send_response(
                    r.pack(), req, qname, qtype, sock, self.client_address, cache_key
                )
            except Exception as inner_e:
                logger.error("Failed to send SERVFAIL response: %s", str(inner_e))
        finally:
            # Record latency if stats enabled
            if self.stats_collector and t0 is not None:
                t1 = time_module.perf_counter()
                self.stats_collector.record_latency(t1 - t0)


def resolve_query_bytes(data: bytes, client_ip: str) -> bytes:
    """
    Resolve a single DNS wire query and return wire response using the same pipeline as UDP handler.

    Inputs:
      - data: Wire-format DNS query bytes.
      - client_ip: String client IP for plugin context and logging.
    Outputs:
      - bytes: Wire-format DNS response.

    Example:
      >>> resp = resolve_query_bytes(query_bytes, '127.0.0.1')
    """
    # Use DNSUDPHandler class-level config and cache
    try:
        req = DNSRecord.parse(data)
        q = req.questions[0]
        qname = str(q.qname).rstrip(".")
        qtype = q.qtype
        cache_key = (qname.lower(), qtype)

        # Pre plugins
        ctx = PluginContext(client_ip=client_ip)
        for p in sorted(
            DNSUDPHandler.plugins, key=lambda p: getattr(p, "pre_priority", 50)
        ):
            decision = p.pre_resolve(qname, qtype, data, ctx)
            if isinstance(decision, PluginDecision):
                if decision.action == "deny":
                    r = req.reply()
                    r.header.rcode = RCODE.NXDOMAIN
                    return _set_response_id(r.pack(), req.header.id)
                if decision.action == "override" and decision.response is not None:
                    return _set_response_id(decision.response, req.header.id)

        # Cache
        cached = DNSUDPHandler.cache.get(cache_key)
        if cached is not None:
            return _set_response_id(cached, req.header.id)

        # Upstreams
        upstreams = ctx.upstream_candidates or DNSUDPHandler.upstream_addrs
        if not upstreams:
            r = req.reply()
            r.header.rcode = RCODE.SERVFAIL
            return _set_response_id(r.pack(), req.header.id)

        # EDNS/DNSSEC adjustments
        try:
            mode = str(DNSUDPHandler.dnssec_mode).lower()
            if mode in ("ignore", "passthrough"):
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
                    flags = (
                        0x8000 if str(dummy.dnssec_mode).lower() == "passthrough" else 0
                    )
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
        except Exception:
            pass

        # Forward
        reply, used_upstream, reason = send_query_with_failover(
            req, upstreams, DNSUDPHandler.timeout_ms, qname, qtype
        )
        if reply is None:
            r = req.reply()
            r.header.rcode = RCODE.SERVFAIL
            return _set_response_id(r.pack(), req.header.id)

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

        # Cache store minimal (NOERROR+answers) like original _cache_store_if_applicable
        try:
            r = DNSRecord.parse(out)
            if r.header.rcode == RCODE.NOERROR and r.rr:
                ttls = [rr.ttl for rr in r.rr]
                ttl = min(ttls) if ttls else 300
                if ttl > 0:
                    DNSUDPHandler.cache.set(cache_key, ttl, out)
        except Exception:
            pass

        return _set_response_id(out, req.header.id)
    except Exception:
        try:
            req = DNSRecord.parse(data)
            r = req.reply()
            r.header.rcode = RCODE.SERVFAIL
            return _set_response_id(r.pack(), req.header.id)
        except Exception:
            return data  # fallback worst-case


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
