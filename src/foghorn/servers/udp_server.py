import logging
import random
import socketserver
import time
from typing import Callable, Dict, List

from dnslib import QTYPE, RCODE, DNSRecord

from ..plugins.resolve.base import PluginDecision
from .dns_runtime_state import DNSRuntimeState

logger = logging.getLogger("foghorn.server")


def _client_udp_payload_limit(req: DNSRecord) -> int:
    """Brief: Determine the client-advertised UDP response size limit.

    Inputs:
      - req: Parsed DNSRecord request.

    Outputs:
      - int: Client UDP payload limit in bytes. Returns 512 when the client did
        not advertise EDNS(0) support.

    Notes:
      - For EDNS(0) requests, this returns the advertised UDP payload size from
        the OPT RR (rclass), clamped to >= 512.
    """

    try:
        additional = getattr(req, "ar", None) or []
        for rr in additional:
            if getattr(rr, "rtype", None) == QTYPE.OPT:
                try:
                    payload = int(getattr(rr, "rclass", 0) or 0)
                except Exception:
                    payload = 0
                return max(512, payload) if payload > 0 else 512
    except Exception:
        return 512

    return 512


def _pack_minimal_tc_header(*, req_id: int, rcode: int, rd: bool = True) -> bytes:
    """Brief: Build a minimal DNS response header with TC=1.

    Inputs:
      - req_id: DNS transaction id.
      - rcode: Integer response code (0-15).
      - rd: Whether to set the RD bit.

    Outputs:
      - bytes: 12-byte DNS header.

    Notes:
      - Used only as a last-resort when dnslib packing cannot produce a response
        under a configured size ceiling.
    """

    try:
        rid = int(req_id) & 0xFFFF
    except Exception:
        rid = 0

    try:
        rc = int(rcode) & 0xF
    except Exception:
        rc = int(RCODE.SERVFAIL) & 0xF

    flags = 0x8000  # QR=1
    flags |= 0x0200  # TC=1
    flags |= 0x0080  # RA=1
    if rd:
        flags |= 0x0100
    flags |= rc

    # QD/AN/NS/AR all zero.
    return (
        int(rid).to_bytes(2, "big")
        + int(flags).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
    )


def enforce_udp_response_size_ceiling(
    query_wire: bytes,
    response_wire: bytes,
    *,
    server_max_bytes: int | None = None,
) -> bytes:
    """Brief: Enforce a UDP response size ceiling; signal truncation with TC=1.

    Inputs:
      - query_wire: Wire-format DNS request bytes.
      - response_wire: Wire-format DNS response bytes.
      - server_max_bytes: Optional explicit server-side UDP ceiling override. When
        None, this uses the active RuntimeSnapshot.edns_udp_payload as the server-side
        ceiling.

    Outputs:
      - bytes: Response bytes. When the original response exceeds the effective
        ceiling, a smaller response is synthesized with TC=1 so the client can
        retry over TCP.

    Effective ceiling:
      - client_limit: client EDNS UDP payload size when present; otherwise 512.
      - server_limit: server_max_bytes when set; otherwise RuntimeSnapshot.edns_udp_payload.
      - effective = min(client_limit, server_limit)

    Notes:
      - This helper is designed for use on UDP listener hot paths and is best-effort.
      - When packing a dnslib DNSRecord cannot fit under the ceiling (for example,
        due to extreme configuration), a minimal 12-byte header-only response is
        returned when possible.
    """

    if not response_wire:
        return response_wire

    try:
        resp_bytes = bytes(response_wire)
    except Exception:
        return response_wire

    # Parse request to determine client limit and to construct truncated replies.
    try:
        req = DNSRecord.parse(query_wire)
    except Exception:
        return resp_bytes

    client_limit = _client_udp_payload_limit(req)

    if server_max_bytes is None:
        try:
            from foghorn.runtime_config import get_runtime_snapshot

            server_max_bytes = int(get_runtime_snapshot().edns_udp_payload or 1232)
        except Exception:
            server_max_bytes = 1232

    try:
        server_limit = max(0, int(server_max_bytes))
    except Exception:
        server_limit = 1232

    effective = min(client_limit, server_limit) if server_limit > 0 else client_limit

    if effective <= 0:
        return resp_bytes

    if len(resp_bytes) <= effective:
        return resp_bytes

    # Determine rcode from the oversized response when possible.
    rcode = int(RCODE.SERVFAIL)
    try:
        parsed_resp = DNSRecord.parse(resp_bytes)
        rcode = int(getattr(parsed_resp.header, "rcode", int(RCODE.SERVFAIL)))
    except Exception:
        rcode = int(RCODE.SERVFAIL)

    # Build a minimal response based on the request.
    try:
        r = req.reply()
        r.header.rcode = rcode
        r.header.tc = 1

        # Echo client EDNS OPT when possible so EDNS-capable clients can still
        # see a consistent EDNS envelope.
        try:
            from . import server as _server_mod

            _server_mod._echo_client_edns(req, r)
        except Exception:
            pass

        out = r.pack()
        if len(out) <= effective:
            return _set_response_id(out, req.header.id)

        # If OPT makes the response too large, retry without additional records.
        try:
            r.ar = []
        except Exception:
            pass

        out2 = r.pack()
        if len(out2) <= effective:
            return _set_response_id(out2, req.header.id)

        # Last resort: header-only truncated response.
        rd_flag = bool(getattr(req.header, "rd", 1))
        return _pack_minimal_tc_header(req_id=req.header.id, rcode=rcode, rd=rd_flag)
    except Exception:
        # Do not risk returning invalid bytes; keep the original response.
        return resp_bytes


def _set_response_id(wire: bytes, req_id: int) -> bytes:
    """Ensure the response DNS ID matches the request ID.

    Inputs:
      - wire: bytes-like DNS response (bytes, bytearray, or memoryview)
      - req_id: int request ID to set in the first two bytes
    Outputs:
      - bytes: response with corrected ID

    This helper now delegates to the shared implementation in
    foghorn.servers.server so that ID-rewrite behaviour is consistent across UDP
    and non-UDP paths.
    """
    from . import server as _server_mod

    return _server_mod._set_response_id(wire, req_id)


def _edns_flags_for_mode(dnssec_mode: str) -> int:
    """Compute EDNS(0) flags bitmask for a given dnssec_mode.

    Inputs:
      - dnssec_mode: DNSSEC mode string (e.g. 'ignore', 'passthrough', 'validate').

    Outputs:
      - int: EDNS flags bitmask with DO set for passthrough/validate modes.
    """
    mode = str(dnssec_mode).lower()
    return 0x8000 if mode in ("passthrough", "validate") else 0


class DNSUDPHandler(DNSRuntimeState, socketserver.BaseRequestHandler):
    """
    Handles UDP DNS requests.
    This class is instantiated for each incoming DNS query.

    Example use:
        This handler is used internally by the DNSServer and is not
        typically instantiated directly by users.
    """

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
        Cache response using the configured min_cache_ttl floor and send to client.

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

        Notes:
          - Uses compute_effective_ttl for all non-SERVFAIL responses so that
            min_cache_ttl semantics are applied consistently.
          - SERVFAIL responses are never cached.
        """
        try:
            r = DNSRecord.parse(response_wire)
            # Never cache SERVFAIL responses regardless of TTL
            if r.header.rcode == RCODE.SERVFAIL:
                logger.debug(
                    "Not caching %s %s (SERVFAIL responses are never cached)",
                    qname,
                    qtype,
                )
            else:
                from .server import compute_effective_ttl as _compute_effective_ttl

                effective_ttl = _compute_effective_ttl(r, self.min_cache_ttl)
                if effective_ttl > 0:
                    rcode_name = RCODE.get(r.header.rcode, f"rcode{r.header.rcode}")
                    logger.debug(
                        "Caching %s %s (%s) with TTL %ds",
                        qname,
                        qtype,
                        rcode_name,
                        effective_ttl,
                    )
                    from ..plugins.resolve import base as plugin_base

                    plugin_base.DNS_CACHE.set(cache_key, effective_ttl, response_wire)
                else:
                    logger.debug(
                        "Not caching %s %s (effective TTL=%d)",
                        qname,
                        qtype,
                        effective_ttl,
                    )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        except (
            Exception
        ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.debug("Failed to parse response for caching: %s", str(e))

        # Ensure the response ID matches the request ID before sending
        response_wire = _set_response_id(response_wire, req.header.id)
        sock.sendto(response_wire, client_address)

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
        # Attach qname to the context when available so BasePlugin domain
        # targeting helpers can operate on it.
        try:
            setattr(ctx, "qname", qname)
        except Exception:  # pragma: no cover - defensive
            pass

        for p in sorted(self.plugins, key=lambda p: getattr(p, "pre_priority", 50)):
            # Skip plugins that do not target this qtype when they opt in via
            # BasePlugin.target_qtypes.
            try:
                if hasattr(p, "targets_qtype") and not p.targets_qtype(qtype):
                    continue
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                pass

            decision = p.pre_resolve(qname, qtype, data, ctx)
            if isinstance(decision, PluginDecision):
                if decision.action == "deny":
                    logger.debug(
                        "Denied %s %s by %s", qname, qtype, p.__class__.__name__
                    )
                    return decision
                elif decision.action == "override" and decision.response is not None:
                    logger.debug(
                        "Override %s type %s by %s", qname, qtype, p.__class__.__name__
                    )
                    return decision
                elif decision.action == "allow":
                    logger.debug(
                        "Allow %s %s by %s (skipping remaining pre plugins)",
                        qname,
                        qtype,
                        p.__class__.__name__,
                    )
                    break

                logger.debug("Plugin %s: %s", p.__class__.__name__, decision.action)
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
        # Determine base upstream candidates from plugins or global config.
        base = ctx.upstream_candidates or self.upstream_addrs or []
        base_list = list(base) if isinstance(base, list) else list(base)

        # Filter out upstreams that are currently marked down until some time in
        # the future. This is a lazy, traffic-driven health mechanism; upstreams
        # are allowed back in automatically once their backoff window expires.
        now = time.time()
        healthy: List[Dict] = []
        for up in base_list:
            up_id = type(self)._upstream_id(up)
            if not up_id:
                healthy.append(up)
                continue
            entry = type(self).upstream_health.get(up_id)
            down_until = float(entry.get("down_until", 0.0)) if entry else 0.0
            if entry and down_until > now:
                # Still in backoff window; skip for this query.
                continue
            healthy.append(up)

        if not healthy:
            logger.warning(
                "No healthy upstreams available for %s type %s", qname, qtype
            )
            return []

        base_list = healthy

        # Resolve strategy and concurrency knobs, falling back to safe defaults.
        try:
            strategy = str(getattr(self, "upstream_strategy", "failover")).lower()
        except Exception:
            strategy = "failover"

        try:
            max_concurrent = int(getattr(self, "upstream_max_concurrent", 1) or 1)
        except Exception:
            max_concurrent = 1
        if max_concurrent < 1:
            max_concurrent = 1

        # Apply selection strategy to derive an ordered list of upstreams.
        ordered: List[Dict] = base_list
        if strategy == "round_robin" and base_list:
            # Simple global round-robin: rotate by a shared index.
            cls = type(self)
            idx = int(getattr(cls, "_upstream_rr_index", 0) or 0)
            offset = idx % len(base_list)
            ordered = base_list[offset:] + base_list[:offset]
            cls._upstream_rr_index = (idx + 1) % len(base_list)
        elif strategy == "random" and len(base_list) > 1:
            ordered = base_list[:]
            try:
                random.shuffle(ordered)
            except Exception:
                # Best-effort shuffle; fall back to original order on error.
                ordered = base_list

        upstreams_to_try = ordered
        logger.debug(
            "Using %d upstreams (strategy=%s, max_concurrent=%d) for %s %s",
            len(upstreams_to_try),
            strategy,
            max_concurrent,
            qname,
            qtype,
        )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        return upstreams_to_try

    def _forward_with_failover_helper(
        self, request: DNSRecord, upstreams, qname: str, qtype: int
    ):
        """
        Forward query to upstream servers with failover support.

        Inputs:
            - request (DNSRecord): DNS request to forward.
            - upstreams (List[Dict]): Upstream servers to try. Each entry must be
              a dict-like object with host/port/transport keys as expected by
              send_query_with_failover.
            - qname (str): Query name for logging.
            - qtype (int): DNS RR type for logging.

        Outputs:
            - reply (bytes or None): Response wire data or None if all failed.
            - used_upstream (Dict or None): Upstream that succeeded or None.
            - reason (str): Result reason ('ok', 'all_failed', etc.).

        Notes:
            Uses existing send_query_with_failover function with timeout handling.
            Non-dict upstream entries are ignored to avoid type errors.

        Example:
            reply, upstream, reason = self._forward_with_failover_helper(req, upstreams, qname, qtype)
        """
        # Filter out any non-dict upstream entries defensively; tests and callers
        # are expected to pass dict-like configs.
        safe_upstreams = [u for u in (upstreams or []) if isinstance(u, dict)]
        # Try upstreams with failover, always resolving send_query_with_failover
        # via foghorn.servers.server so test monkeypatches on server_mod apply.
        from . import server as _server_mod

        try:
            max_concurrent = int(getattr(self, "upstream_max_concurrent", 1) or 1)
        except Exception:
            max_concurrent = 1
        if max_concurrent < 1:
            max_concurrent = 1

        reply, used_upstream, reason = _server_mod.send_query_with_failover(
            request,
            safe_upstreams,
            self.timeout_ms,
            qname,
            qtype,
            max_concurrent=max_concurrent,
        )

        # Lazy health updates: on complete failure, mark all attempted upstreams
        # down with backoff; on success, reset the winning upstream's health.
        if reply is None:
            type(self)._mark_upstreams_down(safe_upstreams, reason)
        else:
            type(self)._mark_upstream_ok(used_upstream)

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
        # Clear any previous override marker on the context to avoid leakage
        if ctx is not None and hasattr(ctx, "_post_override"):
            try:
                delattr(ctx, "_post_override")
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                setattr(ctx, "_post_override", False)

        # Post-resolve plugin hooks in priority order
        try:
            setattr(ctx, "qname", qname)
        except Exception:  # pragma: no cover - defensive
            pass

        for p in sorted(self.plugins, key=lambda p: getattr(p, "post_priority", 50)):
            # Skip plugins that do not target this qtype when they opt in via
            # BasePlugin.target_qtypes.
            try:
                if hasattr(p, "targets_qtype") and not p.targets_qtype(qtype):
                    continue
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                pass

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
                if decision.action == "override" and decision.response is not None:
                    logger.info(
                        "Post-resolve override %s type %s by %s",
                        qname,
                        qtype,
                        p.__class__.__name__,
                    )
                    reply = decision.response
                    if ctx is not None:
                        # Mark on context so callers (e.g., handle()) can
                        # distinguish override paths without changing the
                        # return type of this helper.
                        try:
                            setattr(ctx, "_post_override", True)
                        except (
                            Exception
                        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                            pass
                    break
                if decision.action == "allow":
                    logger.info(
                        "Post-resolve allow %s type %s by %s (skipping remaining post plugins)",
                        qname,
                        qtype,
                        p.__class__.__name__,
                    )
                    break
        return reply

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
        # Echo client EDNS(0) OPT, when present, into this synthetic NXDOMAIN and
        # attach a generic policy EDE when enabled.
        try:
            from . import server as _server_mod

            _server_mod._echo_client_edns(request, reply)
            _server_mod._attach_ede_option(
                request,
                reply,
                15,
                "blocked by policy",
            )  # Blocked
        except Exception:  # pragma: no cover - defensive: best-effort only
            pass
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
        # Echo client EDNS(0) OPT, when present, into this synthetic SERVFAIL and
        # attach a generic EDE "Other" code when enabled.
        try:
            from . import server as _server_mod

            _server_mod._echo_client_edns(request, r)
            _server_mod._attach_ede_option(
                request,
                r,
                0,
                "internal server error",
            )  # Other
        except Exception:  # pragma: no cover - defensive: best-effort only
            pass
        return _set_response_id(r.pack(), request.header.id)

    def handle(self):
        """Process a single UDP DNS query using the shared core resolver.

        Inputs:
          - None (called by socketserver for each UDP datagram).
        Outputs:
          - None; sends a single DNS response back to the client.

        This handler now delegates resolution to foghorn.server.resolve_query_bytes
        so that UDP shares the same plugin/caching/upstream/DNSSEC pipeline as
        othefoghorn.servers.transports (TCP/DoT/DoH). DNSUDPHandler's class-level knobs
        (plugins, upstreams, DNSSEC settings, and optional stats collector)
        are still honored by the core resolver.

        DNS response caching is provided by foghorn.plugins.resolve.base.DNS_CACHE.
        """
        data, sock = self.request
        client_ip = self.client_address[0]

        from . import server as _server_mod

        try:
            # Delegate to the shared core resolver. Any exceptions inside the
            # resolver are converted to SERVFAIL by _resolve_core.
            wire = _server_mod.resolve_query_bytes(
                data,
                client_ip,
                listener="udp",
                secure=False,
            )
            # When plugins request an explicit drop/timeout, the shared
            # resolver returns an empty wire sentinel; in that case we do not
            # send any response so the client observes a timeout.
            if not wire:
                return
        except Exception:  # pragma: no cover - defensive: outermost guard
            logger.exception(
                "Unexpected UDP handler resolver failure for client %s",
                client_ip,
            )
            try:
                # Best-effort SERVFAIL synthesis if the shared resolver fails
                # unexpectedly.
                req = DNSRecord.parse(data)
                r = req.reply()
                r.header.rcode = RCODE.SERVFAIL
                # Echo client EDNS(0) OPT, when present, into this synthetic SERVFAIL
                # and attach a generic EDE "Other" code when enabled.
                try:
                    from . import server as _server_mod

                    _server_mod._echo_client_edns(req, r)
                    _server_mod._attach_ede_option(
                        req,
                        r,
                        0,
                        "internal server error",
                    )  # Other
                except Exception:  # pragma: no cover - defensive: best-effort only
                    pass
                wire = _set_response_id(r.pack(), req.header.id)
            except Exception:
                # Worst-case: never reflect the original query bytes. Return a
                # minimal header-only SERVFAIL so clients don't loop on a QR=0 packet.
                try:
                    rid = int.from_bytes(data[0:2], "big") if len(data) >= 2 else 0
                except Exception:
                    rid = 0
                try:
                    rd_flag = (
                        bool(int.from_bytes(data[2:4], "big") & 0x0100)
                        if len(data) >= 4
                        else True
                    )
                except Exception:
                    rd_flag = True
                wire = _pack_minimal_tc_header(
                    req_id=rid,
                    rcode=int(RCODE.SERVFAIL),
                    rd=rd_flag,
                )

        # Enforce UDP response ceiling; synthesize TC=1 response when needed.
        try:
            from foghorn.runtime_config import get_runtime_snapshot

            server_max = get_runtime_snapshot().udp_max_response_bytes
        except Exception:
            server_max = None

        try:
            wire = enforce_udp_response_size_ceiling(
                query_wire=data,
                response_wire=wire,
                server_max_bytes=server_max,
            )
        except Exception:  # pragma: no cover - defensive
            pass

        sock.sendto(wire, self.client_address)


class _UDPHandler(socketserver.BaseRequestHandler):
    """
    Brief: Simple UDP handler that delegates to a resolver callable.

    Inputs:
    - request: (data, socket) tuple provided by socketserver
    - client_address: peer address

    Outputs:
    - None

    Example:
        See serve_udp.
    """

    resolver: Callable[[bytes, str], bytes] = lambda b, ip: b

    def handle(self) -> None:
        data, sock = self.request  # type: ignore
        peer_ip = (
            self.client_address[0]
            if isinstance(self.client_address, tuple)
            else "0.0.0.0"
        )
        try:
            resp = self.resolver(data, peer_ip)
            sock.sendto(resp, self.client_address)
        except (ConnectionError, OSError, TimeoutError):
            return
        except Exception:  # pragma: no cover - defensive: unexpected transport failure
            logger.exception(
                "Unhandled exception in UDP request handler for client %s",
                peer_ip,
            )


def serve_udp(host: str, port: int, resolver: Callable[[bytes, str], bytes]) -> None:
    """
    Brief: Serve DNS-over-UDP using ThreadingUDPServer.

    Inputs:
    - host: listen address
    - port: listen port
    - resolver: callable mapping (query_bytes, client_ip) -> response_bytes

    Outputs:
    - None (runs forever)

    Example:
        >>> # In a thread:
        >>> # serve_udp('0.0.0.0', 5353, resolver)
    """
    handler_cls = _UDPHandler
    handler_cls.resolver = staticmethod(resolver)  # type: ignore
    server = socketserver.ThreadingUDPServer((host, port), handler_cls)
    server.daemon_threads = True
    try:
        server.serve_forever()
    finally:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        try:
            server.server_close()
        except Exception:
            pass
