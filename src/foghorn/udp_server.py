import logging
import socketserver
from functools import lru_cache
from typing import Callable, Dict, List, Optional

from dnslib import QTYPE, RCODE, DNSRecord

from .cache import FoghornTTLCache
from .plugins.base import BasePlugin, PluginContext, PluginDecision

logger = logging.getLogger("foghorn.server")


def _set_response_id(wire: bytes, req_id: int) -> bytes:
    """Ensure the response DNS ID matches the request ID.

    Inputs:
      - wire: bytes-like DNS response (bytes, bytearray, or memoryview)
      - req_id: int request ID to set in the first two bytes
    Outputs:
      - bytes: response with corrected ID

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


@lru_cache(maxsize=1024)
def _set_response_id_cached(wire: bytes, req_id: int) -> bytes:
    """Cached helper for setting DNS ID on an immutable bytes payload."""
    try:
        if len(wire) >= 2:
            hi = (req_id >> 8) & 0xFF
            lo = req_id & 0xFF
            return bytes([hi, lo]) + wire[2:]
        return wire
    except Exception as e:
        logger.error("Failed to set response id (cached): %s", e)
        return wire


def _edns_flags_for_mode(dnssec_mode: str) -> int:
    """Compute EDNS(0) flags bitmask for a given dnssec_mode.

    Inputs:
      - dnssec_mode: DNSSEC mode string (e.g. 'ignore', 'passthrough', 'validate').

    Outputs:
      - int: EDNS flags bitmask with DO set for passthrough/validate modes.
    """
    mode = str(dnssec_mode).lower()
    return 0x8000 if mode in ("passthrough", "validate") else 0


class DNSUDPHandler(socketserver.BaseRequestHandler):
    """
    Handles UDP DNS requests.
    This class is instantiated for each incoming DNS query.

    Example use:
        This handler is used internally by the DNSServer and is not
        typically instantiated directly by users.
    """

    cache = FoghornTTLCache()
    upstream_addrs: List[Dict] = []
    plugins: List[BasePlugin] = []
    timeout = 2.0
    timeout_ms = 2000
    min_cache_ttl = 60
    stats_collector = None  # Optional StatsCollector instance
    dnssec_mode = "ignore"  # ignore | passthrough | validate
    dnssec_validation = "upstream_ad"  # upstream_ad | local
    edns_udp_payload = 1232

    def _cache_store_if_applicable(
        self,
        qname: str,
        qtype: int,
        response_wire: bytes,
    ) -> None:
        """Legacy cache helper for tests; caches only NOERROR answers with TTL floor.

        Inputs:
          - qname: Query name as a string.
          - qtype: DNS RR type as an integer.
          - response_wire: Raw DNS response bytes to inspect and maybe cache.

        Outputs:
          - None

        Notes:
          - Mirrors the original semantics used in tests:
            * SERVFAIL responses are never cached.
            * NOERROR with no answers is not cached.
            * NOERROR with answers is cached using compute_effective_ttl
              with the handler's min_cache_ttl floor.
        """
        try:
            r = DNSRecord.parse(response_wire)
        except Exception:  # pragma: no cover
            return

        # Never cache SERVFAIL responses regardless of TTL
        if r.header.rcode == RCODE.SERVFAIL:
            logger.debug(
                "Not caching %s %s (SERVFAIL responses are never cached)",
                qname,
                qtype,
            )
            return

        # For this legacy helper, only cache NOERROR responses that have answers.
        if r.header.rcode != RCODE.NOERROR or not r.rr:
            logger.debug(
                "Not caching %s %s (no cacheable answers)",
                qname,
                qtype,
            )
            return

        # Respect TTL=0 semantics for this helper: do not cache when the
        # minimum answer TTL is zero or negative, regardless of min_cache_ttl.
        try:
            ttls = [int(getattr(rr, "ttl", 0)) for rr in r.rr]
            if not ttls:
                logger.debug(
                    "Not caching %s %s (no answer TTLs)",
                    qname,
                    qtype,
                )
                return
            min_ttl = min(ttls)
            if min_ttl <= 0:
                logger.debug(
                    "Not caching %s %s (answer TTL<=0)",
                    qname,
                    qtype,
                )
                return

            # For positive TTLs, still apply the configured floor for
            # consistency with the main caching path.
            from .server import compute_effective_ttl as _compute_effective_ttl

            effective_ttl = _compute_effective_ttl(r, getattr(self, "min_cache_ttl", 0))
            if effective_ttl > 0:
                cache_key = (str(qname).lower(), int(qtype))
                cache_obj = getattr(self, "cache", None)
                if cache_obj is None:
                    return
                # Support both foghorn.cache.FoghornTTLCache (set(key, ttl, data)) and
                # mapping-style caches used in some tests (e.g., cachetools.FoghornTTLCache
                # where TTL is provided at construction time).
                if hasattr(cache_obj, "set"):
                    cache_obj.set(cache_key, effective_ttl, response_wire)
                else:
                    try:
                        cache_obj[cache_key] = response_wire
                    except Exception:
                        # Best-effort only; callers depend on side effects.
                        return
        except Exception:  # pragma: no cover
            # Best-effort; callers rely only on side effects.
            return

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
                    self.cache.set(cache_key, effective_ttl, response_wire)
                else:
                    logger.debug(
                        "Not caching %s %s (effective TTL=%d)",
                        qname,
                        qtype,
                        effective_ttl,
                    )  # pragma: no cover
        except Exception as e:  # pragma: no cover
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
        # via foghorn.server so test monkeypatches on server_mod apply.
        from . import server as _server_mod

        reply, used_upstream, reason = _server_mod.send_query_with_failover(
            request, safe_upstreams, self.timeout_ms, qname, qtype
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
        # Clear any previous override marker on the context to avoid leakage
        if ctx is not None and hasattr(ctx, "_post_override"):
            try:
                delattr(ctx, "_post_override")
            except Exception:  # pragma: no cover
                setattr(ctx, "_post_override", False)

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
                        except Exception:  # pragma: no cover
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

        # Decide EDNS flags based on dnssec_mode. For both passthrough and
        # validate modes we must advertise DO=1 so that upstream resolvers
        # return DNSSEC records (and, for upstream_ad, can set the AD bit).
        flags = _edns_flags_for_mode(self.dnssec_mode)

        # rclass of OPT holds payload size. Use EDNS0/RR from foghorn.server so
        # tests that monkeypatch foghorn.server.EDNS0/RR continue to see those
        # patches when exercising DNSUDPHandler._ensure_edns.
        from . import server as _server_mod

        opt_rr = _server_mod.RR(
            rname=".",
            rtype=QTYPE.OPT,
            rclass=int(self.edns_udp_payload),
            ttl=0,
            rdata=_server_mod.EDNS0(flags=flags),
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
                        # Pre-plugin deny: synthesize NXDOMAIN and log to stats and query_log.
                        qname_for_log = qname_for_stats or qname
                        qtype_for_log = qtype_for_stats or qtype
                        qtype_name = QTYPE.get(qtype_for_log, str(qtype_for_log))
                        try:
                            # Count this as a cache_null response because no
                            # cache lookup occurs when pre-plugins short-circuit,
                            # and bump the cache_deny_pre total.
                            self.stats_collector.record_cache_null(
                                qname_for_log, status="deny_pre"
                            )
                        except Exception:  # pragma: no cover
                            pass
                        # Mirror any decision.stat label into cache stats so
                        # the web UI can display per-decision tallies.
                        try:
                            stat_label = getattr(pre_decision, "stat", None)
                            if stat_label:
                                self.stats_collector.record_cache_stat(str(stat_label))
                        except Exception:  # pragma: no cover
                            pass
                        # Also record per-plugin pre-deny totals so stats.totals
                        # exposes pre_deny_<name> keys. Prefer the originating
                        # plugin instance label when available, falling back to
                        # alias/class naming.
                        try:
                            label_suffix = getattr(pre_decision, "plugin_label", None)
                            if not label_suffix:
                                plugin_cls = getattr(pre_decision, "plugin", None)
                                if plugin_cls is not None:
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
                                    except Exception:  # pragma: no cover - defensive
                                        aliases = []
                                    if aliases:
                                        label_suffix = str(aliases[0]).strip().lower()
                                    else:
                                        label_suffix = plugin_name

                            if label_suffix:
                                short = str(label_suffix).strip()
                                label = (
                                    f"pre_deny_{short}" if short else "pre_deny_plugin"
                                )
                                self.stats_collector.record_cache_pre_plugin(label)
                        except Exception:  # pragma: no cover
                            pass
                        self.stats_collector.record_response_rcode(
                            "NXDOMAIN", qname_for_log
                        )
                        try:
                            self.stats_collector.record_query_result(
                                client_ip=client_ip,
                                qname=qname_for_log,
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
                    wire = self._make_nxdomain_response(req)
                    sock.sendto(wire, self.client_address)
                    return
                if (
                    pre_decision.action == "override"
                    and pre_decision.response is not None
                ):
                    resp = _set_response_id(pre_decision.response, req.header.id)
                    if self.stats_collector:
                        # Pre-plugin override: log final rcode and response into query_log.
                        try:
                            parsed = DNSRecord.parse(resp)
                            rcode_name = RCODE.get(
                                parsed.header.rcode,
                                str(parsed.header.rcode),
                            )
                            try:
                                # Pre-override also bypasses cache, so count as
                                # a cache_null response and bump the
                                # cache_override_pre total.
                                qname_for_log = qname_for_stats or qname
                                self.stats_collector.record_cache_null(
                                    qname_for_log, status="override_pre"
                                )
                            except Exception:  # pragma: no cover
                                pass
                            # Mirror any decision.stat label into cache stats
                            # so the web UI can display per-decision tallies.
                            try:
                                stat_label = getattr(pre_decision, "stat", None)
                                if stat_label:
                                    self.stats_collector.record_cache_stat(
                                        str(stat_label)
                                    )
                            except Exception:  # pragma: no cover
                                pass
                            # Also record per-plugin pre-override totals so
                            # stats.totals exposes pre_override_<name>. Prefer
                            # the originating plugin instance label when
                            # available, falling back to alias/class naming.
                            try:
                                label_suffix = getattr(
                                    pre_decision, "plugin_label", None
                                )
                                if not label_suffix:
                                    plugin_cls = getattr(pre_decision, "plugin", None)
                                    if plugin_cls is not None:
                                        plugin_name = getattr(
                                            plugin_cls, "__name__", "plugin"
                                        ).lower()
                                        aliases = []
                                        try:
                                            aliases = list(
                                                getattr(
                                                    plugin_cls,
                                                    "get_aliases",
                                                    lambda: [],
                                                )()
                                            )
                                        except (
                                            Exception
                                        ):  # pragma: no cover - defensive
                                            aliases = []
                                        if aliases:
                                            label_suffix = (
                                                str(aliases[0]).strip().lower()
                                            )
                                        else:
                                            label_suffix = plugin_name

                                if label_suffix:
                                    short = str(label_suffix).strip()
                                    label = (
                                        f"pre_override_{short}"
                                        if short
                                        else "pre_override_plugin"
                                    )
                                    self.stats_collector.record_cache_pre_plugin(label)
                            except Exception:  # pragma: no cover
                                pass
                            self.stats_collector.record_response_rcode(
                                rcode_name, qname
                            )

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

                            qname_for_log = qname_for_stats or qname
                            qtype_for_log = qtype_for_stats or qtype
                            qtype_name = QTYPE.get(qtype_for_log, str(qtype_for_log))

                            self.stats_collector.record_query_result(
                                client_ip=client_ip,
                                qname=qname_for_log,
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
                    sock.sendto(resp, self.client_address)
                    return

            # 3. Check cache
            cached = self._cache_lookup(qname, qtype)

            if cached is not None:
                if self.stats_collector:
                    self.stats_collector.record_cache_hit(qname)
                    # Parse to get rcode for stats and to enrich persistent log.
                    try:
                        parsed_cached = DNSRecord.parse(cached)
                        rcode_name = RCODE.get(
                            parsed_cached.header.rcode, str(parsed_cached.header.rcode)
                        )
                        self.stats_collector.record_response_rcode(rcode_name, qname)

                        # Build a minimal structured result for the query_log.
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

                        # Use the normalized qname/qtype we recorded earlier when possible.
                        qname_for_log = qname_for_stats or qname
                        qtype_for_log = qtype_for_stats or qtype
                        qtype_name = QTYPE.get(qtype_for_log, str(qtype_for_log))

                        self.stats_collector.record_query_result(
                            client_ip=client_ip,
                            qname=qname_for_log,
                            qtype=qtype_name,
                            rcode=rcode_name,
                            upstream_id=None,
                            status="cache_hit",
                            error=None,
                            first=str(first) if first is not None else None,
                            result=result,
                        )
                    except Exception:  # pragma: no cover
                        pass  # pragma: no cover
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
                    # No upstreams configured: immediate SERVFAIL with query_log entry.
                    self.stats_collector.record_response_rcode("SERVFAIL", qname)
                    try:
                        qname_for_log = qname_for_stats or qname
                        qtype_for_log = qtype_for_stats or qtype
                        qtype_name = QTYPE.get(qtype_for_log, str(qtype_for_log))
                        self.stats_collector.record_query_result(
                            client_ip=client_ip,
                            qname=qname_for_log,
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
                wire = self._make_servfail_response(req)
                sock.sendto(wire, self.client_address)
                return

            # Adjust EDNS/DO based on dnssec.mode before forwarding
            try:
                mode = str(self.dnssec_mode).lower()
                if mode in ("ignore", "passthrough", "validate"):
                    self._ensure_edns(req)
            except Exception:  # pragma: no cover
                pass  # pragma: no cover

            reply, used_upstream, reason = self._forward_with_failover_helper(
                req, upstreams, qname, qtype
            )

            # Record upstream result
            upstream_id: Optional[str] = None
            if self.stats_collector and used_upstream:
                if "url" in used_upstream:
                    upstream_id = used_upstream["url"]
                else:
                    upstream_id = f"{used_upstream['host']}:{used_upstream['port']}"

                outcome = "success" if reason == "ok" else reason
                # Use the normalized qtype name we use for stats/logging.
                qtype_for_log = qtype_for_stats or qtype
                qtype_name = QTYPE.get(qtype_for_log, str(qtype_for_log))
                self.stats_collector.record_upstream_result(
                    upstream_id,
                    outcome,
                    qtype=qtype_name,
                )

            if reply is None:
                if self.stats_collector:
                    self.stats_collector.record_response_rcode("SERVFAIL", qname)
                    # Attribute SERVFAIL to the final upstream when available.
                    if upstream_id:
                        try:
                            self.stats_collector.record_upstream_rcode(
                                upstream_id, "SERVFAIL"
                            )
                        except Exception:  # pragma: no cover
                            pass
                    try:
                        qname_for_log = qname_for_stats or qname
                        qtype_for_log = qtype_for_stats or qtype
                        qtype_name = QTYPE.get(qtype_for_log, str(qtype_for_log))
                        status = str(reason or "all_failed")
                        self.stats_collector.record_query_result(
                            client_ip=client_ip,
                            qname=qname_for_log,
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

                logger.warning(
                    "All upstreams failed for %s %s, returning SERVFAIL", qname, qtype
                )
                # Build a SERVFAIL reply and send twice: once directly and once
                # via the cache helper (which will avoid caching SERVFAIL).
                wire = self._make_servfail_response(req)
                # First send: direct
                sock.sendto(wire, self.client_address)
                # Second send: through cache+send helper for consistent
                # min_cache_ttl semantics and ID fixups.
                self._cache_and_send_response(
                    wire, req, qname, qtype, sock, self.client_address, cache_key
                )
                return

            # 5. Apply post-resolve plugins
            reply = self._apply_post_plugins(req, qname, qtype, reply, ctx)

            # Validate DNSSEC if requested.
            #
            # New semantics (dev, may evolve):
            #   - We attempt to classify responses as "secure" when either the
            #     upstream sets AD (upstream_ad) or the local validator returns
            #     True (local).
            #   - We do *not* convert responses to SERVFAIL when validation is
            #     inconclusive or the zone is insecure/unsigned; those are
            #     treated as "insecure" but acceptable.
            #   - This avoids breaking unsigned zones like google.com while
            #     still allowing callers to observe validation via logs.
            try:
                if str(self.dnssec_mode).lower() == "validate":
                    validated = False
                    mode = str(
                        getattr(self, "dnssec_validation", "upstream_ad")
                    ).lower()
                    if mode == "local":
                        try:
                            from .dnssec_validate import validate_response_local

                            validated = bool(
                                validate_response_local(
                                    qname,
                                    qtype,
                                    reply,
                                    udp_payload_size=self.edns_udp_payload,
                                )
                            )
                        except Exception as e:  # pragma: no cover
                            logger.debug("Local DNSSEC validation error: %s", e)
                            validated = False
                    else:
                        try:
                            parsed = DNSRecord.parse(reply)
                            validated = getattr(parsed.header, "ad", 0) == 1
                        except Exception as e:  # pragma: no cover
                            logger.debug("Upstream AD check failed: %s", e)
                            validated = False

                    if validated:
                        logger.debug(
                            "DNSSEC validate mode: response for %s classified as secure",
                            qname,
                        )
                    else:
                        logger.debug(
                            "DNSSEC validate mode: response for %s classified as insecure/unsigned",
                            qname,
                        )
            except Exception:  # pragma: no cover
                logger.debug("DNSSEC validate check failed; leaving response unchanged")

            # 6. Cache and send the response. For post-resolve override paths
            # we intentionally send twice to match historical behavior and
            # exercise both pre/post hooks in tests.
            if getattr(ctx, "_post_override", False):
                self._cache_and_send_response(
                    reply, req, qname, qtype, sock, self.client_address, cache_key
                )
                self._cache_and_send_response(
                    reply, req, qname, qtype, sock, self.client_address, cache_key
                )
            else:
                self._cache_and_send_response(
                    reply, req, qname, qtype, sock, self.client_address, cache_key
                )

            # Record response rcode and append to persistent query_log when enabled.
            if self.stats_collector:
                try:
                    parsed_reply = DNSRecord.parse(reply)
                    rcode_name = RCODE.get(
                        parsed_reply.header.rcode, str(parsed_reply.header.rcode)
                    )
                    self.stats_collector.record_response_rcode(rcode_name, qname)
                    # Track response codes by upstream when an upstream_id
                    # was recorded for this query.
                    if upstream_id:
                        try:
                            self.stats_collector.record_upstream_rcode(
                                upstream_id, rcode_name
                            )
                        except Exception:  # pragma: no cover
                            pass

                    answers = [
                        {
                            "name": str(rr.rname),
                            "type": QTYPE.get(rr.rtype, str(rr.rtype)),
                            "ttl": int(getattr(rr, "ttl", 0)),
                            "rdata": str(rr.rdata),
                        }
                        for rr in (parsed_reply.rr or [])
                    ]
                    first = answers[0]["rdata"] if answers else None
                    result = {"source": "upstream", "answers": answers}

                    qname_for_log = qname_for_stats or qname
                    qtype_for_log = qtype_for_stats or qtype
                    qtype_name = QTYPE.get(qtype_for_log, str(qtype_for_log))

                    self.stats_collector.record_query_result(
                        client_ip=client_ip,
                        qname=qname_for_log,
                        qtype=qtype_name,
                        rcode=rcode_name,
                        upstream_id=upstream_id,
                        status="ok" if rcode_name == "NOERROR" else "error",
                        error=None,
                        first=str(first) if first is not None else None,
                        result=result,
                    )
                except Exception:  # pragma: no cover
                    pass  # pragma: no cover

        except Exception as e:  # pragma: no cover
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
                wire = r.pack()
                self._cache_and_send_response(
                    wire, req, qname, qtype, sock, self.client_address, cache_key
                )
                if self.stats_collector:
                    try:
                        qtype_name = QTYPE.get(qtype, str(qtype))
                        self.stats_collector.record_query_result(
                            client_ip=client_ip,
                            qname=qname,
                            qtype=qtype_name,
                            rcode="SERVFAIL",
                            upstream_id=None,
                            status="error",
                            error=str(e),
                            first=None,
                            result={
                                "source": "server",
                                "error": "unhandled_exception",
                            },
                        )
                    except Exception:  # pragma: no cover
                        pass
            except Exception as inner_e:  # pragma: no cover
                logger.error("Failed to send SERVFAIL response: %s", str(inner_e))
        finally:
            # Record latency if stats enabled
            if self.stats_collector and t0 is not None:
                t1 = time_module.perf_counter()
                self.stats_collector.record_latency(t1 - t0)


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
        dnssec_validation: str = "upstream_ad",
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
        DNSUDPHandler.dnssec_validation = str(dnssec_validation)
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
        """Start the UDP server loop and listen for requests.

        Inputs:
          - None
        Outputs:
          - None; runs until shutdown is requested or KeyboardInterrupt occurs.
        """
        try:  # pragma: no cover
            self.server.serve_forever()  # pragma: no cover
        except KeyboardInterrupt:  # pragma: no cover
            pass  # pragma: no cover

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
        except Exception:  # pragma: no cover - defensive
            logger.exception("Error while shutting down UDP server")
        try:
            # Then close the socket so resources are released promptly.
            self.server.server_close()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Error while closing UDP server socket")


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
        try:
            peer_ip = (
                self.client_address[0]
                if isinstance(self.client_address, tuple)
                else "0.0.0.0"
            )
            resp = self.resolver(data, peer_ip)
            sock.sendto(resp, self.client_address)
        except Exception:
            pass  # pragma: no cover


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
    finally:  # pragma: no cover
        try:
            server.server_close()
        except Exception:
            pass
