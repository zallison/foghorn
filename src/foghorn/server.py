import logging
import socketserver
from typing import List, Tuple, Dict, Optional
from dnslib import DNSRecord, QTYPE, RCODE

from .cache import TTLCache
from .plugins.base import BasePlugin, PluginDecision, PluginContext

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
    except Exception:
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
        host, port = upstream["host"], upstream["port"]
        try:
            logger.debug("Forwarding %s %s to %s:%d", qname, qtype, host, port)
            response_wire = query.send(host, port, timeout=timeout_sec)

            # Check for SERVFAIL to trigger failover
            try:
                parsed_response = DNSRecord.parse(response_wire)
                if parsed_response.header.rcode == RCODE.SERVFAIL:
                    logger.warning(
                        "Upstream %s:%d returned SERVFAIL for %s, trying next",
                        host, port, qname
                    )
                    last_exception = Exception(f"SERVFAIL from {host}:{port}")
                    continue  # Try next upstream
            except Exception as e:
                # If parsing fails, treat as a server failure
                logger.warning(
                    "Failed to parse response from %s:%d for %s: %s",
                    host, port, qname, e
                )
                last_exception = e
                continue # Try next upstream

            # Success (NOERROR, NXDOMAIN, etc. are all valid final answers)
            return response_wire, upstream, "ok"

        except Exception as e:
            logger.debug(
                "Upstream %s:%d failed for %s: %s", host, port, qname, str(e)
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

    def _cache_and_send_response(self, response_wire: bytes, req: DNSRecord, qname: str, qtype: int, sock, client_address, cache_key):
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
                logger.debug("Caching %s %s (%s) with TTL %ds", qname, qtype, rcode_name, effective_ttl)
                self.cache.set(cache_key, effective_ttl, response_wire)
            else:
                logger.debug("Not caching %s %s (effective TTL=%d)", qname, qtype, effective_ttl)
        except Exception as e:
            logger.debug("Failed to parse response for caching: %s", str(e))

        # Ensure the response ID matches the request ID before sending
        response_wire = _set_response_id(response_wire, req.header.id)
        sock.sendto(response_wire, client_address)

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
        data, sock = self.request
        client_ip = self.client_address[0]
        try:
            req = DNSRecord.parse(data)
            q = req.questions[0]
            qname = str(q.qname).rstrip(".")
            qtype = q.qtype

            logger.debug("Query from %s: %s %s", client_ip, qname, qtype)

            ctx = PluginContext(client_ip=client_ip)

            # Pre-resolve plugin checks
            for p in self.plugins:
                decision = p.pre_resolve(qname, qtype, data, ctx)
                if isinstance(decision, PluginDecision):
                    if decision.action == "deny":
                        logger.warning(
                            "Denied %s %s by %s", qname, qtype, p.__class__.__name__
                        )
                        reply = req.reply()
                        reply.header.rcode = RCODE.NXDOMAIN
                        self._cache_and_send_response(reply.pack(), req, qname, qtype, sock, self.client_address, cache_key)
                        return
                    if decision.action == "override" and decision.response is not None:
                        logger.info(
                            "Override %s %s by %s", qname, qtype, p.__class__.__name__
                        )
                        # Don't cache plugin overrides - they may be dynamic
                        resp = _set_response_id(decision.response, req.header.id)
                        sock.sendto(resp, self.client_address)
                        return
                    # allow -> continue
                    logger.debug("Plugin %s: %s", p.__class__.__name__, decision.action)

            # Check cache for a response.
            cache_key = (qname.lower(), qtype)
            cached = self.cache.get(cache_key)
            if cached is not None:
                logger.debug("Cache hit: %s %s (%d bytes)", qname, qtype, len(cached))
                resp = _set_response_id(cached, req.header.id)
                sock.sendto(resp, self.client_address)
                return
            else:
                logger.debug("Cache miss: %s %s", qname, qtype)

            # Determine upstream candidates to try
            upstreams_to_try = ctx.upstream_candidates or self.upstream_addrs
            if upstreams_to_try:
                logger.debug(
                    "Using %d upstreams for %s %s", len(upstreams_to_try), qname, qtype
                )
            else:
                logger.warning("No upstreams configured for %s %s", qname, qtype)
                r = req.reply()
                r.header.rcode = RCODE.SERVFAIL
                self._cache_and_send_response(r.pack(), req, qname, qtype, sock, self.client_address, cache_key)
                return

            # Try upstreams with failover
            reply, used_upstream, reason = send_query_with_failover(
                req, upstreams_to_try, self.timeout_ms, qname, qtype
            )

            if reply is None:
                logger.warning(
                    "All upstreams failed for %s %s, returning SERVFAIL", qname, qtype
                )
                r = req.reply()
                r.header.rcode = RCODE.SERVFAIL
                self._cache_and_send_response(r.pack(), req, qname, qtype, sock, self.client_address, cache_key)
                return
            # Post-resolve plugin hooks (allow overrides like rewriting)
            for p in self.plugins:
                decision = p.post_resolve(qname, qtype, reply, ctx)
                if isinstance(decision, PluginDecision):
                    if decision.action == "deny":
                        logger.warning(
                            "Post-resolve denied %s %s by %s",
                            qname,
                            qtype,
                            p.__class__.__name__,
                        )
                        r = req.reply()
                        r.header.rcode = RCODE.NXDOMAIN
                        reply = r.pack()
                        break
                    if decision.action == "override" and decision.response is not None:
                        logger.info(
                            "Post-resolve override %s %s by %s",
                            qname,
                            qtype,
                            p.__class__.__name__,
                        )
                        reply = decision.response
                        break

            # Cache and send the final response
            self._cache_and_send_response(reply, req, qname, qtype, sock, self.client_address, cache_key)
        except Exception as e:
            logger.exception(
                "Unhandled error during request handling from %s", client_ip
            )
            try:
                # On parse or other errors, return SERVFAIL
                req = DNSRecord.parse(data)
                q = req.questions[0]
                qname = str(q.qname).rstrip(".")
                qtype = q.qtype
                cache_key = (qname.lower(), qtype)
                r = req.reply()
                r.header.rcode = RCODE.SERVFAIL
                self._cache_and_send_response(r.pack(), req, qname, qtype, sock, self.client_address, cache_key)
            except Exception as inner_e:
                logger.error("Failed to send SERVFAIL response: %s", str(inner_e))


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
        DNSUDPHandler.upstream_addrs = upstreams
        DNSUDPHandler.plugins = plugins
        DNSUDPHandler.timeout = timeout
        DNSUDPHandler.timeout_ms = timeout_ms
        DNSUDPHandler.min_cache_ttl = max(0, int(min_cache_ttl))
        self.server = socketserver.ThreadingUDPServer((host, port), DNSUDPHandler)
        # Ensure request handler threads do not block shutdown
        self.server.daemon_threads = True
        logger.info("DNS UDP server bound to %s:%d", host, port)

    def serve_forever(self):
        """
        Starts the server and listens for requests.

        Example use:
            This method is typically run in a separate thread for testing.
            See the DNSServer class docstring for an example.
        """
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            pass
