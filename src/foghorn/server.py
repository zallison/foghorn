from __future__ import annotations
import socketserver
from typing import List, Tuple
from dnslib import DNSRecord, QTYPE, RCODE

from .cache import TTLCache
from .plugins.base import BasePlugin, PluginDecision, PluginContext

class DNSUDPHandler(socketserver.BaseRequestHandler):
    """
    Handles UDP DNS requests.
    This class is instantiated for each incoming DNS query.

    Example use:
        This handler is used internally by the DNSServer and is not
        typically instantiated directly by users.
    """
    cache = TTLCache()
    upstream_addr: Tuple[str, int] = ("1.1.1.1", 53)
    plugins: List[BasePlugin] = []
    timeout = 2.0

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
            qname = str(q.qname).rstrip('.')
            qtype = q.qtype

            ctx = PluginContext(client_ip=client_ip)

            # Pre-resolve plugin checks
            for p in self.plugins:
                decision = p.pre_resolve(qname, qtype, ctx)
                if isinstance(decision, PluginDecision):
                    if decision.action == "deny":
                        reply = req.reply()
                        reply.header.rcode = RCODE.NXDOMAIN
                        sock.sendto(reply.pack(), self.client_address)
                        return
                    if decision.action == "override" and decision.response is not None:
                        sock.sendto(decision.response, self.client_address)
                        return
                    # allow -> continue

            # Check cache for a response.
            cache_key = (qname.lower(), qtype)
            cached = self.cache.get(cache_key)
            if cached is not None:
                sock.sendto(cached, self.client_address)
                return

            # Forward to upstream
            upstream_addr = getattr(ctx, "upstream_override", None) or self.upstream_addr
            reply = req.send(upstream_addr, timeout=self.timeout)
            # Post-resolve plugin hooks (allow overrides like rewriting)
            for p in self.plugins:
                decision = p.post_resolve(qname, qtype, reply, ctx)
                if isinstance(decision, PluginDecision):
                    if decision.action == "deny":
                        r = req.reply()
                        r.header.rcode = RCODE.NXDOMAIN
                        reply = r.pack()
                        break
                    if decision.action == "override" and decision.response is not None:
                        reply = decision.response
                        break

            # Cache the response based on the minimum TTL in the answer records.
            try:
                r = DNSRecord.parse(reply)
                ttls = [rr.ttl for rr in r.rr]
                ttl = min(ttls) if ttls else 0
                if ttl > 0:
                    self.cache.set(cache_key, ttl, reply)
            except Exception:
                pass

            sock.sendto(reply, self.client_address)
        except Exception:
            try:
                # On parse or other errors, return SERVFAIL
                req = DNSRecord.parse(data)
                r = req.reply()
                r.header.rcode = RCODE.SERVFAIL
                sock.sendto(r.pack(), self.client_address)
            except Exception:
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
    def __init__(self, host: str, port: int, upstream: Tuple[str,int], plugins: List[BasePlugin], timeout: float = 2.0) -> None:
        """
        Initializes the DNSServer.

        Args:
            host: The host to listen on.
            port: The port to listen on.
            upstream: The upstream DNS server address.
            plugins: A list of initialized plugins.
            timeout: The timeout for upstream queries.

        Example use:
            >>> from foghorn.server import DNSServer
            >>> server = DNSServer("127.0.0.1", 5353, ("8.8.8.8", 53), [], 2.0)
            >>> server.server.server_address
            ('127.0.0.1', 5353)
        """
        DNSUDPHandler.upstream_addr = upstream
        DNSUDPHandler.plugins = plugins
        DNSUDPHandler.timeout = timeout
        self.server = socketserver.UDPServer((host, port), DNSUDPHandler)

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
