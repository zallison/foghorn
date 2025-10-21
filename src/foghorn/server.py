from __future__ import annotations
import socketserver
from typing import List, Tuple
from dnslib import DNSRecord, QTYPE, RCODE

from .cache import TTLCache
from .plugins.base import BasePlugin, PluginDecision, PluginContext

class DNSUDPHandler(socketserver.BaseRequestHandler):
    cache = TTLCache()
    upstream_addr: Tuple[str, int] = ("1.1.1.1", 53)
    plugins: List[BasePlugin] = []
    timeout = 2.0

    def handle(self):
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

            cache_key = (qname.lower(), qtype)
            cached = self.cache.get(cache_key)
            if cached is not None:
                sock.sendto(cached, self.client_address)
                return

            # Forward to upstream (allow plugin to override per-request)
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

            # Cache based on minimum TTL in answers
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
    def __init__(self, host: str, port: int, upstream: Tuple[str,int], plugins: List[BasePlugin], timeout: float = 2.0) -> None:
        DNSUDPHandler.upstream_addr = upstream
        DNSUDPHandler.plugins = plugins
        DNSUDPHandler.timeout = timeout
        self.server = socketserver.UDPServer((host, port), DNSUDPHandler)

    def serve_forever(self):
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            pass
