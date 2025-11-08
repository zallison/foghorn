"""
Brief: Tests resolve_query_bytes pipeline for deny/override and cache hit.

Inputs:
  - None

Outputs:
  - None
"""

from dnslib import DNSRecord, QTYPE, RCODE

from foghorn.server import resolve_query_bytes, DNSUDPHandler
from foghorn.plugins.base import BasePlugin, PluginDecision, PluginContext


class _DenyPlugin(BasePlugin):
    def pre_resolve(self, qname, qtype, data, ctx: PluginContext):
        return PluginDecision(action="deny")


class _OverridePlugin(BasePlugin):
    def pre_resolve(self, qname, qtype, data, ctx: PluginContext):
        r = DNSRecord.question(qname, "A").reply()
        return PluginDecision(action="override", response=r.pack())


def test_resolve_query_bytes_deny_and_override():
    DNSUDPHandler.plugins = [_DenyPlugin()]
    q = DNSRecord.question("deny.example", "A")
    resp = resolve_query_bytes(q.pack(), "127.0.0.1")
    assert DNSRecord.parse(resp).header.rcode == RCODE.NXDOMAIN

    DNSUDPHandler.plugins = [_OverridePlugin()]
    q2 = DNSRecord.question("override.example", "A")
    resp2 = resolve_query_bytes(q2.pack(), "127.0.0.1")
    assert DNSRecord.parse(resp2).header.rcode == RCODE.NOERROR


def test_resolve_query_bytes_cache_hit():
    DNSUDPHandler.plugins = []
    q = DNSRecord.question("cache.example", "A")
    r = q.reply()
    DNSUDPHandler.cache.set(("cache.example", QTYPE.A), 10, r.pack())
    resp = resolve_query_bytes(q.pack(), "127.0.0.1")
    out = DNSRecord.parse(resp)
    assert out.header.rcode == RCODE.NOERROR
