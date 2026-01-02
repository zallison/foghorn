"""
Brief: Tests resolve_query_bytes pipeline for deny/override and cache hit.

Inputs:
  - None

Outputs:
  - None
"""

import pytest
from dnslib import QTYPE, RCODE, DNSRecord, RR, A

import foghorn.servers.server as server_mod
from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache
from foghorn.plugins.resolve import base as plugin_base
from foghorn.plugins.resolve.base import BasePlugin, PluginContext, PluginDecision
from foghorn.servers.server import DNSUDPHandler, resolve_query_bytes


class _DenyPlugin(BasePlugin):
    def pre_resolve(self, qname, qtype, data, ctx: PluginContext):
        return PluginDecision(action="deny")


class _OverridePlugin(BasePlugin):
    def pre_resolve(self, qname, qtype, data, ctx: PluginContext):
        r = DNSRecord.question(qname, "A").reply()
        return PluginDecision(action="override", response=r.pack())


class _Stats:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[tuple, dict]]] = []

    def __getattr__(self, name: str):
        def _rec(*a, **k):
            self.calls.append((name, (a, k)))

        return _rec


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
    plugin_base.DNS_CACHE.set(("cache.example", QTYPE.A), 10, r.pack())
    resp = resolve_query_bytes(q.pack(), "127.0.0.1")
    out = DNSRecord.parse(resp)
    assert out.header.rcode == RCODE.NOERROR


def test_resolve_query_bytes_stats_pre_deny_and_override():
    """Brief: resolve_query_bytes records stats for pre deny and override paths.

    Inputs:
      - None

    Outputs:
      - None; asserts key stats hooks are called for deny/override.
    """

    plugin_base.DNS_CACHE = InMemoryTTLCache()

    stats = _Stats()
    DNSUDPHandler.stats_collector = stats

    DNSUDPHandler.plugins = [_DenyPlugin()]
    q1 = DNSRecord.question("deny-stats.example", "A")
    resolve_query_bytes(q1.pack(), "127.0.0.1")

    DNSUDPHandler.plugins = [_OverridePlugin()]
    q2 = DNSRecord.question("override-stats.example", "A")
    resolve_query_bytes(q2.pack(), "127.0.0.1")

    DNSUDPHandler.stats_collector = None

    kinds = [k for k, _ in stats.calls]
    assert "record_query" in kinds
    assert "record_cache_null" in kinds
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds
    assert "record_latency" in kinds


def test_resolve_query_bytes_stats_cache_and_no_upstreams():
    """Brief: resolve_query_bytes records stats for cache hit and no upstreams paths.

    Inputs:
      - None

    Outputs:
      - None; asserts cache and no_upstreams stats hooks are invoked.
    """

    stats = _Stats()
    DNSUDPHandler.stats_collector = stats

    # Cache hit
    DNSUDPHandler.plugins = []
    q = DNSRecord.question("cache-stats.example", "A")
    r = q.reply()
    plugin_base.DNS_CACHE.set(("cache-stats.example", QTYPE.A), 10, r.pack())
    resolve_query_bytes(q.pack(), "127.0.0.1")

    # No upstreams: clear cache and ensure no upstreams configured
    plugin_base.DNS_CACHE = InMemoryTTLCache()
    DNSUDPHandler.upstream_addrs = []
    q2 = DNSRecord.question("no-upstreams-stats.example", "A")
    resolve_query_bytes(q2.pack(), "127.0.0.1")

    DNSUDPHandler.stats_collector = None

    kinds = [k for k, _ in stats.calls]
    assert "record_cache_hit" in kinds
    assert "record_cache_miss" in kinds
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds
    assert "record_latency" in kinds


def test_resolve_query_bytes_stats_upstream_success_and_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: resolve_query_bytes records upstream stats for success and all_failed cases.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts upstream_result and upstream_rcode stats are recorded.
    """

    stats = _Stats()
    DNSUDPHandler.stats_collector = stats
    DNSUDPHandler.plugins = []

    q = DNSRecord.question("upstream-stats.example", "A")
    r_ok = q.reply()

    def _forward_ok(req, upstreams, timeout_ms, qname, qtype, max_concurrent=None):
        return r_ok.pack(), {"host": "1.1.1.1", "port": 53}, "ok"

    def _forward_fail(req, upstreams, timeout_ms, qname, qtype, max_concurrent=None):
        return None, {"host": "2.2.2.2", "port": 53}, "all_failed"

    # Success case
    monkeypatch.setattr(server_mod, "send_query_with_failover", _forward_ok)
    DNSUDPHandler.upstream_addrs = [{"host": "1.1.1.1", "port": 53}]
    resolve_query_bytes(q.pack(), "127.0.0.1")

    # Failure case
    monkeypatch.setattr(server_mod, "send_query_with_failover", _forward_fail)
    DNSUDPHandler.upstream_addrs = [{"host": "2.2.2.2", "port": 53}]
    resolve_query_bytes(q.pack(), "127.0.0.1")

    DNSUDPHandler.stats_collector = None

    kinds = [k for k, _ in stats.calls]
    assert "record_upstream_result" in kinds
    assert "record_upstream_rcode" in kinds
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds
    assert "record_latency" in kinds


def test_resolve_query_bytes_stats_outer_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: resolve_query_bytes outer exception path records SERVFAIL and latency stats.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts response_rcode, query_result, and latency are recorded.
    """

    stats = _Stats()
    DNSUDPHandler.stats_collector = stats
    DNSUDPHandler.plugins = []
    plugin_base.DNS_CACHE = InMemoryTTLCache()
    DNSUDPHandler.upstream_addrs = [{"host": "1.1.1.1", "port": 53}]

    def _boom_send(req, upstreams, timeout_ms, qname, qtype, max_concurrent=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(server_mod, "send_query_with_failover", _boom_send)

    q = DNSRecord.question("outer-stats.example", "A")
    wire = resolve_query_bytes(q.pack(), "127.0.0.1")

    DNSUDPHandler.stats_collector = None

    # Response should be SERVFAIL synthesized by the outer exception handler
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL

    kinds = [k for k, _ in stats.calls]
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds
    assert "record_latency" in kinds


def test_resolve_query_bytes_recursive_mode_uses_recursive_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: recursive resolver mode uses RecursiveResolver and still caches.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures RecursiveResolver.resolve() is called once and results are
        cached so the second query does not invoke it again.
    """

    calls = {"n": 0}

    class _FakeRecursiveResolver:
        def __init__(
            self,
            *,
            cache,
            stats,
            max_depth: int = 16,
            timeout_ms: int = 2000,
            per_try_timeout_ms: int = 2000,
        ) -> None:
            self.cache = cache
            self.stats = stats
            self.max_depth = max_depth
            self.timeout_ms = timeout_ms
            self.per_try_timeout_ms = per_try_timeout_ms

        def resolve(self, req: DNSRecord):  # noqa: D401
            """Resolve via fake recursive path, returning a fixed A answer."""

            calls["n"] += 1
            r = req.reply()
            r.add_answer(RR("rec.example.", QTYPE.A, rdata=A("192.0.2.1"), ttl=60))
            return r.pack(), "fake-auth:53"

    # Patch RecursiveResolver used inside foghorn.servers.server._resolve_core
    monkeypatch.setattr(server_mod, "RecursiveResolver", _FakeRecursiveResolver)

    # Blow up if the forwarder path is accidentally used in recursive mode.
    def _boom_send_recursive(*_a, **_k):  # noqa: ANN001
        raise AssertionError(
            "send_query_with_failover should not be called in recursive mode"
        )

    monkeypatch.setattr(server_mod, "send_query_with_failover", _boom_send_recursive)

    # Configure handler state for recursive mode.
    DNSUDPHandler.plugins = []
    plugin_base.DNS_CACHE = InMemoryTTLCache()
    DNSUDPHandler.resolver_mode = "recursive"
    DNSUDPHandler.upstream_addrs = [{"host": "8.8.8.8", "port": 53}]

    q = DNSRecord.question("rec.example.", "A")

    # First query should go through the fake resolver.
    resp1 = resolve_query_bytes(q.pack(), "127.0.0.1")
    out1 = DNSRecord.parse(resp1)
    assert out1.header.rcode == RCODE.NOERROR
    assert any(rr.rdata == A("192.0.2.1") for rr in out1.rr)

    # Second query should be served from cache with no extra resolver calls.
    resp2 = resolve_query_bytes(q.pack(), "127.0.0.1")
    out2 = DNSRecord.parse(resp2)
    assert out2.header.rcode == RCODE.NOERROR
    assert any(rr.rdata == A("192.0.2.1") for rr in out2.rr)

    assert calls["n"] == 1

    # Restore resolver_mode so other tests see default behaviour.
    DNSUDPHandler.resolver_mode = "forward"
