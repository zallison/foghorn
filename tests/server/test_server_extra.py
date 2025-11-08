"""
Brief: Additional coverage for foghorn.server helpers and edge paths.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from typing import Tuple
from unittest.mock import patch

import pytest
from dnslib import DNSRecord, QTYPE, RCODE, RR, A, DNSHeader

import foghorn.server as srv


def _mk_handler(query_wire: bytes, client_ip: str = "127.0.0.1"):
    """
    Brief: Build a DNSUDPHandler instance with a fake socket.

    Inputs:
      - query_wire (bytes): packed DNS query
      - client_ip (str): client address
    Outputs:
      - (handler, sock): a tuple with configured handler and fake sock that records sendto calls
    """
    h = srv.DNSUDPHandler.__new__(srv.DNSUDPHandler)

    class _Sock:
        def __init__(self):
            self.sent = []

        def sendto(self, data, addr):
            self.sent.append((data, addr))

    sock = _Sock()
    h.request = (query_wire, sock)
    h.client_address = (client_ip, 55333)
    # Reset shared state to avoid leakage between tests
    srv.DNSUDPHandler.plugins = []
    srv.DNSUDPHandler.upstream_addrs = []
    # Reset cache by swapping the instance (TTLCache has no clear())
    srv.DNSUDPHandler.cache = srv.TTLCache()
    return h, sock


def test__set_response_id_overwrites_first_two_bytes():
    """
    Brief: _set_response_id should directly rewrite the first two bytes.

    Inputs:
      - None
    Outputs:
      - None; asserts the ID bytes changed while the rest stayed the same
    """
    q = DNSRecord.question("example.com", "A")
    resp = q.reply().pack()
    new = srv._set_response_id(resp, 0xBEEF)
    assert new[:2] == bytes([0xBE, 0xEF])
    assert new[2:] == resp[2:]


def test__ensure_edns_does_not_crash_in_all_modes(monkeypatch):
    """
    Brief: handle() should tolerate EDNS adjustments across modes without crashing.

    Inputs:
      - monkeypatch: pytest fixture
    Outputs:
      - None; asserts a response is sent for each dnssec_mode
    """
    q = DNSRecord.question("example.com", "A")

    def fake_forward(self, request, upstreams, qname, qtype):
        # Return a simple NOERROR reply
        rep = request.reply()
        return rep.pack(), {"host": "8.8.8.8", "port": 53}, "ok"

    monkeypatch.setattr(
        srv.DNSUDPHandler, "_forward_with_failover_helper", fake_forward
    )

    for mode in ("ignore", "passthrough", "validate"):
        h, sock = _mk_handler(q.pack())
        srv.DNSUDPHandler.upstream_addrs = [{"host": "8.8.8.8", "port": 53}]
        srv.DNSUDPHandler.plugins = []
        h.dnssec_mode = mode
        h.edns_udp_payload = 1400
        h.handle()
        assert len(sock.sent) >= 1


def test__cache_store_if_applicable_variants():
    """
    Brief: Cover NOERROR/answers with TTL>0, TTL=0, SERVFAIL not cached, other rcodes no-answers.

    Inputs:
      - None
    Outputs:
      - None; asserts cache set/miss accordingly
    """
    name = "cache.example"
    # Build replies
    q = DNSRecord.question(name, "A")

    # NOERROR + answer TTL>0 -> cached
    r_ok = q.reply()
    r_ok.add_answer(RR(name, rdata=A("1.2.3.4"), ttl=33))
    h, _ = _mk_handler(q.pack())
    h._cache_store_if_applicable(name, QTYPE.A, r_ok.pack())
    assert h.cache.get((name, QTYPE.A)) is not None

    # NOERROR + answer TTL=0 -> not cached (remains from previous; use new key)
    name2 = "zero.example"
    q2 = DNSRecord.question(name2, "A")
    r_zero = q2.reply()
    r_zero.add_answer(RR(name2, rdata=A("1.2.3.4"), ttl=0))
    h._cache_store_if_applicable(name2, QTYPE.A, r_zero.pack())
    assert h.cache.get((name2, QTYPE.A)) is None

    # SERVFAIL -> never cached
    name3 = "servfail.example"
    q3 = DNSRecord.question(name3, "A")
    r_sf = q3.reply()
    r_sf.header.rcode = RCODE.SERVFAIL
    h._cache_store_if_applicable(name3, QTYPE.A, r_sf.pack())
    assert h.cache.get((name3, QTYPE.A)) is None

    # NXDOMAIN with no answers -> not cached
    name4 = "nx.example"
    q4 = DNSRecord.question(name4, "A")
    r_nx = q4.reply()
    r_nx.header.rcode = RCODE.NXDOMAIN
    h._cache_store_if_applicable(name4, QTYPE.A, r_nx.pack())
    assert h.cache.get((name4, QTYPE.A)) is None


def test__apply_pre_plugins_override_short_circuits():
    """
    Brief: pre plugin override should send response and return.

    Inputs:
      - None
    Outputs:
      - None; asserts the overridden response is sent and not forwarded
    """
    q = DNSRecord.question("pre.example", "A")
    h, sock = _mk_handler(q.pack())

    class _PreOverride:
        pre_priority = 1

        def pre_resolve(self, qname, qtype, data, ctx):
            rep = DNSRecord.parse(data).reply()
            rep.header.rcode = RCODE.NXDOMAIN
            return srv.PluginDecision(action="override", response=rep.pack())

        def post_resolve(self, qname, qtype, data, ctx):
            return None

    srv.DNSUDPHandler.plugins = [_PreOverride()]

    h.handle()
    assert len(sock.sent) >= 1
    last = DNSRecord.parse(sock.sent[-1][0])
    assert last.header.rcode == RCODE.NXDOMAIN


def test__apply_post_plugins_override_path(monkeypatch):
    """
    Brief: post plugin override path should replace reply.

    Inputs:
      - monkeypatch: pytest fixture
    Outputs:
      - None; asserts overridden wire is sent
    """
    q = DNSRecord.question("post.example", "A")
    ok = q.reply().pack()

    def fake_forward(self, request, upstreams, qname, qtype):
        return ok, {"host": "8.8.8.8", "port": 53}, "ok"

    class _PostOverride:
        post_priority = 1

        def pre_resolve(self, qname, qtype, data, ctx):
            return None

        def post_resolve(self, qname, qtype, data, ctx):
            rep = DNSRecord.parse(data)
            rep.header.rcode = RCODE.NXDOMAIN
            return srv.PluginDecision(action="override", response=rep.pack())

    monkeypatch.setattr(
        srv.DNSUDPHandler, "_forward_with_failover_helper", fake_forward
    )

    h, sock = _mk_handler(q.pack())
    srv.DNSUDPHandler.upstream_addrs = [{"host": "8.8.8.8", "port": 53}]
    srv.DNSUDPHandler.plugins = [_PostOverride()]
    h.handle()
    last = DNSRecord.parse(sock.sent[-1][0])
    assert last.header.rcode == RCODE.NXDOMAIN


def test_resolve_query_bytes_end_to_end_paths(monkeypatch):
    """
    Brief: resolve_query_bytes handles cache miss/hit, no upstreams -> SERVFAIL, and pre override.

    Inputs:
      - monkeypatch: pytest fixture
    Outputs:
      - None; asserts various branches
    """
    # 1) No upstreams -> SERVFAIL
    q = DNSRecord.question("no-up.example", "A")
    srv.DNSUDPHandler.upstream_addrs = []
    srv.DNSUDPHandler.plugins = []
    srv.DNSUDPHandler.cache = srv.TTLCache()
    wire = srv.resolve_query_bytes(q.pack(), "127.0.0.1")
    assert DNSRecord.parse(wire).header.rcode == RCODE.SERVFAIL

    # 2) Pre override -> NXDOMAIN
    class _PreOverride:
        pre_priority = 1

        def pre_resolve(self, qname, qtype, data, ctx):
            rep = DNSRecord.parse(data).reply()
            rep.header.rcode = RCODE.NXDOMAIN
            return srv.PluginDecision(action="override", response=rep.pack())

        def post_resolve(self, qname, qtype, data, ctx):
            return None

    srv.DNSUDPHandler.plugins = [_PreOverride()]
    wire2 = srv.resolve_query_bytes(q.pack(), "127.0.0.1")
    assert DNSRecord.parse(wire2).header.rcode == RCODE.NXDOMAIN

    # 3) Cache store on NOERROR+answers
    srv.DNSUDPHandler.plugins = []
    q3 = DNSRecord.question("cachehit.example", "A")
    r3 = q3.reply()
    r3.add_answer(RR("cachehit.example", rdata=A("1.2.3.4"), ttl=5))

    def fake_forward(req, upstreams, timeout_ms, qname, qtype):
        return r3.pack(), {"host": "1.1.1.1", "port": 53}, "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", fake_forward)
    srv.DNSUDPHandler.upstream_addrs = [{"host": "1.1.1.1", "port": 53}]
    out = srv.resolve_query_bytes(q3.pack(), "127.0.0.1")
    assert DNSRecord.parse(out).header.rcode == RCODE.NOERROR
    # Second call should be served from cache
    out2 = srv.resolve_query_bytes(q3.pack(), "127.0.0.1")
    assert DNSRecord.parse(out2).header.rcode == RCODE.NOERROR


def test_send_query_with_failover_doh_without_url_all_failed():
    """
    Brief: DoH upstream without url should be treated as failure and continue.

    Inputs:
      - None
    Outputs:
      - None; asserts (None,None,'all_failed')
    """
    q = DNSRecord.question("example.com", "A")
    upstreams = [{"transport": "doh"}]  # missing url/endpoint
    body, used, reason = srv.send_query_with_failover(
        q, upstreams, 200, "example.com", QTYPE.A
    )
    assert body is None and used is None and reason == "all_failed"
