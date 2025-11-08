"""
Brief: Exercises cache store branches in server._cache_store_if_applicable and EDNS ensure logic.

Inputs:
  - None

Outputs:
  - None
"""

from foghorn.server import DNSUDPHandler, compute_effective_ttl
from dnslib import DNSRecord, QTYPE, RCODE, DNSHeader, RR, A


def test_cache_store_paths():
    h = DNSUDPHandler
    # Fresh cache per test
    h.cache._store = {}

    # Use the class methods by binding minimal shim with required attributes
    class _Shim:
        cache = h.cache
        min_cache_ttl = 60

        def _cache_store_if_applicable(self, qname, qtype, response_wire):
            return DNSUDPHandler._cache_store_if_applicable(
                self, qname, qtype, response_wire
            )

        def _ensure_edns(self, req):
            return DNSUDPHandler._ensure_edns(self, req)

    # 1) NOERROR with no answers -> not cached
    q = DNSRecord.question("example.com", "A")
    r = q.reply()
    wire = r.pack()
    _Shim()._cache_store_if_applicable("example.com", QTYPE.A, wire)
    assert h.cache.get(("example.com", QTYPE.A)) is None

    # 2) SERVFAIL -> never cached
    r2 = q.reply()
    r2.header.rcode = RCODE.SERVFAIL
    _Shim()._cache_store_if_applicable("example.com", QTYPE.A, r2.pack())
    assert h.cache.get(("example.com", QTYPE.A)) is None

    # 3) NOERROR with answers -> cached with min ttl (use unique name to avoid leaking into other tests)
    q3 = DNSRecord.question("cacheonly.example", "A")
    r3 = q3.reply()
    r3.add_answer(RR("cacheonly.example", QTYPE.A, rdata=A("1.2.3.4"), ttl=2))
    _Shim()._cache_store_if_applicable("cacheonly.example", QTYPE.A, r3.pack())
    assert h.cache.get(("cacheonly.example", QTYPE.A)) is not None
    # Clear cache after to avoid influencing other tests
    h.cache._store = {}


def test_handle_calls_ensure_edns_passthrough_no_crash(monkeypatch):
    # Ensure that when dnssec_mode=passthrough, _ensure_edns is invoked inside handle() and any
    # internal EDNS construction issues are swallowed by try/except (no crash).
    DNSUDPHandler.dnssec_mode = "passthrough"
    DNSUDPHandler.edns_udp_payload = 1232

    # Prepare a simple A query and a canned NOERROR response
    q = DNSRecord.question("example.com", "A")
    ok = q.reply().pack()

    # Patch failover to return our canned response and mark success
    import foghorn.server as srv

    def fake_forward(req, upstreams, qname, qtype):
        return ok, {"host": "1.1.1.1", "port": 53}, "ok"

    monkeypatch.setattr(
        srv.DNSUDPHandler,
        "_forward_with_failover_helper",
        lambda self, request, upstreams, qname, qtype: fake_forward(
            request, upstreams, qname, qtype
        ),
    )

    # Ensure at least one upstream so handle doesn't SERVFAIL early
    DNSUDPHandler.upstream_addrs = [{"host": "1.1.1.1", "port": 53}]

    # Mock socket to capture sendto
    class _Sock:
        def __init__(self):
            self.sent = []

        def sendto(self, data, addr):
            self.sent.append((data, addr))

    sock = _Sock()

    # Build handler instance without calling BaseRequestHandler.__init__
    h = DNSUDPHandler.__new__(DNSUDPHandler)
    h.request = (q.pack(), sock)
    h.client_address = ("127.0.0.1", 12345)

    # Execute; should not crash even if _ensure_edns misbehaves internally
    h.handle()

    # We should have sent at least one response
    assert len(sock.sent) >= 1
