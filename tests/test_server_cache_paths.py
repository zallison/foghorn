"""
Brief: Exercises EDNS ensure logic for UDP handlers and core resolver paths.

Inputs:
  - None

Outputs:
  - None
"""

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.resolve import base as plugin_base
from foghorn.servers.server import DNSUDPHandler


def test_handle_calls_ensure_edns_passthrough_no_crash(monkeypatch):
    # Ensure that when dnssec_mode=passthrough, _ensure_edns is invoked inside handle() and any
    # internal EDNS construction issues are swallowed by try/except (no crash).
    DNSUDPHandler.dnssec_mode = "passthrough"
    DNSUDPHandler.edns_udp_payload = 1232

    # Prepare a simple A query and a canned NOERROR response
    q = DNSRecord.question("example.com", "A")
    ok = q.reply().pack()

    # Patch failover to return our canned response and mark success
    import foghorn.servers.server as srv

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


def test_ensure_edns_adds_and_replaces_opt_record(monkeypatch):
    """Brief: _ensure_edns adds OPT when missing and replaces existing OPT record.

    Inputs:
      - None

    Outputs:
      - None; asserts resulting additional section contains a single OPT with payload size.
    """

    # Replace EDNS0 used inside server._ensure_edns with a lightweight stub that
    # accepts integer flags; the tests only inspect rclass, not encoded bytes.
    class _FakeEDNS0:
        def __init__(self, *a, **k):  # pragma: no cover - simple container
            self.args = (a, k)

    class _FakeRR:
        def __init__(self, rname, rtype, rclass, ttl, rdata):  # pragma: no cover
            self.rname = rname
            self.rtype = rtype
            self.rclass = rclass
            self.ttl = ttl
            self.rdata = rdata

    monkeypatch.setattr("foghorn.servers.server.EDNS0", _FakeEDNS0)
    monkeypatch.setattr("foghorn.servers.server.RR", _FakeRR)

    class _Shim:
        cache = plugin_base.DNS_CACHE
        min_cache_ttl = 60
        dnssec_mode = "ignore"
        edns_udp_payload = 1600

        def _ensure_edns(self, req):
            return DNSUDPHandler._ensure_edns(self, req)

    # Case 1: no existing OPT -> one OPT added
    q1 = DNSRecord.question("opt-add.example", "A")
    s = _Shim()
    assert not q1.ar
    s._ensure_edns(q1)
    opts = [rr for rr in (q1.ar or []) if rr.rtype == QTYPE.OPT]
    assert len(opts) == 1
    assert int(opts[0].rclass) == s.edns_udp_payload

    # Case 2: existing OPT present -> replaced with new payload
    q2 = DNSRecord.question("opt-replace.example", "A")

    class _ExistingOpt:
        def __init__(self):
            self.rtype = QTYPE.OPT
            self.rclass = 4096

    q2.ar = [_ExistingOpt()]
    s._ensure_edns(q2)
    opts2 = [rr for rr in (q2.ar or []) if rr.rtype == QTYPE.OPT]
    assert len(opts2) == 1
    assert int(opts2[0].rclass) == s.edns_udp_payload
