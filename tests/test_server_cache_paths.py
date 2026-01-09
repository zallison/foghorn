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


def test_ensure_edns_adds_opt_when_missing_and_sets_payload_and_do():
    """Brief: _ensure_edns adds a single OPT with payload and DO based on dnssec_mode.

    Inputs:
      - None

    Outputs:
      - None; asserts a single OPT exists with rclass=edns_udp_payload and DO bit mapping.
    """

    class _Shim:
        cache = plugin_base.DNS_CACHE
        min_cache_ttl = 60
        dnssec_mode = "ignore"
        edns_udp_payload = 1600

        def _ensure_edns(self, req):
            return DNSUDPHandler._ensure_edns(self, req)

    # Case 1: dnssec_mode=ignore -> DO bit cleared
    q1 = DNSRecord.question("opt-add-ignore.example", "A")
    s1 = _Shim()
    s1.dnssec_mode = "ignore"
    assert not q1.ar
    s1._ensure_edns(q1)
    opts = [rr for rr in (q1.ar or []) if rr.rtype == QTYPE.OPT]
    assert len(opts) == 1
    opt = opts[0]
    assert int(opt.rclass) == s1.edns_udp_payload
    # Low 16 bits of TTL carry EDNS flags; DO must be cleared.
    assert (int(getattr(opt, "ttl", 0)) & 0x8000) == 0

    # Case 2: dnssec_mode=validate -> DO bit set
    q2 = DNSRecord.question("opt-add-validate.example", "A")
    s2 = _Shim()
    s2.dnssec_mode = "validate"
    s2._ensure_edns(q2)
    opts2 = [rr for rr in (q2.ar or []) if rr.rtype == QTYPE.OPT]
    assert len(opts2) == 1
    opt2 = opts2[0]
    assert int(opt2.rclass) == s2.edns_udp_payload
    assert (int(getattr(opt2, "ttl", 0)) & 0x8000) == 0x8000


def test_ensure_edns_respects_client_payload_and_clamps_to_server_max():
    """Brief: _ensure_edns mirrors client UDP payload, clamped by edns_udp_payload.

    Inputs:
      - None

    Outputs:
      - None; asserts resulting OPT rclass is min(client_payload, server_max).
    """

    class _Shim:
        cache = plugin_base.DNS_CACHE
        min_cache_ttl = 60
        dnssec_mode = "ignore"
        edns_udp_payload = 1600

        def _ensure_edns(self, req):
            return DNSUDPHandler._ensure_edns(self, req)

    from dnslib import EDNS0 as _EDNS0

    # Client advertises a larger payload than server_max; we should clamp.
    q = DNSRecord.question("opt-clamp.example", "A")
    q.add_ar(_EDNS0(udp_len=4096))

    s = _Shim()
    s._ensure_edns(q)
    opts = [rr for rr in (q.ar or []) if rr.rtype == QTYPE.OPT]
    assert len(opts) == 1
    opt = opts[0]
    assert int(opt.rclass) == s.edns_udp_payload
    # DO bit remains cleared in ignore mode.
    assert (int(getattr(opt, "ttl", 0)) & 0x8000) == 0
