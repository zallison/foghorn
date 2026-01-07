"""
Brief: Additional coverage for foghorn.servers.server.

Inputs:
  - None (pytest harness)

Outputs:
  - None (pytest assertions)
"""

from dnslib import NS, QTYPE, RCODE, RR, SOA, A, DNSRecord

import foghorn.servers.server as srv
from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache
from foghorn.plugins.resolve import base as plugin_base


def test_compute_effective_ttl_variants():
    """
    Brief: Cover NOERROR with answers (min TTL floor), non-NOERROR, and error fallback.

    Inputs:
      - Synthetic DNSRecord replies with varying TTL/rcode.
    Outputs:
      - Ensures effective TTL applies floor; SERVFAIL uses floor; error path returns floor.
    """
    q = DNSRecord.question("ttl.example", "A")

    # NOERROR + answers with low TTL -> floor applied
    r_low = q.reply()
    r_low.add_answer(RR("ttl.example", rdata=A("1.1.1.1"), ttl=10))
    assert srv.compute_effective_ttl(r_low, 60) == 60

    # NOERROR + answers with high TTL -> high kept
    r_hi = q.reply()
    r_hi.add_answer(RR("ttl.example", rdata=A("1.1.1.1"), ttl=3600))
    assert srv.compute_effective_ttl(r_hi, 60) == 3600

    # NXDOMAIN/no answers -> floor
    r_nx = q.reply()
    r_nx.header.rcode = RCODE.NXDOMAIN
    assert srv.compute_effective_ttl(r_nx, 42) == 42

    # Error path: object missing expected attributes -> fall back to floor
    class _Bad:
        pass

    assert srv.compute_effective_ttl(_Bad(), 15) == 15


def test__set_response_id_error_path_logged(caplog):
    """
    Brief: _set_response_id handles exceptions and returns original object.

    Inputs:
      - Non-bytes object (None) to trigger len() TypeError.
    Outputs:
      - Returns the original object and logs an error.
    """
    with caplog.at_level("ERROR"):
        out = srv._set_response_id(None, 1234)  # type: ignore[arg-type]
    assert out is None
    assert any("Failed to set response id" in rec.message for rec in caplog.records)


def test_send_query_with_failover_no_upstreams():
    """
    Brief: No upstreams yields no_upstreams reason.

    Inputs:
      - Empty upstream list.
    Outputs:
      - (None, None, 'no_upstreams').
    """
    q = DNSRecord.question("example.com", "A")
    resp, used, reason = srv.send_query_with_failover(
        q, [], 200, "example.com", QTYPE.A
    )
    assert resp is None and used is None and reason == "no_upstreams"


def test_send_query_with_failover_servfail_then_success(monkeypatch):
    """
    Brief: SERVFAIL from first upstream triggers failover to second which succeeds.

    Inputs:
      - First UDP upstream returns SERVFAIL; second returns NOERROR.
    Outputs:
      - Final response ok; used_upstream is second.
    """
    q = DNSRecord.question("example.com", "A")

    r_sf = q.reply()
    r_sf.header.rcode = RCODE.SERVFAIL
    r_ok = q.reply()

    def fake_udp_query(host, port, query_bytes, timeout_ms=0):
        if host == "1.1.1.1":
            return r_sf.pack()
        return r_ok.pack()

    import foghorn.servers.transports.udp as udp_mod

    monkeypatch.setattr(udp_mod, "udp_query", fake_udp_query)

    upstreams = [
        {"host": "1.1.1.1", "port": 53, "transport": "udp"},
        {"host": "1.0.0.1", "port": 53, "transport": "udp"},
    ]

    resp, used, reason = srv.send_query_with_failover(
        q, upstreams, 300, "example.com", QTYPE.A
    )
    assert reason == "ok" and used["host"] == "1.0.0.1"


def test_send_query_with_failover_parse_error_then_success(monkeypatch, caplog):
    """
    Brief: Unparseable response from first upstream continues to next.

    Inputs:
      - First returns garbage bytes; second returns valid reply.
    Outputs:
      - Success from second; warning logged for parse failure.
    """
    q = DNSRecord.question("example.com", "A")
    r_ok = q.reply()

    def fake_udp_query(host, port, query_bytes, timeout_ms=0):
        if host == "1.1.1.1":
            return b"\x00\x01garbage"
        return r_ok.pack()

    import foghorn.servers.transports.udp as udp_mod

    monkeypatch.setattr(udp_mod, "udp_query", fake_udp_query)

    upstreams = [
        {"host": "1.1.1.1", "port": 53, "transport": "udp"},
        {"host": "1.0.0.1", "port": 53, "transport": "udp"},
    ]

    with caplog.at_level("WARNING"):
        resp, used, reason = srv.send_query_with_failover(
            q, upstreams, 300, "example.com", QTYPE.A
        )
    assert reason == "ok" and used["host"] == "1.0.0.1"
    assert any("Failed to parse response" in rec.message for rec in caplog.records)


def test_send_query_with_failover_udp_legacy_send_path(monkeypatch):
    """Brief: UDP path supports objects without callable pack() by using send().

    Inputs:
      - Query object with .send() only.
    Outputs:
      - Success over UDP.
    """

    class _Legacy:
        def __init__(self, wire):
            self._wire = wire
            self.pack = None  # not callable

        def send(self, host: str, port: int, timeout: float = 0.1) -> bytes:
            return self._wire

    q = DNSRecord.question("legacy.example", "A")
    legacy = _Legacy(q.reply().pack())

    upstreams = [{"host": "9.9.9.9", "port": 53, "transport": "udp"}]
    resp, used, reason = srv.send_query_with_failover(
        legacy, upstreams, 200, "legacy.example", QTYPE.A
    )  # type: ignore[arg-type]
    assert reason == "ok" and used == upstreams[0]


def test__cache_and_send_response_parse_error_still_sends():
    """
    Brief: _cache_and_send_response logs parse failure but sends bytes to client.

    Inputs:
      - Garbage response bytes to trigger parse error.
    Outputs:
      - Fake socket captured one sendto call.
    """
    h = srv.DNSUDPHandler.__new__(srv.DNSUDPHandler)

    class _Sock:
        def __init__(self):
            self.sent = []

        def sendto(self, data, addr):
            self.sent.append((data, addr))

    sock = _Sock()
    plugin_base.DNS_CACHE = InMemoryTTLCache()
    req = DNSRecord.question("bad.example", "A")
    h._cache_and_send_response(
        b"\x00\x01garbage",
        req,
        "bad.example",
        QTYPE.A,
        sock,
        ("127.0.0.1", 9),
        ("bad.example", QTYPE.A),
    )
    assert len(sock.sent) == 1


def test_handle_pre_deny_sends_nxdomain_and_returns(monkeypatch):
    """
    Brief: pre plugin deny should short-circuit with NXDOMAIN.

    Inputs:
      - Plugin that denies in pre_resolve.
    Outputs:
      - Single send of NXDOMAIN response.
    """
    q = DNSRecord.question("predeny.example", "A")
    h = srv.DNSUDPHandler.__new__(srv.DNSUDPHandler)

    class _Sock:
        def __init__(self):
            self.sent = []

        def sendto(self, data, addr):
            self.sent.append((data, addr))

    sock = _Sock()
    h.request = (q.pack(), sock)
    h.client_address = ("127.0.0.1", 5555)

    class _PreDeny:
        def pre_resolve(self, qname, qtype, data, ctx):
            return srv.PluginDecision(action="deny")

        def post_resolve(self, qname, qtype, data, ctx):
            return None

    srv.DNSUDPHandler.plugins = [_PreDeny()]
    srv.DNSUDPHandler.upstream_addrs = [{"host": "8.8.8.8", "port": 53}]

    h.handle()
    assert len(sock.sent) == 1
    assert DNSRecord.parse(sock.sent[0][0]).header.rcode == RCODE.NXDOMAIN


def testfoghorn_dnssec_dnssec_validate_mode_upstream_ad_and_local_paths(monkeypatch):
    """Brief: dnssec_mode=validate enforces AD bit with upstream/local validation.

    Inputs:
      - dnssec_mode=validate with dnssec_validation set to upstream_ad and
        local.

    Outputs:
      - Upstream path without AD bit yields SERVFAIL.
      - Local path with validator raising yields SERVFAIL.
    """
    # Ensure clean slate
    srv.DNSUDPHandler.plugins = []
    plugin_base.DNS_CACHE = InMemoryTTLCache()


def test_resolve_query_bytes_negative_caches_nxdomain_with_soa(monkeypatch):
    """Brief: resolve_query_bytes should cache NXDOMAIN with SOA authority.

    Inputs:
      - Fake upstream that always returns NXDOMAIN with an SOA in the
        authority section.

    Outputs:
      - Two resolve_query_bytes() calls for the same question trigger exactly
        one send_query_with_failover() call and both responses are NXDOMAIN.
    """

    q = DNSRecord.question("neg-cache-nx.example", "A")
    r = q.reply()
    r.header.rcode = RCODE.NXDOMAIN
    # Authority SOA with TTL>0 so that _compute_negative_ttl can derive a TTL.
    r.add_auth(
        RR(
            "neg-cache-nx.example",
            QTYPE.SOA,
            rdata=SOA(
                "ns.neg-cache-nx.example.",
                "hostmaster.neg-cache-nx.example.",
                (1, 60, 60, 60, 60),
            ),
            ttl=42,
        )
    )
    wire = r.pack()

    calls = {"n": 0}

    def fake_failover(
        req, upstreams, timeout_ms, qname, qtype, max_concurrent=None
    ):  # noqa: ANN001
        calls["n"] += 1
        return wire, upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", fake_failover)

    plugin_base.DNS_CACHE = InMemoryTTLCache()
    srv.DNSUDPHandler.upstream_addrs = [{"host": "1.1.1.1", "port": 53}]
    srv.DNSUDPHandler.plugins = []
    srv.DNSUDPHandler.min_cache_ttl = 5

    resp1 = srv.resolve_query_bytes(q.pack(), "127.0.0.1")
    resp2 = srv.resolve_query_bytes(q.pack(), "127.0.0.1")

    assert DNSRecord.parse(resp1).header.rcode == RCODE.NXDOMAIN
    assert DNSRecord.parse(resp2).header.rcode == RCODE.NXDOMAIN
    # Only the first call should have reached the fake upstream.
    assert calls["n"] == 1


def test_resolve_query_bytes_caches_delegation_with_ns(monkeypatch):
    """Brief: resolve_query_bytes should cache referrals with NS in authority.

    Inputs:
      - Fake upstream that returns NOERROR with no answers but an NS RR in the
        authority section (delegation/referral).

    Outputs:
      - Two resolve_query_bytes() calls for the same question trigger exactly
        one send_query_with_failover() call and both responses are NOERROR.
    """

    q = DNSRecord.question("deleg-cache.example", "A")
    r = q.reply()  # NOERROR by default, no answers
    r.add_auth(
        RR(
            "deleg-cache.example",
            QTYPE.NS,
            rdata=NS("ns1.deleg-cache.example."),
            ttl=300,
        )
    )
    wire = r.pack()

    calls = {"n": 0}

    def fake_failover(
        req, upstreams, timeout_ms, qname, qtype, max_concurrent=None
    ):  # noqa: ANN001
        calls["n"] += 1
        return wire, upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", fake_failover)

    plugin_base.DNS_CACHE = InMemoryTTLCache()
    srv.DNSUDPHandler.upstream_addrs = [{"host": "2.2.2.2", "port": 53}]
    srv.DNSUDPHandler.plugins = []
    srv.DNSUDPHandler.min_cache_ttl = 5

    resp1 = srv.resolve_query_bytes(q.pack(), "127.0.0.1")
    resp2 = srv.resolve_query_bytes(q.pack(), "127.0.0.1")

    assert DNSRecord.parse(resp1).header.rcode == RCODE.NOERROR
    assert DNSRecord.parse(resp2).header.rcode == RCODE.NOERROR
    # Only the first call should have reached the fake upstream.
    assert calls["n"] == 1

    # The remainder of this file continues with dnssec validation tests.
    # Ensure clean slate for those tests.
    srv.DNSUDPHandler.plugins = []
    plugin_base.DNS_CACHE = InMemoryTTLCache()

    name = "dnssec.example"
    q = DNSRecord.question(name, "A")

    # Wire without AD bit
    r_noad = q.reply()
    r_noad.header.ad = 0
    wire_noad = r_noad.pack()

    # Wire with AD (not used for local path)
    r_ad = q.reply()
    r_ad.header.ad = 1
    wire_ok = r_ad.pack()

    def fake_forward_noad(self, request, upstreams, qname, qtype):
        return wire_noad, upstreams[0], "ok"

    def fake_forward_ok(self, request, upstreams, qname, qtype):
        return wire_ok, upstreams[0], "ok"

    # Case 1: validate with upstream_ad -> no AD -> treated as insecure but not SERVFAIL
    h1 = srv.DNSUDPHandler.__new__(srv.DNSUDPHandler)

    class _Sock:
        def __init__(self):
            self.sent = []

        def sendto(self, data, addr):
            self.sent.append((data, addr))

    sock1 = _Sock()
    h1.request = (q.pack(), sock1)
    h1.client_address = ("127.0.0.1", 1)
    h1.dnssec_mode = "validate"
    srv.DNSUDPHandler.upstream_addrs = [{"host": "8.8.8.8", "port": 53}]
    monkeypatch.setattr(
        srv.DNSUDPHandler, "_forward_with_failover_helper", fake_forward_noad
    )
    h1.handle()
    # Upstream path without AD should now be treated as insecure/unsigned,
    # not forced to SERVFAIL.
    assert DNSRecord.parse(sock1.sent[-1][0]).header.rcode == RCODE.NOERROR

    # Case 3: local validator raises -> treated as insecure (exercise exception path)
    h3 = srv.DNSUDPHandler.__new__(srv.DNSUDPHandler)
    sock3 = _Sock()
    h3.request = (q.pack(), sock3)
    h3.client_address = ("127.0.0.1", 3)
    h3.dnssec_mode = "validate"
    h3.dnssec_validation = "local"
    # Replace the stub with a raising one before handle() imports it
    import sys
    import types

    fake_mod2 = types.ModuleType("foghorn.dnssecfoghorn.dnssec.dnssec_validate")

    def _raise(*a, **k):
        raise RuntimeError("boom")

    fake_mod2.validate_response_local = _raise
    monkeypatch.setitem(
        sys.modules, "foghorn.dnssecfoghorn.dnssec.dnssec_validate", fake_mod2
    )
    monkeypatch.setattr(
        srv.DNSUDPHandler, "_forward_with_failover_helper", fake_forward_noad
    )
    h3.handle()
    # Local validator exceptions should no longer force SERVFAIL; the
    # response should flow through unchanged.
    assert DNSRecord.parse(sock3.sent[-1][0]).header.rcode == RCODE.NOERROR


def test_resolve_query_bytes_post_hooks(monkeypatch):
    """
    Brief: resolve_query_bytes honors post deny and post override decisions.

    Inputs:
      - Upstream stubbed to return NOERROR; plugins for deny/override.
    Outputs:
      - NXDOMAIN when denied; forced NXDOMAIN when overridden.
    """
    q = DNSRecord.question("hook.example", "A")
    r_ok = q.reply()

    def fake_forward(req, upstreams, timeout_ms, qname, qtype, max_concurrent=None):
        return r_ok.pack(), {"host": "1.1.1.1", "port": 53}, "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", fake_forward)
    plugin_base.DNS_CACHE = InMemoryTTLCache()
    srv.DNSUDPHandler.upstream_addrs = [{"host": "1.1.1.1", "port": 53}]

    class _PostDeny:
        post_priority = 1

        def pre_resolve(self, qname, qtype, data, ctx):
            return None

        def post_resolve(self, qname, qtype, data, ctx):
            return srv.PluginDecision(action="deny")

    srv.DNSUDPHandler.plugins = [_PostDeny()]
    out1 = srv.resolve_query_bytes(q.pack(), "127.0.0.1")
    assert DNSRecord.parse(out1).header.rcode == RCODE.NXDOMAIN

    class _PostOverride:
        post_priority = 1

        def pre_resolve(self, qname, qtype, data, ctx):
            return None

        def post_resolve(self, qname, qtype, data, ctx):
            rep = DNSRecord.parse(data)
            rep.header.rcode = RCODE.NXDOMAIN
            return srv.PluginDecision(action="override", response=rep.pack())

    srv.DNSUDPHandler.plugins = [_PostOverride()]
    out2 = srv.resolve_query_bytes(q.pack(), "127.0.0.1")
    assert DNSRecord.parse(out2).header.rcode == RCODE.NXDOMAIN
