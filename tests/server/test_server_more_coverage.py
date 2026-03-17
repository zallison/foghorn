"""
Brief: Additional coverage for foghorn.servers.server.

Inputs:
  - None (pytest harness)

Outputs:
  - None (pytest assertions)
"""

from dnslib import NS, QTYPE, RCODE, RR, SOA, A, DNSRecord, EDNS0

import foghorn.servers.server as srv
from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache
from foghorn.plugins.resolve import base as plugin_base
from foghorn.servers.udp_server import DNSUDPHandler


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


def test_compute_negative_ttl_soa_minimum_zero_disables_negative_caching():
    """Brief: SOA minimum TTL=0 yields negative/referral TTL 0 (do not cache).

    Inputs:
      - DNSRecord with SOA in authority section, SOA times minimum=0.
      - fallback_ttl: nonzero.

    Outputs:
      - None; asserts _compute_negative_ttl returns 0.
    """

    q = DNSRecord.question("negttl.example", "A")
    r = q.reply()

    # Authority SOA TTL is nonzero, but SOA minimum field is explicitly 0.
    soa = SOA(
        "ns.negttl.example.",
        "hostmaster.negttl.example.",
        (1, 3600, 600, 86400, 0),
    )
    r.add_auth(RR("negttl.example", QTYPE.SOA, rdata=soa, ttl=300))

    assert srv._compute_negative_ttl(r, fallback_ttl=60) == 0


def test_attach_ede_option_does_not_mutate_request_opt_rr(monkeypatch):
    """Brief: Attaching EDE must not alias/mutate the request OPT RR.

    Inputs:
      - req: DNSRecord with an EDNS0 OPT RR.
      - resp: synthetic reply without OPT.

    Outputs:
      - None; asserts req OPT rdata is unchanged while resp gains EDE.
    """

    class _Snap:
        enable_ede = True

    monkeypatch.setattr("foghorn.runtime_config.get_runtime_snapshot", lambda: _Snap())

    req = DNSRecord.question("ede.example", "A")
    req.add_ar(EDNS0(udp_len=1232))
    req_opt = [rr for rr in (req.ar or []) if rr.rtype == QTYPE.OPT][0]

    # dnslib represents OPT options as a list stored on rdata.
    before = list(getattr(req_opt, "rdata", []) or [])

    resp = req.reply()
    # Ensure resp does not already carry an OPT.
    resp.ar = []

    srv._attach_ede_option(req, resp, 15, "blocked by policy")

    after = list(getattr(req_opt, "rdata", []) or [])
    assert after == before

    resp_opts = [rr for rr in (resp.ar or []) if rr.rtype == QTYPE.OPT]
    assert resp_opts
    resp_rdata = getattr(resp_opts[0], "rdata", None)
    assert isinstance(resp_rdata, list)
    assert any(getattr(opt, "code", None) == 15 for opt in resp_rdata)


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
      - Success from second; debug log emitted for parse failure.
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

    # send_query_with_failover de-dupes upstream skip warnings across the process,
    # so ensure this test is deterministic regardless of test order.
    upstream_key = srv._upstream_key_for_skip_warning(
        upstreams[0], "1.1.1.1", 53, "udp"
    )
    srv._reset_upstream_skip_warning(upstream_key)

    with caplog.at_level("DEBUG"):
        resp, used, reason = srv.send_query_with_failover(
            q, upstreams, 300, "example.com", QTYPE.A
        )
    assert reason == "ok" and used["host"] == "1.0.0.1"
    assert any(
        "failed to parse response" in rec.message.lower() for rec in caplog.records
    )


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
    h = DNSUDPHandler.__new__(DNSUDPHandler)

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


def test_handle_pre_deny_sends_nxdomain_and_returns(monkeypatch, set_runtime_snapshot):
    """
    Brief: pre plugin deny should short-circuit with NXDOMAIN.

    Inputs:
      - Plugin that denies in pre_resolve.
    Outputs:
      - Single send of NXDOMAIN response.
    """
    q = DNSRecord.question("predeny.example", "A")
    h = DNSUDPHandler.__new__(DNSUDPHandler)

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

    set_runtime_snapshot(
        plugins=[_PreDeny()],
        upstream_addrs=[{"host": "8.8.8.8", "port": 53}],
        resolver_mode="forward",
        forward_local=False,
    )

    h.handle()
    assert len(sock.sent) == 1
    assert DNSRecord.parse(sock.sent[0][0]).header.rcode == RCODE.NXDOMAIN


def test_resolve_query_bytes_negative_caches_nxdomain_with_soa(
    monkeypatch, set_runtime_snapshot
):
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
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):  # noqa: ANN001
        calls["n"] += 1
        return wire, upstreams[0], "ok"

    # Ensure clean state before applying monkeypatch
    plugin_base.DNS_CACHE = InMemoryTTLCache()
    # Reset any runtime health state that might affect this test
    try:
        from foghorn.servers.dns_runtime_state import DNSRuntimeState

        for key in list(DNSRuntimeState.upstream_health.keys()):
            DNSRuntimeState.upstream_health[key] = {}  # noqa: SLF001
    except Exception:
        pass
    DNSRuntimeState.upstream_probe_percent = None  # noqa: SLF001
    DNSRuntimeState._upstream_rr_index = 0  # noqa: SLF001

    monkeypatch.setattr(srv, "send_query_with_failover", fake_failover)

    set_runtime_snapshot(
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        plugins=[],
        min_cache_ttl=5,
        resolver_mode="forward",
        forward_local=False,
    )

    resp1 = srv.resolve_query_bytes(q.pack(), "127.0.0.1")
    resp2 = srv.resolve_query_bytes(q.pack(), "127.0.0.1")

    assert DNSRecord.parse(resp1).header.rcode == RCODE.NXDOMAIN
    assert DNSRecord.parse(resp2).header.rcode == RCODE.NXDOMAIN
    # Only the first call should have reached the fake upstream.
    assert calls["n"] == 1


def test_resolve_query_bytes_caches_delegation_with_ns(
    monkeypatch, set_runtime_snapshot
):
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
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):  # noqa: ANN001
        calls["n"] += 1
        return wire, upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", fake_failover)

    plugin_base.DNS_CACHE = InMemoryTTLCache()
    set_runtime_snapshot(
        upstream_addrs=[{"host": "2.2.2.2", "port": 53}],
        plugins=[],
        min_cache_ttl=5,
        resolver_mode="forward",
        forward_local=False,
    )

    resp1 = srv.resolve_query_bytes(q.pack(), "127.0.0.1")
    resp2 = srv.resolve_query_bytes(q.pack(), "127.0.0.1")

    assert DNSRecord.parse(resp1).header.rcode == RCODE.NOERROR
    assert DNSRecord.parse(resp2).header.rcode == RCODE.NOERROR
    # Only the first call should have reached the fake upstream.
    assert calls["n"] == 1


def test_resolve_query_bytes_post_hooks(monkeypatch, set_runtime_snapshot):
    """
    Brief: resolve_query_bytes honors post deny and post override decisions.

    Inputs:
      - Upstream stubbed to return NOERROR; plugins for deny/override.
    Outputs:
      - NXDOMAIN when denied; forced NXDOMAIN when overridden.
    """
    q = DNSRecord.question("hook.example", "A")
    r_ok = q.reply()

    def fake_forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        return r_ok.pack(), {"host": "1.1.1.1", "port": 53}, "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", fake_forward)
    plugin_base.DNS_CACHE = InMemoryTTLCache()
    set_runtime_snapshot(
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        plugins=[],
        resolver_mode="forward",
        forward_local=False,
    )

    class _PostDeny:
        post_priority = 1

        def pre_resolve(self, qname, qtype, data, ctx):
            return None

        def post_resolve(self, qname, qtype, data, ctx):
            return srv.PluginDecision(action="deny")

    set_runtime_snapshot(
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        plugins=[_PostDeny()],
        resolver_mode="forward",
        forward_local=False,
    )
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

    plugin_base.DNS_CACHE = InMemoryTTLCache()
    set_runtime_snapshot(
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        plugins=[_PostOverride()],
        resolver_mode="forward",
        forward_local=False,
    )
    out2 = srv.resolve_query_bytes(q.pack(), "127.0.0.1")
    assert DNSRecord.parse(out2).header.rcode == RCODE.NXDOMAIN
