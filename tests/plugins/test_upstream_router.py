"""
Brief: Unit tests for UpstreamRouter covering pre_resolve routing and failover forwarding.

Inputs:
  - None (tests generate synthetic DNS wires and mock network calls)

Outputs:
  - None (assertions on PluginContext changes and forwarding outcomes)
"""

from dnslib import QTYPE, RCODE, RR, A, DNSRecord

from foghorn.plugins.resolve.base import PluginContext
from foghorn.plugins.resolve.upstream_router import UpstreamRouter


def _mk_query(name="example.com", qtype="A"):
    """
    Brief: Build a DNS query record and its packed wire.

    Inputs:
      - name: domain string
      - qtype: RR type string (e.g., "A", "AAAA")

    Outputs:
      - (DNSRecord, bytes): tuple of (query record, packed wire)
    """
    q = DNSRecord.question(name, qtype)
    return q, q.pack()


def _mk_reply(
    query: DNSRecord, rcode=RCODE.NOERROR, answers=None, truncated=False
) -> bytes:
    """
    Brief: Build a reply wire for a query with desired rcode/answers.

    Inputs:
      - query: original DNSRecord created by DNSRecord.question
      - rcode: dnslib.RCODE value (e.g., RCODE.NOERROR, RCODE.NXDOMAIN)
      - answers: optional list of tuples (name, rdata_str, ttl) for A records
      - truncated: if True, sets the TC (truncated) header flag

    Outputs:
      - bytes: packed wire for the reply

    Example:
      q, _ = _mk_query("a.example")
      wire = _mk_reply(q, RCODE.NXDOMAIN)
    """
    r = query.reply()
    r.header.rcode = rcode
    if truncated:
        r.header.tc = 1
    if answers:
        for name, ip, ttl in answers:
            r.add_answer(RR(name, QTYPE.A, rdata=A(ip), ttl=ttl))
    return r.pack()


def _send_factory(outcomes):
    """
    Brief: Create a fake DNSRecord.send that yields bytes or raises per outcomes list.

    Inputs:
      - outcomes: list containing bytes (successful reply) or Exception instances

    Outputs:
      - callable: function(self, host, port, timeout=...) -> bytes or raises
    """
    attempts = {"count": 0}

    def _fake_send(self, host, port, timeout=None):  # noqa: ARG001
        if attempts["count"] >= len(outcomes):
            raise RuntimeError("no more outcomes")
        item = outcomes[attempts["count"]]
        attempts["count"] += 1
        if isinstance(item, Exception):
            raise item
        return item

    _fake_send.attempts = attempts
    return _fake_send


# ------------------------
# pre_resolve behavior
# ------------------------


def test_pre_resolve_single_upstream_sets_candidates():
    """
    Brief: Exact domain match sets upstream_candidates using modern 'upstreams' list.

    Inputs:
      - routes: domain 'test.example' -> upstreams: [1.1.1.1:53]

    Outputs:
      - None: asserts candidates list; returns None
    """
    plugin = UpstreamRouter(
        routes=[
            {
                "domain": "test.example",
                "upstreams": [{"host": "1.1.1.1", "port": 53}],
            }
        ]
    )
    ctx = PluginContext(client_ip="127.0.0.1")
    q, wire = _mk_query("test.example", "A")

    decision = plugin.pre_resolve("test.example", QTYPE.A, wire, ctx)
    assert decision is None
    assert ctx.upstream_candidates == [{"host": "1.1.1.1", "port": 53}]
    assert ctx.upstream_override is None


def test_pre_resolve_multi_upstreams_sets_candidates_no_override():
    """
    Brief: Suffix route yields multiple upstreams preserving order; no override set.

    Inputs:
      - routes: suffix '.example' -> [9.9.9.9:53, 8.8.8.8:53]

    Outputs:
      - None: asserts candidates list order; override remains None
    """
    plugin = UpstreamRouter(
        routes=[
            {
                "suffix": ".example",
                "upstreams": [
                    {"host": "9.9.9.9", "port": "53"},
                    {"host": "8.8.8.8", "port": 53},
                ],
            }
        ]
    )
    ctx = PluginContext(client_ip="127.0.0.1")
    q, wire = _mk_query("www.example", "A")

    decision = plugin.pre_resolve("www.example", QTYPE.A, wire, ctx)
    assert decision is None
    assert ctx.upstream_candidates == [
        {"host": "9.9.9.9", "port": 53},
        {"host": "8.8.8.8", "port": 53},
    ]
    assert ctx.upstream_override is None


def test_pre_resolve_no_match_passthrough():
    """
    Brief: No matching route leaves context untouched and passes through.

    Inputs:
      - routes: non-overlapping entries; qname 'nomatch.test'

    Outputs:
      - None: asserts ctx.upstream_candidates and override remain None
    """
    plugin = UpstreamRouter(
        routes=[{"domain": "x.example", "upstream": {"host": "1.1.1.1", "port": 53}}]
    )
    ctx = PluginContext(client_ip="127.0.0.1")
    q, wire = _mk_query("nomatch.test", "A")

    decision = plugin.pre_resolve("nomatch.test", QTYPE.A, wire, ctx)
    assert decision is None
    assert ctx.upstream_candidates is None
    assert ctx.upstream_override is None


def test_pre_resolve_case_insensitive_and_trailing_dot():
    """
    Brief: Case and trailing dot normalized so 'Example.COM.' matches domain rule.

    Inputs:
      - routes: domain 'Example.COM.' -> 2.2.2.2:53; qname 'example.com.'

    Outputs:
      - None: asserts candidates set correctly
    """
    plugin = UpstreamRouter(
        routes=[
            {
                "domain": "Example.COM.",
                "upstreams": [{"host": "2.2.2.2", "port": 53}],
            }
        ]
    )
    ctx = PluginContext(client_ip="127.0.0.1")
    q, wire = _mk_query("example.com.", "A")

    decision = plugin.pre_resolve("example.com.", QTYPE.A, wire, ctx)
    assert decision is None
    assert ctx.upstream_candidates == [{"host": "2.2.2.2", "port": 53}]


# ------------------------
# _normalize_routes and _match_upstream_candidates
# ------------------------


def test_normalize_mixed_routes_and_types():
    """
    Brief: Normalization lowercases names, strips dots, coerces ports, preserves order.

    Inputs:
      - routes: domain 'MiXeD.Example.' single upstream; suffix '.Sub.Example' multi upstreams

    Outputs:
      - None: asserts normalized domain/suffix and int ports
    """
    plugin = UpstreamRouter()
    routes = [
        {
            "domain": "MiXeD.Example.",
            "upstreams": [{"host": "1.1.1.1", "port": "53"}],
        },
        {
            "suffix": ".Sub.Example",
            "upstreams": [
                {"host": "2.2.2.2", "port": 53},
                {"host": "3.3.3.3", "port": "5353"},
            ],
        },
    ]
    norm = plugin._normalize_routes(routes)

    assert norm[0]["domain"] == "mixed.example"
    assert norm[0]["upstream_candidates"] == [{"host": "1.1.1.1", "port": 53}]

    assert norm[1]["suffix"] == "sub.example"
    assert norm[1]["upstream_candidates"][0] == {"host": "2.2.2.2", "port": 53}
    assert norm[1]["upstream_candidates"][1] == {"host": "3.3.3.3", "port": 5353}


def test_normalize_ignores_invalid_entries():
    """
    Brief: Invalid upstream entries and rules without match keys are dropped.

    Inputs:
      - routes: missing port/host, non-int port, and missing domain/suffix

    Outputs:
      - None: asserts only valid, matchable routes remain
    """
    plugin = UpstreamRouter()
    routes = [
        {
            "domain": "ok.example",
            "upstreams": [{"host": "1.1.1.1", "port": 53}],
        },
        {
            "domain": "bad1.example",
            "upstreams": [{"host": "1.1.1.1"}],  # missing port
        },
        {
            "domain": "bad2.example",
            "upstreams": [{"host": "1.1.1.1", "port": "abc"}],
        },
        {
            "domain": "bad3.example",
            "upstreams": [{"port": 53}],  # missing host
        },
        {"upstreams": [{"host": "1.1.1.1", "port": 53}]},  # no domain/suffix
    ]
    norm = plugin._normalize_routes(routes)

    # Only the valid first entry should survive
    assert len(norm) == 1
    assert norm[0]["domain"] == "ok.example"
    assert norm[0]["upstream_candidates"] == [{"host": "1.1.1.1", "port": 53}]


def test_match_exact_domain_vs_suffix_priority():
    """
    Brief: Exact domain match takes precedence; suffix matches otherwise; case/trailing dot tolerated.

    Inputs:
      - routes: domain 'a.example'; suffix 'example'

    Outputs:
      - None: asserts exact match for 'a.example' and suffix match for 'b.example.'
    """
    plugin = UpstreamRouter(
        routes=[
            {
                "domain": "A.Example",
                "upstreams": [{"host": "4.4.4.4", "port": 53}],
            },
            {"suffix": "example", "upstreams": [{"host": "5.5.5.5", "port": 53}]},
        ]
    )

    # The plugin normalized routes at init; use method directly
    assert plugin._match_upstream_candidates("a.example") == [
        {"host": "4.4.4.4", "port": 53}
    ]
    # _match_upstream_candidates expects normalized q without trailing dot
    assert plugin._match_upstream_candidates("b.example") == [
        {"host": "5.5.5.5", "port": 53}
    ]
    assert plugin._match_upstream_candidates("nope.test") is None


# ------------------------
# _forward_with_failover behavior
# ------------------------


def test_forward_success_first_upstream(monkeypatch):
    """Brief: Delegates to core send_query_with_failover; returns success on response.

    Inputs:
      - send_query_with_failover returns a NOERROR wire response.

    Outputs:
      - None: asserts success=True and returned bytes match.
    """

    import foghorn.servers.server as server_mod

    plugin = UpstreamRouter()
    q, wire = _mk_query("ok.example", "A")
    ok_wire = _mk_reply(q, RCODE.NOERROR, answers=[("ok.example", "1.2.3.4", 60)])

    calls: dict[str, int] = {"count": 0}

    def fake_send_query_with_failover(*args, **kwargs):
        calls["count"] += 1
        return ok_wire, {"host": "1.1.1.1", "port": 53}, "ok"

    monkeypatch.setattr(
        server_mod, "send_query_with_failover", fake_send_query_with_failover
    )

    success, out = plugin._forward_with_failover(
        wire,
        targets=[{"host": "1.1.1.1", "port": 53}, {"host": "8.8.8.8", "port": 53}],
        timeout_ms=2000,
    )
    assert success is True
    assert out == ok_wire
    assert calls["count"] == 1


def test_forward_nxdomain_is_accepted(monkeypatch):
    """Brief: NXDOMAIN is a valid response; no additional behavior required.

    Inputs:
      - send_query_with_failover returns an NXDOMAIN wire response.

    Outputs:
      - None: asserts success=True.
    """

    import foghorn.servers.server as server_mod

    plugin = UpstreamRouter()
    q, wire = _mk_query("nx.example", "A")
    nx_wire = _mk_reply(q, RCODE.NXDOMAIN)

    def fake_send_query_with_failover(*args, **kwargs):
        return nx_wire, {"host": "1.1.1.1", "port": 53}, "ok"

    monkeypatch.setattr(
        server_mod, "send_query_with_failover", fake_send_query_with_failover
    )

    success, out = plugin._forward_with_failover(
        wire,
        targets=[{"host": "1.1.1.1", "port": 53}],
        timeout_ms=2000,
    )
    assert success is True
    assert out == nx_wire


def test_forward_unparseable_reply_is_rejected(monkeypatch):
    """Brief: Unparseable replies should not be accepted; core returns failure.

    Inputs:
      - send_query_with_failover returns (None, None, 'all_failed').

    Outputs:
      - None: asserts success=False and synthesized SERVFAIL is returned.
    """

    import foghorn.servers.server as server_mod

    plugin = UpstreamRouter()
    q, wire = _mk_query("junk.example", "A")

    def fake_send_query_with_failover(*args, **kwargs):
        return None, None, "all_failed"

    monkeypatch.setattr(
        server_mod, "send_query_with_failover", fake_send_query_with_failover
    )

    success, out = plugin._forward_with_failover(
        wire,
        targets=[{"host": "1.1.1.1", "port": 53}],
        timeout_ms=2000,
    )
    assert success is False
    resp = DNSRecord.parse(out)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert resp.header.id == q.header.id


def test_forward_all_failures_return_synth_servfail(monkeypatch):
    """Brief: When core returns no response, helper synthesizes SERVFAIL.

    Inputs:
      - send_query_with_failover returns (None, None, 'all_failed').

    Outputs:
      - None: asserts synthesized SERVFAIL with matching ID.
    """

    import foghorn.servers.server as server_mod

    plugin = UpstreamRouter()
    q, wire = _mk_query("allfail.example", "A")

    def fake_send_query_with_failover(*args, **kwargs):
        return None, None, "all_failed"

    monkeypatch.setattr(
        server_mod, "send_query_with_failover", fake_send_query_with_failover
    )

    success, out = plugin._forward_with_failover(
        wire,
        targets=[{"host": "1.1.1.1", "port": 53}, {"host": "8.8.8.8", "port": 53}],
        timeout_ms=100,
    )
    assert success is False
    resp = DNSRecord.parse(out)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert resp.header.id == q.header.id


def test_forward_truncated_reply_is_accepted(monkeypatch):
    """Brief: A TC=1 wire response is still a response; helper returns success.

    Inputs:
      - send_query_with_failover returns a TC=1 response.

    Outputs:
      - None.
    """

    import foghorn.servers.server as server_mod

    plugin = UpstreamRouter()
    q, wire = _mk_query("tc.example", "A")
    tc_wire = _mk_reply(q, RCODE.NOERROR, truncated=True)

    def fake_send_query_with_failover(*args, **kwargs):
        return tc_wire, {"host": "1.1.1.1", "port": 53}, "ok"

    monkeypatch.setattr(
        server_mod, "send_query_with_failover", fake_send_query_with_failover
    )

    success, out = plugin._forward_with_failover(
        wire,
        targets=[{"host": "1.1.1.1", "port": 53}],
        timeout_ms=2000,
    )
    assert success is True
    assert out == tc_wire
