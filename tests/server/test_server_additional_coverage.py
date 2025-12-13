"""
Brief: Additional targeted tests to raise coverage for foghorn.server.

Inputs:
  - None

Outputs:
  - None
"""

import pytest
from dnslib import QTYPE, RCODE, RR, A, DNSRecord

import foghorn.servers.server as srv
from foghorn.plugins import base as plugin_base
from foghorn.servers.server import DNSUDPHandler, send_query_with_failover


class _Sock:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))


def _mk_handler(query_wire: bytes, client_ip: str = "127.0.0.1"):
    h = DNSUDPHandler.__new__(DNSUDPHandler)
    sock = _Sock()
    h.request = (query_wire, sock)
    h.client_address = (client_ip, 55333)
    return h, sock


def _mk_ok_reply(q: DNSRecord, *, ad: int = 0) -> bytes:
    r = q.reply()
    r.header.ad = ad
    r.add_answer(RR(str(q.q.qname).rstrip("."), QTYPE.A, rdata=A("1.2.3.4"), ttl=60))
    return r.pack()


# ---- Stats collector coverage ----
class _Stats:
    def __init__(self):
        self.calls = []

    def record_query(self, *a):
        self.calls.append(("record_query", a))

    def record_cache_hit(self, *a):
        self.calls.append(("record_cache_hit", a))

    def record_cache_miss(self, *a):
        self.calls.append(("record_cache_miss", a))

    def record_cache_null(self, *a, **k):
        # Accept optional keyword arguments (e.g., status="deny_pre") to mirror
        # StatsCollector.record_cache_null while only tracking the call kind here.
        self.calls.append(("record_cache_null", a))

    def record_response_rcode(self, *a):
        self.calls.append(("record_response_rcode", a))

    def record_upstream_result(self, *a, **k):
        self.calls.append(("record_upstream_result", (a, k)))

    def record_upstream_rcode(self, *a, **k):
        self.calls.append(("record_upstream_rcode", (a, k)))

    def record_query_result(self, *a, **k):
        self.calls.append(("record_query_result", (a, k)))

    def record_latency(self, *a):
        self.calls.append(("record_latency", a))

    def record_dnssec_status(self, *a, **k):
        self.calls.append(("record_dnssec_status", (a, k)))


@pytest.mark.parametrize("path", ["cache_hit", "upstream_ok", "all_failed"])
def test_stats_hooks_are_called(monkeypatch, path):
    q = DNSRecord.question("stats.example", "A")
    data = q.pack()
    DNSUDPHandler.plugins = []
    DNSUDPHandler.upstream_addrs = [{"host": "h", "port": 53}]

    # Be explicit about cache isolation for this parametrized test.
    try:
        from foghorn.cache_plugins.in_memory_ttl import InMemoryTTLCachePlugin

        plugin_base.DNS_CACHE = InMemoryTTLCachePlugin()
    except Exception:  # pragma: no cover
        pass

    # ensure no pre plugins
    monkeypatch.setattr(DNSUDPHandler, "_apply_pre_plugins", lambda *a, **k: None)

    # cache priming when needed
    cache_key = ("stats.example", QTYPE.A)
    if path == "cache_hit":
        plugin_base.DNS_CACHE.set(cache_key, 30, _mk_ok_reply(q))

    # forwarding behavior
    if path == "upstream_ok":
        # Force the shared resolver path to succeed with an upstream reply.
        monkeypatch.setattr(
            srv,
            "send_query_with_failover",
            lambda request, upstreams, timeout_ms, qname, qtype, max_concurrent=1: (
                _mk_ok_reply(q),
                upstreams[0],
                "ok",
            ),
        )
    elif path == "all_failed":
        # Simulate all upstreams failing in the shared resolver path.
        monkeypatch.setattr(
            srv,
            "send_query_with_failover",
            lambda request, upstreams, timeout_ms, qname, qtype, max_concurrent=1: (
                None,
                None,
                "all_failed",
            ),
        )

    stats = _Stats()
    DNSUDPHandler.stats_collector = stats

    h, sock = _mk_handler(data)
    h.handle()

    # basic sanity: some stats were recorded including latency
    kinds = [k for k, _ in stats.calls]
    assert "record_query" in kinds
    assert "record_latency" in kinds
    if path == "cache_hit":
        assert "record_cache_hit" in kinds
    else:
        assert "record_cache_miss" in kinds
        assert "record_response_rcode" in kinds
    # cleanup
    DNSUDPHandler.stats_collector = None


# ---- EDNS ensure call path across modes ----
@pytest.mark.parametrize("mode", ["ignore", "passthrough", "validate"])
def test_ensure_edns_called_in_handle_without_crashing(mode, monkeypatch):
    # We don't assert on OPT content due to dnslib version differences; just ensure call path executes.
    q = DNSRecord.question("edns.example", "A")
    data = q.pack()
    DNSUDPHandler.plugins = []
    DNSUDPHandler.upstream_addrs = [
        {"host": "h", "port": 53}
    ]  # ensure EDNS path reached

    # count calls to _ensure_edns
    called = {"n": 0}

    def fake_ensure(self, req):
        called["n"] += 1
        return None

    monkeypatch.setattr(DNSUDPHandler, "_ensure_edns", fake_ensure)
    # avoid real forwarding
    monkeypatch.setattr(
        DNSUDPHandler,
        "_forward_with_failover_helper",
        lambda self, request, upstreams, qname, qtype: (None, None, "all_failed"),
    )

    h, sock = _mk_handler(data)
    h.dnssec_mode = mode
    h.handle()

    assert called["n"] == 1
    # response should be SERVFAIL due to no upstreams, but no exception from EDNS handling
    resp = DNSRecord.parse(sock.sent[-1][0])
    assert resp.header.rcode == RCODE.SERVFAIL


def test_handle_pre_deny_records_stats_and_query_result():
    """Brief: pre-resolve deny path records stats and NXDOMAIN.

    Inputs:
      - None

    Outputs:
      - None; asserts NXDOMAIN and key stats calls are present.
    """

    from foghorn.servers.server import PluginDecision

    class _PreDeny:
        def pre_resolve(self, qname, qtype, data, ctx):
            return PluginDecision(action="deny")

        def post_resolve(self, qname, qtype, data, ctx):  # pragma: no cover - not used
            return None

    q = DNSRecord.question("predeny-stats.example", "A")
    DNSUDPHandler.plugins = [_PreDeny()]
    DNSUDPHandler.upstream_addrs = [{"host": "8.8.8.8", "port": 53}]

    stats = _Stats()
    DNSUDPHandler.stats_collector = stats

    h, sock = _mk_handler(q.pack())
    h.handle()

    DNSUDPHandler.stats_collector = None

    wire = sock.sent[-1][0]
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NXDOMAIN

    kinds = [k for k, _ in stats.calls]
    assert "record_cache_null" in kinds
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds


def test_handle_pre_override_records_stats_and_query_result():
    """Brief: pre-resolve override path records stats and uses override reply.

    Inputs:
      - None

    Outputs:
      - None; asserts stats calls present for override path.
    """

    from foghorn.servers.server import PluginDecision

    class _PreOverride:
        def pre_resolve(self, qname, qtype, data, ctx):
            rep = DNSRecord.parse(data).reply()
            rep.header.rcode = RCODE.NXDOMAIN
            return PluginDecision(action="override", response=rep.pack())

        def post_resolve(self, qname, qtype, data, ctx):  # pragma: no cover - not used
            return None

    q = DNSRecord.question("preoverride-stats.example", "A")
    DNSUDPHandler.plugins = [_PreOverride()]
    DNSUDPHandler.upstream_addrs = [{"host": "8.8.8.8", "port": 53}]

    stats = _Stats()
    DNSUDPHandler.stats_collector = stats

    h, sock = _mk_handler(q.pack())
    h.handle()

    DNSUDPHandler.stats_collector = None

    wire = sock.sent[-1][0]
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NXDOMAIN

    kinds = [k for k, _ in stats.calls]
    assert "record_cache_null" in kinds
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds


def test_handle_no_upstreams_with_stats_records_query_result():
    """Brief: No upstreams with stats enabled records SERVFAIL and query result.

    Inputs:
      - None

    Outputs:
      - None; asserts stats hooks were invoked for no_upstreams path.
    """

    q = DNSRecord.question("no-upstreams-stats.example", "A")
    DNSUDPHandler.plugins = []
    DNSUDPHandler.upstream_addrs = []

    stats = _Stats()
    DNSUDPHandler.stats_collector = stats

    h, sock = _mk_handler(q.pack())
    h.handle()

    DNSUDPHandler.stats_collector = None

    wire = sock.sent[-1][0]
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL

    kinds = [k for k, _ in stats.calls]
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds


def test_handle_all_failed_with_stats_records_upstream_rcode(monkeypatch):
    """Brief: All-upstreams-failed path records upstream result and upstream rcode.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts upstream result and upstream rcode were recorded.
    """

    q = DNSRecord.question("allfailed-stats.example", "A")
    DNSUDPHandler.plugins = []
    DNSUDPHandler.upstream_addrs = [
        {"transport": "doh", "url": "https://resolver/dns-query"}
    ]

    # Simulate an all-failed DoH upstream where send_query_with_failover still
    # reports which upstream was attempted.
    monkeypatch.setattr(
        srv,
        "send_query_with_failover",
        lambda request, upstreams, timeout_ms, qname, qtype, max_concurrent=1: (
            None,
            {"url": "https://resolver/dns-query"},
            "all_failed",
        ),
    )

    stats = _Stats()
    DNSUDPHandler.stats_collector = stats

    h, sock = _mk_handler(q.pack())
    h.handle()

    DNSUDPHandler.stats_collector = None

    kinds = [k for k, _ in stats.calls]
    assert "record_upstream_result" in kinds
    assert "record_upstream_rcode" in kinds


# ---- DNSSEC validate branches ----
def test_dnssec_validate_upstream_ad_pass(monkeypatch):
    DNSUDPHandler.plugins = []
    DNSUDPHandler.upstream_addrs = [{"host": "8.8.8.8", "port": 53}]

    base_q = DNSRecord.question("ad.example", "A")
    ok = _mk_ok_reply(base_q, ad=1)

    monkeypatch.setattr(DNSUDPHandler, "_apply_pre_plugins", lambda *a, **k: None)

    # Force the shared resolver path (used by UDP and others) to return an AD=1
    # NOERROR reply so that validate+upstream_ad can classify it as secure.
    monkeypatch.setattr(
        srv,
        "send_query_with_failover",
        lambda req, ups, timeout_ms, qname, qtype, max_concurrent=1: (
            ok,
            ups[0],
            "ok",
        ),
    )

    # validate mode, upstream_ad at the handler class level (used by _resolve_core).
    DNSUDPHandler.dnssec_mode = "validate"
    DNSUDPHandler.dnssec_validation = "upstream_ad"

    h1, sock1 = _mk_handler(base_q.pack())
    h1.handle()
    r1 = DNSRecord.parse(sock1.sent[-1][0])
    assert r1.header.rcode == RCODE.NOERROR


def test_dnssec_validate_local_true(monkeypatch):
    DNSUDPHandler.plugins = []
    DNSUDPHandler.upstream_addrs = [{"host": "9.9.9.9", "port": 53}]
    monkeypatch.setattr(DNSUDPHandler, "_apply_pre_plugins", lambda *a, **k: None)

    q = DNSRecord.question("local.example", "A")
    ok = _mk_ok_reply(q)

    # Force the shared resolver path to return a successful upstream reply.
    monkeypatch.setattr(
        srv,
        "send_query_with_failover",
        lambda req, ups, timeout_ms, qname, qtype, max_concurrent=1: (
            ok,
            ups[0],
            "ok",
        ),
    )

    # Short-circuit local DNSSEC classification to "secure" without performing
    # real DNSSEC validation network fetches.
    import foghorn.dnssec_validate as dval

    monkeypatch.setattr(
        dval,
        "classify_dnssec_status",
        lambda *a, **k: "secure",
    )

    # validate mode, local validation at the handler class level.
    DNSUDPHandler.dnssec_mode = "validate"
    DNSUDPHandler.dnssec_validation = "local"

    h1, s1 = _mk_handler(q.pack())
    h1.handle()
    assert DNSRecord.parse(s1.sent[-1][0]).header.rcode == RCODE.NOERROR


def test_resolve_core_dnssec_upstream_ad_shared_helper(monkeypatch):
    """Brief: _resolve_core uses the shared DNSSEC helper for upstream_ad.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures dnssec_status is 'dnssec_secure' and stats hook is invoked.
    """

    DNSUDPHandler.plugins = []
    DNSUDPHandler.upstream_addrs = [{"host": "8.8.8.8", "port": 53}]

    q = DNSRecord.question("ad-core.example", "A")
    ok = _mk_ok_reply(q, ad=1)

    monkeypatch.setattr(
        srv,
        "send_query_with_failover",
        lambda req, ups, timeout_ms, qname, qtype, max_concurrent=1: (
            ok,
            {"host": "8.8.8.8", "port": 53},
            "ok",
        ),
    )

    DNSUDPHandler.dnssec_mode = "validate"
    DNSUDPHandler.dnssec_validation = "upstream_ad"
    DNSUDPHandler.edns_udp_payload = 1232

    stats = _Stats()
    DNSUDPHandler.stats_collector = stats

    result = srv._resolve_core(q.pack(), "127.0.0.1")

    DNSUDPHandler.stats_collector = None

    assert DNSRecord.parse(result.wire).header.rcode == RCODE.NOERROR
    assert result.dnssec_status == "dnssec_secure"

    kinds = [k for k, _ in stats.calls]
    assert "record_dnssec_status" in kinds


# ---- DoH branch in send_query_with_failover ----
def test_send_query_with_failover_doh_success(monkeypatch):
    q = DNSRecord.question("doh.example", "A")
    ok = _mk_ok_reply(q)

    # Patch doh_query to return body and headers
    import foghorn.transports.doh as doh_mod

    monkeypatch.setattr(doh_mod, "doh_query", lambda url, body, **kw: (ok, {"X": "Y"}))

    resp, used, reason = send_query_with_failover(
        q,
        upstreams=[
            {
                "transport": "doh",
                "url": "https://resolver/dns-query",
                "method": "POST",
                "headers": {"A": "B"},
                "tls": {"verify": True, "ca_file": None},
            }
        ],
        timeout_ms=500,
        qname="doh.example",
        qtype=QTYPE.A,
    )
    assert reason == "ok" and used["transport"] == "doh" and resp[:2] == ok[:2]


def test_send_query_with_failover_doh_missing_url(monkeypatch):
    q = DNSRecord.question("doh-missing.example", "A")
    resp, used, reason = send_query_with_failover(
        q,
        upstreams=[{"transport": "doh", "headers": {}}],
        timeout_ms=100,
        qname="x",
        qtype=QTYPE.A,
    )
    # No valid upstream succeeds -> all_failed
    assert resp is None and reason in {"all_failed", "timeout", "servfail"}


# ---- Pool limits error handling and send success ----
def test_send_query_with_failover_dot_tcp_pool_set_limits_error(monkeypatch):
    q = DNSRecord.question("pool.example", "A")
    ok = _mk_ok_reply(q)

    class _Pool:
        def set_limits(self, **kw):
            raise RuntimeError("boom")

        def send(self, data, *a, **k):
            return ok

    monkeypatch.setattr(srv, "get_dot_pool", lambda *a, **k: _Pool())
    monkeypatch.setattr(srv, "get_tcp_pool", lambda *a, **k: _Pool())

    # dot
    r1, u1, rs1 = send_query_with_failover(
        q,
        upstreams=[
            {
                "transport": "dot",
                "host": "h",
                "port": 853,
                "pool": {"idle_timeout_ms": 10},
            }
        ],
        timeout_ms=100,
        qname="x",
        qtype=QTYPE.A,
    )
    assert rs1 == "ok"

    # tcp
    r2, u2, rs2 = send_query_with_failover(
        q,
        upstreams=[
            {
                "transport": "tcp",
                "host": "h",
                "port": 53,
                "pool": {"idle_timeout_ms": 10},
            }
        ],
        timeout_ms=100,
        qname="x",
        qtype=QTYPE.A,
    )
    assert rs2 == "ok"


# ---- SERVFAIL then success fallback path (UDP) ----
def test_send_query_with_failover_servfail_then_ok_udp(monkeypatch):
    q = DNSRecord.question("sf.example", "A")
    # First upstream returns SERVFAIL; second returns OK
    r_servfail = q.reply()
    r_servfail.header.rcode = RCODE.SERVFAIL
    wire_servfail = r_servfail.pack()
    wire_ok = _mk_ok_reply(q)

    # Use udp_query patch to control responses by host
    import foghorn.transports.udp as udp_mod

    def fake_udp_query(host, port, payload, timeout_ms=None):
        return wire_servfail if host == "bad" else wire_ok

    monkeypatch.setattr(udp_mod, "udp_query", fake_udp_query)

    resp, used, reason = send_query_with_failover(
        q,
        upstreams=[
            {"transport": "udp", "host": "bad", "port": 53},
            {"transport": "udp", "host": "ok", "port": 53},
        ],
        timeout_ms=100,
        qname="sf.example",
        qtype=QTYPE.A,
    )
    assert reason == "ok" and used["host"] == "ok"
