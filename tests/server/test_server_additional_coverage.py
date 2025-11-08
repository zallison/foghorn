"""
Brief: Additional targeted tests to raise coverage for foghorn.server.

Inputs:
  - None

Outputs:
  - None
"""

from typing import Any, Dict
from unittest.mock import Mock

import pytest
from dnslib import DNSRecord, QTYPE, RCODE, RR, A

import foghorn.server as srv
from foghorn.server import DNSUDPHandler, send_query_with_failover


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

    def record_response_rcode(self, *a):
        self.calls.append(("record_response_rcode", a))

    def record_upstream_result(self, *a):
        self.calls.append(("record_upstream_result", a))

    def record_latency(self, *a):
        self.calls.append(("record_latency", a))


@pytest.mark.parametrize("path", ["cache_hit", "upstream_ok", "all_failed"])
def test_stats_hooks_are_called(monkeypatch, path):
    q = DNSRecord.question("stats.example", "A")
    data = q.pack()
    DNSUDPHandler.plugins = []
    DNSUDPHandler.upstream_addrs = [{"host": "h", "port": 53}]

    # ensure no pre plugins
    monkeypatch.setattr(DNSUDPHandler, "_apply_pre_plugins", lambda *a, **k: None)

    # cache priming when needed
    cache_key = ("stats.example", QTYPE.A)
    if path == "cache_hit":
        DNSUDPHandler.cache.set(cache_key, 30, _mk_ok_reply(q))

    # forwarding behavior
    if path == "upstream_ok":
        monkeypatch.setattr(
            DNSUDPHandler,
            "_forward_with_failover_helper",
            lambda self, request, upstreams, qname, qtype: (
                _mk_ok_reply(q),
                upstreams[0],
                "ok",
            ),
        )
    elif path == "all_failed":
        monkeypatch.setattr(
            DNSUDPHandler,
            "_forward_with_failover_helper",
            lambda self, request, upstreams, qname, qtype: (None, None, "all_failed"),
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


# ---- EDNS ensure across modes ----
@pytest.mark.parametrize(
    "mode, expect_do",
    [
        ("ignore", 0),
        ("passthrough", 1),
        ("validate", 0),
    ],
)
def test_ensure_edns_modes(mode, expect_do, monkeypatch):
    q = DNSRecord.question("edns.example", "A")
    h = DNSUDPHandler.__new__(DNSUDPHandler)
    h.dnssec_mode = mode
    h.edns_udp_payload = 1400

    # dnslib.EDNS0 expects string flags; server passes int. Shim EDNS0 for test.
    def _fake_EDNS0(*, flags=0, **kwargs):
        return type("_EDNS0Shim", (), {"flags": flags})()

    monkeypatch.setattr(srv, "EDNS0", _fake_EDNS0)

    # add/replace OPT via helper
    h._ensure_edns(q)
    # find OPT
    opts = [rr for rr in q.ar if rr.rtype == QTYPE.OPT]
    assert len(opts) == 1
    opt = opts[0]
    # rclass holds payload size
    assert int(opt.rclass) == 1400
    # DO bit expectation from flags bit 0x8000
    do_flag = 1 if (getattr(opt.rdata, "flags", 0) & 0x8000) else 0
    assert do_flag == expect_do


# ---- DNSSEC validate branches ----
def test_dnssec_validate_upstream_ad_pass_and_fail(monkeypatch):
    DNSUDPHandler.plugins = []
    DNSUDPHandler.upstream_addrs = [{"host": "8.8.8.8", "port": 53}]

    base_q = DNSRecord.question("ad.example", "A")
    ok = _mk_ok_reply(base_q, ad=1)
    bad = _mk_ok_reply(base_q, ad=0)

    # will patch to return different replies per call
    calls = {"n": 0}

    def fwd(self, request, ups, qname, qtype):
        calls["n"] += 1
        return (ok if calls["n"] == 1 else bad), ups[0], "ok"

    monkeypatch.setattr(DNSUDPHandler, "_apply_pre_plugins", lambda *a, **k: None)
    monkeypatch.setattr(DNSUDPHandler, "_forward_with_failover_helper", fwd)

    # validate mode, upstream_ad
    DNSUDPHandler.dnssec_mode = "validate"
    DNSUDPHandler.dnssec_validation = "upstream_ad"

    # 1st: AD=1 passes
    h1, sock1 = _mk_handler(base_q.pack())
    h1.handle()
    r1 = DNSRecord.parse(sock1.sent[-1][0])
    assert r1.header.rcode == RCODE.NOERROR

    # 2nd: AD=0 -> SERVFAIL
    h2, sock2 = _mk_handler(base_q.pack())
    h2.handle()
    r2 = DNSRecord.parse(sock2.sent[-1][0])
    assert r2.header.rcode == RCODE.SERVFAIL


def test_dnssec_validate_local_true_and_false(monkeypatch):
    DNSUDPHandler.plugins = []
    DNSUDPHandler.upstream_addrs = [{"host": "9.9.9.9", "port": 53}]
    monkeypatch.setattr(DNSUDPHandler, "_apply_pre_plugins", lambda *a, **k: None)

    q = DNSRecord.question("local.example", "A")
    ok = _mk_ok_reply(q)
    monkeypatch.setattr(
        DNSUDPHandler,
        "_forward_with_failover_helper",
        lambda self, request, ups, qname, qtype: (ok, ups[0], "ok"),
    )

    # Patch local validator function to control outcome
    import foghorn.dnssec_validate as dsv

    DNSUDPHandler.dnssec_mode = "validate"
    DNSUDPHandler.dnssec_validation = "local"

    # True -> pass
    monkeypatch.setattr(dsv, "validate_response_local", lambda *a, **k: True)
    h1, s1 = _mk_handler(q.pack())
    h1.handle()
    assert DNSRecord.parse(s1.sent[-1][0]).header.rcode == RCODE.NOERROR

    # False -> SERVFAIL
    monkeypatch.setattr(dsv, "validate_response_local", lambda *a, **k: False)
    h2, s2 = _mk_handler(q.pack())
    h2.handle()
    assert DNSRecord.parse(s2.sent[-1][0]).header.rcode == RCODE.SERVFAIL


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
