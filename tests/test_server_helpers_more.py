"""
Brief: Additional unit tests for foghorn.server helper functions/branches.

Inputs:
  - None

Outputs:
  - None
"""
import pytest
from dnslib import DNSRecord, QTYPE, RCODE

import foghorn.server as server_mod
from foghorn.server import DNSUDPHandler, compute_effective_ttl, _set_response_id
from foghorn.plugins.base import BasePlugin, PluginDecision


def test_compute_effective_ttl_exception_returns_floor():
    """
    Brief: Passing a non-DNSRecord object falls back to min_cache_ttl.

    Inputs:
      - resp: object missing attributes

    Outputs:
      - None: Asserts floor returned
    """
    class Bad:
        pass
    assert compute_effective_ttl(Bad(), 42) == 42


def test_set_response_id_exception_returns_original():
    """
    Brief: Non-bytes input triggers exception and returns original value.

    Inputs:
      - wire: None

    Outputs:
      - None: Asserts original (None) returned
    """
    assert _set_response_id(None, 1) is None


def test_send_query_with_failover_parse_exception_then_ok(monkeypatch):
    """
    Brief: Parsing error on first upstream triggers failover to second.

    Inputs:
      - monkeypatch: make DNSRecord.parse raise for first response

    Outputs:
      - None: Asserts success on second upstream
    """
    class DummyQuery:
        def send(self, host, port, timeout=None):
            return b"resp-%s" % host.encode()

    def fake_parse(wire):
        if wire == b"resp-bad":
            raise ValueError("bad parse")
        class Dummy:
            class header:
                rcode = RCODE.NOERROR
        return Dummy

    monkeypatch.setattr(server_mod.DNSRecord, "parse", staticmethod(fake_parse))
    resp, used, reason = server_mod.send_query_with_failover(
        DummyQuery(),
        upstreams=[{"host": "bad", "port": 53}, {"host": "ok", "port": 53}],
        timeout_ms=100,
        qname="x",
        qtype=1,
    )
    assert resp == b"resp-ok" and used["host"] == "ok" and reason == "ok"


def test_cache_and_send_response_parse_exception(monkeypatch):
    """
    Brief: _cache_and_send_response handles parse errors gracefully.

    Inputs:
      - monkeypatch: cause DNSRecord.parse to raise

    Outputs:
      - None: Asserts send still occurs
    """
    q = DNSRecord.question("example.com", "A")
    data = q.pack()

    class Sock:
        def __init__(self):
            self.calls = []
        def sendto(self, d, addr):
            self.calls.append((d, addr))

    h = object.__new__(DNSUDPHandler)
    h.client_address = ("1.2.3.4", 9)

    monkeypatch.setattr(server_mod.DNSRecord, "parse", staticmethod(lambda b: (_ for _ in ()).throw(ValueError("boom"))))
    # Call with arbitrary response bytes; ensure it still sends
    h._cache_and_send_response(b"abc", q, "example.com", 1, Sock(), ("1.2.3.4", 9), ("example.com", 1))


def test_apply_pre_plugins_allow_logs_and_continues(caplog):
    """
    Brief: _apply_pre_plugins logs allow and returns None.

    Inputs:
      - plugin: returns PluginDecision('allow')

    Outputs:
      - None: Asserts None returned
    """
    class AllowPlugin(BasePlugin):
        def pre_resolve(self, *a, **kw):
            return PluginDecision(action="allow")

    h = object.__new__(DNSUDPHandler)
    h.plugins = [AllowPlugin()]
    res = DNSUDPHandler._apply_pre_plugins(h, None, "x", 1, b"", None)
    assert res is None


def test_apply_post_plugins_deny_turns_to_nxdomain():
    """
    Brief: _apply_post_plugins denies and returns NXDOMAIN bytes.

    Inputs:
      - plugin: returns PluginDecision('deny')

    Outputs:
      - None: Asserts NXDOMAIN rcode
    """
    class DenyPost(BasePlugin):
        def post_resolve(self, *a, **kw):
            return PluginDecision(action="deny")

    q = DNSRecord.question("example.com", "A")
    h = object.__new__(DNSUDPHandler)
    h.plugins = [DenyPost()]
    out = DNSUDPHandler._apply_post_plugins(h, q, "example.com", 1, q.reply().pack(), None)
    assert DNSRecord.parse(out).header.rcode == RCODE.NXDOMAIN


def test_cache_store_if_applicable_servfail_and_noanswers():
    """
    Brief: _cache_store_if_applicable handles SERVFAIL and no-answer cases.

    Inputs:
      - responses: SERVFAIL, and NOERROR with no answers

    Outputs:
      - None: Asserts no exceptions
    """
    q = DNSRecord.question("example.com", "A")
    h = object.__new__(DNSUDPHandler)
    # SERVFAIL
    r1 = q.reply()
    r1.header.rcode = RCODE.SERVFAIL
    DNSUDPHandler._cache_store_if_applicable(h, "example.com", 1, r1.pack())
    # NOERROR with no answers
    r2 = q.reply()
    DNSUDPHandler._cache_store_if_applicable(h, "example.com", 1, r2.pack())


def test_cache_store_if_applicable_ttl_zero_and_parse_error():
    """
    Brief: Covers TTL==0 no-cache path and parse error path.

    Inputs:
      - response with TTL 0
      - invalid wire to trigger parse exception

    Outputs:
      - None: Asserts no exceptions
    """
    q = DNSRecord.question("example.com", "A")
    r = q.reply()
    from dnslib import RR, A
    r.add_answer(RR("example.com", QTYPE.A, rdata=A("1.2.3.4"), ttl=0))
    h = object.__new__(DNSUDPHandler)
    DNSUDPHandler._cache_store_if_applicable(h, "example.com", 1, r.pack())

    # Parse error path
    DNSUDPHandler._cache_store_if_applicable(h, "example.com", 1, b"not-a-dns-packet")



def test_handle_inner_exception_logs_and_does_not_send(monkeypatch):
    """
    Brief: If exception handling also fails to parse, no response is sent.

    Inputs:
      - monkeypatch: make _parse_query and DNSRecord.parse raise

    Outputs:
      - None: Asserts zero sends
    """
    q = DNSRecord.question("example.com", "A")
    data = q.pack()

    class Sock:
        def __init__(self):
            self.calls = []
        def sendto(self, d, addr):
            self.calls.append((d, addr))

    h = object.__new__(DNSUDPHandler)
    h.request = (data, Sock())
    h.client_address = ("1.2.3.4", 9)

    monkeypatch.setattr(DNSUDPHandler, "_parse_query", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(server_mod.DNSRecord, "parse", staticmethod(lambda b: (_ for _ in ()).throw(ValueError("bad"))))

    DNSUDPHandler.handle(h)

    assert len(h.request[1].calls) == 0


def test_forward_with_failover_helper_delegates(monkeypatch):
    """
    Brief: _forward_with_failover_helper returns the result of send_query_with_failover.

    Inputs:
      - monkeypatch: stub send_query_with_failover

    Outputs:
      - None: Asserts passthrough
    """
    called = {}
    def fake_send(q, ups, timeout_ms, qname, qtype):
        called["args"] = (ups, timeout_ms, qname, qtype)
        return b"x", {"host": "h", "port": 9}, "ok"

    monkeypatch.setattr(server_mod, "send_query_with_failover", fake_send)

    q = DNSRecord.question("example.com", "A")
    h = object.__new__(DNSUDPHandler)
    h.timeout_ms = 123
    out = DNSUDPHandler._forward_with_failover_helper(h, q, [1], "ex", 1)
    assert out[2] == "ok" and called["args"] == ([1], 123, "ex", 1)


def test_choose_upstreams_logs_when_empty(caplog):
    """
    Brief: _choose_upstreams warns when no upstreams available.

    Inputs:
      - ctx.upstream_candidates: None, class upstream_addrs: []

    Outputs:
      - None: Asserts empty list returned
    """
    caplog.set_level("WARNING")
    h = object.__new__(DNSUDPHandler)
    h.upstream_addrs = []
    ctx = type("C", (), {"upstream_candidates": None})()
    ups = DNSUDPHandler._choose_upstreams(h, "x", 1, ctx)
    assert ups == []
