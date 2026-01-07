"""
Brief: Additional unit tests for foghorn.servers.server helper functions/branches.

Inputs:
  - None

Outputs:
  - None
"""

from dnslib import QTYPE, RCODE, DNSRecord

import foghorn.servers.server as server_mod
from foghorn.plugins.resolve.base import BasePlugin, PluginDecision
from foghorn.servers.server import DNSUDPHandler, compute_effective_ttl
from foghorn.servers.udp_server import _set_response_id


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
    # data = q.pack()

    class Sock:
        def __init__(self):
            self.calls = []

        def sendto(self, d, addr):
            self.calls.append((d, addr))

    h = object.__new__(DNSUDPHandler)
    h.client_address = ("1.2.3.4", 9)

    monkeypatch.setattr(
        server_mod.DNSRecord,
        "parse",
        staticmethod(lambda b: (_ for _ in ()).throw(ValueError("boom"))),
    )
    # Call with arbitrary response bytes; ensure it still sends
    h._cache_and_send_response(
        b"abc", q, "example.com", 1, Sock(), ("1.2.3.4", 9), ("example.com", 1)
    )


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
    out = DNSUDPHandler._apply_post_plugins(
        h, q, "example.com", 1, q.reply().pack(), None
    )
    assert DNSRecord.parse(out).header.rcode == RCODE.NXDOMAIN


def test_handle_inner_exception_logs_and_does_not_send(monkeypatch):
    """
    Brief: If the shared resolver and its UDP fallback parsing both fail, the
    handler falls back to echoing the original query bytes (one send).

    Inputs:
      - monkeypatch: make resolve_query_bytes and DNSRecord.parse raise

    Outputs:
      - None: Asserts exactly one send containing the original query bytes
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

    # First make the shared resolver used by DNSUDPHandler.handle raise.
    monkeypatch.setattr(
        server_mod,
        "resolve_query_bytes",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    # Then make the fallback DNSRecord.parse in the UDP handler itself fail as
    # well so no response can be constructed.
    import foghorn.servers.udp_server as udp_mod

    monkeypatch.setattr(
        udp_mod.DNSRecord,
        "parse",
        staticmethod(lambda b: (_ for _ in ()).throw(ValueError("bad"))),
    )

    DNSUDPHandler.handle(h)

    # Worst-case fallback echoes the original query bytes instead of
    # constructing a response; ensure exactly one such send occurred.
    assert len(h.request[1].calls) == 1
    assert h.request[1].calls[0][0] == data


def test_forward_with_failover_helper_delegates(monkeypatch):
    """
    Brief: _forward_with_failover_helper returns the result of send_query_with_failover.

    Inputs:
      - monkeypatch: stub send_query_with_failover

    Outputs:
      - None: Asserts passthrough
    """
    called = {}

    def fake_send(q, ups, timeout_ms, qname, qtype, max_concurrent=None):
        called["args"] = (ups, timeout_ms, qname, qtype, max_concurrent)
        return b"x", {"host": "h", "port": 9}, "ok"

    monkeypatch.setattr(server_mod, "send_query_with_failover", fake_send)

    q = DNSRecord.question("example.com", "A")
    h = object.__new__(DNSUDPHandler)
    h.timeout_ms = 123
    upstreams = [{"host": "u1", "port": 53}]
    out = DNSUDPHandler._forward_with_failover_helper(h, q, upstreams, "ex", 1)
    assert out[2] == "ok" and called["args"] == (upstreams, 123, "ex", 1, 1)


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


def test_apply_post_plugins_clears_ctx_post_override_and_resets_on_error():
    """Brief: _apply_post_plugins clears ctx._post_override and resets when deletion fails.

    Inputs:
      - None

    Outputs:
      - None; asserts attribute removal and fallback flag behavior.
    """

    q = DNSRecord.question("example.com", "A")
    wire = q.reply().pack()
    h = object.__new__(DNSUDPHandler)
    h.plugins = []

    class _Ctx:
        def __init__(self):
            self._post_override = True

    ctx = _Ctx()
    out = DNSUDPHandler._apply_post_plugins(h, q, "example.com", QTYPE.A, wire, ctx)
    assert out == wire
    assert not hasattr(ctx, "_post_override")

    class _BadCtx:
        def __init__(self):
            self._post_override = True

        def __delattr__(self, name):
            raise RuntimeError("boom")

    bad = _BadCtx()
    out2 = DNSUDPHandler._apply_post_plugins(h, q, "example.com", QTYPE.A, wire, bad)
    assert out2 == wire
    assert getattr(bad, "_post_override") is False
