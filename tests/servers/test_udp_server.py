"""
Brief: Unit tests for downstream UDP server wrapper.

Inputs:
  - None

Outputs:
  - None
"""

import socket
import threading
import time

import pytest
from dnslib import DNSRecord, QTYPE, RCODE

from foghorn.servers.udp_server import DNSUDPHandler, serve_udp
from foghorn.plugins.resolve.base import PluginContext, PluginDecision


def _echo_resolver(q: bytes, client_ip: str) -> bytes:
    """Inputs: query bytes and client IP. Outputs: identical query bytes."""

    return q


@pytest.fixture
def running_udp_server():
    """Inputs: None.

    Outputs: Yields (host, port) for a running UDP echo server.
    """

    host = "127.0.0.1"
    ready = threading.Event()
    actual = {}

    def runner() -> None:
        """Inputs: None. Outputs: Run UDP server in a background thread."""

        # Bind ephemeral socket to discover a free port, then run server on it
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host, 0))
        actual_port = s.getsockname()[1]
        s.close()
        actual["port"] = actual_port
        ready.set()
        serve_udp(host, actual_port, _echo_resolver)

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    if not ready.wait(1.0):
        pytest.skip("failed to start udp server")
    time.sleep(0.05)
    yield host, actual["port"]
    # daemon thread exits on process end


def test_udp_server_roundtrip(running_udp_server):
    """Inputs: running_udp_server fixture.

    Outputs: Assert that a UDP roundtrip returns the original payload.
    """

    host, port = running_udp_server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        q = b"\x12\x34hello"
        sock.settimeout(1)
        sock.sendto(q, (host, port))
        data, _ = sock.recvfrom(4096)
        assert data == q
    finally:
        sock.close()


def _make_handler() -> DNSUDPHandler:
    """Inputs: None.

    Outputs: Bare DNSUDPHandler instance with minimal attributes set.
    """

    handler = DNSUDPHandler.__new__(DNSUDPHandler)
    handler.plugins = []
    handler.upstream_addrs = []
    handler.timeout_ms = 2000
    handler.upstream_strategy = "failover"
    handler.upstream_max_concurrent = 1
    handler.dnssec_mode = "ignore"
    handler.edns_udp_payload = 1232
    return handler


def test_upstream_id_variants():
    """Inputs: Several upstream config shapes.

    Outputs: Verify _upstream_id handles url, host/port, and bad inputs.
    """

    # Non-dict returns empty identifier
    assert DNSUDPHandler._upstream_id("not-a-dict") == ""

    # URL-based upstream
    assert (
        DNSUDPHandler._upstream_id({"url": "https://example/dns-query"})
        == "https://example/dns-query"
    )

    # Dict without host/port
    assert DNSUDPHandler._upstream_id({"host": None, "port": None}) == ""

    # Bad port value falls back to host string
    assert DNSUDPHandler._upstream_id({"host": "example", "port": "bad"}) == "example"


def test_mark_upstreams_down_backoff(monkeypatch):
    """Inputs: Upstream list including valid and invalid entries.

    Outputs: Ensure health state is updated with growing fail_count and delay.
    """

    from foghorn.servers import udp_server as udp_mod

    monkeypatch.setattr(udp_mod.time, "time", lambda: 1000.0)
    DNSUDPHandler.upstream_health.clear()

    good = {"host": "8.8.8.8", "port": 53}
    bad = {}  # ignored because it has no stable upstream id

    DNSUDPHandler._mark_upstreams_down([good, bad], reason="all_failed")
    up_id = DNSUDPHandler._upstream_id(good)
    entry1 = DNSUDPHandler.upstream_health[up_id]
    assert entry1["fail_count"] == 1.0
    assert entry1["down_until"] == pytest.approx(1005.0)

    DNSUDPHandler._mark_upstreams_down([good], reason="all_failed")
    entry2 = DNSUDPHandler.upstream_health[up_id]
    assert entry2["fail_count"] == 2.0
    # Subsequent failures keep the same base delay but advance fail_count.
    assert entry2["down_until"] == pytest.approx(1005.0)


def test_mark_upstream_ok_noop_for_invalid():
    """Inputs: None and upstreams without a stable id.

    Outputs: Confirm that health map is unchanged for invalid inputs.
    """

    DNSUDPHandler.upstream_health.clear()

    DNSUDPHandler._mark_upstream_ok(None)
    DNSUDPHandler._mark_upstream_ok({"host": None, "port": None})
    assert DNSUDPHandler.upstream_health == {}


def test_mark_upstream_ok_resets_health():
    """Inputs: A healthy upstream id with prior failures.

    Outputs: Ensure health entry is reset to zeroed state.
    """

    DNSUDPHandler.upstream_health.clear()
    up = {"host": "1.1.1.1", "port": 53}
    up_id = DNSUDPHandler._upstream_id(up)
    DNSUDPHandler.upstream_health[up_id] = {"fail_count": 3.0, "down_until": 2000.0}

    DNSUDPHandler._mark_upstream_ok(up)
    entry = DNSUDPHandler.upstream_health[up_id]
    assert entry["fail_count"] == 0.0
    assert entry["down_until"] == 0.0


def test_apply_pre_plugins_deny():
    """Inputs: Plugin that returns a deny decision.

    Outputs: Verify deny is returned and short-circuits remaining plugins.
    """

    handler = _make_handler()

    class DenyPlugin:
        pre_priority = 10

        def pre_resolve(self, qname, qtype, data, ctx):  # noqa: D401
            """Inputs: qname, qtype, data, ctx. Outputs: deny decision."""

            return PluginDecision(action="deny")

    handler.plugins = [DenyPlugin()]
    ctx = PluginContext(client_ip="192.0.2.1")
    decision = handler._apply_pre_plugins(
        request=None,
        qname="example.com.",
        qtype=QTYPE.A,
        data=b"query",
        ctx=ctx,
    )
    assert isinstance(decision, PluginDecision)
    assert decision.action == "deny"


def test_apply_pre_plugins_override():
    """Inputs: Plugin that returns an override decision.

    Outputs: Verify override decision and response are propagated.
    """

    handler = _make_handler()

    class OverridePlugin:
        pre_priority = 10

        def pre_resolve(self, qname, qtype, data, ctx):  # noqa: D401
            """Inputs: qname, qtype, data, ctx. Outputs: override decision."""

            return PluginDecision(action="override", response=b"override")

    handler.plugins = [OverridePlugin()]
    ctx = PluginContext(client_ip="192.0.2.1")
    decision = handler._apply_pre_plugins(
        request=None,
        qname="example.com.",
        qtype=QTYPE.A,
        data=b"query",
        ctx=ctx,
    )
    assert isinstance(decision, PluginDecision)
    assert decision.action == "override"
    assert decision.response == b"override"


def test_apply_pre_plugins_other_action_logs_and_continues():
    """Inputs: Plugin that returns a non-standard action.

    Outputs: Ensure handler continues and returns None.
    """

    handler = _make_handler()

    class OtherPlugin:
        pre_priority = 10

        def pre_resolve(self, qname, qtype, data, ctx):  # noqa: D401
            """Inputs: qname, qtype, data, ctx. Outputs: custom decision."""

            return PluginDecision(action="custom")

    handler.plugins = [OtherPlugin()]
    ctx = PluginContext(client_ip="192.0.2.1")
    decision = handler._apply_pre_plugins(
        request=None,
        qname="example.com.",
        qtype=QTYPE.A,
        data=b"query",
        ctx=ctx,
    )
    assert decision is None


def test_choose_upstreams_filters_down(monkeypatch):
    """Inputs: Mixed healthy and backoff-marked upstreams.

    Outputs: Only healthy upstreams are returned by _choose_upstreams.
    """

    handler = _make_handler()
    ctx = PluginContext(client_ip="192.0.2.1")

    up_good = {"host": "1.1.1.1", "port": 53}
    up_down = {"host": "9.9.9.9", "port": 53}
    handler.upstream_addrs = [up_good, up_down]

    from foghorn.servers import udp_server as udp_mod

    monkeypatch.setattr(udp_mod.time, "time", lambda: 1000.0)
    DNSUDPHandler.upstream_health.clear()
    DNSUDPHandler.upstream_health[DNSUDPHandler._upstream_id(up_down)] = {
        "fail_count": 1.0,
        "down_until": 1010.0,
    }

    upstreams = handler._choose_upstreams("example.com.", QTYPE.A, ctx)
    assert upstreams == [up_good]


def test_choose_upstreams_round_robin(monkeypatch):
    """Inputs: Multiple upstreams and round_robin strategy.

    Outputs: Returned order rotates based on class round-robin index.
    """

    handler = _make_handler()
    ctx = PluginContext(client_ip="192.0.2.1")

    up1 = {"host": "1.1.1.1", "port": 53}
    up2 = {"host": "2.2.2.2", "port": 53}
    up3 = {"host": "3.3.3.3", "port": 53}
    handler.upstream_addrs = [up1, up2, up3]

    from foghorn.servers import udp_server as udp_mod

    monkeypatch.setattr(udp_mod.time, "time", lambda: 1000.0)
    DNSUDPHandler.upstream_health.clear()

    handler.upstream_strategy = "round_robin"
    handler.upstream_max_concurrent = 2
    DNSUDPHandler._upstream_rr_index = 1

    upstreams = handler._choose_upstreams("example.com.", QTYPE.A, ctx)
    assert upstreams == [up2, up3, up1]


def test_choose_upstreams_random_strategy_handles_shuffle_error(monkeypatch):
    """Inputs: Random strategy with shuffle raising an exception.

    Outputs: Falls back to original ordering on shuffle failure.
    """

    import random as _random

    handler = _make_handler()
    ctx = PluginContext(client_ip="192.0.2.1")

    up1 = {"host": "1.1.1.1", "port": 53}
    up2 = {"host": "2.2.2.2", "port": 53}
    handler.upstream_addrs = [up1, up2]

    from foghorn.servers import udp_server as udp_mod

    monkeypatch.setattr(udp_mod.time, "time", lambda: 1000.0)
    DNSUDPHandler.upstream_health.clear()

    handler.upstream_strategy = "random"
    handler.upstream_max_concurrent = 1

    def _boom(seq):  # noqa: D401
        """Inputs: seq. Outputs: always raises to simulate failure."""

        raise RuntimeError("shuffle failed")

    monkeypatch.setattr(_random, "shuffle", _boom)

    upstreams = handler._choose_upstreams("example.com.", QTYPE.A, ctx)
    assert upstreams == [up1, up2]


def test_forward_with_failover_invalid_concurrency(monkeypatch):
    """Inputs: Handler with non-int upstream_max_concurrent.

    Outputs: Falls back to max_concurrent=1 and marks upstream OK on reply.
    """

    handler = _make_handler()
    handler.upstream_max_concurrent = object()

    import foghorn.servers.server as server_mod

    captured = {}

    def _fake_send(
        query, upstreams, timeout_ms, qname, qtype, max_concurrent
    ):  # noqa: D401
        """Inputs: query/upstreams/timeout. Outputs: static ok response."""

        captured["max_concurrent"] = max_concurrent
        return b"resp", {"host": "1.1.1.1", "port": 53}, "ok"

    monkeypatch.setattr(server_mod, "send_query_with_failover", _fake_send)

    called_ok = {}

    def _mark_ok(up):  # noqa: D401
        """Inputs: upstream. Outputs: record that mark_upstream_ok was called."""

        called_ok["up"] = up

    monkeypatch.setattr(
        DNSUDPHandler, "_mark_upstream_ok", classmethod(lambda cls, up: _mark_ok(up))
    )

    req = DNSRecord.question("example.com.")
    reply, used_up, reason = handler._forward_with_failover_helper(
        request=req,
        upstreams=[{"host": "1.1.1.1", "port": 53}],
        qname="example.com.",
        qtype=QTYPE.A,
    )

    assert reply == b"resp"
    assert used_up == {"host": "1.1.1.1", "port": 53}
    assert reason == "ok"
    assert captured["max_concurrent"] == 1
    assert called_ok["up"] == {"host": "1.1.1.1", "port": 53}


def test_forward_with_failover_all_failed_marks_down(monkeypatch):
    """Inputs: Handler with max_concurrent < 1 and failing upstreams.

    Outputs: Ensures mark_upstreams_down is invoked on failure.
    """

    handler = _make_handler()
    handler.upstream_max_concurrent = 0

    import foghorn.servers.server as server_mod

    def _fake_send(
        query, upstreams, timeout_ms, qname, qtype, max_concurrent
    ):  # noqa: D401
        """Inputs: query/upstreams/timeout. Outputs: always fail result."""

        return None, None, "all_failed"

    monkeypatch.setattr(server_mod, "send_query_with_failover", _fake_send)

    called = {}

    def _mark_down(cls, ups, reason):  # noqa: D401
        """Inputs: ups/reason. Outputs: record invocation for assertions."""

        called["ups"] = list(ups)
        called["reason"] = reason

    monkeypatch.setattr(DNSUDPHandler, "_mark_upstreams_down", classmethod(_mark_down))

    req = DNSRecord.question("example.com.")
    upstreams = [{"host": "1.1.1.1", "port": 53}]
    reply, used_up, reason = handler._forward_with_failover_helper(
        request=req,
        upstreams=upstreams,
        qname="example.com.",
        qtype=QTYPE.A,
    )

    assert reply is None
    assert used_up is None
    assert reason == "all_failed"
    assert called["ups"] == upstreams
    assert called["reason"] == "all_failed"


def test_apply_post_plugins_override_sets_flag():
    """Inputs: Plugin that overrides the response.

    Outputs: Response wire is replaced and ctx._post_override is set.
    """

    handler = _make_handler()

    class OverridePlugin:
        post_priority = 10

        def post_resolve(self, qname, qtype, wire, ctx):  # noqa: D401
            """Inputs: qname/qtype/wire/ctx. Outputs: override decision."""

            return PluginDecision(action="override", response=b"override")

    handler.plugins = [OverridePlugin()]
    ctx = PluginContext(client_ip="192.0.2.1")
    req = DNSRecord.question("example.com.")
    out = handler._apply_post_plugins(req, "example.com.", QTYPE.A, b"orig", ctx)

    assert out == b"override"
    assert getattr(ctx, "_post_override", False) is True


def test_apply_post_plugins_allow_short_circuits():
    """Inputs: Plugin that returns allow decision.

    Outputs: Original wire is returned and later plugins are skipped.
    """

    handler = _make_handler()

    class AllowPlugin:
        post_priority = 10

        def post_resolve(self, qname, qtype, wire, ctx):  # noqa: D401
            """Inputs: qname/qtype/wire/ctx. Outputs: allow decision."""

            return PluginDecision(action="allow")

    handler.plugins = [AllowPlugin()]
    ctx = PluginContext(client_ip="192.0.2.1")
    req = DNSRecord.question("example.com.")
    out = handler._apply_post_plugins(req, "example.com.", QTYPE.A, b"orig", ctx)

    assert out == b"orig"


def test_make_nxdomain_response_preserves_id():
    """Inputs: DNS question record.

    Outputs: NXDOMAIN response with matching ID is produced.
    """

    handler = _make_handler()
    req = DNSRecord.question("example.com.")
    req.header.id = 0x1234
    wire = handler._make_nxdomain_response(req)
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NXDOMAIN
    assert resp.header.id == 0x1234


def test_make_servfail_response_preserves_id():
    """Inputs: DNS question record.

    Outputs: SERVFAIL response with matching ID is produced.
    """

    handler = _make_handler()
    req = DNSRecord.question("example.com.")
    req.header.id = 0x5678
    wire = handler._make_servfail_response(req)
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert resp.header.id == 0x5678
