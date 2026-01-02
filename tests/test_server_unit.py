"""
Brief: Focused unit tests for foghorn.servers.server helpers to ensure coverage.

Inputs:
  - None

Outputs:
  - None
"""

from dnslib import QTYPE, RCODE, RR, A, DNSRecord

from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache
from foghorn.plugins.resolve import base as plugin_base
from foghorn.servers.server import (
    DNSUDPHandler,
    compute_effective_ttl,
    send_query_with_failover,
)
from foghorn.servers.udp_server import _set_response_id


def test_set_response_id_rewrites_first_two_bytes():
    """
    Brief: _set_response_id replaces the first two bytes with the request ID.

    Inputs:
      - wire: bytes of DNS response
      - req_id: integer ID to set

    Outputs:
      - None: Asserts bytes[0:2] equal to req_id
    """
    wire = b"\x12\x34restofpacket"
    out = _set_response_id(wire, 0xBEEF)
    assert out[:2] == bytes([0xBE, 0xEF])
    assert out[2:] == b"restofpacket"


def test_set_response_id_short_wire_returns_unchanged():
    """
    Brief: _set_response_id returns original when wire shorter than 2 bytes.

    Inputs:
      - wire: one-byte bytes object

    Outputs:
      - None: Asserts same object content
    """
    wire = b"\x00"
    out = _set_response_id(wire, 0x1234)
    assert out == wire


def test_compute_effective_ttl_noerror_with_answers_uses_min_floor():
    """
    Brief: compute_effective_ttl applies min floor across answers.

    Inputs:
      - resp: DNSRecord with two answers of TTL 30 and 120
      - min_cache_ttl: 60

    Outputs:
      - None: Asserts effective ttl = max(min(answer.ttl), floor)
    """
    q = DNSRecord.question("example.com", "A")
    resp = q.reply()
    resp.add_answer(RR("example.com", QTYPE.A, rdata=A("1.2.3.4"), ttl=30))
    resp.add_answer(RR("example.com", QTYPE.A, rdata=A("2.3.4.5"), ttl=120))
    ttl = compute_effective_ttl(resp, 60)
    assert ttl == 60


def test_compute_effective_ttl_non_noerror_or_no_answers_returns_floor():
    """
    Brief: compute_effective_ttl returns floor for NXDOMAIN or no answers.

    Inputs:
      - resp: DNSRecord with NXDOMAIN

    Outputs:
      - None: Asserts floor returned
    """
    q = DNSRecord.question("example.com", "A")
    resp = q.reply()
    resp.header.rcode = RCODE.NXDOMAIN
    assert compute_effective_ttl(resp, 50) == 50


def test_send_query_with_failover_parsing_and_servfail_failover(monkeypatch):
    """
    Brief: send_query_with_failover skips SERVFAIL and parsing errors, succeeds on next.

    Inputs:
      - upstreams: two servers, first returns SERVFAIL, second OK

    Outputs:
      - None: Asserts second upstream chosen and 'ok' reason
    """

    class DummyQuery:
        def send(self, host, port, timeout=None):
            if host == "bad":
                return b"bad-bytes"
            return b"good-bytes"

    class DummyParsed:
        class header:
            rcode = RCODE.SERVFAIL

    class DummyParsedOK:
        class header:
            rcode = RCODE.NOERROR

    parse_calls = {"count": 0}

    def fake_parse(wire):
        parse_calls["count"] += 1
        if wire == b"bad-bytes":
            return DummyParsed
        return DummyParsedOK

    monkeypatch.setattr("foghorn.servers.server.DNSRecord.parse", fake_parse)

    resp, used, reason = send_query_with_failover(
        DummyQuery(),
        upstreams=[{"host": "bad", "port": 53}, {"host": "good", "port": 53}],
        timeout_ms=1000,
        qname="example.com",
        qtype=QTYPE.A,
    )

    assert resp == b"good-bytes"
    assert used == {"host": "good", "port": 53}
    assert reason == "ok"


def test_send_query_with_failover_all_failed(monkeypatch):
    """
    Brief: send_query_with_failover returns all_failed when all attempts fail.

    Inputs:
      - upstreams: two servers raising exceptions

    Outputs:
      - None: Asserts all_failed with None response
    """

    class DummyQuery:
        def send(self, host, port, timeout=None):
            raise RuntimeError("boom")

    # Make parse raise to simulate malformed bytes (not reached here but keep consistent)
    def fake_parse(wire):
        raise ValueError("bad packet")

    monkeypatch.setattr("foghorn.servers.server.DNSRecord.parse", fake_parse)

    resp, used, reason = send_query_with_failover(
        DummyQuery(),
        upstreams=[{"host": "u1", "port": 53}, {"host": "u2", "port": 53}],
        timeout_ms=500,
        qname="ex",
        qtype=QTYPE.A,
    )

    assert resp is None and used is None and reason == "all_failed"


def test_send_query_with_failover_no_upstreams():
    """
    Brief: send_query_with_failover returns no_upstreams when list is empty.

    Inputs:
      - upstreams: empty list

    Outputs:
      - None: Asserts (None, None, 'no_upstreams')
    """
    q = DNSRecord.question("example.com", "A")
    resp, used, reason = send_query_with_failover(
        q, upstreams=[], timeout_ms=100, qname="x", qtype=1
    )
    assert resp is None and used is None and reason == "no_upstreams"


def test_send_query_with_failover_concurrent_path_uses_first_success(monkeypatch):
    """Brief: send_query_with_failover with max_concurrent>1 returns first successful upstream.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: Asserts winner comes from second upstream when first fails.
    """

    class DummyQuery:
        def send(self, host, port, timeout=None):
            if host == "bad":
                return b"resp-bad"
            return b"resp-good"

    def fake_parse(wire):
        class _R:
            class header:
                rcode = RCODE.NOERROR

        if wire == b"resp-bad":
            raise ValueError("bad parse")
        return _R

    monkeypatch.setattr("foghorn.servers.server.DNSRecord.parse", fake_parse)

    resp, used, reason = send_query_with_failover(
        DummyQuery(),
        upstreams=[{"host": "bad", "port": 53}, {"host": "good", "port": 53}],
        timeout_ms=100,
        qname="example.com",
        qtype=QTYPE.A,
        max_concurrent=2,
    )

    assert resp == b"resp-good"
    assert used == {"host": "good", "port": 53}
    assert reason == "ok"


def test_dnsserver_edns_udp_payload_config_and_fallback(monkeypatch):
    """Brief: DNSServer applies edns_udp_payload and falls back to default on error.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts DNSUDPHandler.edns_udp_payload is set or reset as expected.
    """

    import foghorn.servers.server as srv_mod
    import foghorn.servers.udp_server as udp_srv_mod

    class _DummyServer:
        def __init__(self, *a, **kw):
            self.daemon_threads = False

    # Avoid binding real UDP sockets in tests by patching the UDP server module
    monkeypatch.setattr(udp_srv_mod.socketserver, "ThreadingUDPServer", _DummyServer)

    # Normal numeric edns_udp_payload
    srv_mod.DNSUDPHandler.edns_udp_payload = 0
    srv_mod.DNSUDPHandler.dnssec_mode = "ignore"
    srv_mod.DNSServer("127.0.0.1", 0, [], [], edns_udp_payload=1500)
    assert srv_mod.DNSUDPHandler.dnssec_mode == "ignore"
    assert srv_mod.DNSUDPHandler.edns_udp_payload == 1500

    # Non-int -> fallback to default 1232
    srv_mod.DNSUDPHandler.edns_udp_payload = 0
    srv_mod.DNSServer("127.0.0.1", 0, [], [], edns_udp_payload="not-an-int")
    assert srv_mod.DNSUDPHandler.edns_udp_payload == 1232


def _make_handler_for_cache_tests(min_cache_ttl: int):
    """Brief: Construct a bare DNSUDPHandler instance suitable for calling _cache_and_send_response.

    Inputs:
      - min_cache_ttl: int minimum cache TTL to configure on the handler

    Outputs:
      - DNSUDPHandler instance with fake cache and client metadata
    """
    handler = DNSUDPHandler.__new__(DNSUDPHandler)
    plugin_base.DNS_CACHE = InMemoryTTLCache()
    handler.min_cache_ttl = min_cache_ttl
    handler.client_address = ("127.0.0.1", 12345)
    return handler


def test_cache_and_send_response_uses_effective_ttl(monkeypatch):
    """
    Brief: _cache_and_send_response applies compute_effective_ttl and caches with the floor.

    Inputs:
      - response with low TTL and min_cache_ttl higher than RR TTL

    Outputs:
      - None: Asserts cache.set is called with TTL equal to compute_effective_ttl
    """

    handler = _make_handler_for_cache_tests(min_cache_ttl=60)

    # Build a NOERROR response with two answers (30 and 120 second TTL)
    q = DNSRecord.question("example.com", "A")
    resp = q.reply()
    resp.add_answer(RR("domain1.example.com", QTYPE.A, rdata=A("1.2.3.4"), ttl=30))
    resp.add_answer(RR("domain2.example.com", QTYPE.A, rdata=A("2.3.4.5"), ttl=120))
    wire = resp.pack()

    cache_calls = {"ttl": None, "key": None}

    def fake_set(self, key, ttl, data):
        cache_calls["ttl"] = ttl
        cache_calls["key"] = key

    # Patch at the class level so the assertion is stable even if another test
    # swaps out plugin_base.DNS_CACHE concurrently.
    monkeypatch.setattr(InMemoryTTLCache, "set", fake_set)

    plugin_base.DNS_CACHE = InMemoryTTLCache()

    class DummySock:
        def __init__(self):
            self.sent = []

        def sendto(self, data, addr):
            self.sent.append((data, addr))

    sock = DummySock()
    cache_key = ("example.com", QTYPE.A)

    handler._cache_and_send_response(
        wire,
        q,
        "example.com",
        QTYPE.A,
        sock,
        handler.client_address,
        cache_key,
    )

    assert cache_calls["ttl"] == 60
    assert cache_calls["key"] == cache_key
    assert len(sock.sent) == 1


def test_cache_and_send_response_never_caches_servfail(monkeypatch):
    """
    Brief: _cache_and_send_response does not cache SERVFAIL responses.

    Inputs:
      - SERVFAIL DNSRecord

    Outputs:
      - None: Asserts cache.set is never called
    """

    handler = _make_handler_for_cache_tests(min_cache_ttl=60)

    q = DNSRecord.question("example.com", "A")
    resp = q.reply()
    resp.header.rcode = RCODE.SERVFAIL
    wire = resp.pack()

    cache_calls = {"called": False}

    def fake_set(self, key, ttl, data):
        cache_calls["called"] = True

    # Patch at the class level so the assertion is stable even if another test
    # swaps out plugin_base.DNS_CACHE concurrently.
    monkeypatch.setattr(InMemoryTTLCache, "set", fake_set)

    plugin_base.DNS_CACHE = InMemoryTTLCache()

    class DummySock:
        def __init__(self):
            self.sent = []

        def sendto(self, data, addr):
            self.sent.append((data, addr))

    sock = DummySock()
    cache_key = ("example.com", QTYPE.A)

    handler._cache_and_send_response(
        wire,
        q,
        "example.com",
        QTYPE.A,
        sock,
        handler.client_address,
        cache_key,
    )

    assert cache_calls["called"] is False
    assert len(sock.sent) == 1
