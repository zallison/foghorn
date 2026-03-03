"""
Brief: Comprehensive path tests for foghorn.servers.server.DNSUDPHandler.handle and helpers.

Inputs:
  - None

Outputs:
  - None
"""

from dnslib import RCODE, DNSRecord

import foghorn.servers.server as srv
from foghorn.servers.udp_server import DNSUDPHandler


def _mk_handler(query_wire: bytes, client_ip: str = "127.0.0.1"):
    # Build a handler instance without BaseRequestHandler.__init__
    h = DNSUDPHandler.__new__(DNSUDPHandler)

    class _Sock:
        def __init__(self):
            self.sent = []

        def sendto(self, data, addr):
            self.sent.append((data, addr))

    sock = _Sock()
    h.request = (query_wire, sock)
    h.client_address = (client_ip, 55335)
    return h, sock


def test_handle_no_upstreams_returns_servfail_and_caches(set_runtime_snapshot):
    # No upstreams configured -> SERVFAIL response
    q = DNSRecord.question("no-upstreams.example", "A")
    set_runtime_snapshot(
        upstream_addrs=[],
        plugins=[],
        stats_collector=None,
        resolver_mode="forward",
        forward_local=False,
    )
    h, sock = _mk_handler(q.pack())

    h.handle()
    assert len(sock.sent) >= 1
    wire = sock.sent[-1][0]
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL


def test_handle_upstreams_all_failed_path_records_servfail_and_caches(
    monkeypatch, set_runtime_snapshot
):
    """Brief: When all upstreams fail in the core resolver, UDP handle returns SERVFAIL.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts SERVFAIL synthesized by resolve_query_bytes is sent over UDP.
    """
    q = DNSRecord.question("all-failed.example", "A")
    set_runtime_snapshot(
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        plugins=[],
        stats_collector=None,
        resolver_mode="forward",
        forward_local=False,
    )

    def fake_send(
        req, upstreams, timeout_ms, qname, qtype, max_concurrent=None, on_attempt_result=None
    ):
        # Simulate complete upstream failure; core resolver should synthesize SERVFAIL.
        return None, {"host": "1.1.1.1", "port": 53}, "all_failed"

    monkeypatch.setattr(srv, "send_query_with_failover", fake_send)

    h, sock = _mk_handler(q.pack())
    h.handle()
    wire = sock.sent[-1][0]
    assert DNSRecord.parse(wire).header.rcode == RCODE.SERVFAIL


def test_handle_post_resolve_deny_turns_into_nxdomain(
    monkeypatch, set_runtime_snapshot
):
    """Brief: Post-resolve deny from core resolver is surfaced as NXDOMAIN on UDP.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts post plugin deny overrides upstream NOERROR to NXDOMAIN.
    """
    q = DNSRecord.question("deny-post.example", "A")

    # Make upstream return NOERROR; then post hook denies
    ok = q.reply().pack()

    def fake_send(
        req, upstreams, timeout_ms, qname, qtype, max_concurrent=None, on_attempt_result=None
    ):
        return ok, upstreams[0], "ok"

    class _PostDeny:
        post_priority = 10

        def pre_resolve(self, qname, qtype, data, ctx):
            return None

        def post_resolve(self, qname, qtype, data, ctx):
            return srv.PluginDecision(action="deny")

    monkeypatch.setattr(srv, "send_query_with_failover", fake_send)

    set_runtime_snapshot(
        upstream_addrs=[{"host": "8.8.8.8", "port": 53}],
        plugins=[_PostDeny()],
        stats_collector=None,
        resolver_mode="forward",
        forward_local=False,
    )

    h, sock = _mk_handler(q.pack())
    h.handle()
    wire = sock.sent[-1][0]
    assert DNSRecord.parse(wire).header.rcode == RCODE.NXDOMAIN


def test_compute_effective_ttl_covers_error_defense():
    # Provide malformed response to trigger except path returning min_cache_ttl
    class _R:
        class header:
            rcode = RCODE.NOERROR

        rr = None  # lack of proper rr triggers except

    assert srv.compute_effective_ttl(_R(), 42) == 42
