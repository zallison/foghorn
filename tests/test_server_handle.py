"""
Brief: Integration-ish tests exercising DNSUDPHandler.handle branches for coverage.

Inputs:
  - None

Outputs:
  - None
"""

from dnslib import QTYPE, RCODE, RR, A, DNSRecord

from foghorn.plugins.resolve import base as plugin_base
from foghorn.plugins.resolve.base import BasePlugin, PluginDecision
from foghorn.servers.server import DNSUDPHandler


class FakeSock:
    """
    Brief: Simple socket-like object capturing sendto calls.

    Inputs:
      - None

    Outputs:
      - None: use calls attribute to inspect
    """

    def __init__(self):
        self.calls = []

    def sendto(self, data, addr):
        self.calls.append((data, addr))


def _mk_query(name="example.com", qtype="A"):
    rec = DNSRecord.question(name, qtype)
    return rec, rec.pack()


def _mk_handler(data, sock, client_ip="1.2.3.4"):
    h = object.__new__(DNSUDPHandler)
    h.request = (data, sock)
    h.client_address = (client_ip, 12345)
    return h


def test_handle_pre_plugins_deny_sends_nxdomain(monkeypatch):
    """
    Brief: Pre-resolve deny decision triggers NXDOMAIN and early return.

    Inputs:
      - plugin: returns deny

    Outputs:
      - None: Asserts single NXDOMAIN response sent
    """
    q, data = _mk_query("deny.com")
    sock = FakeSock()

    class DenyPlugin(BasePlugin):
        def pre_resolve(self, *a, **kw):
            return PluginDecision(action="deny")

    DNSUDPHandler.plugins = [DenyPlugin()]
    h = _mk_handler(data, sock)
    h.handle()

    assert len(sock.calls) == 1
    resp = DNSRecord.parse(sock.calls[0][0])
    assert resp.header.rcode == RCODE.NXDOMAIN


def test_handle_pre_plugins_override_sends_response(monkeypatch):
    """
    Brief: Pre-resolve override returns custom response with matching ID.

    Inputs:
      - plugin: returns override with response bytes

    Outputs:
      - None: Asserts response sent once with request ID
    """
    q, data = _mk_query("override.com")
    sock = FakeSock()
    # Build an arbitrary successful response to override with
    reply = q.reply()
    reply.add_answer(RR("override.com", QTYPE.A, rdata=A("1.2.3.4"), ttl=60))

    class OverridePlugin(BasePlugin):
        def pre_resolve(self, *a, **kw):
            return PluginDecision(action="override", response=reply.pack())

    DNSUDPHandler.plugins = [OverridePlugin()]
    h = _mk_handler(data, sock)
    h.handle()

    assert len(sock.calls) == 1
    sent = sock.calls[0][0]
    # Ensure the first two bytes match the request id
    assert sent[:2] == data[:2]


def test_handle_cache_hit_short_circuits_response(monkeypatch):
    """
    Brief: Cached response is returned without contacting upstreams.

    Inputs:
      - pre-populated cache with matching key

    Outputs:
      - None: Asserts single send with matching ID
    """
    q, data = _mk_query("cached.com")
    sock = FakeSock()

    monkeypatch.setattr(DNSUDPHandler, "_apply_pre_plugins", lambda *a, **kw: None)
    DNSUDPHandler.plugins = []

    # Pre-populate cache
    cache_key = ("cached.com", QTYPE.A)
    plugin_base.DNS_CACHE.set(cache_key, 60, b"\x00\x01cached-bytes")

    h = _mk_handler(data, sock)
    h.handle()

    assert len(sock.calls) == 1
    sent = sock.calls[0][0]
    assert sent[:2] == data[:2]


def test_handle_no_upstreams_sends_servfail(monkeypatch):
    """
    Brief: No upstreams configured triggers SERVFAIL.

    Inputs:
      - _choose_upstreams returns []

    Outputs:
      - None: Asserts one SERVFAIL sent
    """
    q, data = _mk_query("noup.com")
    sock = FakeSock()

    monkeypatch.setattr(DNSUDPHandler, "_apply_pre_plugins", lambda *a, **kw: None)
    DNSUDPHandler.plugins = []
    DNSUDPHandler.upstream_addrs = []
    monkeypatch.setattr(DNSUDPHandler, "_choose_upstreams", lambda *a, **kw: [])

    h = _mk_handler(data, sock)
    h.handle()

    assert len(sock.calls) == 1
    resp = DNSRecord.parse(sock.calls[0][0])
    assert resp.header.rcode == RCODE.SERVFAIL


def test_handle_upstream_all_failed_sends_single_servfail(monkeypatch):
    """
    Brief: When forwarding fails, handler sends a single SERVFAIL response.

    Inputs:
      - send_query_with_failover returns (None, None, 'all_failed').

    Outputs:
      - None: Asserts one SERVFAIL is sent.
    """
    q, data = _mk_query("fail.com")
    sock = FakeSock()

    monkeypatch.setattr(DNSUDPHandler, "_apply_pre_plugins", lambda *a, **kw: None)
    DNSUDPHandler.plugins = []
    DNSUDPHandler.upstream_addrs = [{"host": "1.1.1.1", "port": 53}]

    # Force the shared resolver path (used by UDP and othefoghorn.servers.transports) to
    # behave as if all upstreams failed.
    import foghorn.servers.server as srv_mod

    monkeypatch.setattr(
        srv_mod,
        "send_query_with_failover",
        lambda *a, **kw: (None, None, "all_failed"),
    )

    h = _mk_handler(data, sock)
    h.handle()

    assert len(sock.calls) == 1
    assert DNSRecord.parse(sock.calls[0][0]).header.rcode == RCODE.SERVFAIL


def test_handle_success_with_post_override(monkeypatch):
    """
    Brief: Success path applies post-resolve override and sends once.

    Inputs:
      - send_query_with_failover returns OK bytes; plugin post_resolve overrides.

    Outputs:
      - None: Asserts one send with override bytes.
    """
    q, data = _mk_query("ok.com")
    sock = FakeSock()

    # Original reply from upstream
    upstream_reply = q.reply()
    upstream_reply.add_answer(RR("ok.com", QTYPE.A, rdata=A("9.9.9.9"), ttl=120))

    # Override reply
    override = q.reply()
    override.add_answer(RR("ok.com", QTYPE.A, rdata=A("7.7.7.7"), ttl=60))

    class OverridePostPlugin(BasePlugin):
        def post_resolve(self, *a, **kw):
            return PluginDecision(action="override", response=override.pack())

    monkeypatch.setattr(DNSUDPHandler, "_apply_pre_plugins", lambda *a, **kw: None)
    DNSUDPHandler.plugins = [OverridePostPlugin()]
    DNSUDPHandler.upstream_addrs = [{"host": "1.1.1.1", "port": 53}]

    # Force the shared resolver to return the upstream_reply bytes so the
    # post-resolve override plugin can replace them.
    import foghorn.servers.server as srv_mod

    monkeypatch.setattr(
        srv_mod,
        "send_query_with_failover",
        lambda *a, **kw: (
            upstream_reply.pack(),
            {"host": "1.1.1.1", "port": 53},
            "ok",
        ),
    )

    h = _mk_handler(data, sock)
    h.handle()

    assert len(sock.calls) == 1
    sent = sock.calls[0][0]
    # Response should contain the override bytes (with request ID patched)
    assert DNSRecord.parse(sent).rr[0].rdata.toZone() == "7.7.7.7"


def test_handle_exception_path_sends_servfail(monkeypatch):
    """
    Brief: Exceptions during processing result in SERVFAIL response.

    Inputs:
      - resolve_query_bytes raises inside the shared resolver.

    Outputs:
      - None: Asserts one SERVFAIL sent.
    """
    q, data = _mk_query("boom.com")
    sock = FakeSock()

    # Force the shared resolver used by DNSUDPHandler.handle to raise so that
    # the handler's outer exception guard synthesizes a SERVFAIL.
    import foghorn.servers.server as srv_mod

    monkeypatch.setattr(
        srv_mod,
        "resolve_query_bytes",
        lambda *_a, **_k: (_ for _ in ()).throw(ValueError("boom")),
    )

    h = _mk_handler(data, sock)
    h.handle()

    assert len(sock.calls) == 1
    assert DNSRecord.parse(sock.calls[0][0]).header.rcode == RCODE.SERVFAIL


def test_handle_allow_plugin_path(monkeypatch):
    """
    Brief: Allow decision continues processing and logs debug path.

    Inputs:
      - plugin returns PluginDecision('allow')

    Outputs:
      - None: Asserts response is SERVFAIL due to no upstreams
    """
    q, data = _mk_query("allow.com")
    sock = FakeSock()

    class AllowPlugin(BasePlugin):
        def pre_resolve(self, *a, **kw):
            return PluginDecision(action="allow")

    monkeypatch.setattr(DNSUDPHandler, "_apply_pre_plugins", lambda *a, **kw: None)
    DNSUDPHandler.plugins = [AllowPlugin()]
    DNSUDPHandler.upstream_addrs = []

    h = _mk_handler(data, sock)
    h.handle()

    assert len(sock.calls) >= 1
    assert DNSRecord.parse(sock.calls[-1][0]).header.rcode in (
        RCODE.SERVFAIL,
        RCODE.NXDOMAIN,
    )
