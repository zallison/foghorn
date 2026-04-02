"""
Brief: Additional targeted tests to raise coverage for foghorn.servers.server.

Inputs:
  - None

Outputs:
  - None
"""

import pytest
from dnslib import QTYPE, RCODE, RR, A, DNSRecord

import foghorn.servers.server as srv
from foghorn.plugins.resolve import base as plugin_base
from foghorn.servers.udp_server import DNSUDPHandler

send_query_with_failover = srv.send_query_with_failover


class _Sock:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))


def _mk_handler(query_wire: bytes, client_ip: str = "127.0.0.1"):
    h = DNSUDPHandler.__new__(DNSUDPHandler)
    sock = _Sock()
    h.request = (query_wire, sock)
    h.client_address = (client_ip, 55335)
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
def test_stats_hooks_are_called(monkeypatch, path, set_runtime_snapshot):
    q = DNSRecord.question("stats.example", "A")
    data = q.pack()

    # Be explicit about cache isolation for this parametrized test.
    try:
        from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache

        plugin_base.DNS_CACHE = InMemoryTTLCache()
    except Exception:  # pragma: no cover
        pass

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
            lambda request, upstreams, timeout_ms, qname, qtype, max_concurrent=1, on_attempt_result=None: (
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
            lambda request, upstreams, timeout_ms, qname, qtype, max_concurrent=1, on_attempt_result=None: (
                None,
                None,
                "all_failed",
            ),
        )

    stats = _Stats()
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "h", "port": 53}],
        stats_collector=stats,
    )

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


# ---- EDNS normalization helper coverage ----
def test_ensure_edns_request_does_not_add_opt_when_missing() -> None:
    """Brief: _ensure_edns_request does not add EDNS(0) when the client omitted it.

    Inputs:
      - None.

    Outputs:
      - None; asserts no OPT RR is injected.
    """

    from foghorn.servers.server import _ensure_edns_request

    req = DNSRecord.question("edns.example", "A")
    assert not any(rr.rtype == QTYPE.OPT for rr in (req.ar or []))

    _ensure_edns_request(req, dnssec_mode="validate", edns_udp_payload=1232)

    opts = [rr for rr in (req.ar or []) if rr.rtype == QTYPE.OPT]
    assert len(opts) == 0


def test_ensure_edns_request_preserves_client_do_bit() -> None:
    """Brief: _ensure_edns_request preserves the client's DO bit when OPT exists.

    Inputs:
      - None.

    Outputs:
      - None; asserts DO bit remains set when client requested it.
    """

    from dnslib import EDNS0
    from foghorn.servers.server import _ensure_edns_request

    req = DNSRecord.question("edns-do.example", "A")
    req.add_ar(EDNS0(udp_len=1232, flags="do"))

    _ensure_edns_request(req, dnssec_mode="ignore", edns_udp_payload=1232)

    opts = [rr for rr in (req.ar or []) if rr.rtype == QTYPE.OPT]
    assert len(opts) == 1
    flags = int(getattr(opts[0], "ttl", 0) or 0) & 0xFFFF
    assert bool(flags & 0x8000) is True


def test_handle_pre_deny_records_stats_and_query_result(
    monkeypatch, set_runtime_snapshot
):
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

    def _forbidden_send_query_with_failover(*_a, **_kw):
        raise AssertionError(
            "send_query_with_failover should not be called for pre-plugin deny"
        )

    monkeypatch.setattr(
        srv, "send_query_with_failover", _forbidden_send_query_with_failover
    )

    stats = _Stats()
    set_runtime_snapshot(
        plugins=[_PreDeny()],
        upstream_addrs=[{"host": "h", "port": 53}],
        stats_collector=stats,
    )

    h, sock = _mk_handler(q.pack())
    h.handle()

    wire = sock.sent[-1][0]
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NXDOMAIN

    kinds = [k for k, _ in stats.calls]
    assert "record_cache_null" in kinds
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds


def test_handle_pre_override_records_stats_and_query_result(
    monkeypatch, set_runtime_snapshot
):
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

    def _forbidden_send_query_with_failover(*_a, **_kw):
        raise AssertionError(
            "send_query_with_failover should not be called for pre-plugin override"
        )

    monkeypatch.setattr(
        srv, "send_query_with_failover", _forbidden_send_query_with_failover
    )

    stats = _Stats()
    set_runtime_snapshot(
        plugins=[_PreOverride()],
        upstream_addrs=[{"host": "h", "port": 53}],
        stats_collector=stats,
    )

    h, sock = _mk_handler(q.pack())
    h.handle()

    wire = sock.sent[-1][0]
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NXDOMAIN

    kinds = [k for k, _ in stats.calls]
    assert "record_cache_null" in kinds
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds


def test_handle_no_upstreams_with_stats_records_query_result(set_runtime_snapshot):
    """Brief: No upstreams with stats enabled records SERVFAIL and query result.

    Inputs:
      - None

    Outputs:
      - None; asserts stats hooks were invoked for no_upstreams path.
    """

    q = DNSRecord.question("no-upstreams-stats.example", "A")

    stats = _Stats()
    set_runtime_snapshot(plugins=[], upstream_addrs=[], stats_collector=stats)

    h, sock = _mk_handler(q.pack())
    h.handle()

    wire = sock.sent[-1][0]
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL

    kinds = [k for k, _ in stats.calls]
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds


def test_handle_all_failed_with_stats_records_upstream_rcode(
    monkeypatch, set_runtime_snapshot
):
    """Brief: All-upstreams-failed path records upstream result and upstream rcode.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts upstream result and upstream rcode were recorded.
    """

    q = DNSRecord.question("allfailed-stats.example", "A")

    # Simulate an all-failed DoH upstream where send_query_with_failover still
    # reports which upstream was attempted.
    monkeypatch.setattr(
        srv,
        "send_query_with_failover",
        lambda request, upstreams, timeout_ms, qname, qtype, max_concurrent=1, on_attempt_result=None: (
            None,
            {"url": "https://resolver/dns-query"},
            "all_failed",
        ),
    )

    stats = _Stats()
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"transport": "doh", "url": "https://resolver/dns-query"}],
        stats_collector=stats,
    )

    h, sock = _mk_handler(q.pack())
    h.handle()

    kinds = [k for k, _ in stats.calls]
    assert "record_upstream_result" in kinds
    assert "record_upstream_rcode" in kinds
    query_result_entries = [
        payload for kind, payload in stats.calls if kind == "record_query_result"
    ]
    assert query_result_entries
    _, query_kwargs = query_result_entries[-1]
    result_ctx = query_kwargs.get("result") or {}
    assert result_ctx.get("source") == "upstream"
    assert result_ctx.get("upstream") == "https://resolver/dns-query"
    assert result_ctx.get("upstream_url") == "https://resolver/dns-query"


def test_handle_upstream_success_records_query_result_upstream_id_and_url(
    monkeypatch, set_runtime_snapshot
):
    """Brief: Successful upstream responses persist upstream id/url in result context.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts query_log result.source=upstream includes upstream/upstream_url.
    """

    q = DNSRecord.question("upstream-context.example", "A")

    monkeypatch.setattr(
        srv,
        "send_query_with_failover",
        lambda request, upstreams, timeout_ms, qname, qtype, max_concurrent=1, on_attempt_result=None: (
            _mk_ok_reply(q),
            {"transport": "doh", "url": "https://resolver/dns-query"},
            "ok",
        ),
    )

    stats = _Stats()
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"transport": "doh", "url": "https://resolver/dns-query"}],
        stats_collector=stats,
    )

    h, _sock = _mk_handler(q.pack())
    h.handle()

    query_result_entries = [
        payload for kind, payload in stats.calls if kind == "record_query_result"
    ]
    assert query_result_entries
    _, query_kwargs = query_result_entries[-1]
    result_ctx = query_kwargs.get("result") or {}
    assert result_ctx.get("source") == "upstream"
    assert result_ctx.get("upstream") == "https://resolver/dns-query"
    assert result_ctx.get("upstream_url") == "https://resolver/dns-query"


# ---- DNSSEC validate branches ----
def testfoghorn_dnssec_dnssec_validate_upstream_ad_pass(
    monkeypatch, set_runtime_snapshot
):

    base_q = DNSRecord.question("ad.example", "A")
    ok = _mk_ok_reply(base_q, ad=1)

    # Force the shared resolver path (used by UDP and others) to return an AD=1
    # NOERROR reply so that validate+upstream_ad can classify it as secure.
    monkeypatch.setattr(
        srv,
        "send_query_with_failover",
        lambda req, ups, timeout_ms, qname, qtype, max_concurrent=1, on_attempt_result=None: (
            ok,
            ups[0],
            "ok",
        ),
    )

    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "8.8.8.8", "port": 53}],
        dnssec_mode="validate",
        dnssec_validation="upstream_ad",
    )

    h1, sock1 = _mk_handler(base_q.pack())
    h1.handle()
    r1 = DNSRecord.parse(sock1.sent[-1][0])
    assert r1.header.rcode == RCODE.NOERROR


def testfoghorn_dnssec_dnssec_validate_local_true(monkeypatch, set_runtime_snapshot):

    q = DNSRecord.question("local.example", "A")
    ok = _mk_ok_reply(q)

    # Force the shared resolver path to return a successful upstream reply.
    monkeypatch.setattr(
        srv,
        "send_query_with_failover",
        lambda req, ups, timeout_ms, qname, qtype, max_concurrent=1, on_attempt_result=None: (
            ok,
            ups[0],
            "ok",
        ),
    )

    # Short-circuit local DNSSEC classification to "secure" without performing
    # real DNSSEC validation network fetches.
    import foghorn.dnssec.dnssec_validate as dval

    monkeypatch.setattr(
        dval,
        "classify_dnssec_status",
        lambda *a, **k: "secure",
    )

    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "9.9.9.9", "port": 53}],
        dnssec_mode="validate",
        dnssec_validation="local",
    )

    h1, s1 = _mk_handler(q.pack())
    h1.handle()
    assert DNSRecord.parse(s1.sent[-1][0]).header.rcode == RCODE.NOERROR


def test_resolve_core_dnssec_upstream_ad_shared_helper(
    monkeypatch, set_runtime_snapshot
):
    """Brief: _resolve_core uses the shared DNSSEC helper for upstream_ad.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures dnssec_status is 'dnssec_secure' and stats hook is invoked.
    """

    q = DNSRecord.question("ad-core.example", "A")
    ok = _mk_ok_reply(q, ad=1)

    monkeypatch.setattr(
        srv,
        "send_query_with_failover",
        lambda req, ups, timeout_ms, qname, qtype, max_concurrent=1, on_attempt_result=None: (
            ok,
            {"host": "8.8.8.8", "port": 53},
            "ok",
        ),
    )

    stats = _Stats()
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "8.8.8.8", "port": 53}],
        dnssec_mode="validate",
        dnssec_validation="upstream_ad",
        edns_udp_payload=1232,
        stats_collector=stats,
    )

    result = srv._resolve_core(q.pack(), "127.0.0.1")

    assert DNSRecord.parse(result.wire).header.rcode == RCODE.NOERROR
    assert result.dnssec_status == "dnssec_secure"

    kinds = [k for k, _ in stats.calls]
    assert "record_dnssec_status" in kinds


def test_no_upstreams_with_client_edns_preserves_opt_payload(
    monkeypatch, set_runtime_snapshot
):
    """Brief: SERVFAIL/no-upstreams path echoes client EDNS OPT and payload size.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that a SERVFAIL response still carries a matching OPT RR.
    """

    from dnslib import EDNS0 as _EDNS0

    set_runtime_snapshot(plugins=[], upstream_addrs=[])

    # Build a query with an EDNS0 OPT advertising a custom UDP payload.
    q = DNSRecord.question("no-up-edns.example", "A")
    q.add_ar(_EDNS0(udp_len=2048))

    # Use the shared resolver path, which will synthesize SERVFAIL when there
    # are no upstreams configured.
    wire = srv.resolve_query_bytes(q.pack(), "127.0.0.1")
    resp = DNSRecord.parse(wire)

    req_opts = [rr for rr in (q.ar or []) if rr.rtype == QTYPE.OPT]
    resp_opts = [rr for rr in (resp.ar or []) if rr.rtype == QTYPE.OPT]

    assert len(req_opts) == 1
    assert len(resp_opts) == 1
    assert int(resp_opts[0].rclass) == int(req_opts[0].rclass)


def test_schedule_cache_refresh_runs_worker_and_ignores_errors(monkeypatch):
    """Brief: _schedule_cache_refresh spawns a worker that calls resolve_query_bytes.

    Inputs:
        - monkeypatch: pytest monkeypatch fixture.

    Outputs:
        - None; asserts that resolve_query_bytes is invoked even when it raises.
    """

    calls: dict[str, list[tuple[bytes, str]]] = {"seen": []}

    def _fake_resolve(
        data: bytes, client_ip: str, *, listener=None, secure=None
    ) -> bytes:  # noqa: D401, ANN001
        """Inputs: data/client_ip. Outputs: raises after recording call."""

        calls["seen"].append((data, client_ip))
        raise RuntimeError("boom")

    monkeypatch.setattr(srv, "resolve_query_bytes", _fake_resolve)

    # Replace the bounded background submit helper so that the worker runs
    # synchronously for coverage.
    monkeypatch.setattr(srv, "_bg_submit", lambda _key, fn: fn())

    q = DNSRecord.question("refresh.example", "A")
    wire = q.pack()

    srv._schedule_cache_refresh(wire, "127.0.0.1")

    assert calls["seen"] == [(wire, "127.0.0.1")]


def test_handle_pre_plugin_deny_with_client_edns_produces_nxdomain_with_opt(
    monkeypatch,
    set_runtime_snapshot,
):
    """Brief: Pre-plugin deny path echoes client EDNS OPT into NXDOMAIN.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that a synthetic NXDOMAIN from _resolve_core carries OPT.
    """

    from dnslib import EDNS0 as _EDNS0

    class _DenyPlugin:
        pre_priority = 1

        def pre_resolve(self, qname, qtype, data, ctx):  # noqa: D401
            """Inputs: qname/qtype/wire/ctx. Outputs: deny decision."""

            return srv.PluginDecision(action="deny")

        def post_resolve(self, qname, qtype, data, ctx):  # noqa: D401
            """Inputs: qname/qtype/wire/ctx. Outputs: no-op decision."""

            return None

    set_runtime_snapshot(plugins=[_DenyPlugin()], upstream_addrs=[])

    q = DNSRecord.question("pre-deny-edns.example", "A")
    q.add_ar(_EDNS0(udp_len=1800))

    result = srv._resolve_core(q.pack(), "127.0.0.1")
    resp = DNSRecord.parse(result.wire)

    req_opts = [rr for rr in (q.ar or []) if rr.rtype == QTYPE.OPT]
    resp_opts = [rr for rr in (resp.ar or []) if rr.rtype == QTYPE.OPT]

    assert resp.header.rcode == RCODE.NXDOMAIN
    assert len(req_opts) == 1
    assert len(resp_opts) == 1
    assert int(resp_opts[0].rclass) == int(req_opts[0].rclass)


# ---- DoH branch in send_query_with_failover ----
def test_send_query_with_failover_doh_success(monkeypatch):
    q = DNSRecord.question("doh.example", "A")
    ok = _mk_ok_reply(q)

    # Patch doh_query to return body and headers
    import foghorn.servers.transports.doh as doh_mod

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


def test_send_query_with_failover_edns_formerr_udp_fallback(monkeypatch):
    """Brief: UDP FORMERR responses for EDNS queries trigger a no-EDNS retry.

    Inputs:
        - monkeypatch: pytest monkeypatch fixture.

    Outputs:
        - None; asserts that a FORMERR+EDNS response leads to a successful
          fallback query without EDNS.
    """

    from dnslib import EDNS0 as _EDNS0

    qname = "edns-fallback.example"
    q = DNSRecord.question(qname, "A")
    q.add_ar(_EDNS0(udp_len=1232))

    calls = {"edns": 0, "no_edns": 0}

    def _fake_udp_query(host, port, wire, timeout_ms=0):  # noqa: D401
        """Inputs: host/port/wire. Outputs: FORMERR for EDNS, NOERROR otherwise."""

        msg = DNSRecord.parse(wire)
        has_opt = any(rr.rtype == QTYPE.OPT for rr in (msg.ar or []))
        if has_opt:
            calls["edns"] += 1
            r = msg.reply()
            r.header.rcode = RCODE.FORMERR
            return r.pack()
        calls["no_edns"] += 1
        r = msg.reply()
        r.header.rcode = RCODE.NOERROR
        return r.pack()

    import foghorn.servers.transports.udp as udp_mod

    monkeypatch.setattr(udp_mod, "udp_query", _fake_udp_query)

    resp, used, reason = send_query_with_failover(
        q,
        upstreams=[{"host": "8.8.8.8", "port": 53}],
        timeout_ms=500,
        qname=qname,
        qtype=QTYPE.A,
    )

    assert reason == "ok"
    parsed = DNSRecord.parse(resp)
    assert parsed.header.rcode == RCODE.NOERROR
    assert calls["edns"] == 1
    assert calls["no_edns"] == 1


def test_send_query_with_failover_edns_formerr_then_servfail(monkeypatch):
    """Brief: EDNS FORMERR fallback that still yields SERVFAIL is treated as failure.

    Inputs:
        - monkeypatch: pytest monkeypatch fixture.

    Outputs:
        - None; asserts that a FORMERR+EDNS response followed by SERVFAIL
          without EDNS returns all_failed.
    """

    from dnslib import EDNS0 as _EDNS0

    qname = "edns-fallback-servfail.example"
    q = DNSRecord.question(qname, "A")
    q.add_ar(_EDNS0(udp_len=1232))

    def _fake_udp_query(host, port, wire, timeout_ms=0):
        msg = DNSRecord.parse(wire)
        has_opt = any(rr.rtype == QTYPE.OPT for rr in (msg.ar or []))
        r = msg.reply()
        if has_opt:
            r.header.rcode = RCODE.FORMERR
        else:
            r.header.rcode = RCODE.SERVFAIL
        return r.pack()

    import foghorn.servers.transports.udp as udp_mod

    monkeypatch.setattr(udp_mod, "udp_query", _fake_udp_query)

    resp, used, reason = send_query_with_failover(
        q,
        upstreams=[{"host": "8.8.8.8", "port": 53}],
        timeout_ms=500,
        qname=qname,
        qtype=QTYPE.A,
    )

    assert resp is None
    assert used is None
    assert reason == "all_failed"


def test_send_query_with_failover_truncated_udp_falls_back_to_tcp(monkeypatch):
    """Brief: Truncated UDP responses (TC=1) are retried over TCP.

    Inputs:
        - monkeypatch: pytest monkeypatch fixture.

    Outputs:
        - None; asserts that TC=1 over UDP leads to a TCP retry and success.
    """

    qname = "trunc-fallback.example"
    q = DNSRecord.question(qname, "A")

    def _fake_udp_query(host, port, wire, timeout_ms=0):
        msg = DNSRecord.parse(wire)
        r = msg.reply()
        r.header.tc = 1
        return r.pack()

    def _fake_tcp_query(host, port, wire, connect_timeout_ms=0, read_timeout_ms=0):
        msg = DNSRecord.parse(wire)
        r = msg.reply()
        r.header.rcode = RCODE.NOERROR
        return r.pack()

    import foghorn.servers.transports.udp as udp_mod

    monkeypatch.setattr(udp_mod, "udp_query", _fake_udp_query)
    monkeypatch.setattr(srv, "tcp_query", _fake_tcp_query)

    resp, used, reason = send_query_with_failover(
        q,
        upstreams=[{"host": "8.8.8.8", "port": 53, "transport": "udp"}],
        timeout_ms=500,
        qname=qname,
        qtype=QTYPE.A,
    )

    assert reason == "ok"
    assert used["transport"] == "tcp"
    assert DNSRecord.parse(resp).header.rcode == RCODE.NOERROR


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
    import foghorn.servers.transports.udp as udp_mod

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
