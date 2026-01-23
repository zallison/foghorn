"""
Brief: Tests for Extended DNS Errors (EDE) integration in foghorn.servers.server.

Inputs:
  - None (pytest harness)

Outputs:
  - None; assertions verify EDE codes/texts on synthetic responses.
"""

from __future__ import annotations

from typing import List, Tuple

import pytest
from dnslib import DNSRecord, EDNS0, EDNSOption, OPCODE, QTYPE, RCODE

import foghorn.servers.server as srv


def _make_edns_query(name: str = "ede.example", qtype: str = "A") -> DNSRecord:
    """Brief: Build an EDNS(0)-capable DNS question record.

    Inputs:
      - name: Query name.
      - qtype: RR type mnemonic.

    Outputs:
      - DNSRecord with an OPT RR advertising EDNS(0).
    """

    q = DNSRecord.question(name, qtype)
    q.add_ar(EDNS0(udp_len=1232))
    return q


def _extract_ede_options(resp: DNSRecord) -> List[Tuple[int, str]]:
    """Brief: Return a list of (info_code, text) for all EDE options in resp.

    Inputs:
      - resp: Parsed DNSRecord response.

    Outputs:
      - List of (info_code, EXTRA-TEXT) tuples for each EDE (option-code 15).
    """

    out: List[Tuple[int, str]] = []
    for rr in resp.ar or []:
        if getattr(rr, "rtype", None) != QTYPE.OPT:
            continue
        for opt in getattr(rr, "rdata", []) or []:
            if not isinstance(opt, EDNSOption):
                continue
            if int(getattr(opt, "code", 0)) != 15:
                continue
            data = bytes(getattr(opt, "data", b""))
            if len(data) < 2:
                continue
            code = int.from_bytes(data[:2], "big")
            text = ""
            if len(data) > 2:
                try:
                    text = data[2:].decode("utf-8", errors="replace")
                except Exception:
                    text = ""
            out.append((code, text))
    return out


class _PreDenyDefault:
    def pre_resolve(self, qname, qtype, data, ctx):  # noqa: D401
        """Inputs: qname/qtype/wire/ctx. Outputs: deny decision without hints."""

        return srv.PluginDecision(action="deny")

    def post_resolve(self, qname, qtype, data, ctx):  # pragma: no cover - unused
        return None


class _PreDenyRateLimit:
    def pre_resolve(self, qname, qtype, data, ctx):  # noqa: D401
        """Inputs: qname/qtype/wire/ctx. Outputs: deny decision with rate_limit stat."""

        return srv.PluginDecision(action="deny", stat="rate_limit")

    def post_resolve(self, qname, qtype, data, ctx):  # pragma: no cover - unused
        return None


class _PreDenyOverrideEde:
    def pre_resolve(self, qname, qtype, data, ctx):  # noqa: D401
        """Inputs: qname/qtype/wire/ctx. Outputs: deny decision with custom EDE."""

        return srv.PluginDecision(
            action="deny",
            ede_code=0,
            ede_text="custom pre failure",
        )

    def post_resolve(self, qname, qtype, data, ctx):  # pragma: no cover - unused
        return None


def _setup_shared(enable_ede: bool = True) -> None:
    """Brief: Reset shared DNSUDPHandler knobs for these tests.

    Inputs:
      - enable_ede: Whether to enable EDE generation on the handler.

    Outputs:
      - None; mutates srv.DNSUDPHandler.
    """

    srv.DNSUDPHandler.plugins = []
    srv.DNSUDPHandler.upstream_addrs = []
    srv.DNSUDPHandler.enable_ede = bool(enable_ede)


@pytest.mark.parametrize(
    "plugin_cls,expected",
    [
        (_PreDenyDefault, (15, "blocked by policy")),
        (_PreDenyRateLimit, (14, "rate limit exceeded")),
        (_PreDenyOverrideEde, (0, "custom pre failure")),
    ],
)
def test_pre_deny_nxdomain_attaches_expected_ede(plugin_cls, expected):
    """Brief: Pre-resolve deny decisions attach appropriate EDE options.

    Inputs:
      - plugin_cls: Plugin class producing a deny decision.
      - expected: Tuple(info_code, text) for the primary EDE option.

    Outputs:
      - Asserts NXDOMAIN and a single matching EDE for EDNS clients.
    """

    _setup_shared(enable_ede=True)
    srv.DNSUDPHandler.plugins = [plugin_cls()]

    q = _make_edns_query("ede-pre.example")
    result = srv._resolve_core(q.pack(), "127.0.0.1")
    resp = DNSRecord.parse(result.wire)

    assert resp.header.rcode == RCODE.NXDOMAIN
    edes = _extract_ede_options(resp)
    assert edes, "expected at least one EDE option"
    code, text = edes[0]
    exp_code, exp_text = expected
    assert code == exp_code
    assert exp_text in text


class _PostDenyDefault:
    post_priority = 1

    def pre_resolve(self, qname, qtype, data, ctx):  # noqa: D401
        """Inputs: qname/qtype/wire/ctx. Outputs: no-op pre decision."""

        return None

    def post_resolve(self, qname, qtype, data, ctx):  # noqa: D401
        """Inputs: qname/qtype/wire/ctx. Outputs: deny decision without hints."""

        return srv.PluginDecision(action="deny")


class _PostDenyOverrideEde:
    post_priority = 1

    def pre_resolve(self, qname, qtype, data, ctx):  # noqa: D401
        """Inputs: qname/qtype/wire/ctx. Outputs: no-op pre decision."""

        return None

    def post_resolve(self, qname, qtype, data, ctx):  # noqa: D401
        """Inputs: qname/qtype/wire/ctx. Outputs: deny decision with custom EDE."""

        return srv.PluginDecision(
            action="deny",
            ede_code=0,
            ede_text="custom post failure",
        )


@pytest.mark.parametrize(
    "plugin_cls,expected",
    [
        (_PostDenyDefault, (15, "blocked by policy")),
        (_PostDenyOverrideEde, (0, "custom post failure")),
    ],
)
def test_post_deny_nxdomain_attaches_expected_ede(monkeypatch, plugin_cls, expected):
    """Brief: Post-resolve deny decisions attach appropriate EDE options.

    Inputs:
      - plugin_cls: Plugin class producing a post-resolve deny decision.
      - expected: Tuple(info_code, text) for the primary EDE option.

    Outputs:
      - Asserts NXDOMAIN and a single matching EDE for EDNS clients.
    """

    _setup_shared(enable_ede=True)
    # Stub upstream forwarding to return a simple NOERROR answer.
    q = _make_edns_query("ede-post.example")
    ok = q.reply().pack()

    def fake_forward(
        req, upstreams, timeout_ms, qname, qtype, max_concurrent=None
    ):  # noqa: ANN001
        return ok, {"host": "1.1.1.1", "port": 53}, "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", fake_forward)

    srv.DNSUDPHandler.plugins = [plugin_cls()]
    srv.DNSUDPHandler.upstream_addrs = [{"host": "1.1.1.1", "port": 53}]

    result = srv._resolve_core(q.pack(), "127.0.0.1")
    resp = DNSRecord.parse(result.wire)

    assert resp.header.rcode == RCODE.NXDOMAIN
    edes = _extract_ede_options(resp)
    assert edes, "expected at least one EDE option"
    code, text = edes[0]
    exp_code, exp_text = expected
    assert code == exp_code
    assert exp_text in text


def test_all_upstreams_failed_servfail_has_network_error_ede(monkeypatch):
    """Brief: All-upstreams-failed SERVFAIL carries a Network Error EDE.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts SERVFAIL with an EDE code 23 for EDNS clients.
    """

    _setup_shared(enable_ede=True)

    def fail_forward(
        req, upstreams, timeout_ms, qname, qtype, max_concurrent=None
    ):  # noqa: ANN001
        return None, {"host": "8.8.8.8", "port": 53}, "all_failed"

    monkeypatch.setattr(srv, "send_query_with_failover", fail_forward)

    srv.DNSUDPHandler.upstream_addrs = [{"host": "8.8.8.8", "port": 53}]

    q = _make_edns_query("ede-upstream-fail.example")
    result = srv._resolve_core(q.pack(), "127.0.0.1")
    resp = DNSRecord.parse(result.wire)

    assert resp.header.rcode == RCODE.SERVFAIL
    edes = _extract_ede_options(resp)
    assert edes, "expected at least one EDE option"
    code, text = edes[0]
    assert code == 23
    assert "all upstreams failed" in text


def test_resolve_core_outer_exception_attaches_other_ede(monkeypatch):
    """Brief: _resolve_core outer exception path attaches a generic Other EDE.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts SERVFAIL with an EDE code 0 and generic error text.
    """

    _setup_shared(enable_ede=True)

    # Force PluginContext construction to raise so the outer try/except is used.
    class Boom(Exception):
        pass

    def boom_init(self, client_ip, listener=None, secure=None):  # noqa: D401, ANN001
        """Always raise to simulate an unexpected resolver error."""

        raise Boom("boom")

    monkeypatch.setattr(srv.PluginContext, "__init__", boom_init)

    q = _make_edns_query("ede-outer-exc.example")
    result = srv._resolve_core(q.pack(), "127.0.0.1")
    resp = DNSRecord.parse(result.wire)

    assert resp.header.rcode == RCODE.SERVFAIL
    edes = _extract_ede_options(resp)
    assert edes, "expected at least one EDE option"
    code, text = edes[0]
    assert code == 0
    assert "internal" in text.lower() or "error" in text.lower()


def test_dnssec_bogus_attaches_dnssec_ede(monkeypatch):
    """Brief: dnssec_bogus classification results in a DNSSEC Bogus EDE only.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts NOERROR with an EDE code 6 when dnssec_status is dnssec_bogus.
    """

    _setup_shared(enable_ede=True)
    # Ensure DNSSEC validation is active and uses local classification.
    srv.DNSUDPHandler.dnssec_mode = "validate"
    srv.DNSUDPHandler.dnssec_validation = "local"

    # Stub classify_dnssec_status to always return dnssec_bogus so that the
    # resolver attaches a DNSSEC Bogus EDE without needing real DNSSEC material.
    import foghorn.dnssec.dnssec_validate as dval

    monkeypatch.setattr(
        dval,
        "classify_dnssec_status",
        lambda dnssec_mode, dnssec_validation, qname_text, qtype_num, response_wire, udp_payload_size=1232: "dnssec_bogus",
    )

    # Upstream path returns a simple NOERROR A answer so that the pipeline
    # exercises the standard upstream stats and DNSSEC classification path.
    q = _make_edns_query("dnssec-bogus.example")
    # A simple NOERROR reply without real DNSSEC material is sufficient here;
    # classify_dnssec_status is stubbed to force a dnssec_bogus verdict.
    ok = q.reply()
    ok_wire = ok.pack()

    def fake_forward(
        req, upstreams, timeout_ms, qname, qtype, max_concurrent=None
    ):  # noqa: ANN001
        return ok_wire, {"host": "8.8.8.8", "port": 53}, "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", fake_forward)
    srv.DNSUDPHandler.upstream_addrs = [{"host": "8.8.8.8", "port": 53}]

    result = srv._resolve_core(q.pack(), "127.0.0.1")
    resp = DNSRecord.parse(result.wire)

    # Underlying answer remains NOERROR but carries a DNSSEC Bogus EDE.
    assert resp.header.rcode == RCODE.NOERROR
    edes = _extract_ede_options(resp)
    assert edes, "expected at least one EDE option"
    code, text = edes[0]
    assert code == 6
    assert "bogus" in text.lower() or "dnssec" in text.lower()


def _make_notify_query(name: str = "notify.example") -> DNSRecord:
    """Brief: Build a NOTIFY opcode query with EDNS(0) enabled.

    Inputs:
      - name: Zone name used in the SOA-style question.

    Outputs:
      - DNSRecord representing a NOTIFY for the given name.
    """

    q = _make_edns_query(name, "SOA")
    # Switch opcode from QUERY to NOTIFY so the core resolver takes the
    # notification path while preserving the rest of the question.
    q.header.opcode = OPCODE.NOTIFY
    return q


def test_notify_over_udp_is_refused_with_ede() -> None:
    """Brief: UDP NOTIFY queries are refused with a Not Supported EDE when enabled.

    Inputs:
      - None.

    Outputs:
      - Asserts REFUSED and EDE code 22 for EDNS clients on UDP listener.
    """

    _setup_shared(enable_ede=True)
    q = _make_notify_query("notify-udp.example")

    result = srv._resolve_core(q.pack(), "192.0.2.10", listener="udp")
    resp = DNSRecord.parse(result.wire)

    assert resp.header.rcode == RCODE.REFUSED
    edes = _extract_ede_options(resp)
    assert edes, "expected at least one EDE option on UDP NOTIFY"
    code, text = edes[0]
    assert code == 22
    assert "notify" in text.lower()


def test_notify_unknown_sender_over_tcp_is_refused_with_ede() -> None:
    """Brief: Non-UDP NOTIFY from an unknown sender is refused with a Blocked EDE.

    Inputs:
      - None.

    Outputs:
      - Asserts REFUSED and EDE code 15 for EDNS clients on non-UDP listeners.
    """

    _setup_shared(enable_ede=True)
    # Configure a different upstream host so the sender IP does not match.
    srv.DNSUDPHandler.upstream_addrs = [{"host": "192.0.2.200", "port": 53}]

    q = _make_notify_query("notify-unknown.example")

    result = srv._resolve_core(q.pack(), "192.0.2.10", listener="tcp")
    resp = DNSRecord.parse(result.wire)

    assert resp.header.rcode == RCODE.REFUSED
    edes = _extract_ede_options(resp)
    assert edes, "expected at least one EDE option on unknown-sender NOTIFY"
    code, text = edes[0]
    assert code == 15
    assert "upstream" in text.lower() or "notify" in text.lower()


def test_notify_known_sender_logs_and_acks_noerror(caplog) -> None:
    """Brief: Non-UDP NOTIFY from a configured upstream is logged and acknowledged.

    Inputs:
      - caplog: Pytest logging capture fixture.

    Outputs:
      - Asserts NOERROR response and a critical log mentioning NOTIFY.
    """

    _setup_shared(enable_ede=False)
    # Sender IP matches configured upstream host directly.
    sender_ip = "198.51.100.5"
    srv.DNSUDPHandler.upstream_addrs = [{"host": sender_ip, "port": 53}]

    # Clear any prior LRU cache entries so upstream mapping reflects this config.
    resolver = getattr(srv, "_resolve_notify_sender_upstream", None)
    if resolver is not None and hasattr(resolver, "cache_clear"):
        resolver.cache_clear()

    q = _make_notify_query("notify-known.example")

    with caplog.at_level("CRITICAL", logger="foghorn.server"):
        result = srv._resolve_core(q.pack(), sender_ip, listener="tcp")

    resp = DNSRecord.parse(result.wire)
    assert resp.header.rcode == RCODE.NOERROR

    messages = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "NOTIFY" in messages or "notify" in messages


def test_notify_known_sender_triggers_axfr_refresh(monkeypatch, tmp_path) -> None:
    """Brief: Non-UDP NOTIFY from a configured upstream triggers AXFR refresh.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture used to stub AXFR and threading.
      - tmp_path: Pytest temporary directory used for a minimal records file.

    Outputs:
      - Asserts that an AXFR-backed ZoneRecords plugin performs a new AXFR
        transfer when a matching NOTIFY is received from a configured upstream.
    """

    _setup_shared(enable_ede=False)

    # Seed a simple file-backed record so ZoneRecords.setup() succeeds.
    records_file = tmp_path / "records.txt"
    records_file.write_text("seed.test|A|300|192.0.2.10\n", encoding="utf-8")

    # Prepare a ZoneRecords plugin with a single AXFR-backed zone whose masters
    # include the NOTIFY sender IP.
    import foghorn.plugins.resolve.zone_records as mod

    ZoneRecords = mod.ZoneRecords

    calls = {"axfr": 0}

    def fake_axfr_transfer(host, port, zone, **kwargs):  # noqa: ANN001,ARG001
        """Inputs: host/port/zone/kwargs. Outputs: minimal synthetic AXFR RRset."""

        from dnslib import A as _A, RR as _RR

        calls["axfr"] += 1
        return [_RR("host.%s." % zone, QTYPE.A, rdata=_A("203.0.113.5"), ttl=123)]

    monkeypatch.setattr(mod, "axfr_transfer", fake_axfr_transfer)

    sender_ip = "198.51.100.5"
    plugin = ZoneRecords(
        file_paths=[str(records_file)],
        axfr_zones=[
            {
                "zone": "notify-known.example",
                "upstreams": [{"host": sender_ip, "port": 53}],
            }
        ],
    )
    plugin.setup()

    # Initial setup performs one AXFR.
    assert calls["axfr"] == 1

    # Wire the plugin into DNSUDPHandler so NOTIFY handling can find it.
    srv.DNSUDPHandler.plugins = [plugin]
    srv.DNSUDPHandler.upstream_addrs = [{"host": sender_ip, "port": 53}]

    # Ensure NOTIFY sender resolution uses the current upstream config.
    resolver = getattr(srv, "_resolve_notify_sender_upstream", None)
    if resolver is not None and hasattr(resolver, "cache_clear"):
        resolver.cache_clear()

    # Make background AXFR refresh deterministic by replacing Thread with a stub
    # that runs the target synchronously when start() is called.
    class _ImmediateThread:
        def __init__(self, target=None, name=None, daemon=None):  # noqa: D401,ANN001
            """Inputs: target/name/daemon. Outputs: thread-like stub."""

            self._target = target

        def start(self) -> None:  # noqa: D401
            """Inputs: None. Outputs: immediately runs the target callable."""

            if callable(self._target):
                self._target()

    monkeypatch.setattr(srv.threading, "Thread", _ImmediateThread)

    q = _make_notify_query("notify-known.example")
    result = srv._resolve_core(q.pack(), sender_ip, listener="tcp")

    resp = DNSRecord.parse(result.wire)
    assert resp.header.rcode == RCODE.NOERROR

    # AXFR should have been invoked again by the NOTIFY handler.
    assert calls["axfr"] >= 2
