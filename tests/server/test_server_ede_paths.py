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
from dnslib import DNSRecord, EDNS0, EDNSOption, QTYPE, RCODE

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
