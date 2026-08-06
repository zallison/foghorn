"""Brief: Unit and pipeline tests for downstream DNS COOKIE (RFC 7873).

Inputs:
  - None (pytest fixtures provide runtime/monkeypatch state).

Outputs:
  - None; assertions verify cookie crypto, learn mode, require_udp, cache hygiene.
"""

from __future__ import annotations

from dnslib import EDNS0, QTYPE, RR, A, DNSRecord, EDNSOption

import foghorn.servers.edns_utils as edns
import foghorn.servers.server as srv
from foghorn.plugins.resolve import base as plugin_base
from foghorn.runtime_config import resolve_server_feature_flags


def _cookie_opt(payload: bytes) -> EDNS0:
    opt = EDNS0(udp_len=1232)
    opt.rdata.append(EDNSOption(10, bytes(payload)))
    return opt


def _make_query(name: str, cookie_payload: bytes | None = None) -> DNSRecord:
    q = DNSRecord.question(name, "A")
    if cookie_payload is not None:
        q.add_ar(_cookie_opt(cookie_payload))
    else:
        q.add_ar(EDNS0(udp_len=1232))
    return q


def _full_rcode(resp: DNSRecord) -> int:
    """Brief: Combine header RCODE with EDNS extended RCODE.

    Inputs:
      - resp: Parsed DNS response.

    Outputs:
      - int: Full RCODE including extended high bits.
    """

    low = int(getattr(resp.header, "rcode", 0) or 0) & 0x0F
    high = 0
    for rr in getattr(resp, "ar", None) or []:
        if getattr(rr, "rtype", None) != QTYPE.OPT:
            continue
        try:
            ttl_val = int(getattr(rr, "ttl", 0) or 0)
            high = (ttl_val >> 24) & 0xFF
        except Exception:
            high = 0
        break
    return (high << 4) | low


def _extract_cookie(resp: DNSRecord) -> bytes | None:
    for rr in getattr(resp, "ar", None) or []:
        if getattr(rr, "rtype", None) != QTYPE.OPT:
            continue
        for opt in getattr(rr, "rdata", None) or []:
            if isinstance(opt, EDNSOption) and int(getattr(opt, "code", -1)) == 10:
                return bytes(getattr(opt, "data", b"") or b"")
    return None


def test_generate_and_validate_server_cookie_roundtrip():
    """Brief: Server cookie MAC validates for matching IP/client cookie.

    Inputs/Outputs: None; asserts validate_server_cookie True/False cases.
    """

    secret = b"unit-test-secret-key-32-bytes!!"
    client = bytes.fromhex("1111111111111111")
    sc = edns.generate_server_cookie(
        client_cookie=client, client_ip="203.0.113.10", secret=secret, now=1_700_000_000
    )
    assert len(sc) == 16
    assert edns.validate_server_cookie(
        client_cookie=client,
        server_cookie=sc,
        client_ip="203.0.113.10",
        secret=secret,
        lifetime_seconds=86400,
        now=1_700_000_000,
    )
    assert not edns.validate_server_cookie(
        client_cookie=client,
        server_cookie=sc,
        client_ip="203.0.113.11",
        secret=secret,
        lifetime_seconds=86400,
        now=1_700_000_000,
    )


def test_validate_server_cookie_rollover_and_expiry():
    """Brief: Old secret validates during rollover; expired cookies fail.

    Inputs/Outputs: None; asserts secret_old acceptance and lifetime expiry.
    """

    old = b"old-secret-value-xxxxxxxxxxxx"
    new = b"new-secret-value-xxxxxxxxxxxx"
    client = bytes.fromhex("aaaaaaaaaaaaaaaa")
    sc = edns.generate_server_cookie(
        client_cookie=client,
        client_ip="198.51.100.2",
        secret=old,
        key_id=1,
        now=1_700_000_000,
    )
    assert edns.validate_server_cookie(
        client_cookie=client,
        server_cookie=sc,
        client_ip="198.51.100.2",
        secret=new,
        secret_old=old,
        lifetime_seconds=100,
        now=1_700_000_050,
    )
    assert not edns.validate_server_cookie(
        client_cookie=client,
        server_cookie=sc,
        client_ip="198.51.100.2",
        secret=new,
        secret_old=old,
        lifetime_seconds=10,
        now=1_700_000_050,
    )


def test_feature_flags_cookies_default_enabled():
    """Brief: cookies default enabled/learn and mint ephemeral secret.

    Inputs/Outputs: None; asserts resolve_server_feature_flags defaults.
    """

    flags = resolve_server_feature_flags({})
    assert flags["cookies_enabled"] is True
    assert flags["cookies_mode"] == "learn"
    assert isinstance(flags["cookies_secret"], (bytes, bytearray))
    assert flags["cookies_lifetime_seconds"] == 86400


def test_learn_mode_attaches_server_cookie_and_strips_cache(
    monkeypatch, set_runtime_snapshot
):
    """Brief: Learn mode returns client||server cookie; cache stores cookie-free wire.

    Inputs/Outputs: None; asserts response cookie shape and cache hygiene.
    """

    secret = b"pipeline-learn-secret-bytes!!!"
    client = bytes.fromhex("2222222222222222")
    qname = "cookie-learn.example"
    calls = {"count": 0}

    def _forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        calls["count"] += 1
        r = req.reply()
        r.add_answer(RR(qname, rdata=A("1.2.3.4"), ttl=120))
        stale = EDNS0(udp_len=1232)
        stale.rdata.append(
            EDNSOption(10, bytes.fromhex("ffffffffffffffff") + b"stale-server")
        )
        r.add_ar(stale)
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        cookies_enabled=True,
        cookies_mode="learn",
        cookies_secret=secret,
        cookies_secret_old=None,
        cookies_lifetime_seconds=86400,
    )

    resp = DNSRecord.parse(
        srv.resolve_query_bytes(
            _make_query(qname, client).pack(), "203.0.113.5", listener="udp"
        )
    )
    payload = _extract_cookie(resp)
    assert payload is not None
    assert payload[:8] == client
    assert len(payload) == 8 + 16
    assert edns.validate_server_cookie(
        client_cookie=client,
        server_cookie=payload[8:],
        client_ip="203.0.113.5",
        secret=secret,
    )

    cached_wire = plugin_base.DNS_CACHE.get((qname, QTYPE.A))
    assert cached_wire is not None
    cached = DNSRecord.parse(cached_wire)
    assert _extract_cookie(cached) is None
    assert calls["count"] == 1

    # Cache hit rebinds a fresh server cookie for a different client cookie.
    client2 = bytes.fromhex("3333333333333333")
    resp2 = DNSRecord.parse(
        srv.resolve_query_bytes(
            _make_query(qname, client2).pack(), "203.0.113.5", listener="udp"
        )
    )
    payload2 = _extract_cookie(resp2)
    assert payload2 is not None and payload2[:8] == client2
    assert calls["count"] == 1


def test_require_udp_badcookie_skips_upstream(monkeypatch, set_runtime_snapshot):
    """Brief: require_udp returns BADCOOKIE without upstream work when invalid.

    Inputs/Outputs: None; asserts RCODE 23 and zero upstream calls.
    """

    secret = b"pipeline-require-secret-bytes!"
    calls = {"count": 0}

    def _forward(*args, **kwargs):
        calls["count"] += 1
        raise AssertionError("upstream should not be called")

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        cookies_enabled=True,
        cookies_mode="require_udp",
        cookies_secret=secret,
        cookies_secret_old=None,
        cookies_lifetime_seconds=86400,
    )

    client = bytes.fromhex("4444444444444444")
    wire = srv.resolve_query_bytes(
        _make_query("cookie-require.example", client).pack(),
        "198.51.100.9",
        listener="udp",
    )
    resp = DNSRecord.parse(wire)
    assert _full_rcode(resp) == 23
    payload = _extract_cookie(resp)
    assert payload is not None and payload[:8] == client
    assert calls["count"] == 0


def test_require_udp_accepts_valid_cookie(monkeypatch, set_runtime_snapshot):
    """Brief: Valid server cookie allows normal UDP resolve under require_udp.

    Inputs/Outputs: None; asserts NOERROR answer and one upstream call.
    """

    secret = b"pipeline-require-valid-secret!"
    client = bytes.fromhex("5555555555555555")
    server = edns.generate_server_cookie(
        client_cookie=client, client_ip="198.51.100.10", secret=secret
    )
    calls = {"count": 0}

    def _forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        calls["count"] += 1
        r = req.reply()
        r.add_answer(RR(qname, rdata=A("9.9.9.9"), ttl=60))
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        cookies_enabled=True,
        cookies_mode="require_udp",
        cookies_secret=secret,
        cookies_lifetime_seconds=86400,
    )
    resp = DNSRecord.parse(
        srv.resolve_query_bytes(
            _make_query("cookie-ok.example", client + server).pack(),
            "198.51.100.10",
            listener="udp",
        )
    )
    assert int(resp.header.rcode) == 0
    assert calls["count"] == 1


def test_require_udp_does_not_block_tcp(monkeypatch, set_runtime_snapshot):
    """Brief: TCP still resolves without prior cookie under require_udp mode.

    Inputs/Outputs: None; asserts NOERROR on TCP listener without cookie.
    """

    secret = b"pipeline-require-tcp-secret!!!"
    calls = {"count": 0}

    def _forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        calls["count"] += 1
        r = req.reply()
        r.add_answer(RR(qname, rdata=A("8.8.8.8"), ttl=60))
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        cookies_enabled=True,
        cookies_mode="require_udp",
        cookies_secret=secret,
    )
    resp = DNSRecord.parse(
        srv.resolve_query_bytes(
            _make_query("cookie-tcp.example").pack(),
            "198.51.100.11",
            listener="tcp",
        )
    )
    assert int(resp.header.rcode) == 0
    assert calls["count"] == 1


def test_disabled_mode_preserves_client_cookie_hygiene(
    monkeypatch, set_runtime_snapshot
):
    """Brief: Disabled cookies keep legacy client-cookie echo hygiene.

    Inputs/Outputs: None; asserts 8-byte echo and cookie-free cache payload.
    """

    client = bytes.fromhex("6666666666666666")
    qname = "cookie-disabled.example"

    def _forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        r = req.reply()
        r.add_answer(RR(qname, rdata=A("4.4.4.4"), ttl=60))
        stale = EDNS0(udp_len=1232)
        stale.rdata.append(EDNSOption(10, bytes.fromhex("bbbbbbbbbbbbbbbb")))
        r.add_ar(stale)
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        cookies_enabled=False,
        cookies_mode="learn",
        cookies_secret=None,
    )
    resp = DNSRecord.parse(
        srv.resolve_query_bytes(_make_query(qname, client).pack(), "127.0.0.1")
    )
    payload = _extract_cookie(resp)
    assert payload == client
    cached = DNSRecord.parse(plugin_base.DNS_CACHE.get((qname, QTYPE.A)))
    assert _extract_cookie(cached) is None
