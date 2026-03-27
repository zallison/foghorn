"""Brief: Regression tests for EDNS COOKIE handling in resolver/cache paths.

Inputs:
  - None (pytest fixtures provide runtime and monkeypatch state).

Outputs:
  - None; assertions verify COOKIE rebinding/stripping semantics.
"""

from __future__ import annotations

from dnslib import A, EDNS0, QTYPE, RR, DNSRecord, EDNSOption

import foghorn.servers.server as srv
from foghorn.plugins.resolve import base as plugin_base


def _make_cookie_query(name: str, cookie_bytes: bytes) -> DNSRecord:
    """Brief: Build an EDNS query carrying a DNS COOKIE option.

    Inputs:
      - name: Query owner name.
      - cookie_bytes: Raw COOKIE option payload bytes.

    Outputs:
      - DNSRecord: Question with an OPT RR containing COOKIE option-code 10.
    """

    q = DNSRecord.question(name, "A")
    opt = EDNS0(udp_len=1232)
    opt.rdata.append(EDNSOption(10, bytes(cookie_bytes)))
    q.add_ar(opt)
    return q


def _extract_cookie_from_response(resp: DNSRecord) -> bytes | None:
    """Brief: Extract COOKIE option bytes from a parsed response, if present.

    Inputs:
      - resp: Parsed DNS response DNSRecord.

    Outputs:
      - bytes | None: COOKIE option payload from the first OPT, or None.
    """

    for rr in getattr(resp, "ar", None) or []:
        if getattr(rr, "rtype", None) != QTYPE.OPT:
            continue
        for opt in getattr(rr, "rdata", None) or []:
            if isinstance(opt, EDNSOption) and int(getattr(opt, "code", -1)) == 10:
                try:
                    return bytes(getattr(opt, "data", b"") or b"")
                except Exception:
                    return None
    return None


def test_cache_hit_rebinds_cookie_and_cache_payload_strips_cookie(
    monkeypatch,
    set_runtime_snapshot,
):
    """Brief: Cache hits must rebind COOKIE to each request and store cookie-free wire.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - set_runtime_snapshot: Fixture helper to initialize runtime snapshot.

    Outputs:
      - None; asserts request-bound COOKIE response and cookie-free cache payload.
    """

    qname = "cookie-cache.example"
    stale_cookie = bytes.fromhex("aaaaaaaaaaaaaaaa")
    cookie_one = bytes.fromhex("1111111111111111")
    cookie_two = bytes.fromhex("2222222222222222")
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
        opt = EDNS0(udp_len=1232)
        opt.rdata.append(EDNSOption(10, stale_cookie))
        r.add_ar(opt)
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
    )

    resp1 = DNSRecord.parse(
        srv.resolve_query_bytes(
            _make_cookie_query(qname, cookie_one).pack(), "127.0.0.1"
        )
    )
    assert _extract_cookie_from_response(resp1) == cookie_one

    resp2 = DNSRecord.parse(
        srv.resolve_query_bytes(
            _make_cookie_query(qname, cookie_two).pack(), "127.0.0.1"
        )
    )
    assert _extract_cookie_from_response(resp2) == cookie_two

    assert calls["count"] == 1

    cached_wire = plugin_base.DNS_CACHE.get((qname, QTYPE.A))
    assert cached_wire is not None
    cached_resp = DNSRecord.parse(cached_wire)
    assert _extract_cookie_from_response(cached_resp) is None


def test_response_cookie_is_removed_when_request_has_no_cookie(
    monkeypatch,
    set_runtime_snapshot,
):
    """Brief: Requests without COOKIE must not receive stale COOKIE from upstream reply.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - set_runtime_snapshot: Fixture helper to initialize runtime snapshot.

    Outputs:
      - None; asserts response COOKIE option is removed.
    """

    qname = "cookie-strip.example"
    stale_cookie = bytes.fromhex("bbbbbbbbbbbbbbbb")

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
        r.add_answer(RR(qname, rdata=A("5.6.7.8"), ttl=120))
        opt = EDNS0(udp_len=1232)
        opt.rdata.append(EDNSOption(10, stale_cookie))
        r.add_ar(opt)
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
    )

    q = DNSRecord.question(qname, "A")
    resp = DNSRecord.parse(srv.resolve_query_bytes(q.pack(), "127.0.0.1"))
    assert _extract_cookie_from_response(resp) is None
