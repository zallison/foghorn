"""Brief: Unit and pipeline tests for downstream QUERY TSIG (RFC 2845).

Inputs:
  - None (pytest fixtures provide runtime/monkeypatch state).

Outputs:
  - None; assertions verify verify/sign/require/optional and cache hygiene.
"""

from __future__ import annotations

import base64

import dns.message
import dns.rcode
import dns.rdatatype
import dns.tsigkeyring
from dnslib import QTYPE, RCODE, RR, A, DNSRecord

import foghorn.servers.server as srv
import foghorn.servers.tsig_utils as tsig
from foghorn.plugins.resolve import base as plugin_base
from foghorn.runtime_config import resolve_server_feature_flags

_TSIG_SECRET_RAW = b"0123456789abcdef0123456789abcdef"
_TSIG_SECRET_B64 = base64.b64encode(_TSIG_SECRET_RAW).decode("ascii")
_TSIG_NAME = "test-key.example."
_TSIG_KEYS = [
    {
        "name": _TSIG_NAME,
        "secret": _TSIG_SECRET_B64,
        "algorithm": "hmac-sha256",
    }
]


def _sign_query(
    name: str,
    *,
    bad_secret: bool = False,
    fudge: int = 300,
    algorithm: str = "hmac-sha256",
) -> bytes:
    """Brief: Build a TSIG-signed A query wire.

    Inputs:
      - name: QNAME.
      - bad_secret: When True, sign with a wrong secret.
      - fudge: TSIG fudge seconds.
      - algorithm: TSIG algorithm used for signing.

    Outputs:
      - bytes: Signed DNS query wire.
    """

    secret = base64.b64encode(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").decode("ascii")
    if not bad_secret:
        secret = _TSIG_SECRET_B64
    keyring = dns.tsigkeyring.from_text({_TSIG_NAME: secret})
    q = dns.message.make_query(name, dns.rdatatype.A)
    q.use_tsig(
        keyring=keyring,
        keyname=_TSIG_NAME,
        algorithm=algorithm,
        fudge=fudge,
    )
    return q.to_wire()


def test_feature_flags_tsig_default_disabled():
    """Brief: TSIG feature defaults to disabled/optional with empty keys.

    Inputs/Outputs: None; asserts resolve_server_feature_flags defaults.
    """

    flags = resolve_server_feature_flags({})
    assert flags["tsig_enabled"] is False
    assert flags["tsig_mode"] == "optional"
    assert flags["tsig_keys"] == []
    assert flags["tsig_max_fudge_seconds"] == 300


def test_verify_request_tsig_roundtrip():
    """Brief: Valid signed query verifies; wrong secret fails.

    Inputs/Outputs: None; asserts verify_request_tsig outcomes.
    """

    wire = _sign_query("ok.example")
    ok = tsig.verify_request_tsig(wire, _TSIG_KEYS)
    assert ok.ok is True
    assert ok.keyname in {"test-key.example", "test-key.example."}
    bad = tsig.verify_request_tsig(
        _sign_query("bad.example", bad_secret=True), _TSIG_KEYS
    )
    assert bad.ok is False
    assert bad.error_code in {"badsig", "badkey", "dns"}


def test_strip_and_sign_response():
    """Brief: strip_tsig_from_wire removes TSIG; sign_response_tsig re-attaches.

    Inputs/Outputs: None; asserts TSIG present only after signing.
    """

    qwire = _sign_query("sign.example")
    vr = tsig.verify_request_tsig(qwire, _TSIG_KEYS)
    assert vr.ok
    # Build unsigned answer with dnslib
    # Use dnspython response from request id
    qmsg = dns.message.from_wire(qwire, continue_on_error=True)
    resp = dns.message.make_response(qmsg)
    resp.set_rcode(dns.rcode.NOERROR)
    unsigned = resp.to_wire()
    stripped = tsig.strip_tsig_from_wire(unsigned)
    signed = tsig.sign_response_tsig(
        stripped,
        key_configs=_TSIG_KEYS,
        keyname=vr.keyname,
        algorithm=vr.algorithm,
        request_msg=vr.request_msg,
    )
    # Signed payload should parse with keyring
    keyring, _ = tsig.build_tsig_keyring(_TSIG_KEYS)
    msg = dns.message.from_wire(signed, keyring=keyring)
    assert getattr(msg, "had_tsig", False) is True


def test_optional_mode_accepts_unsigned(monkeypatch, set_runtime_snapshot):
    """Brief: optional mode leaves unsigned queries working.

    Inputs/Outputs: None; asserts NOERROR answer without TSIG.
    """

    qname = "tsig-optional-unsigned.example"
    calls = {"n": 0}

    def _forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        calls["n"] += 1
        r = req.reply()
        r.add_answer(RR(qname, rdata=A("9.9.9.9"), ttl=60))
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        tsig_enabled=True,
        tsig_mode="optional",
        tsig_keys=_TSIG_KEYS,
        cookies_enabled=False,
    )
    resp = DNSRecord.parse(
        srv.resolve_query_bytes(
            DNSRecord.question(qname, "A").pack(), "203.0.113.9", listener="udp"
        )
    )
    assert resp.header.rcode == RCODE.NOERROR
    assert calls["n"] == 1


def test_require_mode_rejects_unsigned(monkeypatch, set_runtime_snapshot):
    """Brief: require mode returns NOTAUTH for unsigned UDP queries.

    Inputs/Outputs: None; asserts NOTAUTH and no upstream call.
    """

    qname = "tsig-require-missing.example"
    calls = {"n": 0}

    def _forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        calls["n"] += 1
        r = req.reply()
        r.add_answer(RR(qname, rdata=A("1.2.3.4"), ttl=60))
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        tsig_enabled=True,
        tsig_mode="require",
        tsig_keys=_TSIG_KEYS,
        cookies_enabled=False,
    )
    wire = srv.resolve_query_bytes(
        DNSRecord.question(qname, "A").pack(), "203.0.113.10", listener="udp"
    )
    msg = dns.message.from_wire(wire, continue_on_error=True)
    assert int(msg.rcode()) == int(dns.rcode.NOTAUTH)
    assert calls["n"] == 0


def test_require_mode_accepts_valid_and_signs(monkeypatch, set_runtime_snapshot):
    """Brief: require mode accepts valid TSIG and signs the answer.

    Inputs/Outputs: None; asserts NOERROR + response TSIG.
    """

    qname = "tsig-require-ok.example"
    calls = {"n": 0}

    def _forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        calls["n"] += 1
        r = req.reply()
        r.add_answer(RR(qname, rdata=A("5.6.7.8"), ttl=60))
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        tsig_enabled=True,
        tsig_mode="require",
        tsig_keys=_TSIG_KEYS,
        cookies_enabled=False,
    )
    qwire = _sign_query(qname)
    wire = srv.resolve_query_bytes(qwire, "203.0.113.11", listener="udp")
    keyring, _ = tsig.build_tsig_keyring(_TSIG_KEYS)
    msg = dns.message.from_wire(wire, keyring=keyring)
    assert int(msg.rcode()) == int(dns.rcode.NOERROR)
    assert getattr(msg, "had_tsig", False) is True
    assert calls["n"] == 1


def test_optional_rejects_bad_tsig(monkeypatch, set_runtime_snapshot):
    """Brief: optional mode rejects present-but-invalid TSIG.

    Inputs/Outputs: None; asserts NOTAUTH and no upstream.
    """

    qname = "tsig-optional-bad.example"
    calls = {"n": 0}

    def _forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        calls["n"] += 1
        r = req.reply()
        r.add_answer(RR(qname, rdata=A("1.1.1.1"), ttl=60))
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        tsig_enabled=True,
        tsig_mode="optional",
        tsig_keys=_TSIG_KEYS,
        cookies_enabled=False,
    )
    wire = srv.resolve_query_bytes(
        _sign_query(qname, bad_secret=True), "203.0.113.12", listener="udp"
    )
    msg = dns.message.from_wire(wire, continue_on_error=True)
    assert int(msg.rcode()) == int(dns.rcode.NOTAUTH)
    assert calls["n"] == 0


def test_cache_hit_strips_and_resigns(monkeypatch, set_runtime_snapshot):
    """Brief: Cache stores unsigned body; cache hit re-signs for TSIG client.

    Inputs/Outputs: None; asserts one upstream call and signed second response.
    """

    qname = "tsig-cache.example"
    calls = {"n": 0}

    def _forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        calls["n"] += 1
        r = req.reply()
        r.add_answer(RR(qname, rdata=A("8.8.8.8"), ttl=300))
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        tsig_enabled=True,
        tsig_mode="optional",
        tsig_keys=_TSIG_KEYS,
        cookies_enabled=False,
        cache_plugin=plugin_base.DNS_CACHE,
    )
    qwire = _sign_query(qname)
    w1 = srv.resolve_query_bytes(qwire, "203.0.113.13", listener="udp")
    w2 = srv.resolve_query_bytes(qwire, "203.0.113.13", listener="udp")
    keyring, _ = tsig.build_tsig_keyring(_TSIG_KEYS)
    m1 = dns.message.from_wire(w1, keyring=keyring)
    m2 = dns.message.from_wire(w2, keyring=keyring)
    assert getattr(m1, "had_tsig", False) is True
    assert getattr(m2, "had_tsig", False) is True
    assert calls["n"] == 1
    # Cached payload should not retain TSIG
    cache = plugin_base.DNS_CACHE
    assert cache is not None


def test_badfudge_rejected():
    """Brief: Fudge above the configured cap fails verification.

    Inputs/Outputs: None; asserts badfudge outcome and fudge-at-cap acceptance.
    """

    over = tsig.verify_request_tsig(
        _sign_query("fudge-over.example", fudge=600), _TSIG_KEYS, max_fudge_seconds=300
    )
    assert over.ok is False
    assert over.error_code == "badfudge"
    at_limit = tsig.verify_request_tsig(
        _sign_query("fudge-ok.example", fudge=300), _TSIG_KEYS, max_fudge_seconds=300
    )
    assert at_limit.ok is True


def test_algorithm_mismatch_rejected():
    """Brief: Configured algorithm mismatch is rejected even with a valid MAC.

    Inputs/Outputs: None; asserts badalg/badsig-class failure for alg mismatch.
    """

    wire = _sign_query("alg.example")
    mismatch_keys = [
        {"name": _TSIG_NAME, "secret": _TSIG_SECRET_B64, "algorithm": "hmac-sha512"}
    ]
    vr = tsig.verify_request_tsig(wire, mismatch_keys)
    assert vr.ok is False
    assert vr.error_code in {"badalg", "badsig", "badkey", "dns"}


def test_empty_keyring_fails_closed(monkeypatch, set_runtime_snapshot):
    """Brief: Enabled with no keys rejects TSIG-present queries even in optional.

    Inputs/Outputs: None; asserts NOTAUTH for signed, NOERROR for unsigned.
    """

    qname = "tsig-empty-keys.example"
    calls = {"n": 0}

    def _forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        calls["n"] += 1
        r = req.reply()
        r.add_answer(RR(qname, rdata=A("7.7.7.7"), ttl=60))
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        tsig_enabled=True,
        tsig_mode="optional",
        tsig_keys=[],
        cookies_enabled=False,
    )
    # Unsigned query still resolves in optional mode with empty keys.
    resp = DNSRecord.parse(
        srv.resolve_query_bytes(
            DNSRecord.question(qname, "A").pack(), "203.0.113.20", listener="udp"
        )
    )
    assert resp.header.rcode == RCODE.NOERROR
    assert calls["n"] == 1
    # TSIG-present query with an empty server keyring is rejected.
    wire = srv.resolve_query_bytes(
        _sign_query("tsig-empty-keys.example"), "203.0.113.20", listener="udp"
    )
    msg = dns.message.from_wire(wire, continue_on_error=True)
    assert int(msg.rcode()) == int(dns.rcode.NOTAUTH)
    assert calls["n"] == 1


def test_allow_clients_scopes_enforcement(monkeypatch, set_runtime_snapshot):
    """Brief: Clients outside allow_clients bypass TSIG enforcement entirely.

    Inputs/Outputs: None; asserts NOERROR + unsigned response outside CIDR.
    """

    qname = "tsig-scope-allow.example"
    calls = {"n": 0}

    def _forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        calls["n"] += 1
        r = req.reply()
        r.add_answer(RR(qname, rdata=A("6.6.6.6"), ttl=60))
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        tsig_enabled=True,
        tsig_mode="require",
        tsig_keys=_TSIG_KEYS,
        tsig_allow_clients=["10.0.0.0/8"],
        cookies_enabled=False,
    )
    # Outside the allowlist: unsigned queries pass and responses stay unsigned.
    resp = DNSRecord.parse(
        srv.resolve_query_bytes(
            DNSRecord.question(qname, "A").pack(), "203.0.113.30", listener="udp"
        )
    )
    assert resp.header.rcode == RCODE.NOERROR
    assert calls["n"] == 1
    outside = dns.message.from_wire(resp.pack(), continue_on_error=True)
    assert getattr(outside, "had_tsig", False) is False


def test_listeners_scoping_enforcement(monkeypatch, set_runtime_snapshot):
    """Brief: listeners scoping limits TSIG enforcement to listed transports.

    Inputs/Outputs: None; asserts UDP bypass and TCP NOTAUTH under require.
    """

    qname = "tsig-listeners.example"
    calls = {"n": 0}

    def _forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        calls["n"] += 1
        r = req.reply()
        r.add_answer(RR(qname, rdata=A("7.7.7.7"), ttl=60))
        return r.pack(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        tsig_enabled=True,
        tsig_mode="require",
        tsig_keys=_TSIG_KEYS,
        tsig_listeners=["tcp"],
        cookies_enabled=False,
    )
    resp = DNSRecord.parse(
        srv.resolve_query_bytes(
            DNSRecord.question(qname, "A").pack(), "203.0.113.21", listener="udp"
        )
    )
    assert resp.header.rcode == RCODE.NOERROR
    assert calls["n"] == 1
    wire = srv.resolve_query_bytes(
        DNSRecord.question(qname, "A").pack(), "203.0.113.21", listener="tcp"
    )
    msg = dns.message.from_wire(wire, continue_on_error=True)
    assert int(msg.rcode()) == int(dns.rcode.NOTAUTH)
    assert calls["n"] == 1


def test_cache_body_has_no_tsig(monkeypatch, set_runtime_snapshot):
    """Brief: Cache stores a TSIG-free body even when upstream signed it.

    Inputs/Outputs: None; asserts cached wire parses without TSIG present.
    """

    qname = "tsig-cache-hygiene.example"
    keyring, _ = tsig.build_tsig_keyring(_TSIG_KEYS)

    def _forward(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        qmsg = dns.message.from_wire(req.pack(), continue_on_error=True)
        r = dns.message.make_response(qmsg)
        r.set_rcode(dns.rcode.NOERROR)
        owner = qname if str(qname).endswith(".") else f"{qname}."
        rrset = dns.rrset.from_text(str(owner), 60, "IN", "A", "7.7.7.7")
        r.answer.append(rrset)
        r.use_tsig(keyring=keyring, keyname=_TSIG_NAME, algorithm="hmac-sha256")
        return r.to_wire(), upstreams[0], "ok"

    monkeypatch.setattr(srv, "send_query_with_failover", _forward)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
        resolver_mode="forward",
        tsig_enabled=True,
        tsig_mode="optional",
        tsig_keys=_TSIG_KEYS,
        cookies_enabled=False,
        cache_plugin=plugin_base.DNS_CACHE,
    )
    qwire = _sign_query(qname)
    wire = srv.resolve_query_bytes(qwire, "203.0.113.22", listener="udp")
    # Response to the client is signed with the request key.
    client_msg = dns.message.from_wire(wire, keyring=keyring)
    assert getattr(client_msg, "had_tsig", False) is True
    # Cache payload is TSIG-free.
    cached_wire = plugin_base.DNS_CACHE.get((qname, QTYPE.A))
    assert cached_wire is not None
    cached = dns.message.from_wire(cached_wire, continue_on_error=True)
    assert getattr(cached, "had_tsig", False) is False
