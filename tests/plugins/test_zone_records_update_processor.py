"""Brief: Tests for update_processor authorization helpers and parsing stubs.

Inputs/Outputs:
  - Minimal dnslib DNSRecord messages and temporary allow/block lists.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

import builtins
import threading
from types import SimpleNamespace

import dns.message
import dns.tsigkeyring
import dns.update
import pytest
from dnslib import A, DNSRecord, QTYPE, RCODE, RR

from foghorn.plugins.resolve.zone_records import update_processor as up


def test_normalize_dns_name_strips_dot_and_lowercases() -> None:
    assert up._normalize_dns_name("Example.COM.") == "example.com"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("hmac-sha512.", "hmac-sha512"),
        ("HMAC-SHA384.", "hmac-sha384"),
        ("hmac-sha256.", "hmac-sha256"),
        ("hmac-sha1.", "hmac-sha1"),
        ("hmac-md5.sig-alg.reg.int.", "hmac-md5"),
        ("unknown.", "unknown"),
    ],
)
def test_normalize_tsig_algorithm_variants(raw: str, expected: str) -> None:
    assert up._normalize_tsig_algorithm(raw) == expected


def test_verify_psk_auth_rejects_insecure_listener() -> None:
    ok, err = up.verify_psk_auth(
        request_token="t",
        zone_config={},
        listener="udp",
        token_configs=[{"token": "x"}],
    )
    assert ok is False
    assert err is not None
    assert "only allowed" in err.lower()


def test_verify_psk_auth_returns_error_when_bcrypt_missing(monkeypatch) -> None:
    orig_import = builtins.__import__

    def _fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "bcrypt":
            raise ImportError("no bcrypt")
        return orig_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _fake_import)

    ok, err = up.verify_psk_auth(
        request_token="t",
        zone_config={},
        listener="doh",
        token_configs=[{"token": "x"}],
    )
    assert ok is False
    assert err is not None
    assert "bcrypt" in err.lower()


def test_verify_psk_auth_accepts_valid_token(monkeypatch) -> None:
    class _FakeBcrypt:
        @staticmethod
        def checkpw(request: bytes, stored: bytes) -> bool:
            return request == b"secret" and stored == b"hash"

    monkeypatch.setitem(__import__("sys").modules, "bcrypt", _FakeBcrypt)

    ok, err = up.verify_psk_auth(
        request_token="secret",
        zone_config={},
        listener="dot",
        token_configs=[{"token": "hash"}],
    )
    assert ok is True
    assert err is None


def test_verify_psk_auth_rejects_invalid_token(monkeypatch) -> None:
    class _FakeBcrypt:
        @staticmethod
        def checkpw(request: bytes, stored: bytes) -> bool:
            return False

    monkeypatch.setitem(__import__("sys").modules, "bcrypt", _FakeBcrypt)

    ok, err = up.verify_psk_auth(
        request_token="secret",
        zone_config={},
        listener="dot",
        token_configs=[{"token": "hash"}],
    )
    assert ok is False
    assert err is not None
    assert "invalid" in err.lower()


def test_verify_client_authorization_allows_when_no_allowlist_configured() -> None:
    ctx = up.UpdateContext("example.com", "192.0.2.1", None, plugin=object())
    ok, err = up.verify_client_authorization(ctx, zone_config={})
    assert ok is True
    assert err is None


def test_verify_client_authorization_checks_allow_clients_inline() -> None:
    ctx = up.UpdateContext("example.com", "192.0.2.1", None, plugin=object())
    ok, err = up.verify_client_authorization(
        ctx,
        zone_config={"allow_clients": ["192.0.2.0/24"]},
    )
    assert ok is True
    assert err is None

    ctx2 = up.UpdateContext("example.com", "198.51.100.1", None, plugin=object())
    ok2, err2 = up.verify_client_authorization(
        ctx2,
        zone_config={"allow_clients": ["192.0.2.0/24"]},
    )
    assert ok2 is False
    assert err2 is not None


def test_verify_client_authorization_missing_files_treats_as_empty_list(
    tmp_path,
) -> None:
    # If a file-based allowlist is configured but missing/empty, combine_lists()
    # yields an empty list and the function currently treats that as "allow all".
    missing = tmp_path / "missing.txt"
    ctx = up.UpdateContext("example.com", "198.51.100.1", None, plugin=object())
    ok, err = up.verify_client_authorization(
        ctx,
        zone_config={"allow_clients_files": [str(missing)]},
    )
    assert ok is True
    assert err is None


def test_verify_name_authorization_block_then_allow() -> None:
    zone_cfg = {
        "block_names": ["blocked.*"],
        "allow_names": ["allowed.*"],
    }

    assert up.verify_name_authorization("blocked.example", zone_cfg) is False
    assert up.verify_name_authorization("allowed.example", zone_cfg) is True
    assert up.verify_name_authorization("other.example", zone_cfg) is False


def test_verify_name_authorization_empty_allowlist_is_treated_as_allow_all() -> None:
    assert up.verify_name_authorization("anything.example", {"allow_names": []}) is True


def test_verify_value_authorization_non_a_aaaa_is_not_validated() -> None:
    assert up.verify_value_authorization("203.0.113.1", QTYPE.MX, {}) is True


def test_verify_value_authorization_block_then_allow() -> None:
    zone_cfg = {
        "block_update_ips": ["192.0.2.0/24"],
        "allow_update_ips": ["198.51.100.0/24"],
    }

    assert up.verify_value_authorization("192.0.2.1", QTYPE.A, zone_cfg) is False
    assert up.verify_value_authorization("198.51.100.1", QTYPE.A, zone_cfg) is True
    assert up.verify_value_authorization("203.0.113.1", QTYPE.A, zone_cfg) is False


def test_verify_value_authorization_empty_allowlist_is_treated_as_allow_all() -> None:
    assert (
        up.verify_value_authorization("203.0.113.1", QTYPE.A, {"allow_update_ips": []})
        is True
    )


def test_parse_update_message_returns_none_on_parse_error() -> None:
    assert up.parse_update_message(b"\x00") is None


def test_process_update_message_returns_formerr_when_parse_fails() -> None:
    wire = up.process_update_message(
        b"\x00",
        zone_apex="example.com",
        zone_config={"tsig": {"keys": []}},
        plugin=object(),
        client_ip="192.0.2.1",
        listener="udp",
    )
    resp = dns.message.from_wire(wire, ignore_trailing=True)
    assert resp.rcode() == dns.rcode.FORMERR


def test_process_update_message_returns_notauth_when_no_auth_configured() -> None:
    req = dns.update.Update("example.com.").to_wire()
    wire = up.process_update_message(
        req,
        zone_apex="example.com",
        zone_config={},
        plugin=object(),
        client_ip="192.0.2.1",
        listener="udp",
    )
    resp = dns.message.from_wire(wire, ignore_trailing=True)
    assert resp.rcode() == dns.rcode.NOTAUTH


def test_process_update_message_returns_notimp_for_valid_tsig_update() -> None:
    key_name = "key.example.com."
    secret_b64 = "dGVzdHNlY3JldA=="
    keyring = dns.tsigkeyring.from_text({key_name: secret_b64})

    msg = dns.update.Update("example.com.")
    msg.use_tsig(keyring=keyring, keyname=key_name, algorithm="hmac-sha256")
    msg.add("host", 60, "A", "192.0.2.123")
    req_wire = msg.to_wire()

    # Parse request with keyring so we can validate response TSIG chaining.
    parsed_req = dns.message.from_wire(req_wire, keyring=keyring)

    resp_wire = up.process_update_message(
        req_wire,
        zone_apex="example.com",
        zone_config={
            "tsig": {
                "keys": [
                    {
                        "name": key_name,
                        "algorithm": "hmac-sha256",
                        "secret": secret_b64,
                    }
                ]
            }
        },
        plugin=object(),
        client_ip="192.0.2.1",
        listener="udp",
    )

    # Verify the response TSIG.
    parsed_resp = dns.message.from_wire(
        resp_wire,
        keyring=keyring,
        request_mac=parsed_req.mac,
    )
    assert parsed_resp.rcode() == dns.rcode.NOTIMP


def test_check_prerequisites_returns_noerror_even_when_nonempty() -> None:
    prereq = RR("example.com", QTYPE.A, rdata=A("192.0.2.1"))
    rcode, err = up.check_prerequisites([prereq], records={}, zone_apex="example.com")
    assert rcode == 0
    assert err is None


def test_resolve_tsig_key_by_name() -> None:
    zone_cfg = {
        "tsig": {
            "keys": [
                {"name": "k1.", "secret": "x", "algorithm": "hmac-sha256"},
                {"name": "k2.", "secret": "y", "algorithm": "hmac-sha256"},
            ]
        }
    }

    assert up.resolve_tsig_key_by_name("k2.", zone_cfg, dns_update_config={}) == {
        "name": "k2.",
        "secret": "y",
        "algorithm": "hmac-sha256",
    }
    assert (
        up.resolve_tsig_key_by_name("missing.", zone_cfg, dns_update_config={}) is None
    )
    assert up.resolve_tsig_key_by_name("k1.", {}, dns_update_config={}) is None


def test_apply_update_operations_returns_noerror_and_does_not_mutate_records() -> None:
    plugin = SimpleNamespace(
        records={("example.com", int(QTYPE.A)): (300, ["1.1.1.1"], ["src"])}
    )
    rcode, err = up.apply_update_operations([], plugin=plugin, zone_apex="example.com")
    assert rcode == 0
    assert err is None
    assert ("example.com", int(QTYPE.A)) in plugin.records

    lock = threading.RLock()
    plugin2 = SimpleNamespace(
        records={("example.com", int(QTYPE.A)): (300, ["1.1.1.1"], ["src"])},
        _records_lock=lock,
    )
    rcode2, err2 = up.apply_update_operations(
        [], plugin=plugin2, zone_apex="example.com"
    )
    assert rcode2 == 0
    assert err2 is None


def test_build_update_response_sets_rcode() -> None:
    req = DNSRecord.question("example.com", qtype="A")

    packed = up.build_update_response(RCODE.SERVFAIL, req)
    resp = DNSRecord.parse(packed)
    assert resp.header.rcode == RCODE.SERVFAIL

    # EDE branch is scaffolded but should not crash.
    packed2 = up.build_update_response(
        RCODE.REFUSED, req, ede_code=15, ede_text="Blocked"
    )
    resp2 = DNSRecord.parse(packed2)
    assert resp2.header.rcode == RCODE.REFUSED
