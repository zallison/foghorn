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
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.tsigkeyring
import dns.update
import pytest
from dnslib import QTYPE, RCODE, DNSRecord

from foghorn.plugins.resolve.zone_records import update_helpers as uh
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


def test_verify_name_authorization_caches_file_lists_with_plugin(
    tmp_path, monkeypatch
) -> None:
    blocked_file = tmp_path / "blocked_names.txt"
    blocked_file.write_text("blocked.example.com\n", encoding="utf-8")
    zone_cfg = {"block_names_files": [str(blocked_file)]}
    plugin = SimpleNamespace(
        _dns_update_cache_lock=threading.RLock(),
        _dns_update_timestamps={},
        _dns_update_lists_cache={},
    )
    load_count = {"calls": 0}
    original_loader = uh.load_names_list_from_file

    def _counting_loader(path: str) -> list[str]:
        load_count["calls"] += 1
        return original_loader(path)

    monkeypatch.setattr(uh, "load_names_list_from_file", _counting_loader)

    assert (
        up.verify_name_authorization(
            "allowed.example.com",
            zone_cfg,
            plugin=plugin,
            zone_apex="example.com",
        )
        is True
    )
    assert (
        up.verify_name_authorization(
            "allowed.example.com",
            zone_cfg,
            plugin=plugin,
            zone_apex="example.com",
        )
        is True
    )
    assert load_count["calls"] == 1


def test_verify_value_authorization_caches_file_lists_with_plugin(
    tmp_path, monkeypatch
) -> None:
    blocked_ips_file = tmp_path / "blocked_ips.txt"
    blocked_ips_file.write_text("192.0.2.0/24\n", encoding="utf-8")
    zone_cfg = {"block_update_ips_files": [str(blocked_ips_file)]}
    plugin = SimpleNamespace(
        _dns_update_cache_lock=threading.RLock(),
        _dns_update_timestamps={},
        _dns_update_lists_cache={},
    )
    load_count = {"calls": 0}
    original_loader = uh.load_cidr_list_from_file

    def _counting_loader(path: str) -> list[str]:
        load_count["calls"] += 1
        return original_loader(path)

    monkeypatch.setattr(uh, "load_cidr_list_from_file", _counting_loader)

    assert (
        up.verify_value_authorization(
            "198.51.100.1",
            QTYPE.A,
            zone_cfg,
            plugin=plugin,
            zone_apex="example.com",
        )
        is True
    )
    assert (
        up.verify_value_authorization(
            "198.51.100.1",
            QTYPE.A,
            zone_cfg,
            plugin=plugin,
            zone_apex="example.com",
        )
        is True
    )
    assert load_count["calls"] == 1


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


def test_process_update_message_returns_noerror_for_valid_tsig_update() -> None:
    """ "Brief: Verify a valid TSIG-signed update succeeds and returns NOERROR.

    The test creates a TSIG authenticatored UPDATE request for a valid DNS UPDATE operation
    and verifies the response is signed with NOERROR (not NOTIMP like the old scaffolding).
    """
    key_name = "key.example.com."
    secret_b64 = "dGVzdHNlY3JldA=="
    keyring = dns.tsigkeyring.from_text({key_name: secret_b64})

    msg = dns.update.Update("example.com.")
    msg.use_tsig(keyring=keyring, keyname=key_name, algorithm="hmac-sha256")
    msg.add("host", 60, "A", "192.0.2.123")
    req_wire = msg.to_wire()

    # Parse request with keyring so we can validate response TSIG chaining.
    parsed_req = dns.message.from_wire(req_wire, keyring=keyring)

    plugin = SimpleNamespace(records={})
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
                        "allow_names": ["host.example.com"],
                    }
                ]
            }
        },
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )

    # Verify the response has NOERROR and valid TSIG signing.
    parsed_resp = dns.message.from_wire(
        resp_wire,
        keyring=keyring,
        request_mac=parsed_req.mac,
    )
    assert parsed_resp.rcode() == dns.rcode.NOERROR


def test_process_update_message_accepts_tsig_keys_loaded_from_key_sources_file(
    tmp_path,
) -> None:
    """Brief: Valid TSIG updates succeed when TSIG keys come from key_sources file.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts NOERROR response for a TSIG-signed UPDATE with key_sources config.
    """
    key_name = "file-key.example.com."
    secret_b64 = "dGVzdHNlY3JldA=="
    key_file = tmp_path / "tsig-keys.yaml"
    key_file.write_text(
        "- name: file-key.example.com.\n"
        "  algorithm: hmac-sha256\n"
        "  secret: dGVzdHNlY3JldA==\n",
        encoding="utf-8",
    )

    keyring = dns.tsigkeyring.from_text({key_name: secret_b64})
    msg = dns.update.Update("example.com.")
    msg.use_tsig(keyring=keyring, keyname=key_name, algorithm="hmac-sha256")
    msg.add("host", 60, "A", "192.0.2.124")
    req_wire = msg.to_wire()
    parsed_req = dns.message.from_wire(req_wire, keyring=keyring)

    plugin = SimpleNamespace(records={})
    resp_wire = up.process_update_message(
        req_wire,
        zone_apex="example.com",
        zone_config={
            "tsig": {"key_sources": [{"type": "file", "path": str(key_file)}]}
        },
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )
    parsed_resp = dns.message.from_wire(
        resp_wire,
        keyring=keyring,
        request_mac=parsed_req.mac,
    )
    assert parsed_resp.rcode() == dns.rcode.NOERROR


def test_process_update_message_bad_tsig_key_returns_notauth_with_update_opcode() -> (
    None
):
    """Brief: Unknown TSIG key should return NOTAUTH with opcode UPDATE."""
    req_key_name = "request-key.example.com."
    req_secret_b64 = "dGVzdHNlY3JldA=="
    req_keyring = dns.tsigkeyring.from_text({req_key_name: req_secret_b64})

    msg = dns.update.Update("example.com.")
    msg.use_tsig(keyring=req_keyring, keyname=req_key_name, algorithm="hmac-sha256")
    msg.add("host", 60, "A", "192.0.2.123")
    req_wire = msg.to_wire()

    plugin = SimpleNamespace(records={})
    resp_wire = up.process_update_message(
        req_wire,
        zone_apex="example.com",
        zone_config={
            "tsig": {
                "keys": [
                    {
                        "name": "configured-key.example.com.",
                        "algorithm": "hmac-sha256",
                        "secret": req_secret_b64,
                    }
                ]
            }
        },
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )

    resp = dns.message.from_wire(resp_wire, ignore_trailing=True)
    assert int(resp.opcode()) == int(dns.opcode.UPDATE)
    assert int(resp.rcode()) == int(dns.rcode.NOTAUTH)


def test_process_update_message_algorithm_mismatch_returns_signed_notauth() -> None:
    """Brief: Algorithm mismatch should return TSIG-signed NOTAUTH."""
    key_name = "key.example.com."
    secret_b64 = "dGVzdHNlY3JldA=="
    keyring = dns.tsigkeyring.from_text({key_name: secret_b64})

    msg = dns.update.Update("example.com.")
    msg.use_tsig(keyring=keyring, keyname=key_name, algorithm="hmac-sha256")
    msg.add("host", 60, "A", "192.0.2.123")
    req_wire = msg.to_wire()
    parsed_req = dns.message.from_wire(req_wire, keyring=keyring)

    plugin = SimpleNamespace(records={})
    resp_wire = up.process_update_message(
        req_wire,
        zone_apex="example.com",
        zone_config={
            "tsig": {
                "keys": [
                    {
                        "name": key_name,
                        "algorithm": "hmac-sha512",
                        "secret": secret_b64,
                    }
                ]
            }
        },
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )

    parsed_resp = dns.message.from_wire(
        resp_wire,
        keyring=keyring,
        request_mac=parsed_req.mac,
    )
    assert int(parsed_resp.opcode()) == int(dns.opcode.UPDATE)
    assert int(parsed_resp.rcode()) == int(dns.rcode.NOTAUTH)


def test_process_update_message_enforces_tsig_key_allow_names_scope() -> None:
    """Brief: TSIG key allow_names scope should deny out-of-scope and allow wildcard in-scope names."""
    key_name = "update-key.zaa."
    secret_b64 = "dGVzdHNlY3JldA=="
    keyring = dns.tsigkeyring.from_text({key_name: secret_b64})

    zone_config = {
        "tsig": {
            "keys": [
                {
                    "name": key_name,
                    "algorithm": "hmac-sha256",
                    "secret": secret_b64,
                    "allow_names": ["monkey.zaa", "*.dyn.zaa"],
                }
            ]
        }
    }
    plugin = SimpleNamespace(records={})

    # Out-of-scope owner should be denied.
    deny_msg = dns.update.Update("zaa.")
    deny_msg.use_tsig(keyring=keyring, keyname=key_name, algorithm="hmac-sha256")
    deny_msg.add("test", 60, "A", "192.0.2.10")
    deny_req_wire = deny_msg.to_wire()
    deny_req = dns.message.from_wire(deny_req_wire, keyring=keyring)

    deny_resp_wire = up.process_update_message(
        deny_req_wire,
        zone_apex="zaa",
        zone_config=zone_config,
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )
    deny_resp = dns.message.from_wire(
        deny_resp_wire,
        keyring=keyring,
        request_mac=deny_req.mac,
    )
    assert int(deny_resp.rcode()) == int(dns.rcode.NOTAUTH)
    assert ("test.zaa", int(QTYPE.A)) not in plugin.records

    # Wildcard in-scope owner should be allowed.
    allow_msg = dns.update.Update("zaa.")
    allow_msg.use_tsig(keyring=keyring, keyname=key_name, algorithm="hmac-sha256")
    allow_msg.add("monkey.dyn", 60, "A", "192.0.2.11")
    allow_req_wire = allow_msg.to_wire()
    allow_req = dns.message.from_wire(allow_req_wire, keyring=keyring)

    allow_resp_wire = up.process_update_message(
        allow_req_wire,
        zone_apex="zaa",
        zone_config=zone_config,
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )
    allow_resp = dns.message.from_wire(
        allow_resp_wire,
        keyring=keyring,
        request_mac=allow_req.mac,
    )
    assert int(allow_resp.rcode()) == int(dns.rcode.NOERROR)
    assert ("monkey.dyn.zaa", int(QTYPE.A)) in plugin.records


def test_check_prerequisites_with_none_class_prereq_succeeds_with_empty_records() -> (
    None
):
    # Create a mock RRset as dnspython would parse from UPDATE message
    # Testing CLASS NONE: record must NOT exist (succeeds with empty records)
    import dns.rdataclass
    import dns.rdatatype

    class MockRRset:
        def __init__(self, name: str, rdtype: int, rdclass: int):
            self.name = name
            self.rdtype = rdtype
            self.rdclass = rdclass
            self.ttl = 0

        def __iter__(self):
            return iter([])

    prereq = MockRRset("example.com", dns.rdatatype.A, dns.rdataclass.NONE)
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


def test_resolve_tsig_key_by_name_uses_pluggable_source_loaders() -> None:
    """Brief: TSIG key lookup can resolve keys from pluggable external sources.

    Inputs:
      - None.

    Outputs:
      - Asserts resolve_tsig_key_by_name returns key loaded from custom loader.
    """

    def _api_loader(source: dict) -> list[dict]:
        _ = source
        return [
            {
                "name": "api-key.example.",
                "algorithm": "hmac-sha256",
                "secret": "YXBp",
            }
        ]

    zone_cfg = {
        "tsig": {
            "key_sources": [{"type": "api", "endpoint": "https://example.invalid/keys"}]
        }
    }
    resolved = up.resolve_tsig_key_by_name(
        "api-key.example.",
        zone_cfg,
        dns_update_config={"tsig_key_source_loaders": {"api": _api_loader}},
    )
    assert resolved is not None
    assert resolved["name"] == "api-key.example."


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


def test_apply_update_operations_refreshes_wildcard_owner_index() -> None:
    """Brief: Wildcard UPDATE owners are immediately used for wildcard matching.

    Inputs:
      - None.

    Outputs:
      - Asserts wildcard owner index is rebuilt and wildcard matches resolve.
    """
    from foghorn.plugins.resolve.zone_records import helpers as zone_helpers

    plugin = SimpleNamespace(
        records={},
        _name_index={},
        _wildcard_owners=[],
    )

    update_rrset = dns.rrset.from_text(
        "*.foo.dyn.zaa.",
        60,
        dns.rdataclass.IN,
        dns.rdatatype.A,
        "198.51.100.77",
    )
    rcode, err = up.apply_update_operations(
        [update_rrset],
        plugin=plugin,
        zone_apex="dyn.zaa",
    )
    assert rcode == 0
    assert err is None
    assert "*.foo.dyn.zaa" in plugin._wildcard_owners

    for qname in ("a.foo.dyn.zaa", "bar.foo.dyn.zaa"):
        matched_owner, rrsets = zone_helpers.find_best_rrsets_for_name(
            qname,
            plugin._name_index,
            wildcard_patterns=plugin._wildcard_owners,
        )
        assert matched_owner == "*.foo.dyn.zaa"
        assert int(QTYPE.A) in rrsets
        assert rrsets[int(QTYPE.A)][1] == ["198.51.100.77"]


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


def _signed_update_wire(
    *,
    zone: str,
    key_name: str,
    secret_b64: str,
    owner: str,
    value: str,
) -> bytes:
    """Brief: Build a TSIG-signed UPDATE wire payload.

    Inputs:
      - zone: Zone apex.
      - key_name: TSIG key name.
      - secret_b64: Base64 TSIG secret.
      - owner: Relative owner label in zone.
      - value: A record IPv4 value.

    Outputs:
      - bytes: Signed UPDATE message.
    """
    keyring = dns.tsigkeyring.from_text({key_name: secret_b64})
    msg = dns.update.Update(zone)
    msg.use_tsig(keyring=keyring, keyname=key_name, algorithm="hmac-sha256")
    msg.add(owner, 60, "A", value)
    return msg.to_wire()


def test_process_update_message_replica_role_refuses_direct_updates() -> None:
    """Brief: Replica role rejects direct UPDATE requests."""
    key_name = "key.example.com."
    secret_b64 = "dGVzdHNlY3JldA=="
    req_wire = _signed_update_wire(
        zone="example.com.",
        key_name=key_name,
        secret_b64=secret_b64,
        owner="host",
        value="192.0.2.10",
    )
    keyring = dns.tsigkeyring.from_text({key_name: secret_b64})
    parsed_req = dns.message.from_wire(req_wire, keyring=keyring)
    plugin = SimpleNamespace(
        records={},
        _dns_update_config={
            "replication": {
                "role": "replica",
                "reject_direct_update_on_replica": True,
            }
        },
    )
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
                        "allow_names": ["host.example.com"],
                    }
                ]
            }
        },
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )
    resp = dns.message.from_wire(
        resp_wire,
        keyring=keyring,
        request_mac=parsed_req.mac,
    )
    assert resp.rcode() == dns.rcode.REFUSED


def test_process_update_message_enforces_max_updates_per_message() -> None:
    """Brief: Security max_updates_per_message is enforced."""
    key_name = "key.example.com."
    secret_b64 = "dGVzdHNlY3JldA=="
    keyring = dns.tsigkeyring.from_text({key_name: secret_b64})
    msg = dns.update.Update("example.com.")
    msg.use_tsig(keyring=keyring, keyname=key_name, algorithm="hmac-sha256")
    msg.add("a", 60, "A", "192.0.2.11")
    msg.add("b", 60, "A", "192.0.2.12")
    req_wire = msg.to_wire()
    parsed_req = dns.message.from_wire(req_wire, keyring=keyring)
    plugin = SimpleNamespace(
        records={},
        _dns_update_config={"security": {"max_updates_per_message": 1}},
    )
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
                        "allow_names": ["*.example.com"],
                    }
                ]
            }
        },
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )
    resp = dns.message.from_wire(
        resp_wire,
        keyring=keyring,
        request_mac=parsed_req.mac,
    )
    assert resp.rcode() == dns.rcode.REFUSED


def test_process_update_message_rate_limit_per_client() -> None:
    """Brief: Per-client rate limit rejects requests above threshold."""
    key_name = "key.example.com."
    secret_b64 = "dGVzdHNlY3JldA=="
    req_wire = _signed_update_wire(
        zone="example.com.",
        key_name=key_name,
        secret_b64=secret_b64,
        owner="host",
        value="192.0.2.13",
    )
    keyring = dns.tsigkeyring.from_text({key_name: secret_b64})
    parsed_req = dns.message.from_wire(req_wire, keyring=keyring)
    plugin = SimpleNamespace(
        records={},
        _dns_update_config={"security": {"rate_limit_per_client": 1}},
    )
    zone_cfg = {
        "tsig": {
            "keys": [
                {
                    "name": key_name,
                    "algorithm": "hmac-sha256",
                    "secret": secret_b64,
                    "allow_names": ["host.example.com"],
                }
            ]
        }
    }
    first = up.process_update_message(
        req_wire,
        zone_apex="example.com",
        zone_config=zone_cfg,
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )
    first_resp = dns.message.from_wire(
        first,
        keyring=keyring,
        request_mac=parsed_req.mac,
    )
    assert first_resp.rcode() == dns.rcode.NOERROR

    second = up.process_update_message(
        req_wire,
        zone_apex="example.com",
        zone_config=zone_cfg,
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )
    second_resp = dns.message.from_wire(
        second,
        keyring=keyring,
        request_mac=parsed_req.mac,
    )
    assert second_resp.rcode() == dns.rcode.REFUSED


def test_apply_update_operations_bumps_soa_serial_on_commit() -> None:
    """Brief: Successful dynamic commit increments SOA serial."""
    soa_rdata = "ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"
    plugin = SimpleNamespace(
        records={
            ("example.com", int(QTYPE.SOA)): (300, [soa_rdata], ["src"]),
        },
        _records_lock=threading.RLock(),
    )
    update_rrset = dns.rrset.from_text(
        "host.example.com.",
        60,
        dns.rdataclass.IN,
        dns.rdatatype.A,
        "198.51.100.20",
    )
    rcode, err = up.apply_update_operations(
        [update_rrset],
        plugin=plugin,
        zone_apex="example.com",
    )
    assert rcode == 0
    assert err is None
    soa_after = plugin.records[("example.com", int(QTYPE.SOA))][1][0]
    assert " 2 " in f" {soa_after} "
