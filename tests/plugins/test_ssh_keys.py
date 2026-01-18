"""Tests for foghorn.plugins.resolve.ssh_keys.SshKeys.

Brief:
  - Verify configuration, database helpers, scanning expansion, and SSHFP
    pre_resolve behaviour of the SshKeys plugin.
"""

from __future__ import annotations

import hashlib
from typing import List, Tuple

import pytest
from dnslib import QTYPE, DNSRecord

from foghorn.plugins.resolve.base import PluginContext
from foghorn.plugins.resolve.ssh_keys import SshKeys


@pytest.fixture
def db_path(tmp_path) -> str:
    """Brief: Return a temporary sqlite path for SshKeys tests.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - str: Filesystem path for a per-test sqlite DB.
    """

    return str(tmp_path / "ssh_keys.db")


def _make_sshfp_query(name: str) -> bytes:
    """Brief: Build a wire-format SSHFP DNS query for name.

    Inputs:
      - name: Domain name for the SSHFP question.

    Outputs:
      - bytes: Packed DNS query suitable for passing to pre_resolve.
    """

    q = DNSRecord.question(name, qtype="SSHFP")
    return q.pack()


def test_ssh_keys_setup_creates_db_and_skips_empty_targets(db_path: str) -> None:
    """Brief: setup() creates the sqlite DB and returns early on empty targets.

    Inputs:
      - db_path: Temporary sqlite DB path fixture.

    Outputs:
      - Asserts that setup() succeeds and a sqlite connection is available.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()
    assert plugin._conn is not None


def test_ssh_keys_db_helpers_round_trip(db_path: str) -> None:
    """Brief: _db_upsert_pair, _db_subject_exists and _db_get_row cooperate.

    Inputs:
      - db_path: Temporary sqlite DB path.

    Outputs:
      - Asserts that subjects are persisted and retrievable via helpers.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    plugin._db_upsert_pair("host.example", "192.0.2.10", "ssh-ed25519", "ab" * 16)

    assert plugin._db_subject_exists("host.example")
    assert plugin._db_subject_exists("192.0.2.10")
    assert not plugin._db_subject_exists("")

    row = plugin._db_get_row("host.example")
    assert row is not None
    key_type, key_hex = row
    assert key_type == "ssh-ed25519"
    assert key_hex == ("ab" * 16)

    assert plugin._db_get_row("does-not-exist") is None
    assert plugin._db_get_row("") is None


def test_ssh_keys_iter_scan_items_expands_and_classifies() -> None:
    """Brief: _iter_scan_items expands CIDRs and classifies IPs vs hostnames.

    Inputs:
      - Mixed list of CIDR, IP, and hostname entries.

    Outputs:
      - Asserts that CIDRs expand to IPs and hostnames are preserved.
    """

    # _iter_scan_items does not depend on sqlite state; avoid touching the
    # filesystem so this test remains hermetic.
    plugin = SshKeys(targets=[], db_path="./config/var/unused.db")

    entries = ["192.0.2.10", "198.51.100.0/30", "example.test"]
    items: List[Tuple[str, str]] = list(plugin._iter_scan_items(entries))

    kinds = {k for k, _ in items}
    values = {v for _, v in items}

    # 198.51.100.0/30 has two usable host addresses.
    assert ("ip", "192.0.2.10") in items
    assert "example.test" in values
    assert "ip" in kinds and "hostname" in kinds


def test_ssh_keys_iter_scan_items_ignores_invalid_cidr(caplog) -> None:
    """Brief: Invalid CIDR strings are logged and skipped without raising.

    Inputs:
      - A single invalid CIDR entry.

    Outputs:
      - Asserts that no items are yielded and a warning is logged.
    """

    # _iter_scan_items logging behaviour does not require a live sqlite DB;
    # construct the plugin without calling setup() to keep the test isolated.
    plugin = SshKeys(targets=[], db_path="./config/var/unused.db")

    caplog.clear()
    with caplog.at_level("WARNING"):
        items = list(plugin._iter_scan_items(["not-a/cidr"]))
    assert items == []


def test_ssh_keys_run_initial_scan_filters_existing_and_calls_scan(
    monkeypatch, db_path: str
) -> None:
    """Brief: _run_initial_scan skips existing subjects and scans new ones.

    Inputs:
      - monkeypatch: pytest fixture for patching helpers.
      - db_path: Temporary sqlite DB path.

    Outputs:
      - Asserts that _scan_single is called only for unseen subjects.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    # Pretend that _iter_scan_items found two entries.
    monkeypatch.setattr(
        plugin,
        "_iter_scan_items",
        lambda entries: [("ip", "192.0.2.1"), ("hostname", "host.test")],
    )

    seen_subjects = {"192.0.2.1"}

    def fake_subject_exists(subject: str) -> bool:
        return subject in seen_subjects

    monkeypatch.setattr(plugin, "_db_subject_exists", fake_subject_exists)

    calls: List[Tuple[str, str]] = []

    def fake_scan(kind: str, value: str) -> None:
        calls.append((kind, value))

    monkeypatch.setattr(plugin, "_scan_single", fake_scan)

    plugin._run_initial_scan(["ignored-config-value"])

    # Only the hostname entry should be scanned.
    assert calls == [("hostname", "host.test")]


def test_ssh_keys_run_initial_scan_worker_error_is_logged(
    monkeypatch, caplog, db_path: str
) -> None:
    """Brief: Worker exceptions in _run_initial_scan are logged, not raised.

    Inputs:
      - monkeypatch: pytest fixture.
      - caplog: pytest logging capture fixture.
      - db_path: Temporary sqlite DB path.

    Outputs:
      - Asserts that a worker exception results in a warning log entry.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    monkeypatch.setattr(
        plugin,
        "_iter_scan_items",
        lambda entries: [("ip", "192.0.2.1")],
    )
    monkeypatch.setattr(plugin, "_db_subject_exists", lambda subject: False)

    def boom(kind: str, value: str) -> None:  # noqa: D401 - simple helper
        """Always raise to exercise the worker exception handler."""

        raise RuntimeError("boom")

    monkeypatch.setattr(plugin, "_scan_single", boom)

    caplog.clear()
    with caplog.at_level("WARNING"):
        plugin._run_initial_scan(["irrelevant"])

    assert any("scan worker error" in msg for msg in caplog.text.splitlines())


def test_ssh_keys_normalize_subject_and_algorithm_mapping() -> None:
    """Brief: _normalize_subject and _sshfp_algorithm_for_key_type behave as expected.

    Inputs:
      - Various subject and key_type strings.

    Outputs:
      - Asserts normalization and algorithm codes for known types.
    """

    assert SshKeys._normalize_subject("Host.Example.") == "host.example"
    assert SshKeys._normalize_subject(" ") == ""

    assert SshKeys._sshfp_algorithm_for_key_type("ssh-rsa") == 1
    assert SshKeys._sshfp_algorithm_for_key_type("ssh-dss") == 2
    assert SshKeys._sshfp_algorithm_for_key_type("ecdsa-sha2-nistp256") == 3
    assert SshKeys._sshfp_algorithm_for_key_type("ssh-ed25519") == 4
    assert SshKeys._sshfp_algorithm_for_key_type("ssh-ed448") == 6
    assert SshKeys._sshfp_algorithm_for_key_type("unknown-type") is None
    assert SshKeys._sshfp_algorithm_for_key_type("") is None


def test_ssh_keys_pre_resolve_respects_targets(db_path: str, monkeypatch) -> None:
    """Brief: pre_resolve returns None when the client is not targeted.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture for stubbing out the initial scan.

    Outputs:
      - Asserts that a non-target client yields no decision.
    """

    plugin = SshKeys(db_path=db_path, targets=["10.0.0.0/8"])

    # Avoid expanding and probing the entire 10.0.0.0/8 range during tests;
    # _run_initial_scan behaviour is covered separately.
    monkeypatch.setattr(plugin, "_run_initial_scan", lambda entries: None)

    plugin.setup()

    wire = _make_sshfp_query("host.example")
    ctx = PluginContext(client_ip="192.0.2.1")
    decision = plugin.pre_resolve("host.example", int(QTYPE.SSHFP), wire, ctx)
    assert decision is None


def test_ssh_keys_pre_resolve_non_sshfp_qtype_ignored(
    db_path: str, monkeypatch
) -> None:
    """Brief: pre_resolve ignores queries whose qtype is not SSHFP.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts that no DB lookups occur for non-SSHFP qtypes.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    called = {"db": False}

    def fake_get_row(subject: str):  # noqa: D401 - trivial stub
        """Mark that a DB lookup was attempted (should not be)."""

        called["db"] = True
        return None

    monkeypatch.setattr(plugin, "_db_get_row", fake_get_row)

    q = DNSRecord.question("host.example", qtype="A")
    wire = q.pack()
    ctx = PluginContext(client_ip="127.0.0.1")

    decision = plugin.pre_resolve("host.example", int(QTYPE.A), wire, ctx)
    assert decision is None
    assert called["db"] is False


def test_ssh_keys_pre_resolve_no_row_returns_none(db_path: str) -> None:
    """Brief: pre_resolve falls through when no cached key is present.

    Inputs:
      - db_path: Temporary sqlite DB path.

    Outputs:
      - Asserts that an SSHFP query for an unknown subject returns None.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    wire = _make_sshfp_query("unknown.example")
    ctx = PluginContext(client_ip="127.0.0.1")
    decision = plugin.pre_resolve("unknown.example", int(QTYPE.SSHFP), wire, ctx)
    assert decision is None


def test_ssh_keys_pre_resolve_unsupported_key_type(db_path: str, monkeypatch) -> None:
    """Brief: pre_resolve returns None for unsupported SSH key types.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts that an unknown key_type does not produce an answer.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    monkeypatch.setattr(plugin, "_db_get_row", lambda subject: ("ssh-unknown", "00"))

    wire = _make_sshfp_query("host.example")
    ctx = PluginContext(client_ip="127.0.0.1")
    decision = plugin.pre_resolve("host.example", int(QTYPE.SSHFP), wire, ctx)
    assert decision is None


def test_ssh_keys_pre_resolve_invalid_hex(db_path: str, monkeypatch) -> None:
    """Brief: pre_resolve returns None when stored key_hex cannot be decoded.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts that a ValueError in bytes.fromhex leads to no decision.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    monkeypatch.setattr(
        plugin, "_db_get_row", lambda subject: ("ssh-ed25519", "not-hex")
    )

    wire = _make_sshfp_query("host.example")
    ctx = PluginContext(client_ip="127.0.0.1")
    decision = plugin.pre_resolve("host.example", int(QTYPE.SSHFP), wire, ctx)
    assert decision is None


def test_ssh_keys_pre_resolve_parse_error_is_handled(
    db_path: str, monkeypatch, caplog
) -> None:
    """Brief: pre_resolve handles DNSRecord.parse failures defensively.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.
      - caplog: pytest logging capture fixture.

    Outputs:
      - Asserts that a parse error logs a warning and returns None.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    monkeypatch.setattr(
        plugin, "_db_get_row", lambda subject: ("ssh-ed25519", "aa" * 16)
    )

    def _raise_parse(_wire: bytes) -> None:  # noqa: D401 - simple helper
        """Always raise to exercise the DNSRecord.parse error handler."""

        raise ValueError("bad")

    monkeypatch.setattr(DNSRecord, "parse", _raise_parse)

    ctx = PluginContext(client_ip="127.0.0.1")
    caplog.clear()
    with caplog.at_level("WARNING"):
        decision = plugin.pre_resolve(
            "host.example", int(QTYPE.SSHFP), b"not-a-dns-packet", ctx
        )

    assert decision is None
    assert "failed to parse request" in caplog.text


def test_ssh_keys_pre_resolve_success_builds_sshfp_response(
    db_path: str, monkeypatch
) -> None:
    """Brief: pre_resolve synthesizes SSHFP RRs for cached subjects.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts that two SSHFP RRs (SHA-1 and SHA-256) are present with
        expected algorithm and fingerprint lengths.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    # Use a deterministic key_hex so we can verify both digests.
    key_bytes = b"test-key-material"
    key_hex = key_bytes.hex()
    monkeypatch.setattr(plugin, "_db_get_row", lambda subject: ("ssh-ed25519", key_hex))

    wire = _make_sshfp_query("host.example")
    ctx = PluginContext(client_ip="127.0.0.1")
    decision = plugin.pre_resolve("host.example", int(QTYPE.SSHFP), wire, ctx)
    assert decision is not None
    assert decision.action == "override"
    assert decision.response is not None

    resp = DNSRecord.parse(decision.response)
    sshfp_rrs = [rr for rr in resp.rr if int(rr.rtype) == int(QTYPE.SSHFP)]
    assert len(sshfp_rrs) == 2

    # Validate that the fingerprints match the expected SHA-1 and SHA-256.
    expected_sha1 = hashlib.sha1(key_bytes).hexdigest().upper()
    expected_sha256 = hashlib.sha256(key_bytes).hexdigest().upper()
    rdatas = sorted(str(rr.rdata) for rr in sshfp_rrs)
    assert any(expected_sha1 in r for r in rdatas)
    assert any(expected_sha256 in r for r in rdatas)
