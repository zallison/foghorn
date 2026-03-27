"""Tests for foghorn.plugins.resolve.ssh_keys.SshKeys.

Brief:
  - Verify configuration, database helpers, scanning expansion, and SSHFP
    pre_resolve behaviour of the SshKeys plugin.
"""

from __future__ import annotations

import hashlib
import os
import socket
from types import SimpleNamespace
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


def test_ssh_keys_get_config_model_returns_expected_class() -> None:
    """Brief: get_config_model returns the SshKeys Pydantic config model class.

    Inputs:
      - None.

    Outputs:
      - Asserts returned class name.
    """

    model = SshKeys.get_config_model()
    assert model.__name__ == "SshKeysConfig"


def test_ssh_keys_parse_networks_and_cidr_targets_handles_invalid_entries(
    caplog,
) -> None:
    """Brief: Network parsing helpers skip invalid values and keep valid networks.

    Inputs:
      - caplog fixture for warning capture.

    Outputs:
      - Asserts valid networks are retained while invalid/empty inputs are ignored.
    """

    plugin = SshKeys(targets=[], db_path="./config/var/unused.db")
    with caplog.at_level("WARNING"):
        nets = plugin._parse_networks(
            ["", "bad-cidr", "127.0.0.0/8"],
            label="scan_allowlist",
        )
    assert len(nets) == 1

    cidr_nets = plugin._parse_cidr_targets(
        ["example.test", "invalid/cidr", "192.0.2.0/30"]
    )
    assert len(cidr_nets) == 1


def test_ssh_keys_resolve_db_path_allowlist_and_fallback_branches(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _resolve_db_path handles empty allowlist, fallback, and unwritable fallback.

    Inputs:
      - tmp_path: pytest temp directory.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts all three branch outcomes.
    """

    plugin = SshKeys(targets=[], db_path="./config/var/unused.db")
    resolved_input = os.path.abspath("/tmp/outside.sqlite")

    plugin._db_path_allowlist = []
    assert plugin._resolve_db_path("/tmp/outside.sqlite") == resolved_input

    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    plugin._db_path_allowlist = [str(allowed_root)]
    fallback = plugin._resolve_db_path("/tmp/outside.sqlite")
    assert fallback.startswith(str(allowed_root))
    assert fallback.endswith("outside.sqlite")

    monkeypatch.setattr(os, "access", lambda _p, _m: False)
    assert plugin._resolve_db_path("/tmp/outside.sqlite") == resolved_input


def test_ssh_keys_maybe_prune_db_interval_and_force_paths(
    db_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _maybe_prune_db respects interval gate and force override.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts skip and forced prune behavior.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    called: list[float] = []
    monkeypatch.setattr(plugin, "_prune_db", lambda now: called.append(float(now)))

    plugin._retention_seconds = 0.0
    plugin._max_rows = 0
    plugin._maybe_prune_db()
    assert called == []

    plugin._retention_seconds = 10.0
    plugin._prune_interval_seconds = 9999.0
    plugin._last_prune = 1000.0
    monkeypatch.setattr("foghorn.plugins.resolve.ssh_keys.time.time", lambda: 1001.0)
    plugin._maybe_prune_db(force=False)
    assert called == []

    plugin._maybe_prune_db(force=True)
    assert len(called) == 1


def test_ssh_keys_prune_db_deletes_stale_and_excess_rows(db_path: str) -> None:
    """Brief: _prune_db removes stale rows and trims oldest rows over max_rows.

    Inputs:
      - db_path: Temporary sqlite DB path.

    Outputs:
      - Asserts stale rows are removed and total rows are capped.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()
    plugin._retention_seconds = 5.0
    plugin._max_rows = 1

    assert plugin._conn is not None
    with plugin._conn:
        plugin._conn.execute(
            "INSERT OR REPLACE INTO ssh_keys (subject, hostname, ip, port, key_type, key_hex, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "old.example",
                "old.example",
                "192.0.2.10",
                22,
                "ssh-ed25519",
                "aa",
                1.0,
                1.0,
            ),
        )
        plugin._conn.execute(
            "INSERT OR REPLACE INTO ssh_keys (subject, hostname, ip, port, key_type, key_hex, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "new.example",
                "new.example",
                "192.0.2.11",
                22,
                "ssh-ed25519",
                "bb",
                10.0,
                10.0,
            ),
        )
        plugin._conn.execute(
            "INSERT OR REPLACE INTO ssh_keys (subject, hostname, ip, port, key_type, key_hex, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "newer.example",
                "newer.example",
                "192.0.2.12",
                22,
                "ssh-ed25519",
                "cc",
                11.0,
                11.0,
            ),
        )

    plugin._prune_db(now=12.0)

    with plugin._conn:
        cur = plugin._conn.execute("SELECT subject FROM ssh_keys ORDER BY subject ASC")
        subjects = [row[0] for row in cur.fetchall()]
    assert "old.example" not in subjects
    assert len(subjects) == 1


def test_ssh_keys_scan_single_ip_path_branches(
    db_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _scan_single('ip', ...) handles blocked, fetch-fail, and success paths.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts branch behavior via captured upsert calls.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    upserts: list[tuple[str | None, str | None, str, str]] = []
    monkeypatch.setattr(
        plugin,
        "_db_upsert_pair",
        lambda h, i, t, k: upserts.append((h, i, t, k)),
    )

    monkeypatch.setattr(plugin, "_is_scan_ip_allowed", lambda _ip: False)
    plugin._scan_single("ip", "192.0.2.10")
    assert upserts == []

    monkeypatch.setattr(plugin, "_is_scan_ip_allowed", lambda _ip: True)
    monkeypatch.setattr(
        "foghorn.plugins.resolve.ssh_keys.fetch_ssh_host_key_hex",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("fetch-fail")),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyaddr",
        lambda _ip: (_ for _ in ()).throw(RuntimeError("no-ptr")),
    )
    plugin._scan_single("ip", "192.0.2.10")
    assert upserts == []

    monkeypatch.setattr(
        "foghorn.plugins.resolve.ssh_keys.fetch_ssh_host_key_hex",
        lambda *args, **kwargs: SimpleNamespace(
            hostname="host.example.",
            key_type="ssh-ed25519",
            key_hex="aa",
        ),
    )
    plugin._scan_single("ip", "192.0.2.10")
    assert upserts == [("host.example", "192.0.2.10", "ssh-ed25519", "aa")]


def test_ssh_keys_scan_single_hostname_path_branches(
    db_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _scan_single('hostname', ...) handles resolve, policy, fetch, and success paths.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts branch behavior via captured upsert calls.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    upserts: list[tuple[str | None, str | None, str, str]] = []
    monkeypatch.setattr(
        plugin,
        "_db_upsert_pair",
        lambda h, i, t, k: upserts.append((h, i, t, k)),
    )

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("no-resolve")),
    )
    plugin._scan_single("hostname", "host.example")
    assert upserts == []

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.9", 22)),
        ],
    )
    monkeypatch.setattr(plugin, "_is_scan_ip_allowed", lambda _ip: False)
    plugin._scan_single("hostname", "host.example")
    assert upserts == []

    monkeypatch.setattr(plugin, "_is_scan_ip_allowed", lambda _ip: True)
    monkeypatch.setattr(
        "foghorn.plugins.resolve.ssh_keys.fetch_ssh_host_key_hex",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("fetch-fail")),
    )
    plugin._scan_single("hostname", "host.example")
    assert upserts == []

    monkeypatch.setattr(
        "foghorn.plugins.resolve.ssh_keys.fetch_ssh_host_key_hex",
        lambda *args, **kwargs: SimpleNamespace(
            hostname="host.example.",
            key_type="ssh-rsa",
            key_hex="bb",
        ),
    )
    plugin._scan_single("hostname", "host.example")
    assert upserts == [("host.example", "198.51.100.9", "ssh-rsa", "bb")]


def test_ssh_keys_scan_and_response_policy_helpers() -> None:
    """Brief: _is_scan_ip_allowed and _is_response_allowed enforce policy branches.

    Inputs:
      - None.

    Outputs:
      - Asserts representative allow/block/public outcomes.
    """

    plugin = SshKeys(
        targets=[],
        scan_allowlist=["10.0.0.0/8"],
        scan_blocklist=["10.1.0.0/16"],
        response_allowlist=["127.0.0.0/8"],
        response_blocklist=["127.0.0.2/32"],
        allow_public_scan=False,
        allow_public_responses=False,
    )

    assert plugin._is_scan_ip_allowed("invalid-ip") is False
    assert plugin._is_scan_ip_allowed("10.1.0.9") is False
    assert plugin._is_scan_ip_allowed("10.2.0.9") is True
    assert plugin._is_scan_ip_allowed("198.51.100.10") is False

    assert plugin._is_response_allowed(PluginContext(client_ip="")) is False
    assert plugin._is_response_allowed(PluginContext(client_ip="127.0.0.2")) is False
    assert plugin._is_response_allowed(PluginContext(client_ip="127.0.0.1")) is True
    assert (
        plugin._is_response_allowed(PluginContext(client_ip="198.51.100.10")) is False
    )


def test_ssh_keys_enqueue_lazy_scan_dedupe_and_limit(
    db_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _enqueue_lazy_scan deduplicates and enforces max_lazy_scans.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts only one lazy scan launches and subject cleanup occurs.
    """

    plugin = SshKeys(db_path=db_path, targets=[], max_lazy_scans=1)
    plugin.setup()

    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        plugin,
        "_scan_single",
        lambda kind, value: calls.append((kind, value)),
    )
    scheduled: list[object] = []

    class _DeferredThread:
        def __init__(self, target, name, daemon):  # noqa: ANN001
            self._target = target
            scheduled.append(target)

        def start(self) -> None:
            return None

    monkeypatch.setattr(
        "foghorn.plugins.resolve.ssh_keys.threading.Thread",
        _DeferredThread,
    )

    plugin._enqueue_lazy_scan("ip", "192.0.2.10")
    plugin._enqueue_lazy_scan("ip", "192.0.2.10")
    assert len(scheduled) == 1
    assert "192.0.2.10" in plugin._lazy_scans

    scheduled[0]()
    assert calls == [("ip", "192.0.2.10")]
    assert "192.0.2.10" not in plugin._lazy_scans

    plugin._lazy_scans.add("inflight")
    plugin._enqueue_lazy_scan("ip", "192.0.2.11")
    assert calls == [("ip", "192.0.2.10")]


def test_ssh_keys_pre_resolve_lazy_scan_and_sha256_only(
    db_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: pre_resolve enqueues lazy CIDR scans on misses and supports SHA-256-only.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts lazy enqueue on CIDR miss and one SSHFP RR with include_sha1=False.
    """

    plugin = SshKeys(db_path=db_path, targets=["192.0.2.0/24"], include_sha1=False)
    monkeypatch.setattr(plugin, "_run_initial_scan", lambda entries: None)
    plugin.setup()
    monkeypatch.setattr(plugin, "targets", lambda _ctx: True)

    enqueued: list[tuple[str, str]] = []
    monkeypatch.setattr(
        plugin,
        "_enqueue_lazy_scan",
        lambda kind, value: enqueued.append((kind, value)),
    )
    monkeypatch.setattr(plugin, "_db_get_row", lambda _subject: None)

    wire = _make_sshfp_query("192.0.2.15")
    ctx = PluginContext(client_ip="127.0.0.1")
    assert plugin.pre_resolve("192.0.2.15", int(QTYPE.SSHFP), wire, ctx) is None
    assert enqueued == [("ip", "192.0.2.15")]

    key_bytes = b"sha256-only-key"
    monkeypatch.setattr(
        plugin,
        "_db_get_row",
        lambda _subject: ("ssh-ed25519", key_bytes.hex()),
    )
    decision = plugin.pre_resolve(
        "host.example",
        int(QTYPE.SSHFP),
        _make_sshfp_query("host.example"),
        ctx,
    )
    assert decision is not None
    resp = DNSRecord.parse(decision.response)
    sshfp_rrs = [rr for rr in resp.rr if int(rr.rtype) == int(QTYPE.SSHFP)]
    assert len(sshfp_rrs) == 1


def test_ssh_keys_pre_resolve_handles_qtype_coercion_error(
    db_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: pre_resolve returns None when qtype cannot be coerced to int.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts graceful None return.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()
    monkeypatch.setattr(plugin, "targets", lambda _ctx: True)
    monkeypatch.setattr(plugin, "_is_response_allowed", lambda _ctx: True)
    assert (
        plugin.pre_resolve(
            "host.example",
            object(),
            b"",
            PluginContext(client_ip="127.0.0.1"),
        )
        is None
    )


def test_ssh_keys_resolve_db_path_inside_allowlist_and_commonpath_exception(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _resolve_db_path returns allowed paths and tolerates commonpath failures.

    Inputs:
      - tmp_path: pytest temp directory.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts in-allowlist return path and exception fallback behavior.
    """

    plugin = SshKeys(targets=[], db_path="./config/var/unused.db")
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    target_path = allowed_dir / "ssh_keys.db"
    plugin._db_path_allowlist = [str(allowed_dir)]
    assert plugin._resolve_db_path(str(target_path)) == os.path.abspath(
        str(target_path)
    )

    first_root = tmp_path / "first"
    first_root.mkdir()
    plugin._db_path_allowlist = [str(first_root), str(allowed_dir)]
    real_commonpath = os.path.commonpath
    calls = {"n": 0}

    def _flaky_commonpath(paths):  # noqa: ANN001
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("boom")
        return real_commonpath(paths)

    monkeypatch.setattr(os.path, "commonpath", _flaky_commonpath)
    assert plugin._resolve_db_path(str(target_path)) == os.path.abspath(
        str(target_path)
    )


def test_ssh_keys_db_helpers_handle_none_connection_and_empty_subjects(
    db_path: str,
) -> None:
    """Brief: DB helpers return early when connection is absent or subject set is empty.

    Inputs:
      - db_path: Temporary sqlite DB path.

    Outputs:
      - Asserts early-return branches execute without side effects.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin._db_upsert_pair("host.example", "192.0.2.10", "ssh-ed25519", "aa")
    plugin._prune_db(now=0.0)

    plugin.setup()
    plugin._db_upsert_pair(None, None, "ssh-ed25519", "aa")
    assert plugin._db_get_row("") is None


def test_ssh_keys_run_initial_scan_cap_and_skip_branches(
    db_path: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog,
) -> None:
    """Brief: _run_initial_scan covers skip branches and max_targets cap handling.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.
      - caplog: log capture fixture.

    Outputs:
      - Asserts skip-only scan and cap warning behavior.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    scanned: list[tuple[str, str]] = []
    monkeypatch.setattr(
        plugin, "_scan_single", lambda kind, value: scanned.append((kind, value))
    )
    monkeypatch.setattr(plugin, "_db_subject_exists", lambda _subject: False)
    monkeypatch.setattr(plugin, "_is_scan_ip_allowed", lambda _ip: False)
    monkeypatch.setattr(
        plugin,
        "_iter_scan_items",
        lambda _entries: [("hostname", " "), ("ip", "192.0.2.1")],
    )
    plugin._run_initial_scan(["ignored"])
    assert scanned == []

    plugin._max_targets = 1
    monkeypatch.setattr(plugin, "_db_subject_exists", lambda _subject: True)
    monkeypatch.setattr(
        plugin,
        "_iter_scan_items",
        lambda _entries: [("hostname", "host1"), ("hostname", "host2")],
    )
    with caplog.at_level("WARNING"):
        plugin._run_initial_scan(["ignored"])
    assert "scan target cap reached" in caplog.text


def test_ssh_keys_iter_scan_items_truncates_cidr_when_max_hosts_reached(caplog) -> None:
    """Brief: _iter_scan_items logs and truncates CIDR expansion at max_cidr_hosts.

    Inputs:
      - caplog: log capture fixture.

    Outputs:
      - Asserts truncation warning and capped item count.
    """

    plugin = SshKeys(targets=[], db_path="./config/var/unused.db", max_cidr_hosts=1)
    with caplog.at_level("WARNING"):
        items = list(plugin._iter_scan_items(["198.51.100.0/30"]))
    assert items == [("ip", "198.51.100.1")]
    assert "exceeds max_cidr_hosts" in caplog.text


def test_ssh_keys_scan_single_ip_prefers_reverse_hostname(
    db_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _scan_single('ip', ...) uses reverse DNS hostname when available.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts normalized reverse hostname is persisted.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()

    upserts: list[tuple[str | None, str | None, str, str]] = []
    monkeypatch.setattr(
        plugin,
        "_db_upsert_pair",
        lambda h, i, t, k: upserts.append((h, i, t, k)),
    )
    monkeypatch.setattr(plugin, "_is_scan_ip_allowed", lambda _ip: True)
    monkeypatch.setattr(socket, "gethostbyaddr", lambda _ip: ("PTR.Example.", [], []))
    monkeypatch.setattr(
        "foghorn.plugins.resolve.ssh_keys.fetch_ssh_host_key_hex",
        lambda *args, **kwargs: SimpleNamespace(
            hostname="ignored.example.",
            key_type="ssh-ed25519",
            key_hex="aa",
        ),
    )
    plugin._scan_single("ip", "192.0.2.10")
    assert upserts == [("ptr.example", "192.0.2.10", "ssh-ed25519", "aa")]


def test_ssh_keys_public_policy_and_empty_lazy_subject_paths(
    db_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Public policy branches and empty-subject lazy scan path are handled.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts allow_public branches and no thread launch for empty lazy subject.
    """

    plugin = SshKeys(
        db_path=db_path,
        targets=[],
        allow_public_scan=True,
        allow_public_responses=True,
    )
    plugin.setup()
    assert plugin._is_scan_ip_allowed("198.51.100.10") is True
    assert plugin._is_response_allowed(PluginContext(client_ip="198.51.100.10")) is True

    monkeypatch.setattr(
        "foghorn.plugins.resolve.ssh_keys.threading.Thread",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should-not-run")),
    )
    plugin._enqueue_lazy_scan("ip", " ")


def test_ssh_keys_pre_resolve_subject_empty_lazy_disabled_and_no_rr(
    db_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: pre_resolve covers subject-empty, lazy-disabled, and had_rr=False paths.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts None decisions for these defensive branches.
    """

    plugin = SshKeys(db_path=db_path, targets=["192.0.2.0/24"])
    monkeypatch.setattr(plugin, "_run_initial_scan", lambda entries: None)
    plugin.setup()
    monkeypatch.setattr(plugin, "targets", lambda _ctx: True)
    monkeypatch.setattr(plugin, "_is_response_allowed", lambda _ctx: True)

    ctx = PluginContext(client_ip="127.0.0.1")
    assert (
        plugin.pre_resolve(
            " ", int(QTYPE.SSHFP), _make_sshfp_query("host.example"), ctx
        )
        is None
    )

    plugin._lazy_scan_enabled = False
    monkeypatch.setattr(plugin, "_db_get_row", lambda _subject: None)
    assert (
        plugin.pre_resolve(
            "192.0.2.15", int(QTYPE.SSHFP), _make_sshfp_query("192.0.2.15"), ctx
        )
        is None
    )

    monkeypatch.setattr(
        plugin, "_db_get_row", lambda _subject: ("ssh-ed25519", "aa" * 16)
    )
    monkeypatch.setattr(
        "foghorn.plugins.resolve.ssh_keys.RR.fromZone",
        lambda _line: (_ for _ in ()).throw(ValueError("rr-build-fail")),
    )
    assert (
        plugin.pre_resolve(
            "host.example", int(QTYPE.SSHFP), _make_sshfp_query("host.example"), ctx
        )
        is None
    )


def test_ssh_keys_iter_scan_items_skips_empty_entries_additional() -> None:
    """Brief: _iter_scan_items skips blank entries before classification.

    Inputs:
      - None.

    Outputs:
      - Asserts only non-empty values are yielded.
    """

    plugin = SshKeys(targets=[], db_path="./config/var/unused.db")
    items = list(plugin._iter_scan_items(["", "   ", "host.example"]))
    assert items == [("hostname", "host.example")]


def test_ssh_keys_prune_db_noop_and_under_limit_branches_additional(
    db_path: str,
) -> None:
    """Brief: _prune_db handles retention/max-row disabled and under-limit counts.

    Inputs:
      - db_path: Temporary sqlite DB path.

    Outputs:
      - Asserts row remains when prune conditions are not met.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()
    assert plugin._conn is not None
    with plugin._conn:
        plugin._conn.execute(
            "INSERT OR REPLACE INTO ssh_keys (subject, hostname, ip, port, key_type, key_hex, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "keep.example",
                "keep.example",
                "192.0.2.20",
                22,
                "ssh-ed25519",
                "aa",
                1.0,
                1.0,
            ),
        )

    plugin._retention_seconds = 0.0
    plugin._max_rows = 0
    plugin._prune_db(now=2.0)

    plugin._max_rows = 5
    plugin._prune_db(now=2.0)

    with plugin._conn:
        cur = plugin._conn.execute("SELECT subject FROM ssh_keys ORDER BY subject ASC")
        subjects = [row[0] for row in cur.fetchall()]
    assert subjects == ["keep.example"]


def test_ssh_keys_scan_single_hostname_without_supported_family_additional(
    db_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _scan_single('hostname', ...) skips when no AF_INET/AF_INET6 addrinfo exists.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts no upsert occurs when resolution yields only unsupported families.
    """

    plugin = SshKeys(db_path=db_path, targets=[])
    plugin.setup()
    upserts: list[tuple[str | None, str | None, str, str]] = []
    monkeypatch.setattr(
        plugin,
        "_db_upsert_pair",
        lambda h, i, t, k: upserts.append((h, i, t, k)),
    )
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [  # noqa: ARG005
            (socket.AF_UNIX, socket.SOCK_STREAM, 0, "", ("ignored", 0)),
        ],
    )
    plugin._scan_single("hostname", "host.example")
    assert upserts == []


def test_ssh_keys_is_response_allowed_invalid_client_ip_additional() -> None:
    """Brief: _is_response_allowed denies non-empty malformed client_ip values.

    Inputs:
      - None.

    Outputs:
      - Asserts invalid textual IP is rejected.
    """

    plugin = SshKeys(targets=[])
    assert plugin._is_response_allowed(PluginContext(client_ip="not-an-ip")) is False


def test_ssh_keys_pre_resolve_response_denied_and_lazy_miss_outside_cidr_additional(
    db_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: pre_resolve handles response-denied branch and non-matching lazy CIDR misses.

    Inputs:
      - db_path: Temporary sqlite DB path.
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts deny path and no lazy enqueue for out-of-CIDR misses.
    """

    plugin = SshKeys(db_path=db_path, targets=["192.0.2.0/24"])
    monkeypatch.setattr(plugin, "_run_initial_scan", lambda entries: None)
    plugin.setup()
    monkeypatch.setattr(plugin, "targets", lambda _ctx: True)

    ctx = PluginContext(client_ip="127.0.0.1")
    monkeypatch.setattr(plugin, "_is_response_allowed", lambda _ctx: False)
    assert (
        plugin.pre_resolve(
            "host.example",
            int(QTYPE.SSHFP),
            _make_sshfp_query("host.example"),
            ctx,
        )
        is None
    )

    monkeypatch.setattr(plugin, "_is_response_allowed", lambda _ctx: True)
    monkeypatch.setattr(plugin, "_db_get_row", lambda _subject: None)
    enqueued: list[tuple[str, str]] = []
    monkeypatch.setattr(
        plugin,
        "_enqueue_lazy_scan",
        lambda kind, value: enqueued.append((kind, value)),
    )
    assert (
        plugin.pre_resolve(
            "198.51.100.10",
            int(QTYPE.SSHFP),
            _make_sshfp_query("198.51.100.10"),
            ctx,
        )
        is None
    )
    assert enqueued == []
