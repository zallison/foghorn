"""Brief: Unit tests for foghorn.plugins.resolve.zone_records.transfer.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import dataclasses
import itertools

import dns.exception
import dns.tsig
import pytest
from dnslib import DNSRecord, QTYPE, RCODE, RR

from foghorn.plugins.resolve.zone_records import transfer


class _PluginNoLock:
    """Brief: Minimal plugin object without _records_lock.

    Inputs:
      - name_index: owner -> qtype -> (ttl, [values]) mapping.
      - zone_soa: zone apex -> (ttl, [soa_values]) mapping.

    Outputs:
      - Instance with _name_index/_zone_soa attributes.
    """

    def __init__(
        self,
        *,
        name_index: dict,
        zone_soa: dict,
    ) -> None:
        self._name_index = name_index
        self._zone_soa = zone_soa


class _RecordingLock:
    """Brief: Minimal lock context manager that records entry.

    Inputs:
      - None.

    Outputs:
      - Object with entered=True after __enter__ is invoked.
    """

    def __init__(self) -> None:
        self.entered = False

    def __enter__(self) -> "_RecordingLock":
        self.entered = True
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        return False


class _PluginWithLock(_PluginNoLock):
    """Brief: Minimal plugin object that includes a _records_lock attribute.

    Inputs:
      - name_index: owner -> qtype -> (ttl, [values]) mapping.
      - zone_soa: zone apex -> (ttl, [soa_values]) mapping.
      - lock: lock-like context manager.

    Outputs:
      - Instance with _records_lock plus inherited attributes.
    """

    def __init__(
        self,
        *,
        name_index: dict,
        zone_soa: dict,
        lock: _RecordingLock,
    ) -> None:
        super().__init__(name_index=name_index, zone_soa=zone_soa)
        self._records_lock = lock


def _make_soa(zone: str) -> RR:
    """Brief: Build a single SOA RR for tests.

    Inputs:
      - zone: Zone apex owner name.

    Outputs:
      - SOA RR instance.
    """

    return RR.fromZone(
        f"{zone}. 300 IN SOA ns1.{zone}. hostmaster.{zone}. 1 3600 600 604800 300"
    )[0]


def _make_a(owner: str, ip: str) -> RR:
    """Brief: Build a single A RR for tests.

    Inputs:
      - owner: Owner name.
      - ip: IPv4 value.

    Outputs:
      - A RR instance.
    """

    return RR.fromZone(f"{owner}. 300 IN A {ip}")[0]


def test_iter_zone_rrs_for_transfer_empty_apex_returns_none() -> None:
    """Brief: Empty zone apex should return None immediately.

    Inputs:
      - zone_apex: ''.

    Outputs:
      - None.
    """
    plugin = _PluginNoLock(name_index={}, zone_soa={})

    assert transfer.iter_zone_rrs_for_transfer(plugin, "") is None


def test_iter_zone_rrs_for_transfer_no_lock_snapshots_and_filters_zone() -> None:
    """Brief: Without a lock, helper snapshots dicts and filters owners by apex.

    Inputs:
      - plugin: minimal plugin with _name_index/_zone_soa.

    Outputs:
      - None; asserts only in-zone owners are exported.
    """
    apex = "example.com"
    plugin = _PluginNoLock(
        name_index={
            "example.com": {int(QTYPE.A): (300, ["192.0.2.1"])},
            "www.example.com.": {int(QTYPE.A): (300, ["192.0.2.2"])},
            "other.com": {int(QTYPE.A): (300, ["198.51.100.1"])},
        },
        zone_soa={apex: (300, ["soa"])},
    )

    rrs = transfer.iter_zone_rrs_for_transfer(plugin, "EXAMPLE.COM.")
    assert rrs is not None

    owners = {str(rr.rname).rstrip(".").lower() for rr in rrs}
    assert "example.com" in owners
    assert "www.example.com" in owners
    assert "other.com" not in owners


def test_iter_zone_rrs_for_transfer_with_lock_uses_locked_snapshot() -> None:
    """Brief: Snapshot is taken under _records_lock when lock is present.

    Inputs:
      - Plugin with lock and in-zone data.

    Outputs:
      - Asserts lock was entered and RR export succeeds.
    """

    lock = _RecordingLock()
    plugin = _PluginWithLock(
        name_index={"example.com": {int(QTYPE.A): (60, ["192.0.2.5"])}},
        zone_soa={"example.com": (300, ["soa"])},
        lock=lock,
    )
    rrs = transfer.iter_zone_rrs_for_transfer(plugin, "example.com")
    assert rrs is not None
    assert list(rrs)
    assert lock.entered is True


def test_iter_zone_rrs_for_transfer_non_authoritative_zone_returns_none() -> None:
    """Brief: Export returns None when plugin is not authoritative for requested apex.

    Inputs:
      - Plugin with SOA for a different zone.

    Outputs:
      - Asserts None result.
    """

    plugin = _PluginNoLock(
        name_index={"example.com": {int(QTYPE.A): (60, ["192.0.2.5"])}},
        zone_soa={"other.com": (300, ["soa"])},
    )
    assert transfer.iter_zone_rrs_for_transfer(plugin, "example.com") is None


def test_get_axfr_policy_defaults_when_runtime_snapshot_lookup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _get_axfr_policy returns defaults when snapshot lookup raises.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts default fallback fields.
    """

    import foghorn.runtime_config as runtime_config

    def _raise() -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(runtime_config, "get_runtime_snapshot", _raise)
    policy = transfer._get_axfr_policy()
    assert policy["enabled"] is False
    assert policy["allow_clients"] == []
    assert policy["max_concurrent_transfers"] == 4
    assert policy["message_max_bytes"] == 64000


def test_get_axfr_policy_reads_and_clamps_runtime_snapshot(
    set_runtime_snapshot,
) -> None:
    """Brief: _get_axfr_policy reflects runtime values and bound checks.

    Inputs:
      - set_runtime_snapshot fixture.

    Outputs:
      - Asserts selected fields and clamping behavior.
    """

    set_runtime_snapshot(
        axfr_enabled=True,
        axfr_allow_clients=["127.0.0.0/8"],
        axfr_max_concurrent_transfers=0,
        axfr_message_max_bytes=999999,
        axfr_rate_limit_per_client_per_second=3.5,
        axfr_rate_limit_burst=0.0,
        axfr_tsig_keys=[{"name": "k", "secret": "s"}],
    )
    policy = transfer._get_axfr_policy()
    assert policy["enabled"] is True
    assert policy["allow_clients"] == ["127.0.0.0/8"]
    assert policy["max_concurrent_transfers"] == 4
    assert policy["message_max_bytes"] == 65535
    assert policy["rate_limit_per_client_per_second"] == 3.5
    assert policy["rate_limit_burst"] == 2.0
    assert policy["tsig_keys"] == [{"name": "k", "secret": "s"}]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("hmac-sha512.", "hmac-sha512"),
        ("dnssec-hmac-sha384", "hmac-sha384"),
        ("hmac-sha256", "hmac-sha256"),
        ("HMAC-SHA1", "hmac-sha1"),
        ("hmac-md5.sig-alg.reg.int", "hmac-md5"),
        ("", "hmac-sha256"),
        ("custom-algorithm", "custom-algorithm"),
    ],
)
def test_normalize_tsig_algorithm_variants(raw: str, expected: str) -> None:
    """Brief: _normalize_tsig_algorithm normalizes known names and preserves unknowns.

    Inputs:
      - raw: Raw algorithm text.

    Outputs:
      - Asserts normalized value.
    """

    assert transfer._normalize_tsig_algorithm(raw) == expected


def test_prepare_axfr_tsig_signer_basic_policy_paths() -> None:
    """Brief: _prepare_axfr_tsig_signer handles no-policy and missing-wire cases.

    Inputs:
      - Policies with absent/invalid TSIG requirements.

    Outputs:
      - Asserts expected (signer, error) pairs.
    """

    assert transfer._prepare_axfr_tsig_signer(None, {}) == (None, None)
    assert transfer._prepare_axfr_tsig_signer(
        None,
        {"require_tsig": True, "tsig_keys": []},
    ) == (None, "missing AXFR request wire for TSIG verification")
    assert transfer._prepare_axfr_tsig_signer(
        b"wire",
        {"require_tsig": True, "tsig_keys": [{"name": "", "secret": ""}]},
    ) == (
        None,
        "AXFR TSIG required but no usable server.axfr.tsig_keys configured",
    )


def test_prepare_axfr_tsig_signer_handles_keyring_and_verify_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _prepare_axfr_tsig_signer maps representative keyring/verify errors.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts returned error text for multiple exception classes.
    """

    policy = {
        "require_tsig": True,
        "tsig_keys": [{"name": "k1", "secret": "s1", "algorithm": "hmac-sha256"}],
    }

    monkeypatch.setattr(
        transfer.dns.tsigkeyring,
        "from_text",
        lambda _keys: (_ for _ in ()).throw(ValueError("bad-keyring")),
    )
    signer, err = transfer._prepare_axfr_tsig_signer(b"wire", policy)
    assert signer is None
    assert "failed to build AXFR TSIG keyring" in str(err)

    monkeypatch.setattr(
        transfer.dns.tsigkeyring, "from_text", lambda _keys: {"ok": True}
    )

    monkeypatch.setattr(
        transfer.dns.message,
        "from_wire",
        lambda _wire, keyring=None: (_ for _ in ()).throw(  # noqa: ARG005
            dns.tsig.PeerBadKey("missing")
        ),
    )
    assert (
        transfer._prepare_axfr_tsig_signer(b"wire", policy)[1]
        == "unknown TSIG key: missing"
    )

    monkeypatch.setattr(
        transfer.dns.message,
        "from_wire",
        lambda _wire, keyring=None: (_ for _ in ()).throw(
            dns.tsig.BadSignature()
        ),  # noqa: ARG005
    )
    assert (
        transfer._prepare_axfr_tsig_signer(b"wire", policy)[1]
        == "TSIG signature verification failed"
    )

    monkeypatch.setattr(
        transfer.dns.message,
        "from_wire",
        lambda _wire, keyring=None: (_ for _ in ()).throw(
            dns.exception.FormError("bad")
        ),  # noqa: ARG005
    )
    assert (
        transfer._prepare_axfr_tsig_signer(b"wire", policy)[1]
        == "TSIG verification error: bad"
    )


def test_prepare_axfr_tsig_signer_missing_mismatch_and_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _prepare_axfr_tsig_signer enforces had_tsig and key/algorithm matching.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts missing TSIG, mismatched TSIG, and success output fields.
    """

    @dataclasses.dataclass
    class _FakeRequest:
        had_tsig: bool
        keyname: str = "k1."
        keyalgorithm: str = "hmac-sha256."
        mac: bytes = b"mac"

    policy = {
        "require_tsig": True,
        "tsig_keys": [{"name": "k1", "secret": "s1", "algorithm": "hmac-sha256"}],
    }
    monkeypatch.setattr(
        transfer.dns.tsigkeyring, "from_text", lambda _keys: {"ok": True}
    )

    monkeypatch.setattr(
        transfer.dns.message,
        "from_wire",
        lambda _wire, keyring=None: _FakeRequest(had_tsig=False),  # noqa: ARG005
    )
    assert (
        transfer._prepare_axfr_tsig_signer(b"wire", policy)[1]
        == "TSIG required but missing on AXFR/IXFR request"
    )

    monkeypatch.setattr(
        transfer.dns.message,
        "from_wire",
        lambda _wire, keyring=None: _FakeRequest(  # noqa: ARG005
            had_tsig=True,
            keyname="other.",
        ),
    )
    assert (
        transfer._prepare_axfr_tsig_signer(b"wire", policy)[1]
        == "TSIG key or algorithm not configured for AXFR"
    )

    monkeypatch.setattr(
        transfer.dns.message,
        "from_wire",
        lambda _wire, keyring=None: _FakeRequest(had_tsig=True),  # noqa: ARG005
    )
    signer, err = transfer._prepare_axfr_tsig_signer(b"wire", policy)
    assert err is None
    assert signer is not None
    assert signer["keyname"] == "k1"
    assert signer["algorithm"] == "hmac-sha256"
    assert signer["request_mac"] == b"mac"


def test_prepare_axfr_tsig_signer_skips_mismatched_key_then_selects_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: TSIG key-selection loop skips mismatches and accepts a later match.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts signer uses the second matching key definition.
    """

    @dataclasses.dataclass
    class _FakeRequest:
        had_tsig: bool = True
        keyname: str = "k2."
        keyalgorithm: str = "hmac-sha256."
        mac: bytes = b"mac"

    policy = {
        "require_tsig": True,
        "tsig_keys": [
            {"name": "k1", "secret": "s1", "algorithm": "hmac-sha512"},
            {"name": "k2", "secret": "s2", "algorithm": "hmac-sha256"},
        ],
    }
    monkeypatch.setattr(
        transfer.dns.tsigkeyring, "from_text", lambda _keys: {"ok": True}
    )
    monkeypatch.setattr(
        transfer.dns.message,
        "from_wire",
        lambda _wire, keyring=None: _FakeRequest(),  # noqa: ARG005
    )
    signer, err = transfer._prepare_axfr_tsig_signer(b"wire", policy)
    assert err is None
    assert signer is not None
    assert signer["keyname"] == "k2"


def test_maybe_sign_axfr_wire_without_signer_returns_original() -> None:
    """Brief: _maybe_sign_axfr_wire is pass-through when signer is None.

    Inputs:
      - Unsigned wire bytes.

    Outputs:
      - Same wire bytes.
    """

    req = DNSRecord.question("example.com.", qtype="AXFR")
    assert transfer._maybe_sign_axfr_wire(b"plain", req, None) == b"plain"


def test_maybe_sign_axfr_wire_signs_and_updates_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _maybe_sign_axfr_wire signs payload and updates signer tsig_ctx.

    Inputs:
      - monkeypatch fixture and fake dnspython message.

    Outputs:
      - Asserts signed wire and tsig_ctx rollover.
    """

    class _FakeMsg:
        def __init__(self) -> None:
            self.request_mac = b""
            self.tsig_ctx = "new-tsig-ctx"
            self.used = None
            self.to_wire_args = None

        def use_tsig(self, **kwargs) -> None:  # noqa: ANN003
            self.used = kwargs

        def to_wire(self, multi: bool, tsig_ctx) -> bytes:  # noqa: ANN001
            self.to_wire_args = (multi, tsig_ctx)
            return b"signed-wire"

    fake = _FakeMsg()
    monkeypatch.setattr(transfer.dns.message, "from_wire", lambda _wire: fake)
    signer = {
        "keyring": {"k": "v"},
        "keyname": "k1",
        "algorithm": "hmac-sha256",
        "request_mac": b"req-mac",
        "tsig_ctx": "prior",
    }
    req = DNSRecord.question("example.com.", qtype="AXFR")
    out = transfer._maybe_sign_axfr_wire(b"raw", req, signer)
    assert out == b"signed-wire"
    assert fake.request_mac == b"req-mac"
    assert fake.used is not None
    assert fake.to_wire_args == (True, "prior")
    assert signer["tsig_ctx"] == "new-tsig-ctx"


def test_compiled_allowlist_networks_and_client_policy_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Client policy helper handles disabled, malformed, and matching clients.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts expected allow/deny outcomes.
    """

    parsed = transfer._compiled_allowlist_networks(("127.0.0.0/8", "bad-network"))
    assert len(parsed) == 1

    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {"enabled": False, "allow_clients": ["127.0.0.0/8"]},
    )
    assert transfer._client_allowed_for_axfr("127.0.0.1") is False

    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {"enabled": True, "allow_clients": []},
    )
    assert transfer._client_allowed_for_axfr("127.0.0.1") is False

    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {"enabled": True, "allow_clients": ["127.0.0.0/8"]},
    )
    assert transfer._client_allowed_for_axfr("not-an-ip") is False
    assert transfer._client_allowed_for_axfr("127.0.0.1") is True
    assert transfer._client_allowed_for_axfr("198.51.100.10") is False


def test_axfr_rate_limit_and_slot_counters(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _axfr_rate_limited and slot counters handle edge conditions.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts token transitions and max-slot gate behavior.
    """

    transfer._AXFR_CLIENT_RATE_STATE.clear()
    transfer._AXFR_ACTIVE_TRANSFERS = 0

    assert (
        transfer._axfr_rate_limited(
            "127.0.0.1",
            {"rate_limit_per_client_per_second": 0.0, "rate_limit_burst": 1.0},
        )
        is False
    )
    assert (
        transfer._axfr_rate_limited(
            None,
            {"rate_limit_per_client_per_second": 1.0, "rate_limit_burst": 1.0},
        )
        is True
    )

    ticks = itertools.chain([100.0, 100.0, 101.0], itertools.repeat(101.0))
    monkeypatch.setattr(transfer.time, "monotonic", lambda: next(ticks))
    policy = {"rate_limit_per_client_per_second": 1.0, "rate_limit_burst": 1.0}
    assert transfer._axfr_rate_limited("127.0.0.1", policy) is False
    assert transfer._axfr_rate_limited("127.0.0.1", policy) is True
    assert transfer._axfr_rate_limited("127.0.0.1", policy) is False
    assert transfer._axfr_rate_limited("   ", policy) is True

    assert transfer._axfr_try_acquire_slot({"max_concurrent_transfers": 1}) is True
    assert transfer._axfr_try_acquire_slot({"max_concurrent_transfers": 1}) is False
    transfer._axfr_release_slot()
    transfer._axfr_release_slot()
    assert transfer._AXFR_ACTIVE_TRANSFERS == 0


def test_iter_axfr_messages_refused_for_tsig_rate_limit_and_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: iter_axfr_messages emits REFUSED for TSIG, rate, and slot denials.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts REFUSED in each denial branch.
    """

    req = DNSRecord.question("example.com.", qtype="AXFR")
    monkeypatch.setattr(transfer, "_get_axfr_policy", lambda: {"plugins": []})

    monkeypatch.setattr(
        transfer, "_prepare_axfr_tsig_signer", lambda _rw, _p: (None, "bad-tsig")
    )
    tsig_refused = DNSRecord.parse(
        list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))[0]
    )
    assert tsig_refused.header.rcode == RCODE.REFUSED

    monkeypatch.setattr(
        transfer, "_prepare_axfr_tsig_signer", lambda _rw, _p: (None, None)
    )
    monkeypatch.setattr(transfer, "_client_allowed_for_axfr", lambda _ip: True)
    monkeypatch.setattr(transfer, "_axfr_rate_limited", lambda _ip, _p: True)
    rate_refused = DNSRecord.parse(
        list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))[0]
    )
    assert rate_refused.header.rcode == RCODE.REFUSED

    monkeypatch.setattr(transfer, "_axfr_rate_limited", lambda _ip, _p: False)
    monkeypatch.setattr(transfer, "_axfr_try_acquire_slot", lambda _p: False)
    slot_refused = DNSRecord.parse(
        list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))[0]
    )
    assert slot_refused.header.rcode == RCODE.REFUSED


def test_iter_axfr_messages_refused_for_plugin_and_zone_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: iter_axfr_messages refuses when exporter/zone validation fails.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts REFUSED for no exporter, oversized zone, and missing SOA.
    """

    req = DNSRecord.question("example.com.", qtype="AXFR")
    monkeypatch.setattr(
        transfer, "_prepare_axfr_tsig_signer", lambda _rw, _p: (None, None)
    )
    monkeypatch.setattr(transfer, "_client_allowed_for_axfr", lambda _ip: True)
    monkeypatch.setattr(transfer, "_axfr_rate_limited", lambda _ip, _p: False)
    monkeypatch.setattr(transfer, "_axfr_try_acquire_slot", lambda _p: True)

    monkeypatch.setattr(transfer, "_get_axfr_policy", lambda: {"plugins": [object()]})
    no_export = DNSRecord.parse(
        list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))[0]
    )
    assert no_export.header.rcode == RCODE.REFUSED

    class _BigZonePlugin:
        def iter_zone_rrs_for_transfer(
            self,
            zone_apex: str,
            client_ip: str | None = None,
        ):  # noqa: ARG002
            return [_make_soa(zone_apex), _make_a(zone_apex, "192.0.2.10")]

    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {
            "plugins": [_BigZonePlugin()],
            "max_zone_rrs": 1,
            "message_max_bytes": 64000,
        },
    )
    oversized = DNSRecord.parse(
        list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))[0]
    )
    assert oversized.header.rcode == RCODE.REFUSED

    class _NoSoaPlugin:
        def iter_zone_rrs_for_transfer(
            self,
            zone_apex: str,
            client_ip: str | None = None,
        ):  # noqa: ARG002
            return [_make_a(zone_apex, "192.0.2.20")]

    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {"plugins": [_NoSoaPlugin()], "message_max_bytes": 64000},
    )
    no_soa = DNSRecord.parse(
        list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))[0]
    )
    assert no_soa.header.rcode == RCODE.REFUSED


def test_iter_axfr_messages_success_with_legacy_exporter_and_rate_sleep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: iter_axfr_messages supports legacy exporter signature and streams AXFR.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts non-REFUSED output, duplicate-primary SOA skip, and pacing sleep.
    """

    req = DNSRecord.question("example.com.", qtype="AXFR")

    class _LegacyPlugin:
        def iter_zone_rrs_for_transfer(self, zone_apex: str):
            return [
                _make_soa(zone_apex),
                _make_soa(zone_apex),
                _make_a(zone_apex, "192.0.2.10"),
            ]

    monkeypatch.setattr(
        transfer, "_prepare_axfr_tsig_signer", lambda _rw, _p: (None, None)
    )
    monkeypatch.setattr(transfer, "_client_allowed_for_axfr", lambda _ip: True)
    monkeypatch.setattr(transfer, "_axfr_rate_limited", lambda _ip, _p: False)
    monkeypatch.setattr(transfer, "_axfr_try_acquire_slot", lambda _p: True)
    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {
            "plugins": [_LegacyPlugin()],
            "message_max_bytes": 60,
            "max_transfer_rate_bytes_per_second": 1,
            "max_zone_rrs": None,
        },
    )

    perf_ticks = itertools.chain([100.0] * 32, itertools.repeat(100.0))
    monkeypatch.setattr(transfer.time, "perf_counter", lambda: next(perf_ticks))
    sleeps: list[float] = []
    monkeypatch.setattr(
        transfer.time, "sleep", lambda duration: sleeps.append(float(duration))
    )

    wires = list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))
    assert wires
    decoded = [DNSRecord.parse(w) for w in wires]
    assert all(rec.header.rcode != RCODE.REFUSED for rec in decoded)

    all_rrs = [rr for rec in decoded for rr in rec.rr]
    assert sum(1 for rr in all_rrs if int(rr.rtype) == int(QTYPE.SOA)) == 3
    assert any(int(rr.rtype) == int(QTYPE.A) for rr in all_rrs)
    assert sleeps


def test_iter_axfr_messages_final_pack_failure_falls_back_to_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: iter_axfr_messages yields REFUSED when response packing keeps failing.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts final defensive REFUSED fallback path.
    """

    req = DNSRecord.question("example.com.", qtype="AXFR")

    class _Plugin:
        def iter_zone_rrs_for_transfer(
            self,
            zone_apex: str,
            client_ip: str | None = None,
        ):  # noqa: ARG002
            return [_make_soa(zone_apex), _make_a(zone_apex, "192.0.2.99")]

    monkeypatch.setattr(
        transfer, "_prepare_axfr_tsig_signer", lambda _rw, _p: (None, None)
    )
    monkeypatch.setattr(transfer, "_client_allowed_for_axfr", lambda _ip: True)
    monkeypatch.setattr(transfer, "_axfr_rate_limited", lambda _ip, _p: False)
    monkeypatch.setattr(transfer, "_axfr_try_acquire_slot", lambda _p: True)
    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {"plugins": [_Plugin()], "message_max_bytes": 64000},
    )

    original_pack = transfer.DNSRecord.pack

    def _flaky_pack(self, *args, **kwargs):  # noqa: ANN001
        if int(getattr(self.header, "rcode", 0)) == int(RCODE.REFUSED):
            return original_pack(self, *args, **kwargs)
        raise RuntimeError("pack-fail")

    monkeypatch.setattr(transfer.DNSRecord, "pack", _flaky_pack)

    first_wire = list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))[0]
    first_resp = DNSRecord.parse(first_wire)
    assert first_resp.header.rcode == RCODE.REFUSED


def test_prepare_axfr_tsig_signer_optional_and_additional_error_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Additional TSIG signer branches cover optional-mode and uncommon errors.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts optional TSIG handling and additional exception mappings.
    """

    optional_policy = {
        "require_tsig": False,
        "tsig_keys": [None, {"name": "", "secret": ""}],
    }
    assert transfer._prepare_axfr_tsig_signer(None, optional_policy) == (None, None)
    assert transfer._prepare_axfr_tsig_signer(b"wire", optional_policy) == (None, None)

    policy = {
        "require_tsig": True,
        "tsig_keys": [{"name": "k1", "secret": "s1", "algorithm": "hmac-sha256"}],
    }
    monkeypatch.setattr(
        transfer.dns.tsigkeyring, "from_text", lambda _keys: {"ok": True}
    )
    monkeypatch.setattr(
        transfer.dns.message,
        "from_wire",
        lambda _wire, keyring=None: (_ for _ in ()).throw(
            dns.tsig.PeerBadTime()
        ),  # noqa: ARG005
    )
    assert (
        transfer._prepare_axfr_tsig_signer(b"wire", policy)[1]
        == "TSIG time verification failed"
    )

    monkeypatch.setattr(
        transfer.dns.message,
        "from_wire",
        lambda _wire, keyring=None: (_ for _ in ()).throw(
            RuntimeError("unknown-fail")
        ),  # noqa: ARG005
    )
    assert (
        transfer._prepare_axfr_tsig_signer(b"wire", policy)[1]
        == "TSIG verification error: unknown-fail"
    )

    @dataclasses.dataclass
    class _NoTsigRequest:
        had_tsig: bool = False

    monkeypatch.setattr(
        transfer.dns.message,
        "from_wire",
        lambda _wire, keyring=None: _NoTsigRequest(),  # noqa: ARG005
    )
    assert transfer._prepare_axfr_tsig_signer(
        b"wire", {"require_tsig": False, "tsig_keys": [{"name": "k1", "secret": "s1"}]}
    ) == (None, None)


def test_client_allowed_for_axfr_handles_missing_client_and_invalid_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _client_allowed_for_axfr denies missing clients and unusable allowlist sets.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts false outcomes for these deny branches.
    """

    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {"enabled": True, "allow_clients": ["127.0.0.0/8"]},
    )
    assert transfer._client_allowed_for_axfr(None) is False

    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {"enabled": True, "allow_clients": ["not-a-cidr"]},
    )
    assert transfer._client_allowed_for_axfr("127.0.0.1") is False


def test_iter_axfr_messages_unauthorized_client_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: iter_axfr_messages returns REFUSED for unauthorized clients.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts unauthorized-client deny path.
    """

    req = DNSRecord.question("example.com.", qtype="AXFR")
    monkeypatch.setattr(transfer, "_get_axfr_policy", lambda: {"plugins": []})
    monkeypatch.setattr(
        transfer, "_prepare_axfr_tsig_signer", lambda _rw, _p: (None, None)
    )
    monkeypatch.setattr(transfer, "_client_allowed_for_axfr", lambda _ip: False)

    first_wire = list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))[0]
    assert DNSRecord.parse(first_wire).header.rcode == RCODE.REFUSED


def test_iter_axfr_messages_handles_probe_failures_and_empty_iterables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Plugin probe phase handles export exceptions, None, empty, and bad iterators.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts probe-failure branches end in REFUSED when no exporter is selected.
    """

    req = DNSRecord.question("example.com.", qtype="AXFR")

    class _RaisesPlugin:
        def iter_zone_rrs_for_transfer(
            self, zone_apex: str, client_ip: str | None = None
        ):  # noqa: ARG002
            raise RuntimeError("probe-fail")

    class _NonePlugin:
        def iter_zone_rrs_for_transfer(
            self, zone_apex: str, client_ip: str | None = None
        ):  # noqa: ARG002
            return None

    class _EmptyPlugin:
        def iter_zone_rrs_for_transfer(
            self, zone_apex: str, client_ip: str | None = None
        ):  # noqa: ARG002
            return []

    class _BadIter:
        def __iter__(self):
            return self

        def __next__(self):
            raise RuntimeError("bad-iter")

    class _BadIterPlugin:
        def iter_zone_rrs_for_transfer(
            self, zone_apex: str, client_ip: str | None = None
        ):  # noqa: ARG002
            return _BadIter()

    monkeypatch.setattr(
        transfer, "_prepare_axfr_tsig_signer", lambda _rw, _p: (None, None)
    )
    monkeypatch.setattr(transfer, "_client_allowed_for_axfr", lambda _ip: True)
    monkeypatch.setattr(transfer, "_axfr_rate_limited", lambda _ip, _p: False)
    monkeypatch.setattr(transfer, "_axfr_try_acquire_slot", lambda _p: True)
    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {
            "plugins": [
                _RaisesPlugin(),
                _NonePlugin(),
                _EmptyPlugin(),
                _BadIterPlugin(),
            ]
        },
    )

    first_wire = list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))[0]
    assert DNSRecord.parse(first_wire).header.rcode == RCODE.REFUSED


def test_iter_axfr_messages_handles_exporter_second_pass_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Selected exporter failures during main transfer pass lead to REFUSED.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts second-pass exporter exception and None-return paths.
    """

    req = DNSRecord.question("example.com.", qtype="AXFR")

    class _TogglePlugin:
        def __init__(self) -> None:
            self.calls = 0

        def iter_zone_rrs_for_transfer(
            self, zone_apex: str, client_ip: str | None = None
        ):  # noqa: ARG002
            self.calls += 1
            if self.calls == 1:
                return [_make_soa(zone_apex)]
            raise RuntimeError("second-pass-fail")

    class _NoneOnSecondPassPlugin:
        def __init__(self) -> None:
            self.calls = 0

        def iter_zone_rrs_for_transfer(
            self, zone_apex: str, client_ip: str | None = None
        ):  # noqa: ARG002
            self.calls += 1
            if self.calls == 1:
                return [_make_soa(zone_apex)]
            return None

    for plugin in (_TogglePlugin(), _NoneOnSecondPassPlugin()):
        monkeypatch.setattr(
            transfer, "_prepare_axfr_tsig_signer", lambda _rw, _p: (None, None)
        )
        monkeypatch.setattr(transfer, "_client_allowed_for_axfr", lambda _ip: True)
        monkeypatch.setattr(transfer, "_axfr_rate_limited", lambda _ip, _p: False)
        monkeypatch.setattr(transfer, "_axfr_try_acquire_slot", lambda _p: True)
        monkeypatch.setattr(
            transfer,
            "_get_axfr_policy",
            lambda p=plugin: {"plugins": [p], "message_max_bytes": 64000},
        )
        first_wire = list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))[0]
        assert DNSRecord.parse(first_wire).header.rcode == RCODE.REFUSED


def test_iter_axfr_messages_malformed_query_without_questions_returns_refused() -> None:
    """Brief: Malformed AXFR query without questions is refused.

    Inputs:
      - DNSRecord instance with an empty question section.

    Outputs:
      - Asserts REFUSED response from malformed-query handling.
    """

    req = DNSRecord()
    wire = list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))[0]
    assert DNSRecord.parse(wire).header.rcode == RCODE.REFUSED


def test_prepare_axfr_tsig_signer_algorithm_mismatch_then_match_additional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: TSIG key loop skips algorithm-mismatch entries before selecting a later match.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts signer is built from the second matching algorithm entry.
    """

    @dataclasses.dataclass
    class _FakeRequest:
        had_tsig: bool = True
        keyname: str = "k1."
        keyalgorithm: str = "hmac-sha256."
        mac: bytes = b"mac"

    policy = {
        "require_tsig": True,
        "tsig_keys": [
            {"name": "k1", "secret": "s1", "algorithm": "hmac-sha512"},
            {"name": "k1", "secret": "s1", "algorithm": "hmac-sha256"},
        ],
    }
    monkeypatch.setattr(
        transfer.dns.tsigkeyring, "from_text", lambda _keys: {"ok": True}
    )
    monkeypatch.setattr(
        transfer.dns.message,
        "from_wire",
        lambda _wire, keyring=None: _FakeRequest(),  # noqa: ARG005
    )
    signer, err = transfer._prepare_axfr_tsig_signer(b"wire", policy)
    assert err is None
    assert signer is not None
    assert signer["algorithm"] == "hmac-sha256"


def test_iter_axfr_messages_skips_none_rr_and_streams_without_rate_limit_additional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: AXFR stream ignores None RRs and yields messages when transfer pacing is disabled.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts successful non-REFUSED AXFR output with an A record present.
    """

    req = DNSRecord.question("example.com.", qtype="AXFR")

    class _Plugin:
        def iter_zone_rrs_for_transfer(
            self,
            zone_apex: str,
            client_ip: str | None = None,
        ):  # noqa: ARG002
            return [_make_soa(zone_apex), None, _make_a(zone_apex, "192.0.2.77")]

    monkeypatch.setattr(
        transfer, "_prepare_axfr_tsig_signer", lambda _rw, _p: (None, None)
    )
    monkeypatch.setattr(transfer, "_client_allowed_for_axfr", lambda _ip: True)
    monkeypatch.setattr(transfer, "_axfr_rate_limited", lambda _ip, _p: False)
    monkeypatch.setattr(transfer, "_axfr_try_acquire_slot", lambda _p: True)
    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {"plugins": [_Plugin()], "message_max_bytes": 64000},
    )
    wires = list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))
    decoded = [DNSRecord.parse(w) for w in wires]
    assert decoded
    assert all(rec.header.rcode != RCODE.REFUSED for rec in decoded)
    assert any(int(rr.rtype) == int(QTYPE.A) for rec in decoded for rr in rec.rr)


def test_iter_axfr_messages_rate_limit_branch_can_skip_sleep_additional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Transfer pacing branch executes without sleeping when elapsed time already exceeds budget.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts no sleep calls while AXFR output is still produced.
    """

    req = DNSRecord.question("example.com.", qtype="AXFR")

    class _Plugin:
        def iter_zone_rrs_for_transfer(
            self,
            zone_apex: str,
            client_ip: str | None = None,
        ):  # noqa: ARG002
            return [_make_soa(zone_apex), _make_a(zone_apex, "192.0.2.88")]

    monkeypatch.setattr(
        transfer, "_prepare_axfr_tsig_signer", lambda _rw, _p: (None, None)
    )
    monkeypatch.setattr(transfer, "_client_allowed_for_axfr", lambda _ip: True)
    monkeypatch.setattr(transfer, "_axfr_rate_limited", lambda _ip, _p: False)
    monkeypatch.setattr(transfer, "_axfr_try_acquire_slot", lambda _p: True)
    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {
            "plugins": [_Plugin()],
            "message_max_bytes": 64000,
            "max_transfer_rate_bytes_per_second": 1,
        },
    )
    perf_ticks = itertools.chain([0.0, 1000.0], itertools.repeat(1000.0))
    monkeypatch.setattr(transfer.time, "perf_counter", lambda: next(perf_ticks))
    sleeps: list[float] = []
    monkeypatch.setattr(
        transfer.time, "sleep", lambda seconds: sleeps.append(float(seconds))
    )

    wires = list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))
    assert wires
    assert sleeps == []


def test_iter_axfr_messages_flush_pack_failure_and_final_failure_after_message_additional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Flush-pack failure path restores RR and final-pack failure can return after prior output.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts one yielded wire from overflow flush and no fallback REFUSED append.
    """

    req = DNSRecord.question("example.com.", qtype="AXFR")

    class _Plugin:
        def iter_zone_rrs_for_transfer(
            self,
            zone_apex: str,
            client_ip: str | None = None,
        ):  # noqa: ARG002
            return [_make_soa(zone_apex), _make_a(zone_apex, "192.0.2.99")]

    monkeypatch.setattr(
        transfer, "_prepare_axfr_tsig_signer", lambda _rw, _p: (None, None)
    )
    monkeypatch.setattr(transfer, "_client_allowed_for_axfr", lambda _ip: True)
    monkeypatch.setattr(transfer, "_axfr_rate_limited", lambda _ip, _p: False)
    monkeypatch.setattr(transfer, "_axfr_try_acquire_slot", lambda _p: True)
    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {"plugins": [_Plugin()], "message_max_bytes": 40},
    )

    original_pack = transfer.DNSRecord.pack
    state = {"len1_fail_next": False}

    def _branchy_pack(self, *args, **kwargs):  # noqa: ANN001
        if int(getattr(self.header, "rcode", 0)) == int(RCODE.REFUSED):
            return original_pack(self, *args, **kwargs)
        if len(self.rr) >= 2:
            state["len1_fail_next"] = True
            return b"x" * 500
        if len(self.rr) == 1 and state["len1_fail_next"]:
            state["len1_fail_next"] = False
            raise RuntimeError("flush-pack-fail")
        return b"x" * 20

    monkeypatch.setattr(transfer.DNSRecord, "pack", _branchy_pack)

    wires = list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))
    assert wires == [b"x" * 500]


def test_iter_axfr_messages_keeps_non_apex_soa_records_additional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Non-apex SOA records are not treated as duplicate opening SOA markers.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts transfer succeeds and includes a non-apex SOA record.
    """

    req = DNSRecord.question("example.com.", qtype="AXFR")
    sub_soa = RR.fromZone(
        "sub.example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 2 3600 600 604800 300"
    )[0]

    class _Plugin:
        def iter_zone_rrs_for_transfer(
            self,
            zone_apex: str,
            client_ip: str | None = None,
        ):  # noqa: ARG002
            return [sub_soa, _make_soa(zone_apex), _make_a(zone_apex, "192.0.2.44")]

    monkeypatch.setattr(
        transfer, "_prepare_axfr_tsig_signer", lambda _rw, _p: (None, None)
    )
    monkeypatch.setattr(transfer, "_client_allowed_for_axfr", lambda _ip: True)
    monkeypatch.setattr(transfer, "_axfr_rate_limited", lambda _ip, _p: False)
    monkeypatch.setattr(transfer, "_axfr_try_acquire_slot", lambda _p: True)
    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {"plugins": [_Plugin()], "message_max_bytes": 64000},
    )
    wires = list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))
    decoded = [DNSRecord.parse(w) for w in wires]
    assert decoded
    assert all(rec.header.rcode != RCODE.REFUSED for rec in decoded)
    soa_owners = {
        str(rr.rname).rstrip(".").lower()
        for rec in decoded
        for rr in rec.rr
        if int(rr.rtype) == int(QTYPE.SOA)
    }
    assert "sub.example.com" in soa_owners


def test_iter_axfr_messages_forced_identity_match_non_apex_branch_arc_additional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Rare non-apex SOA branch is exercised by forcing identity equivalence.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts transfer still succeeds when _soa_identity is monkeypatched for this edge path.
    """

    req = DNSRecord.question("example.com.", qtype="AXFR")
    sub_soa = RR.fromZone(
        "sub.example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"
    )[0]
    primary = _make_soa("example.com")
    primary_identity = transfer._soa_identity(primary)

    class _Plugin:
        def iter_zone_rrs_for_transfer(
            self,
            zone_apex: str,
            client_ip: str | None = None,
        ):  # noqa: ARG002
            return [sub_soa, primary, _make_a(zone_apex, "192.0.2.55")]

    real_soa_identity = transfer._soa_identity

    def _forced_identity(rr: RR):  # noqa: ANN201
        if str(rr.rname).rstrip(".").lower() == "sub.example.com":
            return primary_identity
        return real_soa_identity(rr)

    monkeypatch.setattr(transfer, "_soa_identity", _forced_identity)
    monkeypatch.setattr(
        transfer, "_prepare_axfr_tsig_signer", lambda _rw, _p: (None, None)
    )
    monkeypatch.setattr(transfer, "_client_allowed_for_axfr", lambda _ip: True)
    monkeypatch.setattr(transfer, "_axfr_rate_limited", lambda _ip, _p: False)
    monkeypatch.setattr(transfer, "_axfr_try_acquire_slot", lambda _p: True)
    monkeypatch.setattr(
        transfer,
        "_get_axfr_policy",
        lambda: {"plugins": [_Plugin()], "message_max_bytes": 64000},
    )

    wires = list(transfer.iter_axfr_messages(req, client_ip="127.0.0.1"))
    decoded = [DNSRecord.parse(w) for w in wires]
    assert decoded
    assert all(rec.header.rcode != RCODE.REFUSED for rec in decoded)
