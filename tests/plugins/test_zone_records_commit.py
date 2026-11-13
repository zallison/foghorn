"""Brief: Tests for zone_records.commit shared commit pipeline and admin wiring.

Inputs/Outputs:
  - Covers commit_record_actions branches, helpers, and admin apply/delete paths.
"""

from __future__ import annotations

import os
import threading
from types import SimpleNamespace
from typing import Any

import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest
from dnslib import QTYPE

from foghorn.plugins.resolve.zone_records import ZoneRecords
from foghorn.plugins.resolve.zone_records import commit as zone_commit
from foghorn.plugins.resolve.zone_records import update_processor as up


def _soa_entry(serial: int = 1) -> tuple:
    """Brief: Build a SOA records-map entry.

    Inputs:
      - serial: SOA serial number.

    Outputs:
      - (ttl, [soa_rdata], [source]) tuple.
    """
    rdata = f"ns1.example.com. hostmaster.example.com. {serial} 3600 600 604800 300"
    return (300, [rdata], ["src"])


def _plugin(
    *,
    with_lock: bool = True,
    with_soa: bool = True,
    records: dict | None = None,
    name_index: dict | None = None,
    dns_update_config: dict | None = None,
    zone_soa: dict | None = None,
) -> SimpleNamespace:
    """Brief: Build a minimal ZoneRecords-like plugin namespace.

    Inputs:
      - with_lock/with_soa: Feature toggles.
      - records/name_index/dns_update_config/zone_soa: Optional state.

    Outputs:
      - SimpleNamespace plugin stub.
    """
    base = {}
    if with_soa:
        base[("example.com", int(QTYPE.SOA))] = _soa_entry(10)
    if records:
        base.update(records)
    idx = name_index
    if idx is None:
        idx = {}
        for (owner, qtype), entry in base.items():
            idx.setdefault(owner, {})[int(qtype)] = entry
    plugin = SimpleNamespace(
        records=base,
        _name_index=idx,
        _wildcard_owners=[],
        _records_generation=0,
        _update_managed_owners=set(),
        _dns_update_config=dns_update_config
        or {"replication": {"notify_on_update": False}},
        _dns_update_persistence_config={},
        _dns_update_node_id="node-test",
        _zone_soa=(
            zone_soa
            if zone_soa is not None
            else ({"example.com": True} if with_soa else {})
        ),
    )
    if with_lock:
        plugin._records_lock = threading.RLock()
    return plugin


class _RRset:
    """Brief: Minimal RRset-like object for apply_update_operations adapter tests.

    Mirrors dnspython wire shape: zone class on ``rdclass``, optional
    ``deleting`` (NONE/ANY) for delete ops.
    """

    def __init__(self, *, name, rdtype, rdclass, ttl=60, values=None, deleting=None):
        self.name = name
        self.rdtype = int(rdtype)
        self.rdclass = int(rdclass)
        self.ttl = int(ttl)
        self.deleting = None if deleting is None else int(deleting)
        self._values = list(values or [])

    def __iter__(self):
        return iter(self._values)


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


def test_normalize_and_clone_record_entry_shapes() -> None:
    """Brief: Compare/clone helpers accept 2-tuple and 3-tuple RRset shapes."""
    assert zone_commit._normalize_record_entry_for_compare(None) is None
    assert zone_commit._normalize_record_entry_for_compare(("bad",)) is None
    two = zone_commit._normalize_record_entry_for_compare((300, ["1.2.3.4"]))
    assert two == (300, ("1.2.3.4",), ())
    three = zone_commit._normalize_record_entry_for_compare((60, ["a"], ["src"]))
    assert three == (60, ("a",), ("src",))
    cloned = zone_commit._clone_record_entry((10, ["x"]))  # type: ignore[arg-type]
    assert cloned == (10, ["x"], [])
    cloned2 = zone_commit._clone_record_entry((10, ["x"], ["s"]))
    assert cloned2 == (10, ["x"], ["s"])


def test_owner_rrsets_from_view_index_and_fallback() -> None:
    """Brief: Owner RRset extraction prefers name_index then records fallback."""
    records = {
        ("host.example.com", int(QTYPE.A)): (300, ["192.0.2.1"], ["s"]),
        ("host.example.com", int(QTYPE.TXT)): (300, ['"v"'], ["s"]),
        ("other.example.com", int(QTYPE.A)): (300, ["192.0.2.9"], ["s"]),
        ("host.example.com", int(QTYPE.AAAA)): ("bad",),  # ignored
    }
    # Fallback path (no usable index)
    out = zone_commit._owner_rrsets_from_view("host.example.com", records, None)
    assert int(QTYPE.A) in out
    assert int(QTYPE.TXT) in out
    assert int(QTYPE.AAAA) not in out

    idx = {
        "host.example.com": {
            int(QTYPE.A): (300, ["192.0.2.1"], ["s"]),
            int(QTYPE.MX): ("bad",),
        }
    }
    out2 = zone_commit._owner_rrsets_from_view("host.example.com", records, idx)
    assert set(out2.keys()) == {int(QTYPE.A)}


def test_read_and_bump_soa_serial_paths() -> None:
    """Brief: SOA serial read/bump handles missing and malformed entries."""
    records: dict = {}
    assert zone_commit._read_soa_serial(records, "example.com") is None
    assert zone_commit.bump_soa_serial_for_zone(records, "example.com") is None

    records[("example.com", int(QTYPE.SOA))] = (300, [], ["s"])
    assert zone_commit._read_soa_serial(records, "example.com") is None

    records[("example.com", int(QTYPE.SOA))] = (300, ["too short"], ["s"])
    assert zone_commit._read_soa_serial(records, "example.com") is None
    assert zone_commit.bump_soa_serial_for_zone(records, "example.com") is None

    records[("example.com", int(QTYPE.SOA))] = (
        300,
        ["ns. host. notint 3600 600 604800 300"],
        ["s"],
    )
    assert zone_commit._read_soa_serial(records, "example.com") is None

    records[("example.com", int(QTYPE.SOA))] = _soa_entry(41)
    assert zone_commit._read_soa_serial(records, "example.com") == 41
    new_serial = zone_commit.bump_soa_serial_for_zone(records, "example.com")
    assert new_serial == 42
    assert zone_commit._read_soa_serial(records, "example.com") == 42

    # plugin= sync keeps _name_index and _zone_soa aligned with records SOA.
    plugin = SimpleNamespace(
        _name_index={
            "example.com": {int(QTYPE.SOA): _soa_entry(42)},
        },
        _zone_soa={"example.com": True},
    )
    synced = zone_commit.bump_soa_serial_for_zone(records, "example.com", plugin=plugin)
    assert synced == 43
    indexed = plugin._name_index["example.com"][int(QTYPE.SOA)]
    assert " 43 " in indexed[1][0]
    assert records[("example.com", int(QTYPE.SOA))][1][0] == indexed[1][0]
    assert isinstance(plugin._zone_soa["example.com"], tuple)
    assert " 43 " in plugin._zone_soa["example.com"][1][0]

    # Malformed tuple shape
    records[("example.com", int(QTYPE.SOA))] = ("only",)
    assert zone_commit._read_soa_serial(records, "example.com") is None
    assert zone_commit.bump_soa_serial_for_zone(records, "example.com") is None


def test_resolve_zone_apex_for_owner_prefers_update_then_soa() -> None:
    """Brief: Apex resolution prefers dns_update.zones then longest _zone_soa."""
    plugin = SimpleNamespace(
        _dns_update_config={
            "zones": [
                "bad",
                {"zone": ""},
                {"zone": "example.com"},
                {"zone": "sub.example.com"},
            ]
        },
        _zone_soa={"example.com": True, "other.net": True},
    )
    assert (
        zone_commit.resolve_zone_apex_for_owner(plugin, "a.sub.example.com")
        == "sub.example.com"
    )
    assert zone_commit.resolve_zone_apex_for_owner(plugin, "www.example.com") in {
        "example.com",
        "sub.example.com",
    }
    assert zone_commit.resolve_zone_apex_for_owner(plugin, "") == ""

    plugin2 = SimpleNamespace(
        _dns_update_config={"zones": []},
        _zone_soa={"example.com": True, "deep.example.com": True, "": True},
    )
    assert (
        zone_commit.resolve_zone_apex_for_owner(plugin2, "a.deep.example.com")
        == "deep.example.com"
    )
    assert zone_commit.resolve_zone_apex_for_owner(plugin2, "nope.invalid") == ""

    plugin3 = SimpleNamespace(_dns_update_config=None, _zone_soa=None)
    assert zone_commit.resolve_zone_apex_for_owner(plugin3, "x.example.com") == ""


def test_owner_in_zone_empty_apex_allows() -> None:
    """Brief: Empty apex disables zone boundary checks."""
    assert zone_commit._owner_in_zone("anything", "") is True
    assert zone_commit._owner_in_zone("example.com", "example.com") is True
    assert zone_commit._owner_in_zone("a.example.com", "example.com") is True
    assert zone_commit._owner_in_zone("evil.com", "example.com") is False


# ---------------------------------------------------------------------------
# commit_record_actions core
# ---------------------------------------------------------------------------


def test_commit_require_journal_unavailable() -> None:
    """Brief: require_journal_persistence fails closed without writer/actor."""
    plugin = _plugin()
    result = zone_commit.commit_record_actions(
        plugin,
        "example.com",
        [
            {
                "type": "rr_add",
                "owner": "a.example.com",
                "qtype": 1,
                "ttl": 60,
                "value": "1.1.1.1",
            }
        ],
        require_journal_persistence=True,
    )
    assert result.ok is False
    assert result.rcode == 2
    assert result.error == "Journal unavailable"


def test_commit_empty_actions_still_notifies_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Empty action list succeeds and can still emit NOTIFY (UPDATE parity)."""
    plugin = _plugin(
        dns_update_config={"replication": {"notify_on_update": True}},
    )
    calls: list[Any] = []

    import foghorn.plugins.resolve.zone_records.notify as notify_mod

    monkeypatch.setattr(
        notify_mod,
        "send_notify_for_zones",
        lambda p, zones: calls.append(list(zones)),
    )
    result = zone_commit.commit_record_actions(plugin, "example.com", [])
    assert result.ok is True
    assert result.rcode == 0
    assert result.changed is False
    assert calls == [["example.com"]]
    assert int(getattr(plugin, "_dns_update_notify_sent", 0)) == 1


def test_commit_rr_add_replace_delete_matrix() -> None:
    """Brief: rr_add / rr_replace / delete actions mutate state and bump SOA."""
    plugin = _plugin(
        records={
            ("del.example.com", int(QTYPE.A)): (
                300,
                ["192.0.2.10", "192.0.2.11"],
                ["src"],
            ),
            ("wipe.example.com", int(QTYPE.A)): (300, ["198.51.100.1"], ["src"]),
            ("wipe.example.com", int(QTYPE.TXT)): (300, ['"x"'], ["src"]),
        }
    )
    result = zone_commit.commit_record_actions(
        plugin,
        "example.com",
        [
            {
                "type": "rr_add",
                "owner": "www.example.com",
                "qtype": int(QTYPE.A),
                "ttl": 60,
                "value": "203.0.113.1",
                "source": "update",
            },
            {
                "type": "rr_add",
                "owner": "www.example.com",
                "qtype": int(QTYPE.A),
                "ttl": 60,
                "value": "203.0.113.2",
            },
            # no-op add of existing value
            {
                "type": "rr_add",
                "owner": "www.example.com",
                "qtype": int(QTYPE.A),
                "ttl": 60,
                "value": "203.0.113.1",
            },
            {
                "type": "rr_replace",
                "owner": "rep.example.com",
                "qtype": int(QTYPE.A),
                "ttl": 120,
                "values": ["198.51.100.9"],
            },
            {
                "type": "rr_delete_values",
                "owner": "del.example.com",
                "qtype": int(QTYPE.A),
                "value": "192.0.2.10",
            },
            {
                "type": "rr_delete_values",
                "owner": "del.example.com",
                "qtype": int(QTYPE.A),
                "value": "192.0.2.11",
            },
            {"type": "name_delete_all", "owner": "wipe.example.com"},
            {
                "type": "rr_delete_rrset",
                "owner": "missing.example.com",
                "qtype": int(QTYPE.A),
            },
            {
                "type": "rr_delete_values",
                "owner": "del.example.com",
                "qtype": int(QTYPE.A),
                "value": "9.9.9.9",
            },
        ],
        send_notify=False,
    )
    assert result.ok is True
    assert result.serial_before == 10
    assert result.serial_after == 11
    assert plugin.records[("www.example.com", int(QTYPE.A))][1] == [
        "203.0.113.1",
        "203.0.113.2",
    ]
    assert plugin.records[("rep.example.com", int(QTYPE.A))][1] == ["198.51.100.9"]
    assert ("del.example.com", int(QTYPE.A)) not in plugin.records
    assert ("wipe.example.com", int(QTYPE.A)) not in plugin.records
    assert ("wipe.example.com", int(QTYPE.TXT)) not in plugin.records
    assert "wipe.example.com" in plugin._update_managed_owners
    assert result.deleted_rrsets >= 2


def test_commit_rr_replace_value_alias_and_invalid_actions() -> None:
    """Brief: rr_replace accepts single value alias; invalid actions return rcode 1/9."""
    plugin = _plugin()
    ok = zone_commit.commit_record_actions(
        plugin,
        "example.com",
        [
            {
                "type": "rr_replace",
                "owner": "one.example.com",
                "qtype": int(QTYPE.A),
                "ttl": "bad",
                "value": "192.0.2.55",
            }
        ],
        send_notify=False,
    )
    assert ok.ok is True
    assert plugin.records[("one.example.com", int(QTYPE.A))][1] == ["192.0.2.55"]

    cases = [
        ([{"type": "rr_add", "owner": "", "qtype": 1, "value": "1.1.1.1"}], 1),
        (
            [
                {
                    "type": "rr_add",
                    "owner": "a.example.com",
                    "qtype": "nope",
                    "value": "1.1.1.1",
                }
            ],
            1,
        ),
        (
            [
                {
                    "type": "rr_add",
                    "owner": "a.example.com",
                    "qtype": 0,
                    "value": "1.1.1.1",
                }
            ],
            1,
        ),
        (
            [{"type": "rr_add", "owner": "a.example.com", "qtype": 1, "value": ""}],
            1,
        ),
        (
            [
                {
                    "type": "rr_delete_values",
                    "owner": "a.example.com",
                    "qtype": "x",
                    "value": "1",
                }
            ],
            1,
        ),
        (
            [
                {
                    "type": "rr_delete_values",
                    "owner": "a.example.com",
                    "qtype": 1,
                    "value": "",
                }
            ],
            1,
        ),
        (
            [{"type": "rr_delete_rrset", "owner": "a.example.com", "qtype": "x"}],
            1,
        ),
        (
            [
                {
                    "type": "rr_replace",
                    "owner": "a.example.com",
                    "qtype": "x",
                    "values": ["1"],
                }
            ],
            1,
        ),
        (
            [
                {
                    "type": "rr_replace",
                    "owner": "a.example.com",
                    "qtype": 1,
                    "values": [],
                }
            ],
            1,
        ),
        ([{"type": "nope", "owner": "a.example.com"}], 1),
        (
            [
                {
                    "type": "rr_add",
                    "owner": "outside.net",
                    "qtype": 1,
                    "ttl": 60,
                    "value": "1.1.1.1",
                }
            ],
            9,
        ),
    ]
    for actions, rcode in cases:
        plugin2 = _plugin()
        result = zone_commit.commit_record_actions(
            plugin2, "example.com", actions, send_notify=False
        )
        assert result.ok is False
        assert result.rcode == rcode, actions


def test_commit_invalid_owner_raises_from_normalize(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Owner normalization exceptions map to rcode 1."""
    plugin = _plugin()

    def _boom(name: str) -> str:
        if name == "bad":
            raise ValueError("bad owner")
        from foghorn.utils import dns_names

        return dns_names.normalize_name(name)

    monkeypatch.setattr(zone_commit, "_normalize_dns_name", _boom)
    result = zone_commit.commit_record_actions(
        plugin,
        "example.com",
        [{"type": "rr_add", "owner": "bad", "qtype": 1, "ttl": 60, "value": "1.1.1.1"}],
        send_notify=False,
    )
    assert result.ok is False
    assert result.rcode == 1


def test_commit_concurrent_conflict_on_generation() -> None:
    """Brief: Generation mismatch rejects commit with rcode 2."""
    base = _plugin(with_lock=False)
    original_records = base.records

    class _GenPlugin(SimpleNamespace):
        _gen_reads = 0

        @property
        def _records_generation(self) -> int:  # type: ignore[override]
            # First read is snapshot; subsequent read in commit body conflicts.
            self._gen_reads += 1
            return 0 if self._gen_reads == 1 else 99

        @_records_generation.setter
        def _records_generation(self, value: int) -> None:
            return None

    plugin = _GenPlugin(
        **{k: v for k, v in base.__dict__.items() if k != "_records_generation"}
    )
    result = zone_commit.commit_record_actions(
        plugin,
        "example.com",
        [
            {
                "type": "rr_add",
                "owner": "c.example.com",
                "qtype": 1,
                "ttl": 60,
                "value": "1.1.1.1",
            }
        ],
        send_notify=False,
    )
    assert result.ok is False
    assert result.rcode == 2
    assert "conflict" in (result.error or "").lower()
    assert ("c.example.com", 1) not in original_records


def test_commit_journal_fail_closed_and_success(tmp_path) -> None:
    """Brief: Journal write failure is fail-closed; success records journal_seq."""
    plugin = _plugin()
    before = dict(plugin.records)

    class _FailWriter:
        base_dir = str(tmp_path)

        def append_entry(self, **_kwargs):
            return None

    fail = zone_commit.commit_record_actions(
        plugin,
        "example.com",
        [
            {
                "type": "rr_add",
                "owner": "j.example.com",
                "qtype": 1,
                "ttl": 60,
                "value": "1.1.1.1",
            }
        ],
        journal_writer=_FailWriter(),
        actor={"client_ip": "192.0.2.1", "auth_method": "tsig"},
        send_notify=False,
    )
    assert fail.ok is False
    assert fail.rcode == 2
    assert dict(plugin.records) == before

    from foghorn.plugins.resolve.zone_records.journal import JournalWriter

    writer = JournalWriter(zone_apex="example.com", base_dir=str(tmp_path))
    assert writer.acquire_lock()
    try:
        plugin._dns_update_persistence_config = {
            "fsync_mode": "always",
            "fsync_interval_ms": 0,
            "max_journal_bytes": 0,
            "max_journal_entries": 0,
        }
        plugin._dns_update_config = {
            "security": {
                "max_owner_length": 255,
                "max_rdata_length": 1024,
                "max_transaction_bytes": 0,
                "max_updates_per_message": 100,
            },
            "replication": {"notify_on_update": False},
        }
        ok = zone_commit.commit_record_actions(
            plugin,
            "example.com",
            [
                {
                    "type": "rr_add",
                    "owner": "ok.example.com",
                    "qtype": 1,
                    "ttl": 60,
                    "value": "1.1.1.1",
                }
            ],
            journal_writer=writer,
            actor={"client_ip": "192.0.2.1", "auth_method": "tsig"},
            send_notify=False,
        )
    finally:
        writer.release_lock()
        writer.close()
    assert ok.ok is True
    assert ok.journal_seq == 1
    assert ("ok.example.com", 1) in plugin.records


def test_commit_journal_compaction_triggers(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: Post-commit compaction runs when max_journal_entries exceeded."""
    from foghorn.plugins.resolve.zone_records.journal import JournalWriter

    plugin = _plugin()
    plugin._dns_update_persistence_config = {
        "max_journal_entries": 0,  # disabled first path
        "max_journal_bytes": 1,  # force byte threshold after write
    }
    plugin._dns_update_config = {"replication": {"notify_on_update": False}}
    writer = JournalWriter(zone_apex="example.com", base_dir=str(tmp_path))
    assert writer.acquire_lock()
    compacted = {"n": 0}

    import foghorn.plugins.resolve.zone_records.journal as journal_mod

    real_compact = journal_mod.compact_zone_journal

    def _compact(**kwargs):
        compacted["n"] += 1
        return real_compact(**kwargs)

    monkeypatch.setattr(journal_mod, "compact_zone_journal", _compact)
    try:
        result = zone_commit.commit_record_actions(
            plugin,
            "example.com",
            [
                {
                    "type": "rr_add",
                    "owner": "c.example.com",
                    "qtype": 1,
                    "ttl": 60,
                    "value": "1.1.1.1",
                }
            ],
            journal_writer=writer,
            actor={"client_ip": "192.0.2.1"},
            send_notify=False,
        )
    finally:
        writer.release_lock()
        writer.close()
    assert result.ok is True
    assert compacted["n"] >= 1


def test_commit_name_delete_all_without_name_index_fallback() -> None:
    """Brief: name_delete_all falls back to records scan when name_index empty."""
    plugin = _plugin(
        records={
            ("gone.example.com", int(QTYPE.A)): (300, ["192.0.2.1"], ["s"]),
            ("gone.example.com", int(QTYPE.TXT)): (300, ['"t"'], ["s"]),
        },
        name_index={},  # empty forces fallback
    )
    result = zone_commit.commit_record_actions(
        plugin,
        "example.com",
        [{"type": "name_delete_all", "owner": "gone.example.com"}],
        send_notify=False,
        mark_update_managed=False,
    )
    assert result.ok is True
    assert ("gone.example.com", int(QTYPE.A)) not in plugin.records
    assert result.deleted_rrsets >= 2
    assert "gone.example.com" not in plugin._update_managed_owners


def test_commit_wildcard_owner_index_add_and_remove() -> None:
    """Brief: Wildcard owners are tracked and cleared on delete."""
    plugin = _plugin()
    add = zone_commit.commit_record_actions(
        plugin,
        "example.com",
        [
            {
                "type": "rr_add",
                "owner": "*.foo.example.com",
                "qtype": int(QTYPE.A),
                "ttl": 60,
                "value": "198.51.100.7",
            }
        ],
        send_notify=False,
    )
    assert add.ok is True
    assert "*.foo.example.com" in plugin._wildcard_owners
    delete = zone_commit.commit_record_actions(
        plugin,
        "example.com",
        [{"type": "name_delete_all", "owner": "*.foo.example.com"}],
        send_notify=False,
    )
    assert delete.ok is True
    assert "*.foo.example.com" not in plugin._wildcard_owners


def test_commit_notify_failure_increments_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: NOTIFY exceptions increment failure counter without failing commit."""
    plugin = _plugin(dns_update_config={"replication": {"notify_on_update": True}})
    import foghorn.plugins.resolve.zone_records.notify as notify_mod

    monkeypatch.setattr(
        notify_mod,
        "send_notify_for_zones",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("notify boom")),
    )
    result = zone_commit.commit_record_actions(
        plugin,
        "example.com",
        [
            {
                "type": "rr_add",
                "owner": "n.example.com",
                "qtype": 1,
                "ttl": 60,
                "value": "1.1.1.1",
            }
        ],
    )
    assert result.ok is True
    assert int(getattr(plugin, "_dns_update_notify_failed", 0)) == 1


def test_commit_without_apex_skips_soa_and_boundary() -> None:
    """Brief: Empty apex allows commits without SOA bump/NOTIFY/boundary."""
    plugin = _plugin(with_soa=False, zone_soa={})
    result = zone_commit.commit_record_actions(
        plugin,
        "",
        [
            {
                "type": "rr_add",
                "owner": "orphan.example",
                "qtype": 1,
                "ttl": 30,
                "value": "10.0.0.1",
                "source": "admin-temporary",
            }
        ],
        bump_soa=True,
        send_notify=False,
        enforce_zone_boundary=False,
    )
    assert result.ok is True
    assert result.serial_before is None
    assert result.serial_after is None
    assert ("orphan.example", 1) in plugin.records


def test_commit_records_none_and_name_index_none() -> None:
    """Brief: Missing records/_name_index attributes are initialized on commit."""
    plugin = SimpleNamespace(
        records=None,
        _name_index=None,
        _wildcard_owners=[],
        _records_generation=0,
        _dns_update_config={"replication": {"notify_on_update": False}},
    )
    result = zone_commit.commit_record_actions(
        plugin,
        "",
        [
            {
                "type": "rr_add",
                "owner": "x.test",
                "qtype": 1,
                "ttl": 1,
                "value": "1.2.3.4",
            }
        ],
        send_notify=False,
        enforce_zone_boundary=False,
        bump_soa=False,
    )
    assert result.ok is True
    assert plugin.records[("x.test", 1)][1] == ["1.2.3.4"]
    assert "x.test" in plugin._name_index


# ---------------------------------------------------------------------------
# apply_update_operations adapter
# ---------------------------------------------------------------------------


def test_apply_update_operations_adapter_add_and_rrset_delete() -> None:
    """Brief: Adapter maps zone-class add and deleting=ANY empty RRset delete.

    Inputs/Outputs:
      - Wire-like RRsets (rdclass=IN + optional deleting) through apply_update_operations.
      - Asserts add-merge creates the new A and RRset delete removes the old A.
    """
    plugin = _plugin(
        records={("old.example.com", int(QTYPE.A)): (300, ["192.0.2.1"], ["s"])}
    )
    rcode, err = up.apply_update_operations(
        [
            _RRset(
                name="new.example.com",
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.IN),
                values=["203.0.113.8"],
            ),
            _RRset(
                name="old.example.com",
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.IN),
                deleting=int(dns.rdataclass.ANY),
                values=[],
            ),
        ],
        plugin=plugin,
        zone_apex="example.com",
    )
    assert rcode == 0
    assert err is None
    assert plugin.records[("new.example.com", int(QTYPE.A))][1] == ["203.0.113.8"]
    assert ("old.example.com", int(QTYPE.A)) not in plugin.records


def test_apply_update_operations_require_journal_unavailable() -> None:
    """Brief: Adapter preserves require_journal_persistence fail-closed path."""
    plugin = _plugin()
    rcode, err = up.apply_update_operations(
        [
            _RRset(
                name="a.example.com",
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.IN),
                values=["1.1.1.1"],
            )
        ],
        plugin=plugin,
        zone_apex="example.com",
        require_journal_persistence=True,
    )
    assert rcode == 2
    assert err == "Journal unavailable"


# ---------------------------------------------------------------------------
# Admin apply/delete wiring
# ---------------------------------------------------------------------------


def _make_zone_records_plugin(tmp_path=None) -> ZoneRecords:
    """Brief: Construct a ZoneRecords instance with mutable state for admin tests.

    Inputs:
      - tmp_path: Optional temp directory for editable files.

    Outputs:
      - ZoneRecords plugin with in-memory records and SOA.
    """
    plugin = ZoneRecords()
    plugin.name = "zr"
    plugin.config = {}
    if tmp_path is not None:
        editable = str(tmp_path / "records.txt")
        plugin.config["admin_editable_file_paths"] = [editable]
        plugin.file_paths = [editable]
    plugin.records = {
        ("example.com", int(QTYPE.SOA)): _soa_entry(5),
        ("old.example.com", int(QTYPE.A)): (300, ["192.0.2.9"], ["src"]),
    }
    plugin._name_index = {
        "example.com": {
            int(QTYPE.SOA): plugin.records[("example.com", int(QTYPE.SOA))]
        },
        "old.example.com": {
            int(QTYPE.A): plugin.records[("old.example.com", int(QTYPE.A))]
        },
    }
    plugin._wildcard_owners = []
    plugin._records_generation = 0
    plugin._records_lock = threading.RLock()
    plugin._update_managed_owners = set()
    plugin._zone_soa = {"example.com": (300, ["soa"])}
    plugin._dns_update_config = {
        "zones": [{"zone": "example.com"}],
        "replication": {"notify_on_update": False},
        "persistence": {"enabled": False},
    }
    return plugin


def test_admin_apply_and_delete_via_shared_commit(tmp_path) -> None:
    """Brief: Admin apply/delete use commit path and return serial metadata."""
    plugin = _make_zone_records_plugin(tmp_path)
    applied = plugin.admin_apply_record_mutation(
        owner="www.example.com",
        qtype="A",
        value="203.0.113.10",
        ttl=120,
        persist=True,
    )
    assert applied["owner"] == "www.example.com"
    assert applied["persisted"] is True
    assert applied["zone_apex"] == "example.com"
    assert applied["serial_before"] == 5
    assert applied["serial_after"] == 6
    assert ("www.example.com", int(QTYPE.A)) in plugin.records
    # SOA serial bump must refresh name_index, not only records map.
    soa_idx = plugin._name_index["example.com"][int(QTYPE.SOA)]
    assert " 6 " in soa_idx[1][0]
    assert " 6 " in plugin.records[("example.com", int(QTYPE.SOA))][1][0]
    assert os.path.exists(str(applied["file_path"]))

    deleted_value = plugin.admin_delete_record_mutation(
        owner="www.example.com",
        qtype="A",
        value="203.0.113.10",
        persist=True,
    )
    assert deleted_value["deleted"] >= 1
    assert deleted_value["serial_after"] == 7
    assert ("www.example.com", int(QTYPE.A)) not in plugin.records

    # re-add then delete rrset and owner-all
    plugin.admin_apply_record_mutation(
        owner="old.example.com", qtype="TXT", value='"hi"', ttl=30
    )
    del_rrset = plugin.admin_delete_record_mutation(
        owner="old.example.com", qtype="TXT"
    )
    assert del_rrset["qtype"] == int(QTYPE.TXT)
    del_all = plugin.admin_delete_record_mutation(owner="old.example.com")
    assert ("old.example.com", int(QTYPE.A)) not in plugin.records
    assert del_all["qtype"] is None


def test_admin_apply_policy_reject_and_no_editable_paths() -> None:
    """Brief: Admin apply raises on policy reject and missing editable paths."""
    plugin = _make_zone_records_plugin()
    plugin._dns_update_config = {
        "zones": [
            {
                "zone": "example.com",
                "allow_names": ["allowed.example.com"],
            }
        ],
        "replication": {"notify_on_update": False},
    }
    with pytest.raises(ValueError, match="owner blocked"):
        plugin.admin_apply_record_mutation(
            owner="denied.example.com",
            qtype="A",
            value="1.1.1.1",
        )

    plugin2 = _make_zone_records_plugin()
    plugin2.config = {"admin_editable_file_paths": []}
    plugin2.file_paths = []
    with pytest.raises(ValueError, match="no editable file paths"):
        plugin2.admin_apply_record_mutation(
            owner="www.example.com",
            qtype="A",
            value="1.1.1.1",
            persist=True,
        )


def test_admin_apply_rejects_disallowed_file_path(tmp_path) -> None:
    """Brief: persist file_path must be in admin_editable_file_paths."""
    plugin = _make_zone_records_plugin(tmp_path)
    with pytest.raises(ValueError, match="not allowed"):
        plugin.admin_apply_record_mutation(
            owner="www.example.com",
            qtype="A",
            value="1.1.1.1",
            persist=True,
            file_path=str(tmp_path / "other.txt"),
        )


def test_admin_optional_journal_writer_enabled(tmp_path) -> None:
    """Brief: Admin helper opens JournalWriter when persistence is enabled."""
    plugin = _make_zone_records_plugin()
    plugin._dns_update_config = {
        "zones": [{"zone": "example.com"}],
        "persistence": {"enabled": True, "state_dir": str(tmp_path)},
        "replication": {"notify_on_update": False},
    }
    writer = plugin._admin_optional_journal_writer("example.com")
    assert writer is not None
    writer.close()

    assert plugin._admin_optional_journal_writer("") is None
    plugin._dns_update_config = {"persistence": {"enabled": False}}
    assert plugin._admin_optional_journal_writer("example.com") is None


def test_admin_apply_with_journal_persistence(tmp_path) -> None:
    """Brief: Admin apply journals when dns_update persistence is enabled."""
    plugin = _make_zone_records_plugin()
    plugin._dns_update_config = {
        "zones": [{"zone": "example.com"}],
        "persistence": {"enabled": True, "state_dir": str(tmp_path)},
        "replication": {"notify_on_update": False},
        "security": {},
    }
    plugin._dns_update_persistence_config = plugin._dns_update_config["persistence"]
    out = plugin.admin_apply_record_mutation(
        owner="api.example.com",
        qtype="A",
        value="203.0.113.99",
        ttl=60,
    )
    assert out["serial_after"] == 6
    journal_path = tmp_path / "example.com" / "journal.ndjson"
    assert journal_path.exists()
    text = journal_path.read_text(encoding="utf-8")
    assert "api.example.com" in text
    assert "admin_api" in text


def test_admin_delete_persist_and_disallowed_path(tmp_path) -> None:
    """Brief: Admin delete supports persist rewrite and path allow checks."""
    plugin = _make_zone_records_plugin(tmp_path)
    editable = plugin._admin_editable_file_paths()[0]
    with open(editable, "w", encoding="utf-8") as f:
        f.write("old.example.com|A|300|192.0.2.9\nkeep.example.com|A|300|192.0.2.1\n")
    out = plugin.admin_delete_record_mutation(
        owner="old.example.com",
        qtype="A",
        value="192.0.2.9",
        persist=True,
    )
    assert out["persisted"] is True
    with open(editable, encoding="utf-8") as _fh:
        remaining = _fh.read()
    assert "old.example.com" not in remaining
    assert "keep.example.com" in remaining

    with pytest.raises(ValueError, match="not allowed"):
        plugin.admin_delete_record_mutation(
            owner="keep.example.com",
            persist=True,
            file_path=str(tmp_path / "nope.txt"),
        )


def test_admin_delete_empty_owner_raises() -> None:
    """Brief: Admin delete requires a non-empty owner."""
    plugin = _make_zone_records_plugin()
    with pytest.raises(ValueError, match="owner is required"):
        plugin.admin_delete_record_mutation(owner="")


def test_admin_resolve_commit_apex_helper() -> None:
    """Brief: Admin apex helper delegates to resolve_zone_apex_for_owner."""
    plugin = _make_zone_records_plugin()
    assert plugin._admin_resolve_commit_apex("www.example.com") == "example.com"
    assert plugin._admin_resolve_commit_apex("nope.invalid") == ""


def test_admin_journal_lock_failure_still_commits(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: Admin apply continues without journal when lock acquisition fails."""
    plugin = _make_zone_records_plugin()
    plugin._dns_update_config = {
        "zones": [{"zone": "example.com"}],
        "persistence": {"enabled": True, "state_dir": str(tmp_path)},
        "replication": {"notify_on_update": False},
    }

    class _LockedWriter:
        def acquire_lock(self):
            return False

        def close(self):
            return None

        def release_lock(self):
            return None

    monkeypatch.setattr(
        plugin, "_admin_optional_journal_writer", lambda apex: _LockedWriter()
    )
    out = plugin.admin_apply_record_mutation(
        owner="lock.example.com",
        qtype="A",
        value="203.0.113.1",
        ttl=30,
    )
    assert out["serial_after"] == 6
    assert ("lock.example.com", int(QTYPE.A)) in plugin.records


def test_admin_journal_writer_acquire_exception(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: Admin apply tolerates JournalWriter.acquire_lock exceptions."""
    plugin = _make_zone_records_plugin()
    plugin._dns_update_config = {
        "zones": [{"zone": "example.com"}],
        "persistence": {"enabled": True, "state_dir": str(tmp_path)},
        "replication": {"notify_on_update": False},
    }

    class _BoomWriter:
        def acquire_lock(self):
            raise RuntimeError("lock boom")

        def close(self):
            return None

    monkeypatch.setattr(
        plugin, "_admin_optional_journal_writer", lambda apex: _BoomWriter()
    )
    plugin.admin_apply_record_mutation(
        owner="boom.example.com",
        qtype="A",
        value="203.0.113.2",
        ttl=30,
    )
    assert ("boom.example.com", int(QTYPE.A)) in plugin.records


def test_commit_with_lock_conflict_path() -> None:
    """Brief: Locked plugin path also rejects generation conflicts."""
    base = _plugin(with_lock=True)

    class _GenPlugin(SimpleNamespace):
        _gen_reads = 0

        @property
        def _records_generation(self) -> int:  # type: ignore[override]
            self._gen_reads += 1
            return 0 if self._gen_reads <= 1 else 7

        @_records_generation.setter
        def _records_generation(self, value: int) -> None:
            return None

    plugin = _GenPlugin(
        **{k: v for k, v in base.__dict__.items() if k != "_records_generation"}
    )
    result = zone_commit.commit_record_actions(
        plugin,
        "example.com",
        [
            {
                "type": "rr_add",
                "owner": "l.example.com",
                "qtype": 1,
                "ttl": 60,
                "value": "1.1.1.1",
            }
        ],
        send_notify=False,
    )
    assert result.ok is False
    assert result.rcode == 2


def test_commit_journal_seq_non_int(tmp_path) -> None:
    """Brief: Non-integer journal seq is coerced to None without failing commit."""
    plugin = _plugin()

    class _WeirdEntry:
        seq = object()

    class _Writer:
        base_dir = str(tmp_path)

        def append_entry(self, **_kwargs):
            return _WeirdEntry()

    result = zone_commit.commit_record_actions(
        plugin,
        "example.com",
        [
            {
                "type": "rr_add",
                "owner": "seq.example.com",
                "qtype": 1,
                "ttl": 60,
                "value": "1.1.1.1",
            }
        ],
        journal_writer=_Writer(),
        actor={"client_ip": "192.0.2.1"},
        send_notify=False,
    )
    assert result.ok is True
    assert result.journal_seq is None


def test_admin_optional_journal_writer_runtime_state_dir(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: Journal writer falls back to runtime state dir when state_dir omitted."""
    plugin = _make_zone_records_plugin()
    plugin._dns_update_config = {
        "zones": [{"zone": "example.com"}],
        "persistence": {"enabled": True},
        "replication": {"notify_on_update": False},
    }

    import sys
    import types

    fake = types.ModuleType("foghorn.runtime_config")
    fake.get_runtime_state_dir = lambda: str(tmp_path)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "foghorn.runtime_config", fake)
    writer = plugin._admin_optional_journal_writer("example.com")
    assert writer is not None
    writer.close()


def test_admin_apply_commit_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: Admin apply surfaces commit failures as ValueError."""
    plugin = _make_zone_records_plugin()

    def _fail(*_a, **_k):
        return zone_commit.CommitResult(ok=False, rcode=2, error="nope")

    monkeypatch.setattr(zone_commit, "commit_record_actions", _fail)
    with pytest.raises(ValueError, match="nope"):
        plugin.admin_apply_record_mutation(
            owner="www.example.com",
            qtype="A",
            value="1.1.1.1",
        )


def test_admin_delete_commit_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: Admin delete surfaces commit failures as ValueError."""
    plugin = _make_zone_records_plugin()

    def _fail(*_a, **_k):
        return zone_commit.CommitResult(ok=False, rcode=2, error="delete failed")

    monkeypatch.setattr(zone_commit, "commit_record_actions", _fail)
    with pytest.raises(ValueError, match="delete failed"):
        plugin.admin_delete_record_mutation(owner="old.example.com")


def test_commit_max_journal_entries_compaction(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: max_journal_entries threshold triggers compaction path."""
    import foghorn.plugins.resolve.zone_records.journal as journal_mod
    from foghorn.plugins.resolve.zone_records.journal import JournalWriter

    plugin = _plugin()
    plugin._dns_update_persistence_config = {
        "max_journal_entries": 1,
        "max_journal_bytes": 0,
    }
    plugin._dns_update_config = {"replication": {"notify_on_update": False}}
    writer = JournalWriter(zone_apex="example.com", base_dir=str(tmp_path))
    assert writer.acquire_lock()
    # seed one prior entry so entry_seq - compacted > max
    writer.append_entry(
        actions=[
            {
                "type": "rr_add",
                "owner": "seed.example.com",
                "qtype": 1,
                "ttl": 1,
                "value": "1.1.1.1",
            }
        ],
        actor={"client_ip": "192.0.2.1"},
        origin_node_id="n1",
    )
    calls = {"n": 0}
    real = journal_mod.compact_zone_journal

    def _wrap(**kwargs):
        calls["n"] += 1
        return real(**kwargs)

    monkeypatch.setattr(journal_mod, "compact_zone_journal", _wrap)
    try:
        result = zone_commit.commit_record_actions(
            plugin,
            "example.com",
            [
                {
                    "type": "rr_add",
                    "owner": "e.example.com",
                    "qtype": 1,
                    "ttl": 60,
                    "value": "1.1.1.1",
                }
            ],
            journal_writer=writer,
            actor={"client_ip": "192.0.2.1"},
            send_notify=False,
        )
    finally:
        writer.release_lock()
        writer.close()
    assert result.ok is True
    assert calls["n"] >= 1
