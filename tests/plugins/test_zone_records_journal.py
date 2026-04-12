"""Brief: Unit tests for zone_records journal persistence primitives.

Inputs:
  - Temporary directories and in-memory records/actions.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

import builtins
import json
import os
import time

import pytest

from foghorn.plugins.resolve.zone_records import journal


def test_apply_actions_to_records_add_replace_delete() -> None:
    """Brief: Action application mutates records as expected."""
    records = {}
    actions = [
        {
            "type": "rr_add",
            "owner": "a.example.com",
            "qtype": 1,
            "ttl": 60,
            "value": "192.0.2.1",
        },
        {
            "type": "rr_replace",
            "owner": "a.example.com",
            "qtype": 1,
            "ttl": 120,
            "values": ["198.51.100.1"],
        },
        {"type": "rr_delete_rrset", "owner": "a.example.com", "qtype": 1},
    ]
    updated = journal.apply_actions_to_records(records, actions)
    assert ("a.example.com", 1) not in updated


def test_apply_actions_to_records_edge_cases() -> None:
    """Brief: Action application covers empty values and delete/replace branches.

    Inputs:
      - None.

    Outputs:
      - None; asserts edge/corner action handling.
    """
    records = {
        ("keep.example.com", 1): (60, ["192.0.2.1"], ["file"]),
        ("wipe.example.com", 1): (60, ["192.0.2.2"], ["file"]),
    }
    actions = [
        {"type": "rr_add", "owner": "empty.example.com", "qtype": 1, "value": ""},
        {
            "type": "rr_add",
            "owner": "keep.example.com",
            "qtype": 1,
            "value": "192.0.2.1",
        },
        {
            "type": "rr_delete_values",
            "owner": "missing.example.com",
            "qtype": 1,
            "value": "x",
        },
        {
            "type": "rr_delete_values",
            "owner": "keep.example.com",
            "qtype": 1,
            "value": "192.0.2.1",
        },
        {"type": "name_delete_all", "owner": "wipe.example.com"},
        {"type": "rr_replace", "owner": "none.example.com", "qtype": 1, "values": []},
    ]
    updated = journal.apply_actions_to_records(records, actions)

    assert ("empty.example.com", 1) not in updated
    assert ("keep.example.com", 1) not in updated
    assert ("wipe.example.com", 1) not in updated
    assert ("none.example.com", 1) not in updated


def test_replay_journal_to_records_reads_snapshot_and_tail(tmp_path) -> None:
    """Brief: Replay uses snapshot baseline plus later journal entries."""
    base_dir = str(tmp_path)
    zone = "example.com"
    baseline = {
        ("a.example.com", 1): (60, ["192.0.2.1"], ["update"]),
    }
    assert journal.save_snapshot(zone, base_dir, baseline, seq=0) is True

    writer = journal.JournalWriter(zone_apex=zone, base_dir=base_dir)
    assert writer.acquire_lock() is True
    entry = writer.append_entry(
        actions=[
            {
                "type": "rr_add",
                "owner": "b.example.com",
                "qtype": 1,
                "ttl": 60,
                "value": "192.0.2.2",
            }
        ],
        actor={"client_ip": "192.0.2.10", "auth_method": "tsig", "tsig_key_name": "k."},
    )
    assert entry is not None
    writer.release_lock()
    writer.close()

    replayed, last_seq = journal.replay_journal_to_records(
        zone_apex=zone,
        base_dir=base_dir,
        records={},
        start_seq=0,
    )
    assert ("a.example.com", 1) in replayed
    assert ("b.example.com", 1) in replayed
    assert last_seq >= 1


def test_replay_journal_to_records_respects_snapshot_seq(tmp_path) -> None:
    """Brief: Replay starts after snapshot high-watermark.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts replay ignores entries at or below snapshot_seq.
    """
    base_dir = str(tmp_path)
    zone = "example.com"
    assert journal.save_snapshot(zone, base_dir, {}, seq=2) is True

    writer = journal.JournalWriter(zone_apex=zone, base_dir=base_dir)
    assert writer.acquire_lock() is True
    try:
        writer.append_entry(
            actions=[
                {
                    "type": "rr_add",
                    "owner": "one.example.com",
                    "qtype": 1,
                    "value": "192.0.2.1",
                }
            ],
            actor={"client_ip": "192.0.2.10"},
        )
        writer.append_entry(
            actions=[
                {
                    "type": "rr_add",
                    "owner": "two.example.com",
                    "qtype": 1,
                    "value": "192.0.2.2",
                }
            ],
            actor={"client_ip": "192.0.2.10"},
        )
        writer.append_entry(
            actions=[
                {
                    "type": "rr_add",
                    "owner": "three.example.com",
                    "qtype": 1,
                    "value": "192.0.2.3",
                }
            ],
            actor={"client_ip": "192.0.2.10"},
        )
    finally:
        writer.release_lock()
        writer.close()

    replayed, last_seq = journal.replay_journal_to_records(
        zone_apex=zone,
        base_dir=base_dir,
        records={},
        start_seq=0,
    )
    assert ("three.example.com", 1) in replayed
    assert ("one.example.com", 1) not in replayed
    assert last_seq >= 3


def test_replay_journal_to_records_does_not_clobber_other_zones(tmp_path) -> None:
    """Brief: Per-zone replay must not overwrite records for other zones.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts cross-zone records remain unchanged during one-zone replay.
    """
    base_dir = str(tmp_path)
    target_zone = "example.net"
    initial_records = {
        ("newer.example.com", 1): (60, ["192.0.2.100"], ["update"]),
        ("host.example.net", 1): (60, ["192.0.2.20"], ["update"]),
    }

    legacy_global_snapshot = {
        ("stale.example.com", 1): (60, ["192.0.2.10"], ["update"]),
        ("host.example.net", 1): (60, ["192.0.2.20"], ["update"]),
    }
    assert (
        journal.save_snapshot(
            target_zone,
            base_dir,
            legacy_global_snapshot,
            seq=0,
        )
        is True
    )

    writer = journal.JournalWriter(zone_apex=target_zone, base_dir=base_dir)
    assert writer.acquire_lock() is True
    try:
        writer.append_entry(
            actions=[
                {
                    "type": "rr_replace",
                    "owner": "host.example.net",
                    "qtype": 1,
                    "ttl": 60,
                    "values": ["198.51.100.20"],
                }
            ],
            actor={"client_ip": "192.0.2.10"},
        )
    finally:
        writer.release_lock()
        writer.close()

    replayed, _last_seq = journal.replay_journal_to_records(
        zone_apex=target_zone,
        base_dir=base_dir,
        records=initial_records,
        start_seq=0,
    )
    assert ("newer.example.com", 1) in replayed
    assert ("stale.example.com", 1) not in replayed
    assert replayed[("host.example.net", 1)][1] == ["198.51.100.20"]


def test_compact_zone_journal_rotates_and_sets_manifest(tmp_path) -> None:
    """Brief: Compaction writes snapshot, rotates journal, and updates manifest."""
    base_dir = str(tmp_path)
    zone = "example.com"
    writer = journal.JournalWriter(zone_apex=zone, base_dir=base_dir)
    assert writer.acquire_lock() is True
    entry = writer.append_entry(
        actions=[
            {
                "type": "rr_add",
                "owner": "x.example.com",
                "qtype": 1,
                "ttl": 60,
                "value": "203.0.113.1",
            }
        ],
        actor={"client_ip": "192.0.2.10", "auth_method": "tsig", "tsig_key_name": "k."},
    )
    assert entry is not None
    writer.release_lock()
    writer.close()

    records = {("x.example.com", 1): (60, ["203.0.113.1"], ["update"])}
    ok = journal.compact_zone_journal(
        zone_apex=zone,
        base_dir=base_dir,
        records=records,
        seq=int(entry.seq),
    )
    assert ok is True

    manifest = journal.load_manifest(zone, base_dir)
    assert manifest.last_compacted_seq == int(entry.seq)
    assert manifest.active_snapshot_seq == int(entry.seq)


def test_compact_zone_journal_returns_false_when_snapshot_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Brief: Compaction fails fast when snapshot persistence fails.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts False on snapshot failure.
    """
    monkeypatch.setattr(journal, "save_snapshot", lambda *_a, **_k: False)
    ok = journal.compact_zone_journal(
        zone_apex="example.com",
        base_dir=str(tmp_path),
        records={},
        seq=1,
    )
    assert ok is False


def test_journal_append_uses_explicit_origin_node_id(tmp_path) -> None:
    """Brief: append_entry persists provided origin_node_id metadata."""
    base_dir = str(tmp_path)
    zone = "example.com"
    writer = journal.JournalWriter(zone_apex=zone, base_dir=base_dir)
    assert writer.acquire_lock() is True
    entry = writer.append_entry(
        actions=[
            {
                "type": "rr_add",
                "owner": "n.example.com",
                "qtype": 1,
                "ttl": 60,
                "value": "198.51.100.10",
            }
        ],
        actor={"client_ip": "192.0.2.10", "auth_method": "tsig", "tsig_key_name": "k."},
        origin_node_id="node-a",
    )
    writer.release_lock()
    writer.close()
    assert entry is not None
    assert entry.origin_node_id == "node-a"


def test_journal_writer_ensure_dir_raises_on_oserror(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Brief: _ensure_dir raises when os.makedirs fails.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts OSError bubble-up.
    """
    writer = journal.JournalWriter(zone_apex="example.com", base_dir=str(tmp_path))
    monkeypatch.setattr(os.path, "exists", lambda *_a, **_k: False)
    monkeypatch.setattr(
        os, "makedirs", lambda *_a, **_k: (_ for _ in ()).throw(OSError("boom"))
    )

    with pytest.raises(OSError):
        writer._ensure_dir()


def test_journal_writer_acquire_lock_skips_when_fcntl_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Brief: acquire_lock returns True when LOCK_EX is unavailable.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts True when fcntl lacks LOCK_EX.
    """
    monkeypatch.delattr(journal.fcntl, "LOCK_EX", raising=False)
    writer = journal.JournalWriter(zone_apex="example.com", base_dir=str(tmp_path))
    assert writer.acquire_lock() is True


def test_journal_writer_acquire_lock_blocking_returns_false(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Brief: acquire_lock returns False when flock is blocked.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts False on BlockingIOError.
    """
    writer = journal.JournalWriter(zone_apex="example.com", base_dir=str(tmp_path))

    def _raise_blocking(*_a, **_k):
        raise BlockingIOError("locked")

    monkeypatch.setattr(journal.fcntl, "flock", _raise_blocking)
    assert writer.acquire_lock() is False


def test_journal_writer_maybe_fsync_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _maybe_fsync honors always/interval modes.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts fsync calls when expected.
    """

    class _FH:
        def fileno(self) -> int:
            return 3

    writer = journal.JournalWriter(zone_apex="example.com", base_dir="/tmp")
    writer._file_handle = _FH()

    calls: list[int] = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))

    writer._maybe_fsync("always", 1000)
    assert calls == [3]

    calls.clear()
    writer._last_fsync_ns = 0
    monkeypatch.setattr(time, "time_ns", lambda: 2_000_000_000)
    writer._maybe_fsync("interval", 1000)
    assert calls == [3]

    calls.clear()
    writer._maybe_fsync("invalid", 1000)
    assert calls == []


def test_journal_writer_append_entry_handles_write_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: append_entry returns None when file write fails.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts None on write error.
    """

    class _BadHandle:
        closed = False

        def write(self, *_a, **_k):
            raise OSError("write boom")

        def flush(self) -> None:
            return None

    writer = journal.JournalWriter(zone_apex="example.com", base_dir="/tmp")
    monkeypatch.setattr(writer, "_ensure_dir", lambda: None)
    writer._file_handle = _BadHandle()
    entry = writer.append_entry(
        actions=[
            {
                "type": "rr_add",
                "owner": "err.example.com",
                "qtype": 1,
                "value": "192.0.2.99",
            }
        ],
        actor={"client_ip": "192.0.2.10"},
    )
    assert entry is None


def test_journal_reader_read_entries_validation_and_skip(tmp_path) -> None:
    """Brief: read_entries validates checksums and can skip bad lines.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts checksum/hash validation and non-validated skip behavior.
    """
    base_dir = str(tmp_path)
    zone = "example.com"
    writer = journal.JournalWriter(zone_apex=zone, base_dir=base_dir)
    assert writer.acquire_lock() is True
    try:
        e1 = writer.append_entry(
            actions=[
                {
                    "type": "rr_add",
                    "owner": "a.example.com",
                    "qtype": 1,
                    "value": "192.0.2.1",
                }
            ],
            actor={"client_ip": "192.0.2.10"},
        )
        e2 = writer.append_entry(
            actions=[
                {
                    "type": "rr_add",
                    "owner": "b.example.com",
                    "qtype": 1,
                    "value": "192.0.2.2",
                }
            ],
            actor={"client_ip": "192.0.2.10"},
        )
    finally:
        writer.release_lock()
        writer.close()

    assert e1 is not None
    assert e2 is not None

    reader = journal.JournalReader(zone_apex=zone, base_dir=base_dir)
    entries = reader.read_entries(validate=True)
    assert len(entries) == 2

    # Break checksum on first entry.
    with open(reader.journal_path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    entry_data = json.loads(lines[0])
    entry_data["entry_checksum"] = "bad"
    lines[0] = json.dumps(entry_data) + "\n"
    with open(reader.journal_path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    entries_checksum = reader.read_entries(validate=True)
    assert len(entries_checksum) == 0

    # Inject a bad JSON line between two valid entries and skip when validate=False.
    with open(reader.journal_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(e1.to_dict()) + "\n")
        fh.write("{bad json}\n")
        fh.write(json.dumps(e2.to_dict()) + "\n")

    entries_skip = reader.read_entries(validate=False)
    assert len(entries_skip) == 2


def test_journal_reader_hash_chain_break_stops_read(tmp_path) -> None:
    """Brief: Hash chain mismatch stops validation read.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts only entries before the break are returned.
    """
    base_dir = str(tmp_path)
    zone = "example.com"
    writer = journal.JournalWriter(zone_apex=zone, base_dir=base_dir)
    assert writer.acquire_lock() is True
    try:
        writer.append_entry(
            actions=[
                {
                    "type": "rr_add",
                    "owner": "a.example.com",
                    "qtype": 1,
                    "value": "192.0.2.1",
                }
            ],
            actor={"client_ip": "192.0.2.10"},
        )
        writer.append_entry(
            actions=[
                {
                    "type": "rr_add",
                    "owner": "b.example.com",
                    "qtype": 1,
                    "value": "192.0.2.2",
                }
            ],
            actor={"client_ip": "192.0.2.10"},
        )
    finally:
        writer.release_lock()
        writer.close()

    reader = journal.JournalReader(zone_apex=zone, base_dir=base_dir)
    with open(reader.journal_path, "r", encoding="utf-8") as fh:
        lines = [json.loads(line) for line in fh if line.strip()]
    lines[1]["prev_hash"] = "broken"
    with open(reader.journal_path, "w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(json.dumps(line) + "\n")

    entries = reader.read_entries(validate=True)
    assert len(entries) == 1


def test_journal_reader_size_and_count_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: Size/count helpers return safe defaults on errors.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts safe defaults.
    """
    reader = journal.JournalReader(zone_apex="example.com", base_dir="/tmp")
    monkeypatch.setattr(
        os.path, "getsize", lambda *_a, **_k: (_ for _ in ()).throw(OSError("boom"))
    )
    assert reader.get_size_bytes() == 0

    def _bad_open(*_a, **_k):
        raise IOError("boom")

    monkeypatch.setattr(builtins, "open", _bad_open)
    assert reader.get_entry_count() == 0


def test_manifest_load_save_errors(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: Manifest load/save handles invalid JSON and mkdir failures.

    Inputs:
      - tmp_path: Pytest temp directory.
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts fallback Manifest and False on save failure.
    """
    zone = "example.com"
    base_dir = str(tmp_path)
    zone_dir = os.path.join(base_dir, zone)
    os.makedirs(zone_dir, exist_ok=True)
    manifest_path = os.path.join(zone_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        fh.write("{bad json}")

    manifest = journal.load_manifest(zone, base_dir)
    assert isinstance(manifest, journal.Manifest)
    assert manifest.last_compacted_seq == 0

    monkeypatch.setattr(os.path, "exists", lambda *_a, **_k: False)
    monkeypatch.setattr(
        os, "makedirs", lambda *_a, **_k: (_ for _ in ()).throw(OSError("boom"))
    )
    ok = journal.save_manifest(journal.Manifest(), zone, base_dir)
    assert ok is False


def test_snapshot_load_save_errors(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: Snapshot load/save handles parse errors and mkdir failures.

    Inputs:
      - tmp_path: Pytest temp directory.
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts safe defaults and False on save error.
    """
    zone = "example.com"
    base_dir = str(tmp_path)
    zone_dir = os.path.join(base_dir, zone)
    os.makedirs(zone_dir, exist_ok=True)
    snapshot_path = os.path.join(zone_dir, "snapshot.ndjson")
    with open(snapshot_path, "w", encoding="utf-8") as fh:
        fh.write("{bad json}\n")

    records, seq = journal.load_snapshot(zone, base_dir)
    assert records == {}
    assert seq == 0

    monkeypatch.setattr(
        os, "makedirs", lambda *_a, **_k: (_ for _ in ()).throw(OSError("boom"))
    )
    ok = journal.save_snapshot(zone, base_dir, {}, seq=1)
    assert ok is False


def test_journal_writer_acquire_lock_handles_dir_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Brief: acquire_lock returns False when _ensure_dir fails.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts False on _ensure_dir error.
    """
    writer = journal.JournalWriter(zone_apex="example.com", base_dir=str(tmp_path))
    monkeypatch.setattr(
        writer, "_ensure_dir", lambda: (_ for _ in ()).throw(OSError("boom"))
    )
    assert writer.acquire_lock() is False


def test_journal_writer_close_ignores_errors() -> None:
    """Brief: close ignores exceptions from file handle close.

    Inputs:
      - None.

    Outputs:
      - None; asserts close does not raise.
    """

    class _BadClose:
        closed = False

        def close(self) -> None:
            raise RuntimeError("close boom")

    writer = journal.JournalWriter(zone_apex="example.com", base_dir="/tmp")
    writer._file_handle = _BadClose()
    writer.close()
    assert writer._file_handle is None


def test_journal_reader_read_entries_missing_file(tmp_path) -> None:
    """Brief: Missing journal file yields empty entry list.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts empty entries list.
    """
    reader = journal.JournalReader(zone_apex="example.com", base_dir=str(tmp_path))
    assert reader.read_entries(validate=True) == []


def test_journal_reader_read_entries_bad_json_breaks(tmp_path) -> None:
    """Brief: Invalid JSON breaks validation read.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts no entries returned on invalid JSON with validate=True.
    """
    base_dir = str(tmp_path)
    zone = "example.com"
    zone_dir = os.path.join(base_dir, zone)
    os.makedirs(zone_dir, exist_ok=True)
    journal_path = os.path.join(zone_dir, "journal.ndjson")
    with open(journal_path, "w", encoding="utf-8") as fh:
        fh.write("{bad json}\n")

    reader = journal.JournalReader(zone_apex=zone, base_dir=base_dir)
    assert reader.read_entries(validate=True) == []


def test_manifest_load_missing_file_returns_default(tmp_path) -> None:
    """Brief: Missing manifest returns a default Manifest.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts default Manifest values.
    """
    manifest = journal.load_manifest("example.com", str(tmp_path))
    assert isinstance(manifest, journal.Manifest)
    assert manifest.last_compacted_seq == 0


def test_normalize_zone_apex_and_owner_in_zone_edges() -> None:
    """Brief: Zone apex normalization rejects unsafe names and zone membership is strict.

    Inputs:
      - None.

    Outputs:
      - None; asserts ValueError branches and in-zone membership behavior.
    """
    assert journal._normalize_zone_apex("EXAMPLE.com.") == "example.com"
    assert journal._is_owner_in_zone("www.example.com.", "example.com") is True
    assert journal._is_owner_in_zone("outside.net.", "example.com") is False

    with pytest.raises(ValueError):
        journal._normalize_zone_apex("")
    with pytest.raises(ValueError):
        journal._normalize_zone_apex(f"bad{os.path.sep}zone.com")
    with pytest.raises(ValueError):
        journal._normalize_zone_apex("bad..zone.com")
    with pytest.raises(ValueError):
        journal._normalize_zone_apex("bad zone.com")


def test_filter_and_replace_zone_records_handle_invalid_shapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Zone filtering/replacement skip malformed entries and handle 2-tuple fallback.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts malformed owners/entries are ignored and valid records are normalized.
    """
    original_normalize = journal.dns_names.normalize_name

    def _normalize(value: str) -> str:
        if str(value) == "boom.invalid":
            raise ValueError("normalize boom")
        return original_normalize(value)

    monkeypatch.setattr(journal.dns_names, "normalize_name", _normalize)

    records = {
        ("a.example.com", 1): (60, ["192.0.2.1"], ["file"]),
        ("b.example.com", 1): (120, ["192.0.2.2"]),
        ("c.example.com", 1): (300,),
        ("fallback.outside.net", 1): (45, ["203.0.113.77"]),
        ("outside.net", 1): (300, ["203.0.113.5"], ["file"]),
        ("boom.invalid", 1): (300, ["203.0.113.9"], ["file"]),
    }
    filtered = journal.filter_records_for_zone(records, "example.com")
    assert filtered[("a.example.com", 1)] == (60, ["192.0.2.1"], ["file"])
    assert filtered[("b.example.com", 1)] == (120, ["192.0.2.2"], [])
    assert ("c.example.com", 1) not in filtered
    assert ("outside.net", 1) not in filtered
    assert ("boom.invalid", 1) not in filtered

    replaced = journal.replace_zone_records(
        records=records,
        zone_apex="example.com",
        zone_records={
            ("new.example.com", 1): (30, ["198.51.100.1"], ["dynamic"]),
        },
    )
    assert ("a.example.com", 1) not in replaced
    assert ("b.example.com", 1) not in replaced
    assert replaced[("fallback.outside.net", 1)] == (45, ["203.0.113.77"], [])
    assert replaced[("outside.net", 1)] == (300, ["203.0.113.5"], ["file"])
    assert replaced[("new.example.com", 1)] == (30, ["198.51.100.1"], ["dynamic"])


def test_sanitize_actor_and_validate_actions_matrix() -> None:
    """Brief: Actor sanitization and action validation enforce shape/length constraints.

    Inputs:
      - None.

    Outputs:
      - None; asserts invalid payload branches and normalized valid payloads.
    """
    assert journal._sanitize_actor("not-a-dict") == {}
    assert journal._sanitize_actor({"client_ip": "x" * 8}, max_value_length=4) == {}
    assert journal._sanitize_actor(
        {
            "client_ip": "192.0.2.1",
            "auth_method": None,
            "tsig_key_name": 1234,
        },
        max_value_length=64,
    ) == {"client_ip": "192.0.2.1", "tsig_key_name": "1234"}

    assert journal._validate_actions("bad") is None
    assert journal._validate_actions([{}, {}], max_actions=1) is None
    assert journal._validate_actions([1]) is None
    assert journal._validate_actions([{"type": "rr_add"}]) is None
    assert (
        journal._validate_actions(
            [
                {
                    "type": "rr_add",
                    "owner": "owner.example.com",
                    "qtype": 1,
                    "value": "v",
                }
            ],
            max_owner_length=3,
        )
        is None
    )
    assert (
        journal._validate_actions(
            [
                {
                    "type": "rr_add",
                    "owner": "owner.example.com",
                    "qtype": "bad",
                    "value": "v",
                }
            ]
        )
        is None
    )
    assert (
        journal._validate_actions(
            [{"type": "rr_add", "owner": "owner.example.com", "qtype": 1, "value": ""}]
        )
        is None
    )
    assert (
        journal._validate_actions(
            [
                {
                    "type": "rr_add",
                    "owner": "owner.example.com",
                    "qtype": 1,
                    "value": "abcd",
                }
            ],
            max_rdata_length=2,
        )
        is None
    )
    assert (
        journal._validate_actions(
            [
                {
                    "type": "rr_delete_values",
                    "owner": "owner.example.com",
                    "qtype": 1,
                    "value": "",
                }
            ]
        )
        is None
    )
    assert (
        journal._validate_actions(
            [
                {
                    "type": "rr_delete_values",
                    "owner": "owner.example.com",
                    "qtype": 1,
                    "value": "abcd",
                }
            ],
            max_rdata_length=2,
        )
        is None
    )
    assert (
        journal._validate_actions(
            [
                {
                    "type": "rr_replace",
                    "owner": "owner.example.com",
                    "qtype": 1,
                    "values": [],
                }
            ]
        )
        is None
    )
    assert (
        journal._validate_actions(
            [
                {
                    "type": "rr_replace",
                    "owner": "owner.example.com",
                    "qtype": 1,
                    "values": ["abcd"],
                }
            ],
            max_rdata_length=2,
        )
        is None
    )
    assert (
        journal._validate_actions(
            [{"type": "unknown", "owner": "owner.example.com", "qtype": 1}]
        )
        is None
    )

    validated = journal._validate_actions(
        [
            {
                "type": "rr_add",
                "owner": "a.example.com",
                "qtype": 1,
                "ttl": 60,
                "value": "192.0.2.1",
            },
            {
                "type": "rr_delete_values",
                "owner": "a.example.com",
                "qtype": 1,
                "value": "192.0.2.1",
            },
            {"type": "rr_delete_rrset", "owner": "a.example.com", "qtype": 1},
            {"type": "name_delete_all", "owner": "a.example.com", "qtype": 1},
            {
                "type": "rr_replace",
                "owner": "a.example.com",
                "qtype": 1,
                "ttl": 30,
                "values": ["198.51.100.1"],
            },
        ]
    )
    assert validated == [
        {
            "type": "rr_add",
            "owner": "a.example.com",
            "qtype": 1,
            "ttl": 60,
            "value": "192.0.2.1",
        },
        {
            "type": "rr_delete_values",
            "owner": "a.example.com",
            "qtype": 1,
            "value": "192.0.2.1",
        },
        {"type": "rr_delete_rrset", "owner": "a.example.com", "qtype": 1},
        {"type": "name_delete_all", "owner": "a.example.com"},
        {
            "type": "rr_replace",
            "owner": "a.example.com",
            "qtype": 1,
            "ttl": 30,
            "values": ["198.51.100.1"],
        },
    ]


def test_scan_journal_tail_handles_offsets_and_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Brief: Tail scanning finds the last valid sequence and tolerates read failures.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts missing/corrupt file handling and valid tail hash extraction.
    """
    missing_seq, missing_hash = journal._scan_journal_tail(
        str(tmp_path / "missing.ndjson")
    )
    assert (missing_seq, missing_hash) == (0, None)

    journal_path = tmp_path / "journal.ndjson"
    with open(journal_path, "w", encoding="utf-8") as fh:
        fh.write("padding-line-" * 20 + "\n")
        fh.write("{bad json}\n")
        fh.write(json.dumps({"seq": 0, "note": "ignore"}) + "\n")
        fh.write(json.dumps({"seq": 4, "op_id": "abc"}) + "\n")
    seq, entry_hash = journal._scan_journal_tail(str(journal_path), max_bytes=64)
    expected_hash = journal.hashlib.sha256(
        json.dumps({"seq": 4, "op_id": "abc"}, sort_keys=True).encode()
    ).hexdigest()
    assert seq == 4
    assert entry_hash == expected_hash

    monkeypatch.setattr(
        os.path, "getsize", lambda *_a, **_k: (_ for _ in ()).throw(OSError("boom"))
    )
    assert journal._scan_journal_tail(str(journal_path)) == (0, None)


def test_journal_writer_initialize_state_and_persist_warn_branches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Brief: Writer initialization, manifest persistence, and size warning branches behave safely.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts sequence/hash initialization and warning/persistence edge paths.
    """
    monkeypatch.setattr(
        journal,
        "load_manifest",
        lambda *_a, **_k: journal.Manifest(last_seq=2),
    )
    monkeypatch.setattr(
        journal, "_scan_journal_tail", lambda *_a, **_k: (7, "tail-hash")
    )
    writer = journal.JournalWriter(zone_apex="example.com", base_dir=str(tmp_path))
    assert writer._sequences[journal.JournalEntry] == 7
    assert writer._last_hash == "tail-hash"

    monkeypatch.setattr(
        journal,
        "load_manifest",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("manifest boom")),
    )
    monkeypatch.setattr(
        journal,
        "_scan_journal_tail",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("scan boom")),
    )
    writer_err = journal.JournalWriter(zone_apex="example.net", base_dir=str(tmp_path))
    assert writer_err._sequences == {}
    assert writer_err._last_hash is None

    saved_seq: list[int] = []
    monkeypatch.setattr(journal, "load_manifest", lambda *_a, **_k: journal.Manifest())
    monkeypatch.setattr(
        journal,
        "save_manifest",
        lambda manifest, *_a, **_k: saved_seq.append(int(manifest.last_seq)) or True,
    )
    monkeypatch.setattr(time, "time_ns", lambda: 10_000_000_000)

    writer._last_manifest_write_ns = 0
    writer._maybe_persist_sequence(9, interval_ms=1)
    assert saved_seq == [9]
    saved_seq.clear()
    writer._last_manifest_write_ns = 10_000_000_000
    writer._maybe_persist_sequence(10, interval_ms=5000)
    assert saved_seq == []

    monkeypatch.setattr(
        journal,
        "load_manifest",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("persist boom")),
    )
    writer._last_manifest_write_ns = 0
    writer._maybe_persist_sequence(11, interval_ms=1)

    os.makedirs(writer.zone_dir, exist_ok=True)
    with open(writer.journal_path, "w", encoding="utf-8") as fh:
        fh.write("line\n")

    writer._last_size_warn_ns = 0
    monkeypatch.setattr(time, "time_ns", lambda: 70_000_000_000)
    writer._maybe_warn_journal_size(max_journal_bytes=1)
    warned_at = writer._last_size_warn_ns
    assert warned_at == 70_000_000_000
    monkeypatch.setattr(time, "time_ns", lambda: 70_500_000_000)
    writer._maybe_warn_journal_size(max_journal_bytes=1)
    assert writer._last_size_warn_ns == warned_at
    monkeypatch.setattr(time, "time_ns", lambda: 200_000_000_000)
    monkeypatch.setattr(
        os.path,
        "getsize",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("size boom")),
    )
    writer._maybe_warn_journal_size(max_journal_bytes=1)
    writer._maybe_warn_journal_size(max_journal_bytes=0)


def test_journal_writer_append_entry_validation_and_size_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: append_entry rejects invalid actions/actors and oversized payloads.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts early-return validation branches.
    """
    writer = journal.JournalWriter(zone_apex="example.com", base_dir="/tmp")
    monkeypatch.setattr(writer, "_ensure_dir", lambda: None)

    assert (
        writer.append_entry(
            actions=[
                {
                    "type": "rr_add",
                    "owner": "a.example.com",
                    "qtype": 1,
                    "value": "",
                }
            ],
            actor={"client_ip": "192.0.2.1"},
        )
        is None
    )
    assert (
        writer.append_entry(
            actions=[
                {
                    "type": "rr_add",
                    "owner": "a.example.com",
                    "qtype": 1,
                    "value": "192.0.2.1",
                }
            ],
            actor={},
        )
        is None
    )
    assert (
        writer.append_entry(
            actions=[
                {
                    "type": "rr_add",
                    "owner": "a.example.com",
                    "qtype": 1,
                    "value": "192.0.2.1",
                }
            ],
            actor={"client_ip": "192.0.2.1"},
            max_transaction_bytes=1,
        )
        is None
    )


def test_journal_reader_iter_entries_max_line_bytes(tmp_path) -> None:
    """Brief: iter_entries enforces max_line_bytes with validate and non-validate modes.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts oversize lines break/skip according to validation mode.
    """
    base_dir = str(tmp_path)
    zone = "example.com"
    zone_dir = os.path.join(base_dir, zone)
    os.makedirs(zone_dir, exist_ok=True)
    journal_path = os.path.join(zone_dir, "journal.ndjson")

    entry = journal.JournalEntry(
        seq=1,
        ts_unix_ns=1,
        op_id="op",
        origin_node_id="node",
        zone=zone,
        actor={"client_ip": "192.0.2.1"},
        actions=[
            {
                "type": "rr_add",
                "owner": "a.example.com",
                "qtype": 1,
                "ttl": 60,
                "value": "192.0.2.1",
            }
        ],
    )
    entry.entry_checksum = entry.compute_checksum()

    with open(journal_path, "w", encoding="utf-8") as fh:
        fh.write("x" * 2048 + "\n")
        fh.write(json.dumps(entry.to_dict()) + "\n")

    reader = journal.JournalReader(zone_apex=zone, base_dir=base_dir)
    assert list(reader.iter_entries(validate=True, max_line_bytes=1024)) == []
    skipped = list(reader.iter_entries(validate=False, max_line_bytes=1024))
    assert len(skipped) == 1
    assert skipped[0].seq == 1


def test_manifest_and_snapshot_invalid_zone_and_line_limit_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Brief: Manifest/snapshot helpers handle invalid zones and snapshot line-limit branches.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts invalid-zone fallbacks and snapshot line-limit safeguards.
    """
    base_dir = str(tmp_path)
    assert isinstance(journal.load_manifest("bad/zone", base_dir), journal.Manifest)
    assert journal.save_manifest(journal.Manifest(), "bad/zone", base_dir) is False
    assert journal.save_snapshot("bad/zone", base_dir, {}, seq=1) is False
    assert journal.load_snapshot("bad/zone", base_dir) == ({}, 0)

    zone = "example.com"
    zone_dir = os.path.join(base_dir, zone)
    os.makedirs(zone_dir, exist_ok=True)
    snapshot_path = os.path.join(zone_dir, "snapshot.ndjson")

    monkeypatch.setattr(journal, "DEFAULT_MAX_JOURNAL_LINE_BYTES", 16)
    with open(snapshot_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"snapshot_seq": 1, "pad": "x" * 64}) + "\n")
    assert journal.load_snapshot(zone, base_dir) == ({}, 0)

    monkeypatch.setattr(journal, "DEFAULT_MAX_JOURNAL_LINE_BYTES", 0)
    with open(snapshot_path, "w", encoding="utf-8") as fh:
        fh.write("\n")
        fh.write(
            json.dumps(
                {
                    "owner": "a.example.com",
                    "qtype": 1,
                    "ttl": 60,
                    "values": ["192.0.2.5"],
                    "sources": ["file"],
                }
            )
            + "\n"
        )
        fh.write("\n")
    records, seq = journal.load_snapshot(zone, base_dir)
    assert seq == 0
    assert records[("a.example.com", 1)] == (60, ["192.0.2.5"], ["file"])

    monkeypatch.setattr(journal, "DEFAULT_MAX_JOURNAL_LINE_BYTES", 16)
    with open(snapshot_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"snapshot_seq": 2}) + "\n")
        fh.write("x" * 64 + "\n")
    assert journal.load_snapshot(zone, base_dir) == ({}, 0)


def test_compact_zone_journal_invalid_zone_and_missing_journal(tmp_path) -> None:
    """Brief: Compaction rejects invalid zones and succeeds when no journal exists yet.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts invalid-zone fast-fail and no-journal rotation path.
    """
    base_dir = str(tmp_path)
    assert journal.compact_zone_journal("bad/zone", base_dir, {}, seq=1) is False

    records = {("host.example.com", 1): (60, ["192.0.2.1"], ["file"])}
    assert (
        journal.compact_zone_journal(
            zone_apex="example.com",
            base_dir=base_dir,
            records=records,
            seq=1,
        )
        is True
    )


def test_compact_zone_journal_write_and_manifest_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Brief: Compaction returns False on write-path and manifest persistence failures.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Pytest temp directory.

    Outputs:
      - None; asserts failure branches after snapshot succeeds.
    """
    base_dir = str(tmp_path)
    zone = "example.net"
    zone_dir = os.path.join(base_dir, zone)
    os.makedirs(zone_dir, exist_ok=True)
    journal_path = os.path.join(zone_dir, "journal.ndjson")
    old_path = os.path.join(zone_dir, "journal.old")
    with open(journal_path, "w", encoding="utf-8") as fh:
        fh.write('{"seq":1}\n')
    with open(old_path, "w", encoding="utf-8") as fh:
        fh.write("stale\n")

    monkeypatch.setattr(journal, "save_manifest", lambda *_a, **_k: False)
    assert (
        journal.compact_zone_journal(
            zone_apex=zone,
            base_dir=base_dir,
            records={("a.example.net", 1): (60, ["192.0.2.8"], ["file"])},
            seq=2,
        )
        is False
    )

    monkeypatch.setattr(journal, "save_manifest", lambda *_a, **_k: True)
    monkeypatch.setattr(journal, "save_snapshot", lambda *_a, **_k: True)
    monkeypatch.setattr(
        builtins,
        "open",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("open boom")),
    )
    assert (
        journal.compact_zone_journal(
            zone_apex="example.org",
            base_dir=base_dir,
            records={("a.example.org", 1): (60, ["192.0.2.9"], ["file"])},
            seq=3,
        )
        is False
    )
