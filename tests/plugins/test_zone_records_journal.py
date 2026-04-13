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

    writer = journal.JournalWriter(zone_apex="example.com", base_dir="/tmp")
    monkeypatch.setattr(writer, "_ensure_dir", lambda: None)
    writer._file_handle = _BadHandle()
    entry = writer.append_entry(actions=[], actor={})
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
