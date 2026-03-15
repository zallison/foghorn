"""Brief: Unit tests for zone_records journal persistence primitives.

Inputs:
  - Temporary directories and in-memory records/actions.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

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
