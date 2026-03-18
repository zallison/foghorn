"""Brief: Journal management for DNS UPDATE persistence.

Inputs:
  - zone_apex: Zone name.
  - state_dir: Base directory for journal files.
  - actions: Normalized RFC 2136 update actions.

Outputs:
  - Durable append-only journal with checksum and chained hash verification.
  - Replay support for recovery.
  - Compaction for size management.

Notes:
  - Journal entries are stored as NDJSON (one JSON per line).
  - Each entry includes SHA256 checksum and chained hash for integrity.
  - Crash-safe writes using atomic appends and predicate ordering.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from foghorn.utils import dns_names

logger = logging.getLogger(__name__)

JOURNAL_SCHEMA_VERSION = 1
DEFAULT_FILE_PERMISSIONS = 0o600
DEFAULT_DIR_PERMISSIONS = 0o700


@dataclass
class JournalEntry:
    """Brief: A journal entry representing a committed UPDATE transaction.

    Inputs:
      - seq: Monotonic sequence number.
      - ts_unix_ns: Commit timestamp.
      - op_id: Operation UUID.
      - origin_node_id: Node that originated this entry.
      - zone: Zone apex.
      - actor: Actor metadata (client_ip, auth_method, tsig_key_name).
      - actions: Normalized update actions.
      - entry_checksum: SHA256 checksum (included in hash).
      - prev_hash: Chained hash of previous entry.

    Outputs:
      - JournalEntry instance for serialization.
    """

    seq: int
    ts_unix_ns: int
    op_id: str
    origin_node_id: str
    zone: str
    actor: Dict[str, Any]
    actions: List[Dict[str, Any]]
    entry_checksum: Optional[str] = None
    prev_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Brief: Convert to dict for JSON serialization.

        Outputs:
          - Dict representation.
        """
        return {
            "schema_version": JOURNAL_SCHEMA_VERSION,
            "seq": self.seq,
            "ts_unix_ns": self.ts_unix_ns,
            "op_id": self.op_id,
            "origin_node_id": self.origin_node_id,
            "zone": self.zone,
            "actor": self.actor,
            "actions": self.actions,
            "entry_checksum": self.entry_checksum,
            "prev_hash": self.prev_hash,
        }

    def compute_checksum(self) -> str:
        """Brief: Compute SHA256 checksum of entry (excluding checksum field).

        Outputs:
          - Hex-encoded SHA256 digest.
        """
        fields = {
            "schema_version": JOURNAL_SCHEMA_VERSION,
            "seq": self.seq,
            "ts_unix_ns": self.ts_unix_ns,
            "op_id": self.op_id,
            "origin_node_id": self.origin_node_id,
            "zone": self.zone,
            "actor": self.actor,
            "actions": self.actions,
            "prev_hash": self.prev_hash,
        }
        return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()


@dataclass
class Manifest:
    """Brief: Journal manifest tracking compaction state.

    Inputs:
      - last_compacted_seq: Highest seq included in snapshot.
      - active_snapshot_seq: Snapshot high-watermark.
      - last_compact_time: Timestamp of last compaction.

    Outputs:
      - Manifest instance.
    """

    last_compacted_seq: int = 0
    active_snapshot_seq: int = 0
    last_compact_time: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Brief: Convert to dict for JSON serialization.

        Outputs:
          - Dict representation.
        """
        return {
            "schema_version": JOURNAL_SCHEMA_VERSION,
            "last_compacted_seq": self.last_compacted_seq,
            "active_snapshot_seq": self.active_snapshot_seq,
            "last_compact_time": self.last_compact_time,
        }


class JournalWriter:
    """Brief: Thread-safe append-only journal writer.

    Inputs:
      - zone_apex: Zone name.
      - base_dir: Base directory for zone journals.

    Outputs:
      - JournalWriter instance.

    Notes:
      - Uses advisory file locks for coordination.
      - Atomic appends with O_APPEND for safety.
    """

    def __init__(self, zone_apex: str, base_dir: str) -> None:
        """Brief: Initialize journal writer.

        Inputs:
          - zone_apex: Zone name.
          - base_dir: Base directory for journals.
        """
        self.zone_apex = dns_names.normalize_name(zone_apex)

        self.base_dir = str(base_dir)
        self.zone_dir = os.path.join(self.base_dir, self.zone_apex)
        self.journal_path = os.path.join(self.zone_dir, "journal.ndjson")
        self.lock_path = os.path.join(self.zone_dir, "lock")
        self._lock = threading.Lock()
        self._sequences: Dict[type, int] = {}
        self._last_hash: Optional[str] = None
        self._file_handle: Optional[Any] = None
        self._last_fsync_ns: int = 0

    def _ensure_dir(self) -> None:
        """Brief: Ensure journal directory exists with correct permissions.

        Outputs:
          - None; creates directory if missing.
        """
        if not os.path.exists(self.zone_dir):
            try:
                os.makedirs(self.zone_dir, mode=DEFAULT_DIR_PERMISSIONS, exist_ok=True)
            except OSError:
                logger.error(
                    "Failed to create journal directory %s",
                    self.zone_dir,
                    exc_info=True,
                )
                raise

    def acquire_lock(self) -> bool:
        """Brief: Acquire advisory lock for this zone's journal.

        Outputs:
          - bool: True if lock acquired, False otherwise.
        """
        if not hasattr(fcntl, "LOCK_EX"):
            return True

        try:
            self._ensure_dir()
            fh = open(self.lock_path, "w")
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            setattr(self, "_lock_fh", fh)
            return True
        except (OSError, BlockingIOError):
            return False

    def release_lock(self) -> None:
        """Brief: Release lock if held.

        Outputs:
          - None.
        """
        fh = getattr(self, "_lock_fh", None)
        if fh is not None:
            try:
                fcntl.flock(fh, fcntl.LOCK_UN)
                fh.close()
            except Exception:
                pass
            delattr(self, "_lock_fh")

    def next_sequence(self, key: type = JournalEntry) -> int:
        """Brief: Get next monotonic sequence number.

        Inputs:
          - key: Type key for sequence tracking.

        Outputs:
          - int: Next sequence number.
        """
        with self._lock:
            current = self._sequences.get(key, 0)
            next_seq = current + 1
            self._sequences[key] = next_seq
            return next_seq

    def _maybe_fsync(self, fsync_mode: str, fsync_interval_ms: int) -> None:
        """Brief: Conditionally fsync based on mode.

        Inputs:
          - fsync_mode: 'always' or 'interval'.
          - fsync_interval_ms: Interval in ms.

        Outputs:
          - None.
        """
        if fsync_mode != "always" and fsync_mode != "interval":
            return

        if fsync_mode == "always":
            if self._file_handle:
                try:
                    os.fsync(self._file_handle.fileno())
                except Exception:
                    pass
        elif fsync_mode == "interval":
            now_ns = time.time_ns()
            interval_ns = fsync_interval_ms * 1_000_000
            if now_ns - self._last_fsync_ns > interval_ns:
                if self._file_handle:
                    try:
                        os.fsync(self._file_handle.fileno())
                        self._last_fsync_ns = now_ns
                    except Exception:
                        pass

    def append_entry(
        self,
        actions: List[Dict[str, Any]],
        actor: Dict[str, Any],
        origin_node_id: Optional[str] = None,
        fsync_mode: str = "interval",
        fsync_interval_ms: int = 5000,
    ) -> Optional[JournalEntry]:
        """Brief: Append a journal entry atomically.

        Inputs:
          - actions: Normalized update actions.
          - actor: Actor metadata (client_ip, auth_method, tsig_key_name).
          - origin_node_id: Optional stable node identity for the entry origin.
          - fsync_mode: Durability mode.
          - fsync_interval_ms: Interval fsync threshold.

        Outputs:
          - JournalEntry if successful, None on error.
        """
        self._ensure_dir()

        seq = self.next_sequence(JournalEntry)
        op_id = str(uuid.uuid4())
        ts_unix_ns = time.time_ns()

        entry = JournalEntry(
            seq=seq,
            ts_unix_ns=ts_unix_ns,
            op_id=op_id,
            origin_node_id=str(
                origin_node_id or os.getenv("FOGHORN_NODE_ID", "unknown")
            ),
            zone=self.zone_apex,
            actor=actor,
            actions=actions,
            prev_hash=self._last_hash,
        )

        entry.entry_checksum = entry.compute_checksum()
        entry_hash = hashlib.sha256(
            json.dumps(entry.to_dict(), sort_keys=True).encode()
        ).hexdigest()

        line = json.dumps(entry.to_dict(), separators=(",", ":"))
        try:
            if self._file_handle is None or self._file_handle.closed:
                self._file_handle = open(self.journal_path, "a", encoding="utf-8")

            self._file_handle.write(line + "\n")
            self._file_handle.flush()
            self._maybe_fsync(fsync_mode, fsync_interval_ms)

            self._last_hash = entry_hash
            return entry

        except (OSError, IOError) as exc:
            logger.error("Failed to write journal entry: %s", exc)
            return None

    def close(self) -> None:
        """Brief: Close any open file handle.

        Outputs:
          - None.
        """
        if self._file_handle and not self._file_handle.closed:
            try:
                self._file_handle.close()
            except Exception:
                pass
        self._file_handle = None


class JournalReader:
    """Brief: Journal reader for replay and inspection.

    Inputs:
      - zone_apex: Zone name.
      - base_dir: Base directory for journals.

    Outputs:
      - JournalReader instance.

    Notes:
      - Validates checksums and chained hashes during read.
    """

    def __init__(self, zone_apex: str, base_dir: str) -> None:
        """Brief: Initialize journal reader.

        Inputs:
          - zone_apex: Zone name.
          - base_dir: Base directory for journals.
        """
        self.zone_apex = dns_names.normalize_name(zone_apex)
        self.base_dir = str(base_dir)
        self.zone_dir = os.path.join(self.base_dir, self.zone_apex)
        self.journal_path = os.path.join(self.zone_dir, "journal.ndjson")

    def read_entries(
        self, start_seq: int = 0, validate: bool = True
    ) -> List[JournalEntry]:
        """Brief: Read entries from journal, optionally validating.

        Inputs:
          - start_seq: Starting sequence number.
          - validate: Whether to validate checksums and hashes.

        Outputs:
          - List of JournalEntry objects.
        """
        entries: List[JournalEntry] = []
        last_hash: Optional[str] = None

        if not os.path.exists(self.journal_path):
            return entries

        try:
            with open(self.journal_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                        entry = JournalEntry(
                            seq=data.get("seq", 0),
                            ts_unix_ns=data.get("ts_unix_ns", 0),
                            op_id=data.get("op_id", ""),
                            origin_node_id=data.get("origin_node_id", ""),
                            zone=data.get("zone", ""),
                            actor=data.get("actor", {}),
                            actions=data.get("actions", []),
                            entry_checksum=data.get("entry_checksum"),
                            prev_hash=data.get("prev_hash"),
                        )

                        if validate:
                            if entry.entry_checksum != entry.compute_checksum():
                                logger.warning(
                                    "Checksum mismatch for seq %d in zone %s",
                                    entry.seq,
                                    self.zone_apex,
                                )
                                break

                            entry_hash = hashlib.sha256(
                                json.dumps(entry.to_dict(), sort_keys=True).encode()
                            ).hexdigest()

                            if last_hash is not None and entry.prev_hash != last_hash:
                                logger.warning(
                                    "Hash chain broken at seq %d in zone %s",
                                    entry.seq,
                                    self.zone_apex,
                                )
                                break

                            last_hash = entry_hash

                        if entry.seq >= start_seq:
                            entries.append(entry)

                    except (json.JSONDecodeError, KeyError) as exc:
                        logger.warning("Failed to parse journal line: %s", exc)
                        if validate:
                            break

        except IOError as exc:
            logger.error("Failed to read journal: %s", exc)

        return entries

    def get_size_bytes(self) -> int:
        """Brief: Get journal file size in bytes.

        Outputs:
          - int: File size or 0 if missing.
        """
        try:
            return os.path.getsize(self.journal_path)
        except OSError:
            return 0

    def get_entry_count(self) -> int:
        """Brief: Get number of entries in journal.

        Outputs:
          - int: Entry count.
        """
        count = 0
        if os.path.exists(self.journal_path):
            try:
                with open(self.journal_path, "r", encoding="utf-8") as f:
                    for _ in f:
                        count += 1
            except IOError:
                pass
        return count


def load_manifest(zone_apex: str, base_dir: str) -> Manifest:
    """Brief: Load manifest for a zone.

    Inputs:
      - zone_apex: Zone name.
      - base_dir: Base directory for journals.

    Outputs:
      - Manifest instance (empty if missing).
    """
    manifest_path = os.path.join(
        base_dir, dns_names.normalize_name(zone_apex), "manifest.json"
    )

    if not os.path.exists(manifest_path):
        return Manifest()

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return Manifest(
                last_compacted_seq=data.get("last_compacted_seq", 0),
                active_snapshot_seq=data.get("active_snapshot_seq", 0),
                last_compact_time=data.get("last_compact_time", 0),
            )
    except (IOError, json.JSONDecodeError) as exc:
        logger.warning("Failed to load manifest: %s", exc)
        return Manifest()


def save_manifest(manifest: Manifest, zone_apex: str, base_dir: str) -> bool:
    """Brief: Save manifest atomically.

    Inputs:
      - manifest: Manifest to save.
      - zone_apex: Zone name.
      - base_dir: Base directory for journals.

    Outputs:
      - bool: True if successful.
    """
    zone_apex_norm = dns_names.normalize_name(zone_apex)
    zone_dir = os.path.join(base_dir, zone_apex_norm)
    manifest_path = os.path.join(zone_dir, "manifest.json")
    tmp_path = manifest_path + ".tmp"

    if not os.path.exists(zone_dir):
        try:
            os.makedirs(zone_dir, mode=DEFAULT_DIR_PERMISSIONS, exist_ok=True)
        except OSError:
            return False

    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(manifest.to_dict(), f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, manifest_path)
        return True
    except (IOError, OSError) as exc:
        logger.error("Failed to save manifest: %s", exc)
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
        return False


def apply_actions_to_records(
    records: Dict[tuple[str, int], tuple[int, List[str], List[str]]],
    actions: List[Dict[str, Any]],
) -> Dict[tuple[str, int], tuple[int, List[str], List[str]]]:
    """Brief: Apply normalized journal actions onto records mapping.

    Inputs:
      - records: Existing records mapping.
      - actions: Normalized action list from journal entry.

    Outputs:
      - Updated records mapping.
    """
    updated = dict(records or {})
    for action in actions or []:
        action_type = str(action.get("type", ""))
        owner = dns_names.normalize_name(action.get("owner", ""))
        qtype = int(action.get("qtype", 0) or 0)
        key = (owner, qtype)

        if action_type == "rr_add":
            ttl = int(action.get("ttl", 300) or 300)
            value = str(action.get("value", ""))
            if not value:
                continue
            if key not in updated:
                updated[key] = (ttl, [value], ["update"])
            else:
                existing_ttl, values, sources = updated[key]
                if value not in values:
                    values = list(values) + [value]
                sources_list = list(sources or [])
                if "update" not in sources_list:
                    sources_list.append("update")
                updated[key] = (int(existing_ttl), values, sources_list)
            continue

        if action_type == "rr_delete_values":
            value = str(action.get("value", ""))
            if key not in updated or not value:
                continue
            existing_ttl, values, sources = updated[key]
            values_list = [v for v in list(values or []) if str(v) != value]
            if values_list:
                updated[key] = (int(existing_ttl), values_list, list(sources or []))
            else:
                updated.pop(key, None)
            continue

        if action_type == "rr_delete_rrset":
            updated.pop(key, None)
            continue

        if action_type == "name_delete_all":
            owners = [k for k in updated.keys() if k[0] == owner]
            for owner_key in owners:
                updated.pop(owner_key, None)
            continue

        if action_type == "rr_replace":
            ttl = int(action.get("ttl", 300) or 300)
            values = [str(v) for v in list(action.get("values", []) or [])]
            if values:
                updated[key] = (ttl, values, ["update"])
            continue

    return updated


def replay_journal_to_records(
    zone_apex: str,
    base_dir: str,
    records: Dict[tuple[str, int], tuple[int, List[str], List[str]]],
    *,
    start_seq: int = 0,
) -> tuple[Dict[tuple[str, int], tuple[int, List[str], List[str]]], int]:
    """Brief: Replay zone journal onto records and return highest applied seq.

    Inputs:
      - zone_apex: Zone apex.
      - base_dir: Journal base directory.
      - records: Baseline records mapping.
      - start_seq: Minimum sequence number to replay.

    Outputs:
      - Tuple of (updated_records, last_applied_seq).
    """
    snapshot_records, snapshot_seq = load_snapshot(zone_apex, base_dir)
    updated = dict(records or {})
    if snapshot_records:
        updated = dict(snapshot_records)
    effective_start_seq = max(int(start_seq), int(snapshot_seq) + 1, 1)
    reader = JournalReader(zone_apex=zone_apex, base_dir=base_dir)
    entries = reader.read_entries(start_seq=effective_start_seq)
    last_seq = max(int(start_seq), int(snapshot_seq))
    for entry in entries:
        updated = apply_actions_to_records(updated, entry.actions)
        last_seq = max(last_seq, int(entry.seq))
    return updated, last_seq


def save_snapshot(
    zone_apex: str,
    base_dir: str,
    records: Dict[tuple[str, int], tuple[int, List[str], List[str]]],
    *,
    seq: int,
) -> bool:
    """Brief: Persist a compact snapshot atomically for a zone.

    Inputs:
      - zone_apex: Zone apex.
      - base_dir: Journal base directory.
      - records: Current records map.
      - seq: High-watermark seq covered by this snapshot.

    Outputs:
      - bool: True when snapshot persisted.
    """
    zone = dns_names.normalize_name(zone_apex)

    zone_dir = os.path.join(base_dir, zone)
    snapshot_path = os.path.join(zone_dir, "snapshot.ndjson")
    tmp_path = snapshot_path + ".tmp"

    try:
        os.makedirs(zone_dir, mode=DEFAULT_DIR_PERMISSIONS, exist_ok=True)
    except OSError:
        return False

    try:
        with open(tmp_path, "w", encoding="utf-8") as fh:
            header = {
                "schema_version": JOURNAL_SCHEMA_VERSION,
                "snapshot_seq": int(seq),
            }
            fh.write(json.dumps(header, separators=(",", ":")) + "\n")
            for (owner, qtype), (ttl, values, sources) in sorted(records.items()):
                row = {
                    "owner": dns_names.normalize_name(owner),
                    "qtype": int(qtype),
                    "ttl": int(ttl),
                    "values": [str(v) for v in list(values or [])],
                    "sources": [str(s) for s in list(sources or [])],
                }
                fh.write(json.dumps(row, separators=(",", ":")) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, snapshot_path)
        return True
    except (OSError, IOError):
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
        return False


def load_snapshot(
    zone_apex: str,
    base_dir: str,
) -> tuple[Dict[tuple[str, int], tuple[int, List[str], List[str]]], int]:
    """Brief: Load a compact snapshot for a zone.

    Inputs:
      - zone_apex: Zone apex.
      - base_dir: Journal base directory.

    Outputs:
      - Tuple of (records, snapshot_seq).
    """
    zone = dns_names.normalize_name(zone_apex)

    snapshot_path = os.path.join(base_dir, zone, "snapshot.ndjson")
    if not os.path.exists(snapshot_path):
        return {}, 0

    records: Dict[tuple[str, int], tuple[int, List[str], List[str]]] = {}
    snapshot_seq = 0
    try:
        with open(snapshot_path, "r", encoding="utf-8") as fh:
            first = fh.readline().strip()
            if first:
                head = json.loads(first)
                snapshot_seq = int(head.get("snapshot_seq", 0) or 0)
            for line in fh:
                raw = line.strip()
                if not raw:
                    continue
                row = json.loads(raw)
                key = (
                    dns_names.normalize_name(row.get("owner", "")),
                    int(row.get("qtype", 0) or 0),
                )
                records[key] = (
                    int(row.get("ttl", 300) or 300),
                    [str(v) for v in list(row.get("values", []) or [])],
                    [str(s) for s in list(row.get("sources", []) or [])],
                )
    except (OSError, IOError, ValueError, json.JSONDecodeError):
        return {}, 0
    return records, snapshot_seq


def compact_zone_journal(
    zone_apex: str,
    base_dir: str,
    records: Dict[tuple[str, int], tuple[int, List[str], List[str]]],
    *,
    seq: int,
) -> bool:
    """Brief: Compact a zone journal using snapshot + journal rotation.

    Inputs:
      - zone_apex: Zone apex.
      - base_dir: Journal base directory.
      - records: Effective records map to snapshot.
      - seq: Last applied journal sequence.

    Outputs:
      - bool: True when compaction succeeded.
    """
    zone = dns_names.normalize_name(zone_apex)
    zone_dir = os.path.join(base_dir, zone)
    journal_path = os.path.join(zone_dir, "journal.ndjson")
    old_path = os.path.join(zone_dir, "journal.old")

    if not save_snapshot(zone, base_dir, records, seq=seq):
        return False

    try:
        if os.path.exists(journal_path):
            if os.path.exists(old_path):
                os.unlink(old_path)
            os.replace(journal_path, old_path)
        with open(journal_path, "w", encoding="utf-8") as fh:
            fh.flush()
            os.fsync(fh.fileno())
    except (OSError, IOError):
        return False

    manifest = load_manifest(zone, base_dir)
    manifest.last_compacted_seq = int(seq)
    manifest.active_snapshot_seq = int(seq)
    manifest.last_compact_time = int(time.time())
    if not save_manifest(manifest, zone, base_dir):
        return False

    try:
        if os.path.exists(old_path):
            os.unlink(old_path)
    except OSError:
        pass
    return True
