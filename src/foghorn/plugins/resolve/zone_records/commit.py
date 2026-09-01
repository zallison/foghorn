"""Brief: Shared ZoneRecords commit pipeline for normalized record actions.

Inputs:
  - Normalized action dicts (rr_add / rr_delete_* / name_delete_all / rr_replace).
  - Plugin state, optional journal writer, actor metadata.

Outputs:
  - Atomic memory commit with optional journal, SOA bump, and NOTIFY.
  - Shared by DNS UPDATE and admin API mutation paths.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from dnslib import QTYPE

logger = logging.getLogger(__name__)

RecordKey = Tuple[str, int]
RecordEntry = Tuple[int, List[str], List[str]]


@dataclass
class CommitResult:
    """Brief: Result of commit_record_actions.

    Inputs:
      - Populated by commit_record_actions.

    Outputs:
      - Structured commit outcome for callers.
    """

    ok: bool
    rcode: int
    error: Optional[str] = None
    zone_apex: str = ""
    serial_before: Optional[int] = None
    serial_after: Optional[int] = None
    actions_applied: List[Dict[str, Any]] = field(default_factory=list)
    journal_seq: Optional[int] = None
    touched_owners: List[str] = field(default_factory=list)
    deleted_rrsets: int = 0
    changed: bool = False


def _normalize_dns_name(name: str) -> str:
    """Brief: Normalize a DNS name for comparisons.

    Inputs:
      - name: DNS name, with or without trailing dot.

    Outputs:
      - Lowercased name without trailing dot.
    """
    from foghorn.utils import dns_names

    return dns_names.normalize_name(name)


def _normalize_record_entry_for_compare(
    entry: Optional[RecordEntry],
) -> Optional[Tuple[int, Tuple[str, ...], Tuple[str, ...]]]:
    """Brief: Normalize RRset tuples into comparable immutable form.

    Inputs:
      - entry: RRset tuple as (ttl, values[, sources]), or None.

    Outputs:
      - Comparable tuple (ttl, values_tuple, sources_tuple), or None.
    """
    if entry is None:
        return None
    try:
        ttl, values, sources = entry
    except (TypeError, ValueError):
        try:
            ttl, values = entry  # type: ignore[misc]
        except (TypeError, ValueError):
            return None
        sources = []
    return (
        int(ttl),
        tuple(str(v) for v in list(values or [])),
        tuple(str(s) for s in list(sources or [])),
    )


def _clone_record_entry(entry: RecordEntry) -> RecordEntry:
    """Brief: Clone one RRset entry into detached mutable lists.

    Inputs:
      - entry: RRset tuple as (ttl, values[, sources]).

    Outputs:
      - (ttl, values_copy, sources_copy) tuple.
    """
    try:
        ttl, values, sources = entry
    except (TypeError, ValueError):
        ttl, values = entry  # type: ignore[misc]
        sources = []
    return (int(ttl), list(values or []), list(sources or []))


def _owner_rrsets_from_view(
    owner_norm: str,
    records_map: Dict[RecordKey, RecordEntry],
    name_index_map: Optional[Dict[str, Dict[int, RecordEntry]]],
) -> Dict[int, Tuple[int, Tuple[str, ...], Tuple[str, ...]]]:
    """Brief: Extract all RRsets for one owner from records/index view.

    Inputs:
      - owner_norm: Normalized owner name.
      - records_map: Mapping of (owner, qtype) -> RRset tuple.
      - name_index_map: Optional owner->qtype->RRset index.

    Outputs:
      - Mapping of qtype -> normalized comparable RRset tuple.
    """
    rrsets: Dict[int, Tuple[int, Tuple[str, ...], Tuple[str, ...]]] = {}
    per_owner: Dict[int, RecordEntry] = {}
    if isinstance(name_index_map, dict):
        candidate = name_index_map.get(owner_norm, {})
        if isinstance(candidate, dict):
            per_owner = candidate  # type: ignore[assignment]
    if per_owner:
        for rr_qtype, rr_entry in per_owner.items():
            normalized = _normalize_record_entry_for_compare(rr_entry)
            if normalized is None:
                continue
            rrsets[int(rr_qtype)] = normalized
        return rrsets
    for (record_owner, record_qtype), rr_entry in (records_map or {}).items():
        if str(record_owner) != owner_norm:
            continue
        normalized = _normalize_record_entry_for_compare(rr_entry)
        if normalized is None:
            continue
        rrsets[int(record_qtype)] = normalized
    return rrsets


def _read_soa_serial(
    records_map: Dict[RecordKey, RecordEntry],
    zone_name: str,
) -> Optional[int]:
    """Brief: Read SOA serial for a zone apex from a records mapping.

    Inputs:
      - records_map: Records mapping.
      - zone_name: Zone apex (normalized).

    Outputs:
      - SOA serial integer, or None when unavailable.
    """
    try:
        soa_code = int(QTYPE.SOA)
    except Exception:
        soa_code = 6
    key = (_normalize_dns_name(zone_name), int(soa_code))
    entry = records_map.get(key)
    if entry is None:
        return None
    try:
        _ttl, values, _sources = entry
    except (TypeError, ValueError):
        return None
    if not values:
        return None
    parts = str(values[0]).split()
    if len(parts) < 7:
        return None
    try:
        return int(parts[2])
    except Exception:
        return None


def bump_soa_serial_for_zone(
    records_map: Dict[RecordKey, RecordEntry],
    zone_name: str,
    *,
    plugin: Optional[object] = None,
) -> Optional[int]:
    """Brief: Bump SOA serial for zone apex in a records mapping.

    Inputs:
      - records_map: Mutable records mapping.
      - zone_name: Zone apex (normalized).
      - plugin: Optional ZoneRecords instance; when set, also updates
        ``_name_index`` and ``_zone_soa`` so resolver/transfer views stay consistent.

    Outputs:
      - New serial after bump, or None when SOA missing/unparseable.
    """
    try:
        soa_code = int(QTYPE.SOA)
    except Exception:
        soa_code = 6
    apex_norm = _normalize_dns_name(zone_name)
    key = (apex_norm, int(soa_code))
    if key not in records_map:
        return None
    try:
        ttl, values, sources = records_map[key]
    except (TypeError, ValueError):  # pragma: no cover - defensive malformed SOA tuple
        return None
    if not values:  # pragma: no cover - defensive malformed SOA value list
        return None
    first = str(values[0])
    parts = first.split()
    if len(parts) < 7:
        return None
    try:
        serial = int(parts[2])
    except Exception:  # pragma: no cover - defensive non-integer SOA serial
        return None
    new_serial = max(1, serial + 1)
    parts[2] = str(new_serial)
    new_values = [" ".join(parts)] + [str(v) for v in list(values[1:])]
    new_sources = list(sources or [])
    new_entry: RecordEntry = (int(ttl), new_values, new_sources)
    records_map[key] = new_entry

    if plugin is not None:
        name_index = getattr(plugin, "_name_index", None)
        if isinstance(name_index, dict):
            per_owner = name_index.setdefault(apex_norm, {})
            if isinstance(per_owner, dict):
                per_owner[int(soa_code)] = (
                    int(ttl),
                    list(new_values),
                    list(new_sources),
                )
        zone_soa = getattr(plugin, "_zone_soa", None)
        if isinstance(zone_soa, dict):
            # Keep apex present for authority checks; store refreshed SOA rdata.
            zone_soa[apex_norm] = (int(ttl), list(new_values), list(new_sources))

    return new_serial


def resolve_zone_apex_for_owner(plugin: object, owner: str) -> str:
    """Brief: Resolve authoritative zone apex for an owner name.

    Inputs:
      - plugin: ZoneRecords plugin instance.
      - owner: Owner name (any common DNS form).

    Outputs:
      - Normalized apex string, or empty string when unresolved.

    Notes:
      - Prefers dns_update.zones match, then longest _zone_soa apex match.
    """
    owner_norm = _normalize_dns_name(owner)
    if not owner_norm:
        return ""

    dns_update_cfg = getattr(plugin, "_dns_update_config", None)
    if isinstance(dns_update_cfg, dict):
        zones = dns_update_cfg.get("zones")
        if isinstance(zones, list):
            matches: List[str] = []
            for item in zones:
                if not isinstance(item, dict):
                    continue
                zone_name = _normalize_dns_name(item.get("zone", ""))
                if not zone_name:
                    continue
                if owner_norm == zone_name or owner_norm.endswith(f".{zone_name}"):
                    matches.append(zone_name)
            if matches:
                return max(matches, key=len)

    zone_soa = getattr(plugin, "_zone_soa", None) or {}
    if isinstance(zone_soa, dict) and zone_soa:
        matches = []
        for apex in zone_soa.keys():
            zone_name = _normalize_dns_name(apex)
            if not zone_name:
                continue
            if owner_norm == zone_name or owner_norm.endswith(f".{zone_name}"):
                matches.append(zone_name)
        if matches:
            return max(matches, key=len)
    return ""


def _owner_in_zone(owner_norm: str, apex_norm: str) -> bool:
    """Brief: Return whether owner is inside zone apex.

    Inputs:
      - owner_norm: Normalized owner.
      - apex_norm: Normalized apex.

    Outputs:
      - True when owner equals apex or is a descendant.
    """
    if not apex_norm:
        return True
    return owner_norm == apex_norm or owner_norm.endswith(f".{apex_norm}")


def commit_record_actions(
    plugin: object,
    zone_apex: str,
    actions: List[Dict[str, Any]],
    *,
    actor: Optional[Dict[str, Any]] = None,
    journal_writer: Optional[object] = None,
    require_journal_persistence: bool = False,
    bump_soa: bool = True,
    send_notify: Optional[bool] = None,
    mark_update_managed: bool = True,
    default_source: str = "update",
    enforce_zone_boundary: bool = True,
) -> CommitResult:
    """Brief: Atomically commit normalized record actions to ZoneRecords state.

    Inputs:
      - plugin: ZoneRecords plugin instance.
      - zone_apex: Zone apex (normalized preferred); empty skips SOA/NOTIFY/zone checks when allowed.
      - actions: Normalized action dicts.
      - actor: Optional actor metadata for journaling.
      - journal_writer: Optional JournalWriter.
      - require_journal_persistence: Fail closed when journal cannot be used.
      - bump_soa: When True and actions non-empty, bump apex SOA serial.
      - send_notify: When None, use dns_update.replication.notify_on_update (default True).
      - mark_update_managed: Track name_delete_all owners as update-managed.
      - default_source: Source label used when creating/replacing RRsets.
      - enforce_zone_boundary: Reject owners outside zone_apex when apex is set.

    Outputs:
      - CommitResult with rcode/error and commit metadata.

    Example:
      commit_record_actions(plugin, "example.com", [{
          "type": "rr_add", "owner": "www.example.com", "qtype": 1,
          "ttl": 300, "value": "192.0.2.1",
      }], actor={"auth_method": "admin_api"})
    """
    if require_journal_persistence and (journal_writer is None or actor is None):
        return CommitResult(ok=False, rcode=2, error="Journal unavailable")

    try:
        apex_norm = _normalize_dns_name(zone_apex) if zone_apex else ""
    except Exception:
        apex_norm = ""

    action_list = [a for a in list(actions or []) if isinstance(a, dict)]

    def _snapshot_state() -> tuple:
        """Brief: Capture plugin records snapshot, initializing missing maps.

        Inputs:
          - None (reads plugin attributes).

        Outputs:
          - (records, count, name_index, compare_index_identity, generation)
        """
        snapshot_records = getattr(plugin, "records", None)
        if snapshot_records is None:
            snapshot_records = {}
            plugin.records = snapshot_records
        snapshot_name_index = getattr(plugin, "_name_index", None)
        if snapshot_name_index is None:
            snapshot_name_index = {}
            plugin._name_index = snapshot_name_index
        compare_name_index_identity = True
        snapshot_generation = int(getattr(plugin, "_records_generation", 0) or 0)
        return (
            snapshot_records,
            len(snapshot_records),
            snapshot_name_index,
            compare_name_index_identity,
            snapshot_generation,
        )

    lock = getattr(plugin, "_records_lock", None)
    if lock is None:
        (
            snapshot_records,
            snapshot_records_count,
            snapshot_name_index,
            compare_name_index_identity,
            snapshot_generation,
        ) = _snapshot_state()
    else:
        with lock:
            (
                snapshot_records,
                snapshot_records_count,
                snapshot_name_index,
                compare_name_index_identity,
                snapshot_generation,
            ) = _snapshot_state()

    serial_before = _read_soa_serial(snapshot_records, apex_norm) if apex_norm else None

    pending_rrset_updates: Dict[RecordKey, Optional[RecordEntry]] = {}
    pending_name_delete_all: set[str] = set()
    touched_owners: set[str] = set()
    normalized_actions: List[Dict[str, Any]] = []
    update_managed_owner_additions: set[str] = set()
    source_label = str(default_source or "update")

    def _effective_rrset_entry(
        owner_norm: str,
        qtype_int: int,
    ) -> Optional[RecordEntry]:
        """Brief: Read the transactional RRset view for a key.

        Inputs:
          - owner_norm: Normalized owner name.
          - qtype_int: RRtype integer.

        Outputs:
          - Current RRset tuple in transactional view, or None if absent.
        """
        key = (owner_norm, int(qtype_int))
        if key in pending_rrset_updates:
            entry = pending_rrset_updates[key]
            if entry is None:
                return None
            return _clone_record_entry(entry)
        if owner_norm in pending_name_delete_all:
            return None
        base_entry = snapshot_records.get(key)
        if base_entry is None:
            return None
        return _clone_record_entry(base_entry)

    for raw_action in action_list:
        action_type = str(raw_action.get("type", "") or "")
        try:
            owner_norm = _normalize_dns_name(str(raw_action.get("owner", "") or ""))
        except Exception:
            return CommitResult(
                ok=False,
                rcode=1,
                error="Invalid owner name in action",
                zone_apex=apex_norm,
            )
        if not owner_norm:
            return CommitResult(
                ok=False,
                rcode=1,
                error="Invalid owner name in action",
                zone_apex=apex_norm,
            )
        if (
            enforce_zone_boundary
            and apex_norm
            and not _owner_in_zone(owner_norm, apex_norm)
        ):
            return CommitResult(
                ok=False,
                rcode=9,
                error=f"Update owner {owner_norm} not in zone {apex_norm}",
                zone_apex=apex_norm,
            )

        touched_owners.add(owner_norm)
        action_source = str(raw_action.get("source", "") or "") or source_label

        if action_type == "rr_add":
            try:
                qtype_int = int(raw_action.get("qtype", 0) or 0)
            except (TypeError, ValueError):
                return CommitResult(
                    ok=False,
                    rcode=1,
                    error="Invalid qtype in rr_add",
                    zone_apex=apex_norm,
                )
            if qtype_int <= 0:
                return CommitResult(
                    ok=False,
                    rcode=1,
                    error="Invalid qtype in rr_add",
                    zone_apex=apex_norm,
                )
            try:
                ttl = int(raw_action.get("ttl", 300) or 300)
            except (TypeError, ValueError):
                ttl = 300
            rdata_str = str(raw_action.get("value", "") or "")
            if not rdata_str:
                return CommitResult(
                    ok=False,
                    rcode=1,
                    error="Missing value in rr_add",
                    zone_apex=apex_norm,
                )
            record_key = (owner_norm, qtype_int)
            current_entry = _effective_rrset_entry(owner_norm, qtype_int)
            if current_entry is None:
                pending_rrset_updates[record_key] = (ttl, [rdata_str], [action_source])
            else:
                _existing_ttl, existing_values, sources = current_entry
                has_source = action_source in list(sources or [])
                if rdata_str not in existing_values:
                    new_values = list(existing_values) + [rdata_str]
                    new_sources = list(sources or [])
                    if not has_source:
                        new_sources.append(action_source)
                    pending_rrset_updates[record_key] = (ttl, new_values, new_sources)
            normalized_actions.append(
                {
                    "type": "rr_add",
                    "owner": owner_norm,
                    "qtype": qtype_int,
                    "ttl": ttl,
                    "value": rdata_str,
                }
            )

        elif action_type == "rr_delete_values":
            try:
                qtype_int = int(raw_action.get("qtype", 0) or 0)
            except (TypeError, ValueError):
                return CommitResult(
                    ok=False,
                    rcode=1,
                    error="Invalid qtype in rr_delete_values",
                    zone_apex=apex_norm,
                )
            rdata_str = str(raw_action.get("value", "") or "")
            if not rdata_str:
                return CommitResult(
                    ok=False,
                    rcode=1,
                    error="Missing value in rr_delete_values",
                    zone_apex=apex_norm,
                )
            record_key = (owner_norm, qtype_int)
            existing_entry = _effective_rrset_entry(owner_norm, qtype_int)
            if existing_entry is None:
                continue
            existing_ttl, existing_values, sources = existing_entry
            if rdata_str not in existing_values:
                continue
            if len(existing_values) > 1:
                new_values = [v for v in existing_values if v != rdata_str]
                pending_rrset_updates[record_key] = (
                    existing_ttl,
                    new_values,
                    list(sources or []),
                )
                normalized_actions.append(
                    {
                        "type": "rr_delete_values",
                        "owner": owner_norm,
                        "qtype": qtype_int,
                        "value": rdata_str,
                    }
                )
            else:
                pending_rrset_updates[record_key] = None
                normalized_actions.append(
                    {
                        "type": "rr_delete_rrset",
                        "owner": owner_norm,
                        "qtype": qtype_int,
                    }
                )

        elif action_type == "rr_delete_rrset":
            try:
                qtype_int = int(raw_action.get("qtype", 0) or 0)
            except (TypeError, ValueError):
                return CommitResult(
                    ok=False,
                    rcode=1,
                    error="Invalid qtype in rr_delete_rrset",
                    zone_apex=apex_norm,
                )
            record_key = (owner_norm, qtype_int)
            existing_entry = _effective_rrset_entry(owner_norm, qtype_int)
            if existing_entry is None:
                continue
            pending_rrset_updates[record_key] = None
            normalized_actions.append(
                {
                    "type": "rr_delete_rrset",
                    "owner": owner_norm,
                    "qtype": qtype_int,
                }
            )

        elif action_type == "name_delete_all":
            pending_name_delete_all.add(owner_norm)
            keys_to_clear = [
                k for k in list(pending_rrset_updates.keys()) if k[0] == owner_norm
            ]
            for key_to_clear in keys_to_clear:
                del pending_rrset_updates[key_to_clear]
            if mark_update_managed:
                update_managed_owner_additions.add(owner_norm)
            normalized_actions.append(
                {
                    "type": "name_delete_all",
                    "owner": owner_norm,
                }
            )

        elif action_type == "rr_replace":
            try:
                qtype_int = int(raw_action.get("qtype", 0) or 0)
            except (TypeError, ValueError):
                return CommitResult(
                    ok=False,
                    rcode=1,
                    error="Invalid qtype in rr_replace",
                    zone_apex=apex_norm,
                )
            try:
                ttl = int(raw_action.get("ttl", 300) or 300)
            except (TypeError, ValueError):
                ttl = 300
            values_raw = raw_action.get("values", None)
            if values_raw is None and raw_action.get("value") is not None:
                values_list = [str(raw_action.get("value"))]
            else:
                values_list = [str(v) for v in list(values_raw or [])]
            if not values_list:
                return CommitResult(
                    ok=False,
                    rcode=1,
                    error="Missing values in rr_replace",
                    zone_apex=apex_norm,
                )
            record_key = (owner_norm, qtype_int)
            pending_rrset_updates[record_key] = (
                ttl,
                list(values_list),
                [action_source],
            )
            normalized_actions.append(
                {
                    "type": "rr_replace",
                    "owner": owner_norm,
                    "qtype": qtype_int,
                    "ttl": ttl,
                    "values": values_list,
                }
            )
        else:
            return CommitResult(
                ok=False,
                rcode=1,
                error=f"Unsupported action type {action_type}",
                zone_apex=apex_norm,
            )

    def _has_concurrent_conflict(
        *,
        current_records: Dict[RecordKey, RecordEntry],
        current_name_index: Dict[str, Dict[int, RecordEntry]],
        current_generation: int,
    ) -> bool:
        """Brief: Detect whether in-scope state changed since snapshot.

        Inputs:
          - current_records: Current plugin records mapping.
          - current_name_index: Current plugin owner index mapping.
          - current_generation: Current records generation counter.

        Outputs:
          - True if a conflicting concurrent mutation is detected.
        """
        if current_records is not snapshot_records:
            return True
        if len(current_records) != snapshot_records_count:
            return True
        if current_generation != snapshot_generation:
            return True
        if (
            compare_name_index_identity
            and current_name_index is not snapshot_name_index
        ):
            return True

        conflict_keys: set[RecordKey] = set(
            (str(owner), int(qtype)) for (owner, qtype) in pending_rrset_updates.keys()
        )
        for owner_norm in pending_name_delete_all:
            owner_rrsets = _owner_rrsets_from_view(
                owner_norm,
                snapshot_records,
                snapshot_name_index if isinstance(snapshot_name_index, dict) else None,
            )
            for rr_qtype in owner_rrsets.keys():
                conflict_keys.add((owner_norm, int(rr_qtype)))

        for owner_norm, qtype_int in conflict_keys:
            expected = _normalize_record_entry_for_compare(
                snapshot_records.get((owner_norm, int(qtype_int)))
            )
            actual = _normalize_record_entry_for_compare(
                current_records.get((owner_norm, int(qtype_int)))
            )
            if expected != actual:
                return True

        for owner_norm in pending_name_delete_all:
            expected_owner_rrsets = _owner_rrsets_from_view(
                owner_norm,
                snapshot_records,
                snapshot_name_index if isinstance(snapshot_name_index, dict) else None,
            )
            actual_owner_rrsets = _owner_rrsets_from_view(
                owner_norm,
                current_records,
                current_name_index,
            )
            if expected_owner_rrsets != actual_owner_rrsets:
                return True
        return False

    journal_entry = None
    journal_append_kwargs: Optional[Dict[str, Any]] = None
    if journal_writer is not None and actor is not None:
        persistence_cfg = getattr(plugin, "_dns_update_persistence_config", None)
        fsync_mode = "interval"
        fsync_interval = 5000
        max_journal_bytes = 0
        if isinstance(persistence_cfg, dict):
            fsync_mode = persistence_cfg.get("fsync_mode", "interval")
            fsync_interval = persistence_cfg.get("fsync_interval_ms", 5000)
            max_journal_bytes = int(persistence_cfg.get("max_journal_bytes", 0) or 0)

        security_cfg: Dict[str, Any] = {}
        dns_update_cfg = getattr(plugin, "_dns_update_config", None)
        if isinstance(dns_update_cfg, dict):
            scfg = dns_update_cfg.get("security")
            if isinstance(scfg, dict):
                security_cfg = scfg
        max_owner_length = int(security_cfg.get("max_owner_length", 0) or 0)
        max_rdata_length = int(security_cfg.get("max_rdata_length", 0) or 0)
        max_transaction_bytes = int(security_cfg.get("max_transaction_bytes", 0) or 0)
        max_actions = int(security_cfg.get("max_updates_per_message", 0) or 0)
        journal_append_kwargs = {
            "actions": normalized_actions,
            "actor": actor,
            "origin_node_id": str(getattr(plugin, "_dns_update_node_id", "unknown")),
            "fsync_mode": fsync_mode,
            "fsync_interval_ms": fsync_interval,
            "max_actions": max_actions,
            "max_owner_length": max_owner_length,
            "max_rdata_length": max_rdata_length,
            "max_transaction_bytes": max_transaction_bytes,
            "max_journal_bytes": max_journal_bytes,
        }

    deleted_rrsets = 0

    def _apply_commit_delta() -> Dict[RecordKey, RecordEntry]:
        """Brief: Apply transactional deltas to plugin state.

        Inputs:
          - None (reads plugin state and pending deltas from closure).

        Outputs:
          - Current records mapping after successful mutation.
        """
        nonlocal deleted_rrsets
        from . import helpers as zone_helpers

        live_records = getattr(plugin, "records", None)
        if live_records is None:
            live_records = {}
        live_name_index = getattr(plugin, "_name_index", None)
        if live_name_index is None:
            live_name_index = {}

        for owner_norm in pending_name_delete_all:
            rrsets_for_owner = live_name_index.get(owner_norm, {}) or {}
            for rr_qtype in list(rrsets_for_owner.keys()):
                if live_records.pop((owner_norm, int(rr_qtype)), None) is not None:
                    deleted_rrsets += 1
            # Fallback if name_index incomplete.
            if not rrsets_for_owner:
                for key in list(live_records.keys()):
                    if key[0] == owner_norm:
                        live_records.pop(key, None)
                        deleted_rrsets += 1
            live_name_index.pop(owner_norm, None)

        for (owner_norm, qtype_int), entry in pending_rrset_updates.items():
            qtype_code = int(qtype_int)
            if entry is None:
                if live_records.pop((owner_norm, qtype_code), None) is not None:
                    deleted_rrsets += 1
                per_name = live_name_index.get(owner_norm, {})
                if isinstance(per_name, dict):
                    per_name.pop(qtype_code, None)
                    if not per_name:
                        live_name_index.pop(owner_norm, None)
                continue

            ttl_val, values_val, sources_val = _clone_record_entry(entry)
            normalized_entry = (ttl_val, values_val, sources_val)
            live_records[(owner_norm, qtype_code)] = normalized_entry
            per_name = live_name_index.setdefault(owner_norm, {})
            per_name[qtype_code] = normalized_entry

        wildcard_set = set(getattr(plugin, "_wildcard_owners", []) or [])
        for owner_norm in touched_owners:
            is_wild_owner = zone_helpers.is_wildcard_domain_pattern(str(owner_norm))
            if not is_wild_owner:
                continue
            if owner_norm in live_name_index and bool(live_name_index.get(owner_norm)):
                wildcard_set.add(owner_norm)
            else:
                wildcard_set.discard(owner_norm)
        plugin._wildcard_owners = zone_helpers.sort_wildcard_patterns(
            list(wildcard_set)
        )
        plugin._name_index = live_name_index
        plugin.records = live_records
        return live_records

    conflict_error = "Concurrent update conflict detected"
    # Initialized before lock; _commit_body assigns the live mapping on success.
    committed_records: Dict[RecordKey, RecordEntry] = {}

    def _commit_body() -> Optional[CommitResult]:
        """Brief: Conflict-check, journal, and apply under optional lock body.

        Inputs:
          - None (closure over plugin snapshot/pending state).

        Outputs:
          - CommitResult on failure, otherwise None and sets committed_records.
        """
        nonlocal journal_entry, committed_records
        current_records = getattr(plugin, "records", None)
        if current_records is None:
            current_records = {}
        current_name_index = getattr(plugin, "_name_index", None)
        if current_name_index is None:
            current_name_index = {}
        current_generation = int(getattr(plugin, "_records_generation", 0) or 0)
        if _has_concurrent_conflict(
            current_records=current_records,
            current_name_index=current_name_index,
            current_generation=current_generation,
        ):
            logger.warning(
                "Concurrent zone commit conflict detected for zone %s; stale commit rejected",
                apex_norm or "<none>",
            )
            return CommitResult(
                ok=False,
                rcode=2,
                error=conflict_error,
                zone_apex=apex_norm,
                serial_before=serial_before,
                actions_applied=normalized_actions,
            )
        if journal_writer is not None and journal_append_kwargs is not None:
            journal_entry = journal_writer.append_entry(**journal_append_kwargs)
            if journal_entry is None:
                return CommitResult(
                    ok=False,
                    rcode=2,
                    error="Journal write failed",
                    zone_apex=apex_norm,
                    serial_before=serial_before,
                    actions_applied=normalized_actions,
                )
        committed_records = _apply_commit_delta()
        plugin._records_generation = current_generation + 1
        if mark_update_managed:
            update_managed_owners = getattr(plugin, "_update_managed_owners", None)
            if isinstance(update_managed_owners, set):
                update_managed_owners.update(update_managed_owner_additions)
        return None

    if lock is None:
        fail = _commit_body()
        if fail is not None:
            return fail
    else:
        with lock:
            fail = _commit_body()
            if fail is not None:
                return fail

    journal_seq: Optional[int] = None
    if journal_writer is not None and journal_entry is not None:
        try:
            journal_seq = int(getattr(journal_entry, "seq", 0) or 0) or None
        except Exception:
            journal_seq = None
        try:
            from .journal import JournalReader, compact_zone_journal, load_manifest

            persistence_cfg = (
                getattr(plugin, "_dns_update_persistence_config", {}) or {}
            )
            max_journal_bytes = int(persistence_cfg.get("max_journal_bytes", 0) or 0)
            max_journal_entries = int(
                persistence_cfg.get("max_journal_entries", 0) or 0
            )
            should_compact = False
            reader = JournalReader(
                zone_apex=apex_norm, base_dir=journal_writer.base_dir
            )
            if max_journal_bytes > 0 and reader.get_size_bytes() > max_journal_bytes:
                should_compact = True
            if not should_compact and max_journal_entries > 0:
                entry_seq = int(getattr(journal_entry, "seq", 0) or 0)
                compacted_seq = 0
                try:
                    manifest = load_manifest(
                        zone_apex=apex_norm,
                        base_dir=journal_writer.base_dir,
                    )
                    compacted_seq = int(getattr(manifest, "last_compacted_seq", 0) or 0)
                except Exception:
                    compacted_seq = 0
                if max(0, entry_seq - compacted_seq) > max_journal_entries:
                    should_compact = True
            if should_compact:
                compacted = compact_zone_journal(
                    zone_apex=apex_norm,
                    base_dir=journal_writer.base_dir,
                    records=committed_records,
                    seq=int(getattr(journal_entry, "seq", 0) or 0),
                )
                if compacted:
                    try:
                        plugin._dns_update_compact_count = int(
                            getattr(plugin, "_dns_update_compact_count", 0) + 1
                        )
                    except Exception:
                        pass
        except Exception:  # pragma: no cover - defensive journal compaction path
            logger.warning(
                "Zone commit journal compaction check failed for zone %s",
                apex_norm,
                exc_info=True,
            )

    serial_after = serial_before
    if bump_soa and apex_norm and action_list:
        try:
            if lock is None:
                serial_after = bump_soa_serial_for_zone(
                    plugin.records, apex_norm, plugin=plugin
                )
            else:
                with lock:
                    serial_after = bump_soa_serial_for_zone(
                        plugin.records, apex_norm, plugin=plugin
                    )
            if serial_after is None:
                serial_after = serial_before
        except Exception:  # pragma: no cover - defensive SOA bump path
            logger.warning(
                "Failed to bump SOA serial after zone commit for zone %s",
                apex_norm,
                exc_info=True,
            )
            serial_after = serial_before

    notify_enabled = send_notify
    if notify_enabled is None:
        dns_update_cfg = getattr(plugin, "_dns_update_config", None)
        replication_cfg: Dict[str, Any] = {}
        if isinstance(dns_update_cfg, dict):
            rcfg = dns_update_cfg.get("replication")
            if isinstance(rcfg, dict):
                replication_cfg = rcfg
        notify_enabled = bool(replication_cfg.get("notify_on_update", True))

    if notify_enabled and apex_norm:
        try:
            from . import notify as notify_mod

            notify_mod.send_notify_for_zones(plugin, [apex_norm])
            try:
                plugin._dns_update_notify_sent = int(
                    getattr(plugin, "_dns_update_notify_sent", 0) + 1
                )
            except Exception:  # pragma: no cover - defensive notify metric path
                pass
        except Exception:
            try:
                plugin._dns_update_notify_failed = int(
                    getattr(plugin, "_dns_update_notify_failed", 0) + 1
                )
            except Exception:
                pass
            logger.warning(
                "Failed sending NOTIFY after zone commit for zone %s",
                apex_norm,
                exc_info=True,
            )

    changed = bool(pending_rrset_updates or pending_name_delete_all)
    return CommitResult(
        ok=True,
        rcode=0,
        error=None,
        zone_apex=apex_norm,
        serial_before=serial_before,
        serial_after=serial_after if isinstance(serial_after, int) else serial_before,
        actions_applied=normalized_actions,
        journal_seq=journal_seq,
        touched_owners=sorted(touched_owners),
        deleted_rrsets=int(deleted_rrsets),
        changed=changed,
    )
