"""Brief: Record loading and processing infrastructure.

Inputs/Outputs:
  - Parse and load records from files, BIND zones, inline config, and AXFR transfers.
"""

from __future__ import annotations

import ipaddress
import logging
import pathlib
from typing import Dict, List, Optional, Set, Tuple

from dnslib import QTYPE, RR

from . import axfr_dnssec as _axfr_dnssec
from . import helpers
from foghorn.servers.transports.axfr import axfr_transfer

logger = logging.getLogger(__name__)


def _clone_records_mapping(
    records: Dict[Tuple[str, int], Tuple[int, List[str]]],  # noqa: ARG001
) -> Dict[Tuple[str, int], Tuple[int, List[str], Set[str]]]:
    """Brief: Deep-clone the (name,qtype)->(ttl,values,sources) mapping.

    Inputs:
      - records: Mapping of (owner, qtype) -> (ttl, [values], {sources}).

    Outputs:
      - New mapping with copied tuples and value lists, preserving sources.
    """
    cloned: Dict[Tuple[str, int], Tuple[int, List[str], Set[str]]] = {}
    for key, entry in (records or {}).items():
        try:
            # Try 3-tuple format first
            ttl, values, sources = entry
        except (ValueError, TypeError):
            try:
                # Fall back to 2-tuple format for backward compatibility
                ttl, values = entry
                sources = set()
            except (ValueError, TypeError):
                ttl = 0
                values = []
                sources = set()

        try:
            ttl_i = int(ttl)
        except Exception:
            ttl_i = 0

        cloned[(str(key[0]), int(key[1]))] = (
            ttl_i,
            list(values or []),
            set(sources or set()),
        )
    return cloned


def _clone_name_index(
    name_index: Dict[str, Dict[int, Tuple[int, List[str]]]],
) -> Dict[str, Dict[int, Tuple[int, List[str], Set[str]]]]:
    """Brief: Deep-clone the per-owner name index.

    Inputs:
      - name_index: owner -> qtype -> (ttl, [values], {sources}).

    Outputs:
      - New nested dict with copied tuples and value lists, preserving sources.
    """
    cloned: Dict[str, Dict[int, Tuple[int, List[str], Set[str]]]] = {}
    for owner, rrsets in (name_index or {}).items():
        inner: Dict[int, Tuple[int, List[str], Set[str]]] = {}
        for qcode, entry in (rrsets or {}).items():
            try:
                # Try 3-tuple format first
                ttl, values, sources = entry
            except (ValueError, TypeError):
                try:
                    # Fall back to 2-tuple format for backward compatibility
                    ttl, values = entry
                    sources = set()
                except (ValueError, TypeError):
                    ttl = 0
                    values = []
                    sources = set()

            try:
                ttl_i = int(ttl)
            except Exception:
                ttl_i = 0

            inner[int(qcode)] = (ttl_i, list(values or []), set(sources or set()))
        cloned[str(owner)] = inner
    return cloned


def _clone_zone_soa(
    zone_soa: Dict[str, Tuple[int, List[str]]],
) -> Dict[str, Tuple[int, List[str], Set[str]]]:
    """Brief: Deep-clone the zone apex SOA mapping.

    Inputs:
      - zone_soa: apex -> (ttl, [soa_values], {sources}).

    Outputs:
      - New mapping with copied tuples and value lists, preserving sources.
    """
    cloned: Dict[str, Tuple[int, List[str], Set[str]]] = {}
    for apex, entry in (zone_soa or {}).items():
        try:
            # Try 3-tuple format first
            ttl, values, sources = entry
        except (ValueError, TypeError):
            try:
                # Fall back to 2-tuple format for backward compatibility
                ttl, values = entry
                sources = set()
            except (ValueError, TypeError):
                ttl = 0
                values = []
                sources = set()

        try:
            ttl_i = int(ttl)
        except Exception:
            ttl_i = 0

        cloned[str(apex)] = (ttl_i, list(values or []), set(sources or set()))
    return cloned


def _merge_rr_value(
    *,
    owner: str,
    qtype_code: int,
    ttl: int,
    value: str,
    source_label: str,
    mapping: Dict[Tuple[str, int], Tuple[int, List[str], Set[str]]],
    name_index: Dict[str, Dict[int, Tuple[int, List[str], Set[str]]]],
    zone_soa: Dict[str, Tuple[int, List[str], Set[str]]],
    soa_code: Optional[int],
    load_mode: str,
    merge_policy: str,
    seen_rrsets: Set[Tuple[str, int]],
    overwritten_by_source: Dict[str, Set[str]],
) -> None:
    """Brief: Merge a single RR value into the aggregated mappings.

    Inputs:
      - owner: Lowercased owner name without trailing dot.
      - qtype_code: Numeric QTYPE code.
      - ttl: TTL for the RR.
      - value: Presentation-format rdata value.
      - source_label: Human-readable source identifier.
      - mapping: Aggregated (owner, qtype) -> (ttl, [values], {sources}) mapping.
      - name_index: Per-owner index mapping owner -> qtype -> (ttl, [values], {sources}).
      - zone_soa: Mapping of zone apex -> (ttl, [soa_values], {sources}).
      - soa_code: Numeric SOA qtype code or None.
      - load_mode: One of 'replace', 'merge', or 'first'.
      - merge_policy: Either 'add' (default) or 'overwrite'.
      - seen_rrsets: Set tracking which RRsets have been seen for this source.
      - overwritten_by_source: Source -> set of owners whose RRsets were overwritten.

    Outputs:
      - None; mutates mapping/name_index/zone_soa in-place and updates
        overwritten_by_source when merge_policy='overwrite'.
    """
    owner_norm = str(owner).rstrip(".").lower()
    key = (owner_norm, int(qtype_code))

    existing = mapping.get(key)

    if merge_policy == "overwrite":
        if existing is not None and key not in seen_rrsets:
            # First time this source touches this RRset: replace it.
            values_list: List[str] = []
            sources_set: Set[str] = {source_label}
            mapping[key] = (int(ttl), values_list, sources_set)
            per_name = name_index.setdefault(owner_norm, {})
            per_name[int(qtype_code)] = (int(ttl), values_list, sources_set)
            overwritten_by_source.setdefault(source_label, set()).add(owner_norm)
            seen_rrsets.add(key)
            existing = mapping.get(key)
        elif existing is None:
            values_list = []
            sources_set = {source_label}
            mapping[key] = (int(ttl), values_list, sources_set)
            per_name = name_index.setdefault(owner_norm, {})
            per_name[int(qtype_code)] = (int(ttl), values_list, sources_set)
            seen_rrsets.add(key)
            existing = mapping.get(key)

    if existing is None:
        stored_ttl = int(ttl)
        values: List[str] = []
        sources_set: Set[str] = {source_label}
    else:
        try:
            stored_ttl, values, sources_set = existing
        except (ValueError, TypeError):
            # Legacy 2-tuple format; upgrade to 3-tuple
            stored_ttl, values = existing
            sources_set = {source_label}

    if value not in values:
        values.append(value)
    sources_set.add(source_label)

    mapping[key] = (stored_ttl, values, sources_set)
    per_name = name_index.setdefault(owner_norm, {})
    per_name[int(qtype_code)] = (stored_ttl, values, sources_set)

    # Track SOA records as zone apexes for authoritative zones.
    if soa_code is not None and int(qtype_code) == int(soa_code):
        # With overwrite policy, allow later sources to replace the apex SOA.
        if merge_policy == "overwrite" or owner_norm not in zone_soa:
            zone_soa[owner_norm] = (stored_ttl, values, sources_set)


def process_record_line(
    plugin: object,
    raw_line: str,
    source_label: str,
    lineno: int,
    mapping: Dict[Tuple[str, int], Tuple[int, List[str], Set[str]]],
    name_index: Dict[str, Dict[int, Tuple[int, List[str], Set[str]]]],
    zone_soa: Dict[str, Tuple[int, List[str], Set[str]]],
    soa_code: Optional[int],
    load_mode: str,
    merge_policy: str,
    seen_rrsets: Set[Tuple[str, int]],
    overwritten_by_source: Dict[str, Set[str]],
) -> None:
    """Brief: Parse a single record line and merge it into mappings.

    Inputs:
      - plugin: ZoneRecords plugin instance.
      - raw_line: Original line text including any comments.
      - source_label: Human-readable source identifier (file path or inline config label).
      - lineno: 1-based line number within the source.
      - mapping: Aggregated (domain, qtype) -> (ttl, [values], {sources}) mapping.
      - name_index: Per-name index mapping domain -> qtype -> (ttl, [values], {sources}).
      - zone_soa: Mapping of zone apex -> (ttl, [soa_values], {sources}).
      - soa_code: Numeric QTYPE code for SOA, or None when unavailable.
      - load_mode: One of 'replace', 'merge', or 'first'.
      - merge_policy: Either 'add' or 'overwrite'.
      - seen_rrsets: Per-source set tracking which (domain,qtype) RRsets have been seen.
      - overwritten_by_source: Mapping updated when merge_policy='overwrite'.

    Outputs:
      - None; updates mapping, name_index, and zone_soa in-place.
    """
    # Remove inline comments and surrounding whitespace
    line = raw_line.split("#", 1)[0].strip()
    if not line:
        return

    parts = [p.strip() for p in line.split("|")]
    if len(parts) != 4:
        raise ValueError(
            f"Source {source_label} malformed line {lineno}: "
            f"expected <domain>|<qtype>|<ttl>|<value>, got {raw_line!r}"
        )

    domain_raw, qtype_raw, ttl_raw, value_raw = parts
    if not domain_raw or not qtype_raw or not ttl_raw or not value_raw:
        raise ValueError(
            f"Source {source_label} malformed line {lineno}: "
            f"empty field in {raw_line!r}"
        )

    domain = domain_raw.rstrip(".").lower()

    # Parse qtype as number or mnemonic (e.g., "A", "AAAA").
    qtype_code: Optional[int]
    if qtype_raw.isdigit():
        qtype_code = int(qtype_raw)
    else:
        name = qtype_raw.upper()
        qtype_code = None
        try:
            attr_val = getattr(QTYPE, name)
        except Exception:
            attr_val = None
        if isinstance(attr_val, int):
            qtype_code = int(attr_val)
        else:
            try:
                qtype_val = QTYPE.get(name, None)
            except Exception:
                qtype_val = None
            if isinstance(qtype_val, int):
                qtype_code = int(qtype_val)

    if qtype_code is None:
        raise ValueError(
            f"Source {source_label} malformed line {lineno}: "
            f"unknown qtype {qtype_raw!r}"
        )

    try:
        ttl = int(ttl_raw)
    except ValueError as exc:
        raise ValueError(
            f"Source {source_label} malformed line {lineno}: "
            f"invalid ttl {ttl_raw!r}"
        ) from exc
    if ttl < 0:
        raise ValueError(
            f"Source {source_label} malformed line {lineno}: " f"negative ttl {ttl}"
        )

    value = value_raw

    _merge_rr_value(
        owner=domain,
        qtype_code=int(qtype_code),
        ttl=int(ttl),
        value=value,
        source_label=source_label,
        mapping=mapping,
        name_index=name_index,
        zone_soa=zone_soa,
        soa_code=soa_code,
        load_mode=str(load_mode or "merge").lower(),
        merge_policy=str(merge_policy or "add").lower(),
        seen_rrsets=seen_rrsets,
        overwritten_by_source=overwritten_by_source,
    )


def _normalize_bind_zone_entry(
    entry: object,
) -> Optional[Dict[str, object]]:
    """Brief: Normalize a bind_paths entry into a mapping with path/origin/ttl.

    Inputs:
      - entry: A bind_paths list element which may be a string path, a mapping
        with a 'path' key, or a typed object with a .path attribute.

    Outputs:
      - dict with keys: 'path' (str), 'origin' (Optional[str]), 'ttl' (Optional[int]),
        or None if the entry is invalid.
    """
    if isinstance(entry, dict):
        path_val = entry.get("path")
        origin_val = entry.get("origin")
        ttl_val = entry.get("ttl")
    elif hasattr(entry, "path"):
        path_val = getattr(entry, "path", None)
        origin_val = getattr(entry, "origin", None)
        ttl_val = getattr(entry, "ttl", None)
    else:
        path_val = entry
        origin_val = None
        ttl_val = None

    if path_val is None:
        return None

    try:
        path_text = str(path_val)
    except Exception:
        return None

    origin_text: Optional[str]
    if origin_val is None:
        origin_text = None
    else:
        try:
            origin_text = str(origin_val).strip() or None
        except Exception:
            origin_text = None

    ttl_int: Optional[int]
    if ttl_val is None:
        ttl_int = None
    else:
        try:
            ttl_int = int(ttl_val)
        except (TypeError, ValueError):
            ttl_int = None

    return {"path": path_text, "origin": origin_text, "ttl": ttl_int}


def _strip_bind_directives_when_overridden(
    *,
    text: str,
    zone_path: pathlib.Path,
    origin_override: Optional[str],
    ttl_override: Optional[int],
) -> str:
    """Brief: Remove $ORIGIN/$TTL directives when config overrides are provided.

    Inputs:
      - text: Full zonefile content.
      - zone_path: Zonefile path used for logging.
      - origin_override: Config override for zone origin.
      - ttl_override: Config override for default TTL.

    Outputs:
      - Zonefile content with overridden directives removed.

    Notes:
      - When an override is provided and the corresponding directive exists in
        the file, a warning is logged and the config value is used.
      - This only affects $ORIGIN and $TTL directives; explicit per-record TTLs
        remain unchanged.
    """
    strip_origin = origin_override is not None
    strip_ttl = ttl_override is not None
    if not strip_origin and not strip_ttl:
        return text

    found_origin = False
    found_ttl = False
    kept: List[str] = []

    for raw_line in text.splitlines(keepends=True):
        line = raw_line.lstrip()
        # Strip BIND-style comments (";"), and also tolerate "#" comments.
        content = line
        for sep in (";", "#"):
            content = content.split(sep, 1)[0]
        content = content.strip()

        upper = content.upper()
        if strip_origin and upper.startswith("$ORIGIN"):
            found_origin = True
            continue
        if strip_ttl and upper.startswith("$TTL"):
            found_ttl = True
            continue

        kept.append(raw_line)

    if strip_origin and found_origin:
        logger.warning(
            "ZoneRecords: BIND zone file %s contains $ORIGIN; overriding with config origin=%r",
            zone_path,
            origin_override,
        )
    if strip_ttl and found_ttl:
        logger.warning(
            "ZoneRecords: BIND zone file %s contains $TTL; overriding with config ttl=%r",
            zone_path,
            ttl_override,
        )

    return "".join(kept)


def load_records(plugin: object) -> None:
    """Brief: Read custom records files and build lookup structures.

    Inputs:
      - plugin: ZoneRecords plugin instance.

    Outputs:
      - None (populates self.records, self._name_index, self._zone_soa).
    """
    cfg = getattr(plugin, "config", {}) if hasattr(plugin, "config") else {}

    try:
        load_mode = str(cfg.get("load_mode", "merge") or "merge").lower()
    except Exception:  # pragma: no cover - defensive
        load_mode = "merge"

    try:
        merge_policy = str(cfg.get("merge_policy", "add") or "add").lower()
    except Exception:  # pragma: no cover - defensive
        merge_policy = "add"

    if load_mode not in {"replace", "merge", "first"}:
        logger.warning(
            "ZoneRecords: invalid load_mode=%r; expected 'replace', 'merge', or 'first'",
            load_mode,
        )
        load_mode = "merge"

    if merge_policy not in {"add", "overwrite"}:
        logger.warning(
            "ZoneRecords: invalid merge_policy=%r; expected 'add' or 'overwrite'",
            merge_policy,
        )
        merge_policy = "add"

    overwritten_by_source: Dict[str, Set[str]] = {}

    lock = getattr(plugin, "_records_lock", None)

    if load_mode == "merge":
        if lock is None:
            base_records = dict(getattr(plugin, "records", {}) or {})
            base_name_index = dict(getattr(plugin, "_name_index", {}) or {})
            base_zone_soa = dict(getattr(plugin, "_zone_soa", {}) or {})
            base_dnssec_axfr = (
                getattr(plugin, "_dnssec_classified_axfr", set()) or set()
            )
        else:
            with lock:
                base_records = dict(getattr(plugin, "records", {}) or {})
                base_name_index = dict(getattr(plugin, "_name_index", {}) or {})
                base_zone_soa = dict(getattr(plugin, "_zone_soa", {}) or {})
                base_dnssec_axfr = (
                    getattr(plugin, "_dnssec_classified_axfr", set()) or set()
                )

        mapping = _clone_records_mapping(base_records)
        name_index = _clone_name_index(
            base_name_index if isinstance(base_name_index, dict) else {}
        )
        zone_soa = _clone_zone_soa(base_zone_soa)
        dnssec_classified_axfr: set[str] = {
            str(x).rstrip(".").lower() for x in set(base_dnssec_axfr)
        }
    else:
        mapping = {}
        name_index = {}
        zone_soa = {}
        dnssec_classified_axfr = set()

    axfr_zones = getattr(plugin, "_axfr_zones", None) or []
    do_axfr = bool(axfr_zones) and not getattr(plugin, "_axfr_loaded_once", False)
    zone_metadata = getattr(plugin, "_axfr_zone_metadata", None) or {}

    # Get SOA type code once at start
    try:
        raw = getattr(QTYPE, "SOA", None)
    except Exception:
        raw = None
    if raw is None:
        try:
            raw = QTYPE.get("SOA", None)
        except Exception:
            raw = None
    try:
        soa_code: Optional[int] = int(raw) if raw is not None else None
    except Exception:
        soa_code = None

    # load_mode='first': Use the first configured source group and ignore
    # the others (no cross-group overlays).
    # This uses the documented precedence order: inline > axfr > file_paths > bind_paths
    inline_records = getattr(plugin, "_inline_records", None) or []
    axfr_zones = getattr(plugin, "_axfr_zones", None) or []
    file_paths = getattr(plugin, "file_paths", [])
    bind_paths = getattr(plugin, "bind_paths", None) or []

    if load_mode == "first":
        if inline_records:
            selected = "inline"
        elif do_axfr:
            selected = "axfr"
        elif file_paths:
            selected = "files"
        elif bind_paths:
            selected = "bind"
        else:
            selected = "none"
    else:
        selected = "all"

    # Merge inline records (highest priority)
    if selected in {"all", "inline"}:
        seen_rrsets = set()
        for lineno, raw_line in enumerate(inline_records, start=1):
            try:
                text = str(raw_line)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "Skipping non-string inline record at index %d: %r (%s)",
                    lineno,
                    raw_line,
                    exc,
                )
                continue
            process_record_line(
                plugin,
                text,
                "inline-config-records",
                lineno,
                mapping,
                name_index,
                zone_soa,
                soa_code,
                load_mode,
                merge_policy,
                seen_rrsets,
                overwritten_by_source,
            )

    # Overlay AXFR-backed zones
    if selected in {"all", "axfr"} and do_axfr:
        _axfr_dnssec.overlay_axfr_zones(
            mapping,
            name_index,
            zone_soa,
            axfr_zones,
            soa_code,
            dnssec_classified_axfr,
            axfr_fn=axfr_transfer,
            zone_metadata=zone_metadata,
            force_reload=not getattr(plugin, "_axfr_loaded_once", False),
        )
        plugin._axfr_loaded_once = True

    # Load custom pipe-delimited files
    if selected in {"all", "files"}:
        for fp in file_paths:
            logger.debug("reading recordfile: %s", fp)
            records_path = pathlib.Path(fp)
            seen_rrsets: Set[Tuple[str, int]] = set()
            with records_path.open("r", encoding="utf-8") as f:
                for lineno, raw_line in enumerate(f, start=1):
                    process_record_line(
                        plugin,
                        raw_line,
                        str(records_path),
                        lineno,
                        mapping,
                        name_index,
                        zone_soa,
                        soa_code,
                        load_mode,
                        merge_policy,
                        seen_rrsets,
                        overwritten_by_source,
                    )

    # Load RFC-1035 BIND-style zone files
    if selected in {"all", "bind"}:
        for raw_entry in bind_paths:
            entry = _normalize_bind_zone_entry(raw_entry)
            if not entry:
                logger.warning(
                    "ZoneRecords: skipping invalid bind_paths entry %r", raw_entry
                )
                continue

            fp = entry.get("path")
            origin_override = entry.get("origin")
            ttl_override = entry.get("ttl")

            logger.debug("reading bind zonefile: %s", fp)
            zone_path = pathlib.Path(str(fp))
            try:
                text = zone_path.read_text(encoding="utf-8")
            except Exception as exc:
                raise ValueError(
                    f"Failed to read BIND zone file {zone_path}: {exc}"
                ) from exc

            # When origin/ttl are specified in config, strip any in-file
            # $ORIGIN/$TTL directives so config takes precedence.
            text = _strip_bind_directives_when_overridden(
                text=text,
                zone_path=zone_path,
                origin_override=(
                    str(origin_override) if origin_override is not None else None
                ),
                ttl_override=int(ttl_override) if ttl_override is not None else None,
            )

            origin_arg = str(origin_override) if origin_override is not None else ""
            ttl_arg = int(ttl_override) if ttl_override is not None else 0

            try:
                rrs = RR.fromZone(text, origin=origin_arg, ttl=ttl_arg)
            except Exception as exc:
                raise ValueError(
                    f"Failed to parse BIND zone file {zone_path}: {exc}"
                ) from exc

            seen_rrsets = set()
            for rr in rrs:
                try:
                    owner = str(rr.rname).rstrip(".").lower()
                    qtype_code = int(rr.rtype)
                    ttl = int(rr.ttl)
                    value = str(rr.rdata)
                except Exception as exc:  # pragma: no cover - defensive parsing
                    logger.warning(
                        "Skipping RR %r from BIND zone %s due to parse error: %s",
                        rr,
                        zone_path,
                        exc,
                    )
                    continue

                _merge_rr_value(
                    owner=owner,
                    qtype_code=int(qtype_code),
                    ttl=int(ttl),
                    value=str(value),
                    source_label=str(zone_path),
                    mapping=mapping,
                    name_index=name_index,
                    zone_soa=zone_soa,
                    soa_code=soa_code,
                    load_mode=str(load_mode or "merge").lower(),
                    merge_policy=str(merge_policy or "add").lower(),
                    seen_rrsets=seen_rrsets,
                    overwritten_by_source=overwritten_by_source,
                )

    # Synthesize SOA if needed
    if not zone_soa:
        try:
            candidate_names: List[str] = []
            for (owner_name, qcode), (_ttl_val, _vals, _sources) in mapping.items():
                if soa_code is not None and int(qcode) == int(soa_code):
                    continue
                candidate_names.append(str(owner_name))

            if candidate_names:
                label_lists = [
                    str(n).rstrip(".").lower().split(".") for n in candidate_names
                ]
                common_suffix_rev: List[str] = list(reversed(label_lists[0]))
                for labels in label_lists[1:]:
                    rev = list(reversed(labels))
                    i = 0
                    while (
                        i < len(common_suffix_rev)
                        and i < len(rev)
                        and common_suffix_rev[i] == rev[i]
                    ):
                        i += 1
                    common_suffix_rev = common_suffix_rev[:i]
                    if not common_suffix_rev:
                        break

                accept_suffix = False
                if len(common_suffix_rev) >= 2:
                    accept_suffix = True
                elif len(common_suffix_rev) == 1:
                    try:
                        cfg = getattr(plugin, "config", {})  # type: ignore[union-attr]
                        dnssec_cfg = (
                            cfg.get("dnssec_signing") if isinstance(cfg, dict) else None
                        )
                        cfg_tld = None
                        if isinstance(dnssec_cfg, dict):
                            cfg_tld = dnssec_cfg.get("use_tld")
                    except Exception:  # pragma: no cover - defensive
                        cfg_tld = None
                    if cfg_tld:
                        suffix_label = common_suffix_rev[0].lower()
                        if suffix_label == str(cfg_tld).rstrip(".").lower():
                            accept_suffix = True

                if accept_suffix:
                    inferred_apex = ".".join(reversed(common_suffix_rev))
                    if inferred_apex not in zone_soa:
                        try:
                            default_ttl = int(plugin.config.get("ttl", 300))  # type: ignore[union-attr]
                        except Exception:  # pragma: no cover - defensive
                            default_ttl = 300
                        soa_rdata = (
                            f"ns1.{inferred_apex}. hostmaster.{inferred_apex}. "
                            "1 3600 600 604800 300"
                        )
                        synthetic_line = (
                            f"{inferred_apex}|SOA|{default_ttl}|{soa_rdata}"
                        )
                        auto_seen_rrsets: Set[Tuple[str, int]] = set()
                        process_record_line(
                            plugin,
                            synthetic_line,
                            "auto-soa",
                            0,
                            mapping,
                            name_index,
                            zone_soa,
                            soa_code,
                            load_mode,
                            merge_policy,
                            auto_seen_rrsets,
                            overwritten_by_source,
                        )
        except Exception:  # pragma: no cover - defensive logging only
            logger.warning(
                "ZoneRecords: failed to synthesize SOA for inferred zone apex",
                exc_info=True,
            )

    # Auto-generate reverse PTR records
    try:
        try:
            a_code = int(QTYPE.A)
        except Exception:  # pragma: no cover - defensive
            a_code = 1
        try:
            aaaa_code = int(QTYPE.AAAA)
        except Exception:  # pragma: no cover - defensive
            aaaa_code = 28
        try:
            ptr_code = int(QTYPE.PTR)
        except Exception:  # pragma: no cover - defensive
            ptr_code = 12

        for owner_name, rrsets in list(name_index.items()):
            owner_norm = str(owner_name).rstrip(".").lower()

            for rr_qtype in (a_code, aaaa_code):
                if rr_qtype not in rrsets:
                    continue
                try:
                    ttl_val, vals, _sources = rrsets[rr_qtype]
                except (ValueError, TypeError):
                    # Legacy 2-tuple format
                    ttl_val, vals = rrsets[rr_qtype]
                for v in list(vals):
                    try:
                        ip_obj = ipaddress.ip_address(str(v))
                    except ValueError:
                        continue

                    if ip_obj.version == 4 and rr_qtype != a_code:
                        continue
                    if ip_obj.version == 6 and rr_qtype != aaaa_code:
                        continue

                    reverse_owner = ip_obj.reverse_pointer.rstrip(".").lower()
                    ptr_target = owner_norm + "."
                    key_ptr = (reverse_owner, int(ptr_code))
                    existing_ptr = mapping.get(key_ptr)
                    if existing_ptr is None:
                        stored_ttl = int(ttl_val)
                        ptr_vals: List[str] = []
                        ptr_sources: Set[str] = set(["ptr-auto-" + owner_norm])
                    else:
                        try:
                            stored_ttl, ptr_vals, ptr_sources = existing_ptr
                        except (ValueError, TypeError):
                            # Legacy 2-tuple format
                            stored_ttl, ptr_vals = existing_ptr
                            ptr_sources = set(["ptr-auto-" + owner_norm])

                    if ptr_target not in ptr_vals:
                        ptr_vals.append(ptr_target)
                    ptr_sources.add("ptr-auto-" + owner_norm)

                    mapping[key_ptr] = (stored_ttl, ptr_vals, ptr_sources)
                    per_name_ptr = name_index.setdefault(reverse_owner, {})
                    per_name_ptr[int(ptr_code)] = (stored_ttl, ptr_vals, ptr_sources)
    except Exception:  # pragma: no cover - defensive logging only
        logger.warning(
            "ZoneRecords: failed to auto-generate PTR records from A/AAAA",
            exc_info=True,
        )

    # Post-process DNSSEC
    dnssec_cfg_raw = (
        plugin.config.get("dnssec_signing") if hasattr(plugin, "config") else None
    )

    mapping_by_qtype = _axfr_dnssec.dnssec_postprocess_zones(
        mapping,
        name_index,
        zone_soa,
        dnssec_classified_axfr,
        dnssec_cfg_raw if isinstance(dnssec_cfg_raw, dict) else dnssec_cfg_raw,
    )

    # Pre-compute wildcard owner patterns for query-time matching.
    wildcard_owners = helpers.sort_wildcard_patterns(
        [
            owner
            for owner in (name_index or {}).keys()
            if helpers.is_wildcard_domain_pattern(str(owner))
        ]
    )

    if overwritten_by_source:
        parts: List[str] = []
        for src in sorted(overwritten_by_source.keys()):
            parts.append(f"{src}={len(overwritten_by_source.get(src, set()) or set())}")
        logger.warning(
            "ZoneRecords: overwritten RRsets during load (merge_policy=%s): %s",
            merge_policy,
            "; ".join(parts),
        )

    lock = getattr(plugin, "_records_lock", None)

    if lock is None:
        plugin.records = mapping
        plugin._name_index = name_index
        plugin._zone_soa = zone_soa
        plugin.mapping = mapping_by_qtype
        plugin._wildcard_owners = wildcard_owners
        plugin._dnssec_classified_axfr = set(dnssec_classified_axfr)
    else:
        with lock:
            plugin.records = mapping
            plugin._name_index = name_index
            plugin._zone_soa = zone_soa
            plugin.mapping = mapping_by_qtype
            plugin._wildcard_owners = wildcard_owners
            plugin._dnssec_classified_axfr = set(dnssec_classified_axfr)
