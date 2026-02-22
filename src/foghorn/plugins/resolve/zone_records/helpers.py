"""Brief: Helper functions for zone records management.

Inputs/Outputs:
  - Zone lookup, state snapshots, change detection, config normalization.
"""

from __future__ import annotations

import logging
import os
import pathlib
import re
from typing import Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)


def normalize_paths(
    file_paths: Optional[Iterable[str]], legacy: Optional[str]
) -> List[str]:
    """Brief: Coerce provided file path inputs into an ordered, de-duplicated list.

    Inputs:
      - file_paths: iterable of file path strings (may be None)
      - legacy: single legacy file path string (may be None)

    Outputs:
      - list[str]: Non-empty list of unique paths (order preserved).
      - Raises ValueError when neither file_paths nor legacy are provided.
        If both file_paths and legacy file_path are given, the legacy path is
        included in the returned list.

    Example:
      normalize_paths(["/a", "/b"], None) -> ["/a", "/b"]
      normalize_paths(["/a", "/b"], "/a") -> ["/a", "/b"]
      normalize_paths(None, "/a") -> ["/a"]
    """
    paths: List[str] = []
    if file_paths:
        for p in file_paths:
            paths.append(os.path.expanduser(str(p)))
    if legacy:
        paths.append(os.path.expanduser(str(legacy)))
    if not paths:
        raise ValueError("No paths given")
    # De-duplicate while preserving order
    paths = list(dict.fromkeys(paths))
    return paths


def normalize_zone_suffixes(raw: object) -> List[str]:
    """Brief: Normalize a zone suffix list for NXDOMAIN enforcement.

    Inputs:
      - raw: Expected to be either a list of strings, a single string, or None.

    Outputs:
      - list[str]: Lowercased zone names without trailing dots, de-duplicated,
        sorted longest-first so that the most-specific suffix matches first.

    Notes:
      - This is used by the ZoneRecords `nxdomain_zones` option.
      - Empty strings and non-string entries are ignored.
    """
    if raw is None:
        return []

    items = raw
    if isinstance(items, str):
        items = [items]

    if not isinstance(items, list):
        logger.warning(
            "ZoneRecords nxdomain_zones ignored: expected list/str, got %r", type(items)
        )
        return []

    zones: List[str] = []
    for idx, entry in enumerate(items):
        if entry is None:
            continue
        try:
            text = str(entry).strip()
        except Exception:
            logger.warning(
                "ZoneRecords nxdomain_zones[%d] ignored: could not coerce %r to str",
                idx,
                entry,
            )
            continue
        if not text:
            continue
        zones.append(text.rstrip(".").lower())

    # De-duplicate while preserving order.
    zones = list(dict.fromkeys(zones))
    zones.sort(key=len, reverse=True)
    return zones


def normalize_bind_paths(raw: object) -> List[Dict[str, object]]:
    """Brief: Normalize bind_paths entries into a list of per-file config mappings.

    Inputs:
      - raw: Value expected to be one of:
        - list[str] of zonefile paths
        - list[dict] with at least a 'path' key, plus optional 'origin' and 'ttl'
        - a single str/dict/object as shorthand for a 1-item list

    Outputs:
      - list[dict]: Each entry contains:
          - 'path': expanded filesystem path string
          - 'origin': optional origin override string
          - 'ttl': optional integer TTL override

    Notes:
      - This function is intentionally permissive because ZoneRecords can be
        instantiated directly in tests without Pydantic validation.
    """
    entries: List[Dict[str, object]] = []

    if raw is None:
        return entries

    items = raw
    if (
        isinstance(items, (str, pathlib.Path))
        or isinstance(items, dict)
        or hasattr(items, "path")
    ):
        items = [items]

    if not isinstance(items, list):
        logger.warning(
            "ZoneRecords bind_paths ignored: expected list, got %r", type(items)
        )
        return entries

    for idx, entry in enumerate(items):
        path_val: Optional[str]
        origin_val: Optional[str]
        ttl_val: object

        if isinstance(entry, (str, pathlib.Path)):
            path_val = str(entry)
            origin_val = None
            ttl_val = None
        elif hasattr(entry, "path"):
            try:
                path_val = str(getattr(entry, "path"))
            except Exception:
                path_val = None
            try:
                origin_val = getattr(entry, "origin", None)
            except Exception:
                origin_val = None
            ttl_val = getattr(entry, "ttl", None)
        elif isinstance(entry, dict):
            raw_path = entry.get("path")
            path_val = str(raw_path) if raw_path is not None else None
            origin_val = entry.get("origin")  # type: ignore[assignment]
            ttl_val = entry.get("ttl")
        else:
            logger.warning(
                "ZoneRecords bind_paths[%d] ignored: expected str/mapping/object with .path, got %r",
                idx,
                type(entry),
            )
            continue

        if not path_val:
            logger.warning("ZoneRecords bind_paths[%d] ignored: missing 'path'", idx)
            continue

        expanded_path = os.path.expanduser(str(path_val))

        origin_norm: Optional[str]
        if origin_val is None:
            origin_norm = None
        else:
            origin_text = str(origin_val).strip()
            origin_norm = origin_text if origin_text else None

        ttl_norm: Optional[int]
        if ttl_val is None:
            ttl_norm = None
        else:
            try:
                ttl_norm = int(ttl_val)
            except (TypeError, ValueError):
                logger.warning(
                    "ZoneRecords bind_paths[%d] ignored: invalid ttl %r", idx, ttl_val
                )
                continue
            if ttl_norm < 0:
                logger.warning(
                    "ZoneRecords bind_paths[%d] ignored: negative ttl %r", idx, ttl_norm
                )
                continue

        entries.append({"path": expanded_path, "origin": origin_norm, "ttl": ttl_norm})

    return entries


def normalize_axfr_notify_targets(raw: object) -> List[Dict[str, object]]:
    """Brief: Normalize axfr_notify targets into upstream-like mappings.

    Inputs:
      - raw: Value expected to be a list of mappings or objects with at least a
        "host" key.

    Outputs:
      - list[dict]: Each entry contains:
          - "host": target hostname or IP.
          - "port": integer port (default 53).
          - "timeout_ms": integer timeout in milliseconds (default 2000).
          - "transport": "tcp" (default) or "dot" for DNS-over-TLS.
          - "server_name": optional TLS SNI name for DoT.
          - "verify": boolean TLS verification flag for DoT.
          - "ca_file": optional CA bundle path for DoT.
    """
    targets: List[Dict[str, object]] = []
    if raw is None:
        return targets

    items = raw
    # Allow a single mapping/typed object as shorthand for a list.
    if isinstance(items, dict) or hasattr(items, "host"):
        items = [items]

    if not isinstance(items, list):
        logger.warning(
            "ZoneRecords axfr_notify ignored: expected list, got %r", type(items)
        )
        return targets

    for idx, entry in enumerate(items):
        host: Optional[str]
        port_val: object
        timeout_val: object
        transport_val: object
        server_name_val: Optional[str]
        verify_val: object
        ca_file_val: object

        # Support both typed AxfrUpstreamConfig and plain dicts.
        if hasattr(entry, "host") and hasattr(entry, "port"):
            try:
                host = str(getattr(entry, "host"))
            except Exception:
                host = None
            port_val = getattr(entry, "port", 53)
            timeout_val = getattr(entry, "timeout_ms", 2000)
            transport_val = getattr(entry, "transport", "tcp")
            server_name_val = getattr(entry, "server_name", None)
            verify_val = getattr(entry, "verify", True)
            ca_file_val = getattr(entry, "ca_file", None)
        elif isinstance(entry, dict):
            host = entry.get("host")  # type: ignore[assignment]
            port_val = entry.get("port", 53)
            timeout_val = entry.get("timeout_ms", 2000)
            transport_val = entry.get("transport", "tcp")
            server_name_val = entry.get("server_name")  # type: ignore[assignment]
            verify_val = entry.get("verify", True)
            ca_file_val = entry.get("ca_file")  # type: ignore[assignment]
        else:
            logger.warning(
                "ZoneRecords axfr_notify[%d] ignored: expected mapping or AxfrUpstreamConfig, got %r",
                idx,
                type(entry),
            )
            continue

        if not host:
            logger.warning("ZoneRecords axfr_notify[%d] ignored: missing 'host'", idx)
            continue

        transport = str(transport_val or "tcp").lower()
        if transport not in {"tcp", "dot"}:
            logger.warning(
                "ZoneRecords axfr_notify[%d] ignored: unsupported transport %r",
                idx,
                transport,
            )
            continue

        try:
            port_i = int(port_val)
            timeout_i = int(timeout_val)
        except (TypeError, ValueError):
            logger.warning(
                "ZoneRecords axfr_notify[%d] ignored: invalid port/timeout %r/%r",
                idx,
                port_val,
                timeout_val,
            )
            continue

        targets.append(
            {
                "host": str(host),
                "port": port_i,
                "timeout_ms": timeout_i,
                "transport": transport,
                "server_name": (
                    str(server_name_val) if server_name_val is not None else None
                ),
                "verify": bool(verify_val),
                "ca_file": (str(ca_file_val) if ca_file_val is not None else None),
            }
        )

    return targets


def normalize_axfr_config(raw: object) -> List[Dict[str, object]]:
    """Brief: Normalize raw axfr_zones config into a list of zones.

    Inputs:
      - raw: Value expected to be a list of mappings, each with a "zone" key
        and an "upstreams" key. For backward compatibility a legacy "masters"
        key is also accepted and treated as "upstreams".

    Outputs:
      - list[dict]: Each entry contains:
          - "zone": lowercased apex without trailing dot.
          - "allow_no_dnssec": boolean (default True).
          - "upstreams": list of mappings with host/port/timeout_ms/transport/etc.
          - "poll_interval_seconds": optional polling interval (when > 0).
    """
    if raw is None:
        return []

    zones: List[Dict[str, object]] = []

    if not isinstance(raw, list):
        logger.warning(
            "ZoneRecords axfr_zones ignored: expected list, got %r", type(raw)
        )
        return zones

    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            logger.warning(
                "ZoneRecords axfr_zones[%d] ignored: expected mapping, got %r",
                idx,
                type(entry),
            )
            continue

        zone_val = entry.get("zone")
        # Prefer the new "upstreams" key, but continue to accept legacy
        # "masters" for backwards compatibility with existing configs.
        masters_val = entry.get("upstreams")
        if masters_val is None and "masters" in entry:
            masters_val = entry.get("masters")

        # Optional per-zone polling interval (seconds).
        poll_interval_val = entry.get("poll_interval_seconds")
        poll_interval: Optional[int]
        try:
            poll_interval = (
                int(poll_interval_val) if poll_interval_val is not None else None
            )
        except (TypeError, ValueError):
            poll_interval = None
        if poll_interval is not None and poll_interval <= 0:
            poll_interval = None

        zone_text = str(zone_val).rstrip(".").lower() if zone_val is not None else ""
        if not zone_text:
            logger.warning(
                "ZoneRecords axfr_zones[%d] ignored: missing or empty 'zone'", idx
            )
            continue

        upstreams: List[Dict[str, object]] = []
        if isinstance(masters_val, dict):
            masters_val = [masters_val]
        if isinstance(masters_val, list):
            for midx, m in enumerate(masters_val):
                if not isinstance(m, dict):
                    logger.warning(
                        "ZoneRecords axfr_zones[%d].upstreams[%d] ignored: expected mapping, got %r",
                        idx,
                        midx,
                        type(m),
                    )
                    continue
                host = m.get("host")
                if not host:
                    logger.warning(
                        "ZoneRecords axfr_zones[%d].upstreams[%d] ignored: missing 'host'",
                        idx,
                        midx,
                    )
                    continue
                port = m.get("port", 53)
                timeout_ms = m.get("timeout_ms", 5000)
                transport = str(m.get("transport", "tcp")).lower()
                if transport not in {"tcp", "dot"}:
                    logger.warning(
                        "ZoneRecords axfr_zones[%d].upstreams[%d] ignored: unsupported transport %r",
                        idx,
                        midx,
                        transport,
                    )
                    continue
                server_name = m.get("server_name")
                verify_flag = m.get("verify", True)
                ca_file = m.get("ca_file")
                try:
                    port_i = int(port)
                    timeout_i = int(timeout_ms)
                except (TypeError, ValueError):
                    logger.warning(
                        "ZoneRecords axfr_zones[%d].upstreams[%d] ignored: invalid port/timeout %r/%r",
                        idx,
                        midx,
                        port,
                        timeout_ms,
                    )
                    continue
                upstreams.append(
                    {
                        "host": str(host),
                        "port": port_i,
                        "timeout_ms": timeout_i,
                        "transport": transport,
                        "server_name": (
                            str(server_name) if server_name is not None else None
                        ),
                        "verify": bool(verify_flag),
                        "ca_file": str(ca_file) if ca_file is not None else None,
                    }
                )

        if not upstreams:
            logger.warning(
                "ZoneRecords axfr_zones[%d] for %s ignored: no usable upstreams",
                idx,
                zone_text,
            )
            continue

        allow_no_dnssec_val = entry.get("allow_no_dnssec")
        if allow_no_dnssec_val is None:
            allow_no_dnssec = True
        else:
            allow_no_dnssec = bool(allow_no_dnssec_val)

        zone_cfg: Dict[str, object] = {
            "zone": zone_text,
            "upstreams": upstreams,
            "allow_no_dnssec": allow_no_dnssec,
        }
        if poll_interval is not None:
            zone_cfg["poll_interval_seconds"] = int(poll_interval)

        zones.append(zone_cfg)

    return zones


def find_zone_for_name(
    name: str, zone_soa: Dict[str, Tuple[int, List[str]]]
) -> Optional[str]:
    """Brief: Find the longest-matching authoritative zone apex for a name.

    Inputs:
      - name: Lowercased domain name without trailing dot.
      - zone_soa: Mapping of zone apex -> (ttl, [soa_values]).

    Outputs:
      - The matching zone apex string, or None when no authoritative zone
        covers this name.

    Example:
      Given zones {"example.com", "sub.example.com"}:
        find_zone_for_name("www.sub.example.com", ...) -> "sub.example.com"
        find_zone_for_name("other.example.com", ...) -> "example.com"
        find_zone_for_name("example.org", ...) -> None
    """
    best: Optional[str] = None
    for apex in zone_soa.keys():
        if name == apex or name.endswith("." + apex):
            if best is None or len(apex) > len(best):
                best = apex
    return best


_DNS_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


def _split_dns_labels(text: str) -> List[str]:
    """Brief: Split a domain into normalized DNS labels.

    Inputs:
      - text: Domain-like string (may include trailing dot).

    Outputs:
      - list[str]: Lowercased labels.

    Notes:
      - Returns an empty list when the input appears invalid (empty labels like
        "..", leading dot, or labels with unexpected characters).
      - This is primarily to avoid surprising wildcard matches on malformed
        inputs.
    """
    try:
        norm = str(text).strip().rstrip(".").lower()
    except Exception:  # pragma: no cover - defensive
        norm = str(text).rstrip(".").lower()

    if not norm:
        return []

    # Reject empty-label constructs such as ".." or a leading dot.
    if norm.startswith(".") or ".." in norm:
        return []

    labels = norm.split(".")

    for lbl in labels:
        # Wildcard label is only valid when the entire label is exactly "*".
        if lbl == "*":
            continue
        if not _DNS_LABEL_RE.match(lbl):
            return []

    return labels


def is_wildcard_domain_pattern(pattern: str) -> bool:
    """Brief: Return True when *pattern* contains one or more wildcard labels.

    Inputs:
      - pattern: Owner/pattern string such as "*.example.com".

    Outputs:
      - bool: True when any label is exactly "*".

    Notes:
      - A label containing "*" plus other characters (e.g. "foo*") is treated as
        a literal label and is not considered a wildcard.
    """
    labels = _split_dns_labels(pattern)
    return any(lbl == "*" for lbl in labels)


def match_wildcard_domain(name: str, pattern: str) -> bool:
    """Brief: Match a domain name against a ZoneRecords wildcard pattern.

    Inputs:
      - name: Queried name (no trailing dot preferred).
      - pattern: Owner/pattern string. Wildcards are expressed as "*" labels.

    Outputs:
      - bool: True when *name* matches *pattern*.

    Wildcard rules:
      - A "*" label matches exactly one label.
      - If the pattern's first label is "*", that "*" matches **one or more**
        leading labels (i.e. any depth) so the remainder of the pattern still
        matches the name suffix.

    Examples:
      - foo.my.domain.org matches "*.domain.org" (leading "*" matches "foo.my")
      - foo.my.domain.org matches "foo.my.*.org" ("*" matches "domain")
      - foo.my.domain.org does not match "foo.my.*" (last "*" only matches one label)
    """
    name_labels = _split_dns_labels(name)
    pat_labels = _split_dns_labels(pattern)

    if not name_labels or not pat_labels:
        return False

    # Special case: "*" alone.
    if pat_labels == ["*"]:
        return True

    # Special case: leading "*" matches any number of labels (>=1).
    if pat_labels and pat_labels[0] == "*":
        remainder = pat_labels[1:]
        if not remainder:
            return True

        # Must have at least one label consumed by the leading wildcard.
        if len(name_labels) < (len(remainder) + 1):
            return False

        suffix = name_labels[-len(remainder) :]
        for want, got in zip(remainder, suffix):
            if want == "*":
                continue
            if want != got:
                return False
        return True

    # Non-leading patterns require label-for-label matches.
    if len(name_labels) != len(pat_labels):
        return False

    for want, got in zip(pat_labels, name_labels):
        if want == "*":
            continue
        if want != got:
            return False
    return True


def wildcard_matched_character_count(name: str, pattern: str) -> Optional[int]:
    """Brief: Count how many characters were consumed by a leading wildcard match.

    Inputs:
      - name: Queried domain name (no trailing dot preferred).
      - pattern: Wildcard owner/pattern string using "*" labels.

    Outputs:
      - int: Number of characters consumed by the *leading* "*" label.
        Returns 0 for patterns that do not start with "*".
      - None: When either value is invalid or *pattern* does not match *name*.

    Notes:
      - ZoneRecords treats a leading "*" as matching one-or-more leading labels
        (any depth). When multiple wildcard owners match, the best match is the
        one whose leading "*" consumed the fewest characters.
      - "Empty" names never match (because _split_dns_labels() returns []).
    """
    name_labels = _split_dns_labels(name)
    pat_labels = _split_dns_labels(pattern)

    if not name_labels or not pat_labels:
        return None

    if not match_wildcard_domain(name, pattern):
        return None

    # Patterns without a leading wildcard are treated as a 0-cost match.
    if not pat_labels or pat_labels[0] != "*":
        return 0

    # Pattern "*" alone: it matches the whole name.
    if pat_labels == ["*"]:
        return len(".".join(name_labels))

    remainder = pat_labels[1:]
    if not remainder:
        return len(".".join(name_labels))

    # By match_wildcard_domain() contract this is >= 1.
    leading_len = len(name_labels) - len(remainder)
    if leading_len <= 0:
        return None

    return len(".".join(name_labels[:leading_len]))


def sort_wildcard_patterns(patterns: Iterable[str]) -> List[str]:
    """Brief: Sort wildcard patterns from most-specific to least-specific.

    Inputs:
      - patterns: Iterable of owner/pattern strings.

    Outputs:
      - list[str]: Sorted patterns.

    Notes:
      - Specificity is defined as (literal_labels, total_labels, -wildcard_labels).
      - The sort is stable and deterministic across reloads.
    """

    def _score(p: str) -> tuple[int, int, int, str]:
        labels = _split_dns_labels(p)
        literal = sum(1 for lbl in labels if lbl != "*")
        wildcard = sum(1 for lbl in labels if lbl == "*")
        return (literal, len(labels), -wildcard, str(p))

    # Sort descending by score.
    return sorted([str(p) for p in patterns or []], key=_score, reverse=True)


def find_best_rrsets_for_name(
    name: str,
    name_index: Dict[str, Dict[int, Tuple[int, List[str]]]],
    wildcard_patterns: Optional[List[str]] = None,
) -> tuple[Optional[str], Dict[int, Tuple[int, List[str]]]]:
    """Brief: Find the best matching RRsets for *name* using wildcard owners.

    Inputs:
      - name: Query name (no trailing dot preferred).
      - name_index: Mapping of owner -> qtype -> (ttl, [values]).
      - wildcard_patterns: Optional pre-sorted list of wildcard owners to check.

    Outputs:
      - (matched_owner, rrsets)
        * matched_owner: exact owner or wildcard owner key from name_index.
        * rrsets: RRsets dict, or {} when no match.

    Notes:
      - Exact owner matches always win.
      - When multiple wildcard patterns match, the "best" match is chosen as:
          1) the match whose *leading* wildcard consumed the fewest characters
          2) on ties, the most-specific pattern (per sort_wildcard_patterns())
    """
    try:
        norm = str(name).rstrip(".").lower()
    except Exception:  # pragma: no cover - defensive
        norm = str(name).lower()

    if norm in name_index:
        return norm, name_index.get(norm, {}) or {}

    # If the caller didn't provide a pre-sorted wildcard list, derive it.
    patterns = wildcard_patterns
    if patterns is None:
        patterns = sort_wildcard_patterns(
            [owner for owner in name_index.keys() if is_wildcard_domain_pattern(owner)]
        )

    best_pat: Optional[str] = None
    best_cost: Optional[int] = None

    # We scan all candidates because the "fewest leading-wildcard characters"
    # metric is query-dependent.
    for pat in patterns or []:
        if pat not in name_index:
            continue

        cost = wildcard_matched_character_count(norm, pat)
        if cost is None:
            continue

        if best_cost is None or cost < best_cost:
            best_pat = pat
            best_cost = cost

    if best_pat is not None:
        return best_pat, name_index.get(best_pat, {}) or {}

    return None, {}


def snapshot_zone_state(
    zone_apex: str,
    name_index: Dict[str, Dict[int, Tuple[int, List[str]]]],
) -> set[Tuple[str, int, int, Tuple[str, ...]]]:
    """Brief: Build a hashable snapshot of RRsets for a given zone.

    Inputs:
      - zone_apex: Zone apex string without trailing dot.
      - name_index: Mapping of owner -> qtype -> (ttl, values).

    Outputs:
      - set of (owner, qtype, ttl, values) tuples for owners inside zone.
    """
    snapshot: set[Tuple[str, int, int, Tuple[str, ...]]] = set()
    try:
        apex = str(zone_apex).rstrip(".").lower()
    except Exception:  # pragma: no cover - defensive
        apex = str(zone_apex).lower()
    if not apex:
        return snapshot

    for owner, rrsets in name_index.items():
        try:
            owner_norm = str(owner).rstrip(".").lower()
        except Exception:  # pragma: no cover - defensive
            owner_norm = str(owner).lower()
        if owner_norm != apex and not owner_norm.endswith("." + apex):
            continue
        for qcode, (ttl, values) in rrsets.items():
            try:
                ttl_i = int(ttl)
            except Exception:  # pragma: no cover - defensive
                ttl_i = 0
            snapshot.add(
                (
                    owner_norm,
                    int(qcode),
                    ttl_i,
                    tuple(list(values)),
                )
            )
    return snapshot


def compute_changed_zones(
    old_name_index: Dict[str, Dict[int, Tuple[int, List[str]]]],
    old_zone_soa: Dict[str, Tuple[int, List[str]]],
    new_name_index: Dict[str, Dict[int, Tuple[int, List[str]]]],
    new_zone_soa: Dict[str, Tuple[int, List[str]]],
) -> List[str]:
    """Brief: Determine which authoritative zones changed between snapshots.

    Inputs:
      - old_name_index/new_name_index: Pre- and post-reload name indexes.
      - old_zone_soa/new_zone_soa: Pre- and post-reload SOA mappings.

    Outputs:
      - list of zone apex names whose RRsets changed.
    """
    changed: List[str] = []
    all_apexes = set(old_zone_soa.keys()) | set(new_zone_soa.keys())
    for apex in sorted(all_apexes):
        if apex not in old_zone_soa or apex not in new_zone_soa:
            changed.append(apex)
            continue
        before = snapshot_zone_state(apex, old_name_index)
        after = snapshot_zone_state(apex, new_name_index)
        if before != after:
            changed.append(apex)
    return changed
