"""Brief: Helpers for DNS UPDATE message processing, authentication, and validation.

Inputs/Outputs:
  - File loading, CIDR/domain matching, TSIG/PSK authentication, name/IP filtering.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac
import ipaddress
import logging
import os
import struct
import threading
import time
from typing import Callable, Dict, List, Optional, Set, Tuple
from foghorn.utils import dns_names

logger = logging.getLogger(__name__)
TsigKeySourceLoader = Callable[[dict], List[dict]]


def load_cidr_list_from_file(path: str) -> List[str]:
    """Brief: Load newline-separated CIDR list from file.

    Inputs:
      - path: File path.

    Outputs:
      - List of CIDR strings (comments stripped, blank lines skipped).
    """
    cidrs = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                cidrs.append(line)
    except Exception as exc:
        logger.warning("Failed to load CIDR list from %s: %s", path, exc)
    return cidrs


def load_names_list_from_file(path: str) -> List[str]:
    """Brief: Load newline-separated domain names from file.

    Inputs:
      - path: File path.

    Outputs:
      - List of domain names (comments stripped, blank lines skipped).
    """
    names = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                from foghorn.utils import dns_names

                names.append(dns_names.normalize_name(line))
    except Exception as exc:
        logger.warning("Failed to load names list from %s: %s", path, exc)
    return names


def combine_lists(
    inline: Optional[List[str]], files: Optional[List[str]], loader_func
) -> List[str]:
    """Brief: Combine inline list with entries from files.

    Inputs:
      - inline: Inline list (may be None).
      - files: File paths to load and append (may be None).
      - loader_func: Function used to load entries from each file.

    Outputs:
      - Combined list (inline entries followed by file-loaded entries).

    Notes:
      - This function does not de-duplicate; callers should treat it as an
        ordered concatenation helper.
    """
    combined = list(inline or [])
    if files:
        for path in files:
            combined.extend(loader_func(path))
    return combined


def load_tsig_keys_from_file(path: str) -> List[dict]:
    """Brief: Load TSIG key definitions from a YAML/JSON file.

    Inputs:
      - path: File path containing either:
          * a top-level list of TSIG key dicts, or
          * a mapping with a `keys` list.

    Outputs:
      - List of TSIG key configuration dicts.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_text = f.read()
    except Exception as exc:
        logger.warning("Failed to load TSIG keys from %s: %s", path, exc)
        return []

    try:
        import yaml
    except Exception as exc:  # pragma: no cover - yaml is a core dependency
        logger.warning("Failed to import yaml for TSIG key loading: %s", exc)
        return []

    try:
        parsed = yaml.safe_load(raw_text)
    except Exception as exc:
        logger.warning("Failed to parse TSIG key file %s: %s", path, exc)
        return []

    if parsed is None:
        return []

    if isinstance(parsed, dict):
        keys_obj = parsed.get("keys", [])
    elif isinstance(parsed, list):
        keys_obj = parsed
    else:
        logger.warning(
            "Invalid TSIG key file structure in %s: expected list or mapping",
            path,
        )
        return []

    keys: List[dict] = []
    for idx, item in enumerate(keys_obj or []):
        if isinstance(item, dict):
            keys.append(dict(item))
        else:
            logger.warning(
                "Ignoring non-dict TSIG key entry at %s[%d]: %r",
                path,
                idx,
                item,
            )
    return keys


def load_tsig_keys_from_source_file(source: dict) -> List[dict]:
    """Brief: Load TSIG keys from a file-based source definition.

    Inputs:
      - source: Source mapping with at least:
          * type: "file"
          * path: Filesystem path to YAML/JSON TSIG key definitions.

    Outputs:
      - List of TSIG key dicts.
    """
    path = source.get("path") if isinstance(source, dict) else None
    if not path:
        logger.warning("TSIG key source type=file missing required 'path'")
        return []
    return load_tsig_keys_from_file(str(path))


def get_default_tsig_key_source_loaders() -> Dict[str, TsigKeySourceLoader]:
    """Brief: Return default TSIG key-source loader registry.

    Inputs:
      - None.

    Outputs:
      - Mapping of source type -> loader callable.
    """
    return {"file": load_tsig_keys_from_source_file}


def resolve_tsig_key_configs(
    zone_config: dict,
    source_loaders: Optional[Dict[str, TsigKeySourceLoader]] = None,
) -> List[dict]:
    """Brief: Resolve TSIG key configs from inline and external sources.

    Inputs:
      - zone_config: DNS UPDATE zone config that may contain:
          * tsig.keys (inline list of key dicts)
          * tsig.key_sources (list of source mappings with a type field)
      - source_loaders: Optional loader registry to extend/override source
        types (e.g. "database", "api").

    Outputs:
      - Ordered list of resolved TSIG key dicts.

    Notes:
      - Resolution order is inline keys first, then key_sources.
      - This function provides a single extensibility seam for future UPDATE
        key/config loading backends.
    """
    if not isinstance(zone_config, dict):
        return []

    tsig_cfg = zone_config.get("tsig")
    if not isinstance(tsig_cfg, dict):
        return []

    resolved: List[dict] = []

    for item in tsig_cfg.get("keys", []) or []:
        if isinstance(item, dict):
            resolved.append(dict(item))

    loaders = get_default_tsig_key_source_loaders()
    if isinstance(source_loaders, dict):
        loaders.update(source_loaders)

    for source in tsig_cfg.get("key_sources", []) or []:
        if not isinstance(source, dict):
            logger.warning("Ignoring non-dict TSIG key source: %r", source)
            continue
        source_type = str(source.get("type", "")).strip().lower()
        if not source_type:
            logger.warning("Ignoring TSIG key source without type: %r", source)
            continue
        loader = loaders.get(source_type)
        if loader is None:
            logger.warning("No TSIG key source loader for type=%s", source_type)
            continue
        try:
            loaded = loader(source)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "TSIG key source loader failed for type=%s: %s",
                source_type,
                exc,
                exc_info=True,
            )
            continue
        for item in loaded or []:
            if isinstance(item, dict):
                resolved.append(dict(item))
            else:
                logger.warning(
                    "Ignoring non-dict TSIG key from source type=%s: %r",
                    source_type,
                    item,
                )

    return resolved


def normalize_cidr(
    cidr: str,
) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Brief: Normalize CIDR string to network object.

    Inputs:
      - cidr: CIDR notation string.

    Outputs:
      - Network object or None if invalid.
    """
    from foghorn.utils import ip_networks

    return ip_networks.parse_network(cidr, strict=False)


def collect_update_file_paths(dns_update_config: dict) -> List[str]:
    """Brief: Collect all file paths referenced in DNS UPDATE configuration.

    Inputs:
      - dns_update_config: DNS_UPDATE configuration dict.

    Outputs:
      - List of unique file paths.

    Notes:
      - Includes both zone-level lists and per-TSIG-key / per-PSK-token scope files.
    """
    file_set = set()
    zones = dns_update_config.get("zones", []) or []

    def _collect_scope_files(scope: dict) -> None:
        """Collect allow/block scope file paths from a scope dict.

        Inputs:
          - scope: dict which may contain *_files entries.

        Outputs:
          - None; updates outer file_set.
        """
        if not isinstance(scope, dict):
            return
        file_set.update(scope.get("allow_names_files") or [])
        file_set.update(scope.get("block_names_files") or [])
        file_set.update(scope.get("allow_update_ips_files") or [])
        file_set.update(scope.get("block_update_ips_files") or [])

    for zone in zones:
        if not isinstance(zone, dict):
            continue

        # Zone-level lists
        file_set.update(zone.get("allow_names_files") or [])
        file_set.update(zone.get("block_names_files") or [])
        file_set.update(zone.get("allow_clients_files") or [])
        file_set.update(zone.get("allow_update_ips_files") or [])
        file_set.update(zone.get("block_update_ips_files") or [])

        # Per-TSIG key scopes
        tsig = zone.get("tsig")
        if isinstance(tsig, dict):
            for key_cfg in tsig.get("keys", []) or []:
                _collect_scope_files(key_cfg)
            for source in tsig.get("key_sources", []) or []:
                if not isinstance(source, dict):
                    continue
                source_type = str(source.get("type", "")).strip().lower()
                if source_type != "file":
                    continue
                source_path = source.get("path")
                if not source_path:
                    continue
                file_set.add(str(source_path))
                for key_cfg in load_tsig_keys_from_source_file(source):
                    _collect_scope_files(key_cfg)

        # Per-PSK token scopes
        psk = zone.get("psk")
        if isinstance(psk, dict):
            for tok_cfg in psk.get("tokens", []) or []:
                _collect_scope_files(tok_cfg)

    return list(file_set)


def reload_update_lists(plugin: object) -> None:
    """Brief: Reload DNS UPDATE filter lists from files.

    Inputs:
      - plugin: ZoneRecords plugin instance.

    Outputs:
      - None (caches updated in-place).
    """
    dns_update_config = getattr(plugin, "_dns_update_config", None)
    if not dns_update_config:
        return

    zones = dns_update_config.get("zones", []) or []
    cache_lock = getattr(plugin, "_dns_update_cache_lock", None)
    if not cache_lock:
        return

    with cache_lock:
        for zone in zones:
            if not isinstance(zone, dict):
                continue

            zone_key = dns_names.normalize_name(zone.get("zone", ""))

            # Reload each list type
            for list_type in [
                "allow_names",
                "block_names",
                "allow_clients",
                "allow_update_ips",
                "block_update_ips",
            ]:
                files_key = f"{list_type}_files"
                cache_key = f"{zone_key}_{list_type}"

                files = zone.get(files_key, [])
                if files:
                    # Check if any file changed
                    need_reload = False
                    for path in files:
                        current_mtime = (
                            os.path.getmtime(path) if os.path.exists(path) else 0
                        )
                        timestamps = getattr(plugin, "_dns_update_timestamps", {})
                        last_mtime = timestamps.get(path, 0)
                        if current_mtime != last_mtime:
                            need_reload = True
                            timestamps[path] = current_mtime

                    if need_reload:
                        # Reload and cache
                        loader = (
                            load_names_list_from_file
                            if "name" in list_type
                            else load_cidr_list_from_file
                        )
                        new_list = combine_lists(None, files, loader)
                        cache = getattr(plugin, "_dns_update_lists_cache", {})
                        cache[cache_key] = new_list


def is_ip_in_cidr_list(ip_str: str, cidr_list: List[str]) -> bool:
    """Brief: Check if IP is in any CIDR in list.

    Inputs:
      - ip_str: IP address string.
      - cidr_list: List of CIDR strings.

    Outputs:
      - bool: True if IP is in any CIDR.
    """
    from foghorn.utils import ip_networks

    return ip_networks.ip_string_in_cidrs(ip_str, cidr_list)


def matches_name_pattern(name: str, patterns: List[str]) -> bool:
    """Brief: Check if name matches any pattern (supports wildcards).

    Inputs:
      - name: Domain name (normalized to lowercase, no trailing dot).
      - patterns: List of patterns (may include * wildcard).

    Outputs:
      - bool: True if name matches any pattern.
    """
    from foghorn.utils import dns_names

    name_norm = dns_names.normalize_name(name)
    for pattern in patterns:
        pattern_norm = dns_names.normalize_name(pattern)
        if fnmatch.fnmatch(name_norm, pattern_norm):
            return True
    return False


def tsig_hmac_verify(
    key_name: str,
    secret_b64: str,
    algorithm: str,
    msg: bytes,
    client_time: int,
    fudge: int,
    tsig_mac: bytes,
    msg_id: int,
) -> bool:
    """Brief: Verify a timestamped HMAC over msg.

    Inputs:
      - key_name: TSIG key name (currently unused; reserved for future RFC 2845
        canonicalization).
      - secret_b64: Base64-encoded secret.
      - algorithm: Algorithm name (hmac-md5, hmac-sha256, hmac-sha512).
      - msg: Bytes to MAC.
      - client_time: Client timestamp from TSIG.
      - fudge: Max allowed timestamp skew.
      - tsig_mac: Expected MAC bytes.
      - msg_id: DNS message ID (currently unused; reserved for future RFC 2845
        canonicalization).

    Outputs:
      - bool: True if timestamp is within fudge and MAC matches.

    Notes:
      - This helper currently computes HMAC(secret, msg) directly and does not
        implement the full RFC 2845 TSIG canonical MAC input. For UPDATE request
        verification, prefer update_processor.verify_tsig_auth (dnspython).
    """
    # Validate timestamp
    now = int(time.time())
    if abs(now - client_time) > fudge:
        logger.warning(
            "TSIG timestamp out of fudge window: %d (fudge %d)", client_time, fudge
        )
        return False

    # Decode secret
    try:
        secret = base64.b64decode(secret_b64)
    except Exception as exc:
        logger.warning("Failed to decode TSIG secret: %s", exc)
        return False

    # Select HMAC algorithm
    if algorithm.lower() == "hmac-md5":
        hash_func = hashlib.md5
    elif algorithm.lower() == "hmac-sha256":
        hash_func = hashlib.sha256
    elif algorithm.lower() == "hmac-sha512":
        hash_func = hashlib.sha512
    else:
        logger.warning("Unknown HMAC algorithm: %s", algorithm)
        return False

    try:
        computed_mac = hmac.new(secret, msg, hash_func).digest()
        return hmac.compare_digest(computed_mac, tsig_mac)
    except Exception as exc:
        logger.warning("TSIG verification failed: %s", exc)
        return False


def parse_domain_name_wire(data: bytes, offset: int) -> Tuple[Optional[str], int]:
    """Brief: Parse DNS wire-format domain name.

    Inputs:
      - data: Wire-format data.
      - offset: Offset to start parsing.

    Outputs:
      - Tuple of (domain_name, new_offset) or (None, offset) on error.
    """
    labels = []
    pos = offset

    while pos < len(data):
        length = data[pos]
        pos += 1

        if length == 0:
            return ".".join(labels) if labels else ".", pos
        if length & 0xC0 == 0xC0:
            # Pointer - not supported in this context
            return None, offset
        if pos + length > len(data):
            return None, offset

        label = data[pos : pos + length].decode("utf-8", errors="ignore")
        labels.append(label)
        pos += length

    return None, offset
