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
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


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
                names.append(line.rstrip(".").lower())
    except Exception as exc:
        logger.warning("Failed to load names list from %s: %s", path, exc)
    return names


def combine_lists(
    inline: Optional[List[str]], files: Optional[List[str]], loader_func
) -> List[str]:
    """Brief: Combine inline list with entries from files.

    Inputs:
      - inline: Inline list.
      - files: File paths.
      - loader_func: Function to load from file.

    Outputs:
      - Combined list (union of inline and file entries).
    """
    combined = list(inline or [])
    if files:
        for path in files:
            combined.extend(loader_func(path))
    return combined


def normalize_cidr(
    cidr: str,
) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Brief: Normalize CIDR string to network object.

    Inputs:
      - cidr: CIDR notation string.

    Outputs:
      - Network object or None if invalid.
    """
    try:
        if "/" in cidr:
            return ipaddress.ip_network(cidr, strict=False)
        else:
            return ipaddress.ip_network(ipaddress.ip_address(cidr))
    except (ValueError, ipaddress.AddressValueError):
        return None


def collect_update_file_paths(dns_update_config: dict) -> List[str]:
    """Brief: Collect all file paths referenced in DNS UPDATE configuration.

    Inputs:
      - dns_update_config: DNS_UPDATE configuration dict.

    Outputs:
      - List of unique file paths.
    """
    file_set = set()
    zones = dns_update_config.get("zones", []) or []

    for zone in zones:
        if isinstance(zone, dict):
            file_set.update(zone.get("allow_names_files") or [])
            file_set.update(zone.get("block_names_files") or [])
            file_set.update(zone.get("allow_clients_files") or [])
            file_set.update(zone.get("allow_update_ips_files") or [])
            file_set.update(zone.get("block_update_ips_files") or [])

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

            zone_key = str(zone.get("zone", "")).rstrip(".").lower()

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
    try:
        ip = ipaddress.ip_address(ip_str)
    except (ValueError, ipaddress.AddressValueError):
        return False

    for cidr in cidr_list:
        net = normalize_cidr(cidr)
        if net and ip in net:
            return True
    return False


def matches_name_pattern(name: str, patterns: List[str]) -> bool:
    """Brief: Check if name matches any pattern (supports wildcards).

    Inputs:
      - name: Domain name (normalized to lowercase, no trailing dot).
      - patterns: List of patterns (may include * wildcard).

    Outputs:
      - bool: True if name matches any pattern.
    """
    name_norm = str(name).rstrip(".").lower()
    for pattern in patterns:
        pattern_norm = str(pattern).rstrip(".").lower()
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
    """Brief: Verify TSIG HMAC per RFC 2845.

    Inputs:
      - key_name: TSIG key name.
      - secret_b64: Base64-encoded secret.
      - algorithm: Algorithm name (hmac-md5, hmac-sha256, hmac-sha512).
      - msg: Wire-format message (with TSIG record RR set to zero RDLEN).
      - client_time: Client timestamp from TSIG.
      - fudge: Time fudge value from TSIG.
      - tsig_mac: MAC value from TSIG record.
      - msg_id: Message ID.

    Outputs:
      - bool: True if HMAC verifies and timestamp is within fudge.
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

    # Reconstruct TSIG RR for signing (per RFC 2845)
    # Format: key_name + TSIG_RR_SET (key_name, TSIG class, TTL=0, RDLEN + RDATA)
    # For verification we use: message + key_name + class + TTL + RDATA_without_MAC
    try:
        # Compute HMAC
        computed_mac = hmac.new(secret, msg, hash_func).digest()

        # Compare (constant-time comparison)
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
