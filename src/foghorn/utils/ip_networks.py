"""Brief: Shared IP parsing and CIDR membership helpers.

Inputs/Outputs:
  - Parsing helpers for IP addresses and networks.
  - Membership helpers for CIDR allow/deny lists.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Optional

from foghorn.utils.register_caches import registered_lru_cached


@registered_lru_cached(maxsize=4096)
def parse_ip(
    value: object,
) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Brief: Parse an IP address string into an ipaddress object.

    Inputs:
      - value: Candidate IP value (string-like).

    Outputs:
      - IPv4Address/IPv6Address instance, or None when parsing fails.

    Example:
      >>> str(parse_ip("192.0.2.1"))
      '192.0.2.1'
    """
    try:
        return ipaddress.ip_address(str(value).strip())
    except Exception:
        return None


@registered_lru_cached(maxsize=4096)
def parse_network(
    value: object,
    *,
    strict: bool = False,
) -> Optional[ipaddress._BaseNetwork]:
    """Brief: Parse a CIDR or IP string into an ipaddress network.

    Inputs:
      - value: Candidate CIDR or IP (string-like).
      - strict: Passed to ip_network when CIDR is provided (default False).

    Outputs:
      - IPv4Network/IPv6Network instance, or None when parsing fails.

    Notes:
      - IP literals without a slash are converted to a single-host network.
    """
    if value is None:
        return None
    try:
        text = str(value).strip()
    except Exception:
        return None
    if not text:
        return None
    try:
        if "/" in text:
            return ipaddress.ip_network(text, strict=strict)
        addr = ipaddress.ip_address(text)
        return ipaddress.ip_network(addr)
    except Exception:
        return None


@registered_lru_cached(maxsize=131072)
def _ip_in_network(
    ip: ipaddress._BaseAddress,
    network: ipaddress._BaseNetwork,
) -> bool:
    """Brief: Cached IP membership check for one parsed network.

    Inputs:
      - ip: IPv4Address or IPv6Address instance.
      - network: Parsed IPv4Network or IPv6Network.

    Outputs:
      - bool: True when the IP is contained in the network.
    """
    try:
        return ip in network
    except Exception:
        return False


def ip_in_any_network(
    ip: ipaddress._BaseAddress,
    networks: Iterable[ipaddress._BaseNetwork],
) -> bool:
    """Brief: Return True if *ip* is contained in any network.

    Inputs:
      - ip: IPv4Address or IPv6Address instance.
      - networks: Iterable of ipaddress network objects.

    Outputs:
      - bool: True when ip is in any network.
    """
    for net in networks or []:
        if _ip_in_network(ip, net):
            return True
    return False


def ip_string_in_cidrs(ip_str: str, cidrs: Iterable[str]) -> bool:
    """Brief: Check whether an IP string is in any CIDR entry.

    Inputs:
      - ip_str: IP address string.
      - cidrs: Iterable of CIDR strings.

    Outputs:
      - bool: True when the IP is contained in any CIDR.
    """
    ip_obj = parse_ip(ip_str)
    if ip_obj is None:
        return False
    for cidr in cidrs or []:
        net = parse_network(cidr, strict=False)
        if net is None:
            continue
        if _ip_in_network(ip_obj, net):
            return True
    return False
