"""Brief: Unit tests for foghorn.utils.ip_networks helpers.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import ipaddress

from foghorn.utils import ip_networks


def test_parse_ip_handles_success_and_failure_inputs() -> None:
    """Brief: parse_ip trims input and returns None for invalid strings.

    Inputs:
      - None

    Outputs:
      - None
    """
    assert ip_networks.parse_ip(" 192.0.2.1 ") == ipaddress.ip_address("192.0.2.1")
    assert ip_networks.parse_ip("not-an-ip") is None


def test_parse_network_handles_none_blank_and_bad_string_values() -> None:
    """Brief: parse_network handles None/blank and coercion failures safely.

    Inputs:
      - None

    Outputs:
      - None
    """

    class BadStrValue:
        """Value object whose string conversion raises."""

        def __str__(self) -> str:
            raise RuntimeError("boom")

    assert ip_networks.parse_network(None, strict=False) is None
    assert ip_networks.parse_network("   ", strict=False) is None
    assert ip_networks.parse_network(BadStrValue(), strict=False) is None


def test_parse_network_honors_strict_and_host_literal_paths() -> None:
    """Brief: parse_network honors strict CIDR parsing and host normalization.

    Inputs:
      - None

    Outputs:
      - None
    """
    assert ip_networks.parse_network("192.0.2.7/24", strict=True) is None
    assert ip_networks.parse_network(
        "192.0.2.7/24", strict=False
    ) == ipaddress.ip_network("192.0.2.0/24")
    assert ip_networks.parse_network(
        "2001:db8::1", strict=False
    ) == ipaddress.ip_network("2001:db8::1/128")


def test_ip_in_any_network_handles_none_and_match_paths() -> None:
    """Brief: ip_in_any_network covers empty, no-match, and match branches.

    Inputs:
      - None

    Outputs:
      - None
    """
    ip_obj = ip_networks.parse_ip("192.0.2.5")
    assert ip_obj is not None

    in_range = ip_networks.parse_network("192.0.2.0/24", strict=False)
    out_of_range = ip_networks.parse_network("198.51.100.0/24", strict=False)
    assert in_range is not None
    assert out_of_range is not None

    assert ip_networks.ip_in_any_network(ip_obj, None) is False
    assert ip_networks.ip_in_any_network(ip_obj, [out_of_range]) is False
    assert ip_networks.ip_in_any_network(ip_obj, [out_of_range, in_range]) is True


def test_ip_string_in_cidrs_returns_false_for_no_match_and_empty_lists() -> None:
    """Brief: ip_string_in_cidrs returns False when no CIDRs match.

    Inputs:
      - None

    Outputs:
      - None
    """
    assert (
        ip_networks.ip_string_in_cidrs(
            "192.0.2.25", ["198.51.100.0/24", "203.0.113.0/24"]
        )
        is False
    )
    assert ip_networks.ip_string_in_cidrs("192.0.2.25", None) is False


def test_ip_string_in_cidrs_handles_invalid_values_and_matches() -> None:
    """Brief: ip_string_in_cidrs covers invalid IP, invalid CIDR, and match paths.

    Inputs:
      - None

    Outputs:
      - None
    """
    assert ip_networks.ip_string_in_cidrs("not-an-ip", ["192.0.2.0/24"]) is False
    assert (
        ip_networks.ip_string_in_cidrs("192.0.2.5", ["not-a-cidr", "192.0.2.0/24"])
        is True
    )
