"""Brief: Unit tests for foghorn.plugins.resolve.zone_records.transfer.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from dnslib import QTYPE

from foghorn.plugins.resolve.zone_records import transfer


class _PluginNoLock:
    """Brief: Minimal plugin object without _records_lock.

    Inputs:
      - name_index: owner -> qtype -> (ttl, [values]) mapping.
      - zone_soa: zone apex -> (ttl, [soa_values]) mapping.

    Outputs:
      - Instance with _name_index/_zone_soa attributes.
    """

    def __init__(
        self,
        *,
        name_index: dict,
        zone_soa: dict,
    ) -> None:
        self._name_index = name_index
        self._zone_soa = zone_soa


def test_iter_zone_rrs_for_transfer_empty_apex_returns_none() -> None:
    """Brief: Empty zone apex should return None immediately.

    Inputs:
      - zone_apex: ''.

    Outputs:
      - None.
    """
    plugin = _PluginNoLock(name_index={}, zone_soa={})

    assert transfer.iter_zone_rrs_for_transfer(plugin, "") is None


def test_iter_zone_rrs_for_transfer_no_lock_snapshots_and_filters_zone() -> None:
    """Brief: Without a lock, the helper snapshots dicts and filters owners by apex.

    Inputs:
      - plugin: minimal plugin with _name_index/_zone_soa.

    Outputs:
      - None; asserts only in-zone owners are exported.
    """
    apex = "example.com"
    plugin = _PluginNoLock(
        name_index={
            "example.com": {int(QTYPE.A): (300, ["192.0.2.1"])},
            "www.example.com.": {int(QTYPE.A): (300, ["192.0.2.2"])},
            "other.com": {int(QTYPE.A): (300, ["198.51.100.1"])},
        },
        zone_soa={apex: (300, ["soa"])},
    )

    rrs = transfer.iter_zone_rrs_for_transfer(plugin, "EXAMPLE.COM.")
    assert rrs is not None

    owners = {str(rr.rname).rstrip(".").lower() for rr in rrs}
    assert "example.com" in owners
    assert "www.example.com" in owners
    assert "other.com" not in owners
