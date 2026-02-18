"""Brief: Zone transfer export for AXFR/IXFR.

Inputs/Outputs:
  - Export RRsets for zone transfers, with optional client learning.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from dnslib import QTYPE, RR

from . import notify

logger = logging.getLogger(__name__)


def iter_zone_rrs_for_transfer(
    plugin: object,
    zone_apex: str,
    client_ip: Optional[str] = None,
) -> Optional[List[RR]]:
    """Brief: Export authoritative RRsets for a zone for AXFR/IXFR.

    Inputs:
      - plugin: ZoneRecords plugin instance with records and zone state.
      - zone_apex: Zone apex name (with or without trailing dot), case-insensitive.
      - client_ip: Optional IP address of the AXFR/IXFR client; when
        provided and axfr_notify_all is enabled, this is recorded as a
        learned NOTIFY target for the zone.

    Outputs:
      - list[RR]: All RRs in the zone suitable for AXFR/IXFR transfer, or
        None when this plugin is not authoritative for the requested apex.

    Notes:
      - The returned list is built from a snapshot of the plugin's name index.
        When plugin._records_lock is available, the snapshot is taken under that
        lock so mid-transfer reloads do not change the view.
      - DNSSEC-related RR types (for example, DNSKEY, RRSIG) are included when
        present in the zone data; AXFR-specific DNSSEC policy is intentionally
        out of scope for this helper.
    """
    # Normalize apex and check whether this plugin is authoritative.
    apex = str(zone_apex).rstrip(".").lower() if zone_apex is not None else ""
    if not apex:
        return None

    # Optionally remember the AXFR client as a NOTIFY target when
    # axfr_notify_all is enabled.
    if client_ip and getattr(plugin, "_axfr_notify_all", False):
        try:
            notify.record_axfr_client(plugin, apex, client_ip)
        except Exception:  # pragma: no cover - defensive logging only
            logger.warning(
                "ZoneRecords: failed to record AXFR client %s for zone %s",
                client_ip,
                apex,
                exc_info=True,
            )

    lock = getattr(plugin, "_records_lock", None)

    if lock is None:
        name_index = dict(getattr(plugin, "_name_index", {}) or {})
        zone_soa = dict(getattr(plugin, "_zone_soa", {}) or {})
    else:
        with lock:
            name_index = dict(getattr(plugin, "_name_index", {}) or {})
            zone_soa = dict(getattr(plugin, "_zone_soa", {}) or {})

    if apex not in zone_soa:
        return None

    rrs: List[RR] = []

    # Walk all owners inside this zone. An owner belongs to the zone when it
    # is equal to the apex or is a strict subdomain.
    for owner, rrsets in name_index.items():
        try:
            owner_norm = str(owner).rstrip(".").lower()
        except Exception:  # pragma: no cover - defensive
            owner_norm = str(owner).lower()

        if owner_norm != apex and not owner_norm.endswith("." + apex):
            continue

        for qtype_code, (ttl, values) in rrsets.items():
            rr_type_name = QTYPE.get(qtype_code, str(qtype_code))
            for value in values:
                zone_line = f"{owner_norm}. {ttl} IN {rr_type_name} {value}"
                try:
                    parsed = RR.fromZone(zone_line)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "ZoneRecords transfer: skipping RR %r for %s type %s: %s",
                        value,
                        owner_norm,
                        rr_type_name,
                        exc,
                    )
                    continue
                rrs.extend(parsed)

    return rrs
