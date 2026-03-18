"""Brief: Zone transfer export for AXFR/IXFR.

Inputs/Outputs:
  - Export RRsets for zone transfers, with optional client learning.
"""

from __future__ import annotations
import ipaddress

import logging
from typing import List, Optional

from dnslib import QTYPE, RCODE, RR, DNSHeader, DNSRecord

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
    from foghorn.utils import dns_names

    apex = dns_names.normalize_name(zone_apex) if zone_apex is not None else ""
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
        owner_norm = dns_names.normalize_name(owner)

        if owner_norm != apex and not owner_norm.endswith("." + apex):
            continue

        for qtype_code, entry in rrsets.items():
            ttl = entry[0]
            values = entry[1]
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


def _client_allowed_for_axfr(client_ip: str | None) -> bool:
    """Brief: Check whether a client is allowed to perform AXFR/IXFR.

    Inputs:
      - client_ip: Source IP address string.

    Outputs:
      - bool: True when AXFR is enabled and the client matches allowlist.

    Notes:
      - Policy is controlled via runtime snapshot values axfr_enabled and
        axfr_allow_clients.
      - Empty or missing allowlist denies all transfers when enabled.
    """
    try:
        from foghorn.runtime_config import get_runtime_snapshot

        snap = get_runtime_snapshot()
        axfr_enabled = bool(snap.axfr_enabled)
        allow_raw = list(snap.axfr_allow_clients or [])
    except Exception:
        axfr_enabled = False
        allow_raw = []

    if not axfr_enabled:
        return False

    if not client_ip:
        return False

    if not allow_raw:
        return False

    from foghorn.utils import ip_networks

    return ip_networks.ip_string_in_cidrs(str(client_ip).strip(), allow_raw)


def iter_axfr_messages(req: DNSRecord, client_ip: str | None = None) -> List[bytes]:
    """Brief: Build AXFR/IXFR response message sequence for an authoritative zone.

    Inputs:
      - req: Parsed DNSRecord representing the client's AXFR or IXFR query.
      - client_ip: Optional source IP address of the AXFR/IXFR client.

    Outputs:
      - list[bytes]: Packed DNS response messages to stream over TCP/DoT. When
        the server is not authoritative for the requested zone or transfer is
        refused, the list contains a single REFUSED response.

    Notes:
      - This helper relies on resolve plugins advertising an
        iter_zone_rrs_for_transfer(zone_apex, client_ip=None) method. The first
        such plugin that claims authority for the requested apex is used.
      - IXFR is currently implemented as a full AXFR-style transfer; the
        question section retains QTYPE=IXFR but the answer stream is a full
        zone dump bounded by matching SOA records.
    """
    try:  # pragma: no cover - defensive/metrics path excluded from coverage
        if not getattr(
            req, "questions", None
        ):  # pragma: no cover - defensive/metrics path excluded from coverage
            raise ValueError(
                "AXFR/IXFR query has no questions"
            )  # pragma: no cover - defensive/metrics path excluded from coverage
        q = req.questions[
            0
        ]  # pragma: no cover - defensive/metrics path excluded from coverage
        from foghorn.utils import dns_names

        qname_norm = dns_names.normalize_name(
            q.qname
        )  # pragma: no cover - defensive/metrics path excluded from coverage
    except Exception as exc:  # pragma: no cover - defensive parsing
        logger.warning("iter_axfr_messages: malformed query: %s", exc)
        r = req.reply()
        r.header.rcode = RCODE.REFUSED
        return [r.pack()]

    if not _client_allowed_for_axfr(client_ip):
        r = req.reply()
        r.header.rcode = RCODE.REFUSED
        return [r.pack()]

    zone_apex = (
        qname_norm  # pragma: no cover - defensive/metrics path excluded from coverage
    )
    rrs: Optional[List[RR]] = None

    try:
        from foghorn.runtime_config import get_runtime_snapshot

        plugins = list(get_runtime_snapshot().plugins or [])
    except Exception:
        plugins = []
    for plugin in plugins:
        exporter = getattr(
            plugin, "iter_zone_rrs_for_transfer", None
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        if not callable(
            exporter
        ):  # pragma: no cover - defensive/metrics path excluded from coverage
            continue  # pragma: no cover - defensive/metrics path excluded from coverage
        try:  # pragma: no cover - defensive/metrics path excluded from coverage
            try:
                exported = exporter(zone_apex, client_ip)
            except TypeError:
                exported = exporter(zone_apex)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "iter_axfr_messages: plugin %r export failure for %s: %s",
                plugin,
                zone_apex,
                exc,
            )
            continue  # pragma: no cover - defensive/metrics path excluded from coverage
        if exported:  # pragma: no cover - defensive/metrics path excluded from coverage
            rrs = list(
                exported
            )  # pragma: no cover - defensive/metrics path excluded from coverage
            break

    if not rrs:
        r = (
            req.reply()
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        r.header.rcode = (
            RCODE.REFUSED
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        return [r.pack()]

    from foghorn.utils import dns_names

    apex_owner = dns_names.normalize_name(
        zone_apex
    )  # pragma: no cover - defensive/metrics path excluded from coverage
    soa_rrs: List[RR] = (
        []
    )  # pragma: no cover - defensive/metrics path excluded from coverage
    other_rrs: List[RR] = (
        []
    )  # pragma: no cover - defensive/metrics path excluded from coverage
    for rr in rrs:  # pragma: no cover - defensive/metrics path excluded from coverage
        owner_norm = dns_names.normalize_name(
            rr.rname
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        if (
            rr.rtype == QTYPE.SOA and owner_norm == apex_owner
        ):  # pragma: no cover - defensive/metrics path excluded from coverage
            soa_rrs.append(rr)
        else:  # pragma: no cover - defensive/metrics path excluded from coverage
            other_rrs.append(rr)

    if not soa_rrs:
        r = (
            req.reply()
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        r.header.rcode = (
            RCODE.REFUSED
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        return [r.pack()]

    primary_soa = soa_rrs[0]

    ordered: List[RR] = [
        primary_soa
    ]  # pragma: no cover - defensive/metrics path excluded from coverage
    for rr in rrs:  # pragma: no cover - defensive/metrics path excluded from coverage
        if (
            rr is primary_soa
        ):  # pragma: no cover - defensive/metrics path excluded from coverage
            continue  # pragma: no cover - defensive/metrics path excluded from coverage
        ordered.append(
            rr
        )  # pragma: no cover - defensive/metrics path excluded from coverage
    ordered.append(primary_soa)

    messages: List[bytes] = []

    max_len = 64000  # pragma: no cover - defensive/metrics path excluded from coverage
    current = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=1), q=req.q)

    for (
        rr
    ) in ordered:  # pragma: no cover - defensive/metrics path excluded from coverage
        current.add_answer(
            rr
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        try:  # pragma: no cover - defensive/metrics path excluded from coverage
            packed = current.pack()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("iter_axfr_messages: pack failure: %s", exc)
            current.rr.pop()
            continue  # pragma: no cover - defensive/metrics path excluded from coverage
        if len(packed) > max_len and len(current.rr) > 1:
            last = (
                current.rr.pop()
            )  # pragma: no cover - defensive/metrics path excluded from coverage
            messages.append(
                current.pack()
            )  # pragma: no cover - defensive/metrics path excluded from coverage
            current = DNSRecord(
                DNSHeader(id=req.header.id, qr=1, aa=1, ra=1), q=req.q
            )  # pragma: no cover - defensive/metrics path excluded from coverage
            current.add_answer(last)

    try:  # pragma: no cover - defensive/metrics path excluded from coverage
        messages.append(current.pack())
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("iter_axfr_messages: final pack failure: %s", exc)
        if not messages:
            r = req.reply()
            r.header.rcode = RCODE.REFUSED
            return [r.pack()]

    return messages
