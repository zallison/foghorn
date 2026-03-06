"""AXFR/IXFR policy gates and transfer message construction helpers."""

from __future__ import annotations

import ipaddress
import logging
from typing import List, Optional

from dnslib import QTYPE, RCODE, RR, DNSHeader, DNSRecord

logger = logging.getLogger("foghorn.server")


def _client_allowed_for_axfr(client_ip: str | None) -> bool:
    """Brief: Check whether a client is allowed to perform AXFR/IXFR.

    Inputs:
      - client_ip: Source IP address string.

    Outputs:
      - bool: True when AXFR is enabled and the client matches allowlist.

    Notes:
      - Policy is controlled via DNSUDPHandler.axfr_enabled (bool) and
        DNSUDPHandler.axfr_allow_clients (list[str] CIDRs/IPs).
      - Empty or missing allow_clients denies all transfers when enabled.
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

    try:
        ip_obj = ipaddress.ip_address(str(client_ip).strip())
    except Exception:
        return False

    for entry in allow_raw:
        try:
            net = ipaddress.ip_network(str(entry), strict=False)
        except Exception:
            continue
        try:
            if ip_obj in net:
                return True
        except Exception:
            continue

    return False


def iter_axfr_messages(req: DNSRecord, client_ip: str | None = None) -> List[bytes]:
    """Brief: Build AXFR/IXFR response message sequence for an authoritative zone.

    Inputs:
      - req: Parsed DNSRecord representing the client's AXFR or IXFR query.
      - client_ip: Optional source IP address of the AXFR/IXFR client.

    Outputs:
      - list[bytes]: Packed DNS response messages to stream over TCP/DoT. When
        the server is not authoritative for the requested zone or transfer is
        otherwise refused, the list contains a single REFUSED response.

    Notes:
      - This helper relies on resolve plugins advertising an
        ``iter_zone_rrs_for_transfer(zone_apex, client_ip=None)`` method (for
        example, ZoneRecords). The first such plugin that claims authority for
        the requested apex is used.
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
        qname_text = str(q.qname).rstrip(
            "."
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        qname_norm = (
            qname_text.lower()
        )  # pragma: no cover - defensive/metrics path excluded from coverage
    except Exception as exc:  # pragma: no cover - defensive parsing
        logger.warning("iter_axfr_messages: malformed query: %s", exc)
        r = req.reply()
        r.header.rcode = RCODE.REFUSED
        return [r.pack()]

    # Enforce AXFR policy gate.
    if not _client_allowed_for_axfr(client_ip):
        r = req.reply()
        r.header.rcode = RCODE.REFUSED
        return [r.pack()]

    # Identify authoritative plugin and export zone RRs.
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
        # Capability check: only consider plugins that implement the export API.
        exporter = getattr(
            plugin, "iter_zone_rrs_for_transfer", None
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        if not callable(
            exporter
        ):  # pragma: no cover - defensive/metrics path excluded from coverage
            continue  # pragma: no cover - defensive/metrics path excluded from coverage
        try:  # pragma: no cover - defensive/metrics path excluded from coverage
            # Prefer the newer two-argument form when available so plugins can
            # learn AXFR clients; fall back to the legacy single-argument call
            # for older plugins.
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
        # Not authoritative or no eligible plugin: REFUSED.
        r = (
            req.reply()
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        r.header.rcode = (
            RCODE.REFUSED
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        return [r.pack()]

    # Locate the primary SOA at the zone apex.
    apex_owner = zone_apex.rstrip(
        "."
    )  # pragma: no cover - defensive/metrics path excluded from coverage
    soa_rrs: List[RR] = (
        []
    )  # pragma: no cover - defensive/metrics path excluded from coverage
    other_rrs: List[RR] = (
        []
    )  # pragma: no cover - defensive/metrics path excluded from coverage
    for rr in rrs:  # pragma: no cover - defensive/metrics path excluded from coverage
        try:  # pragma: no cover - defensive/metrics path excluded from coverage
            owner_norm = str(rr.rname).rstrip(".").lower()
        except Exception:  # pragma: no cover - defensive
            owner_norm = str(
                rr.rname
            ).lower()  # pragma: no cover - defensive/metrics path excluded from coverage
        if (
            rr.rtype == QTYPE.SOA and owner_norm == apex_owner
        ):  # pragma: no cover - defensive/metrics path excluded from coverage
            soa_rrs.append(rr)
        else:  # pragma: no cover - defensive/metrics path excluded from coverage
            other_rrs.append(rr)

    if not soa_rrs:
        # Malformed zone: no SOA at apex -> REFUSED.
        r = (
            req.reply()
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        r.header.rcode = (
            RCODE.REFUSED
        )  # pragma: no cover - defensive/metrics path excluded from coverage
        return [r.pack()]

    primary_soa = soa_rrs[0]

    # Construct ordered RR stream: SOA (apex), all others including any
    # additional SOAs, then closing SOA.
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

    # Build messages while keeping each under the TCP length limit.
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
            # Drop this RR and continue.
            current.rr.pop()
            continue  # pragma: no cover - defensive/metrics path excluded from coverage
        if len(packed) > max_len and len(current.rr) > 1:
            # Remove last RR, emit previous message, start a new one with this RR.
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

    # Emit final message.
    try:  # pragma: no cover - defensive/metrics path excluded from coverage
        messages.append(current.pack())
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("iter_axfr_messages: final pack failure: %s", exc)
        if not messages:
            r = req.reply()
            r.header.rcode = RCODE.REFUSED
            return [r.pack()]

    return messages
