from __future__ import annotations

import logging
import pathlib
from typing import Callable, Dict, List, Optional, Set, Tuple

import ipaddress  # reused by DNSSEC auto-sign helper when building PTRs, kept for future use
from dnslib import QTYPE, RR

from foghorn.dnssec import zone_helpers as _zone_helpers
from foghorn.servers.transports.axfr import AXFRError, axfr_transfer

logger = logging.getLogger(__name__)


def overlay_axfr_zones(
    mapping: Dict[Tuple[str, int], Tuple[int, List[str]]],
    name_index: Dict[str, Dict[int, Tuple[int, List[str]]]],
    zone_soa: Dict[str, Tuple[int, List[str]]],
    axfr_zones: List[Dict[str, object]],
    soa_code: Optional[int],
    dnssec_classified_axfr: Set[str],
    axfr_fn: Optional[Callable[..., List[RR]]] = None,
) -> None:
    """Brief: Overlay AXFR-backed zones onto existing mappings.

    Inputs:
      - mapping: Current (owner, qtype) -> (ttl, [values]) mapping.
      - name_index: Per-owner index owner -> qtype -> (ttl, [values]).
      - zone_soa: Mapping of apex -> (ttl, [soa_values]).
      - axfr_zones: Normalized axfr_zones configuration list from ZoneRecords.
      - soa_code: Numeric QTYPE code for SOA, or None when unavailable.
      - dnssec_classified_axfr: Set of apex names already DNSSEC-classified.
      - axfr_fn: Optional callable used to perform the AXFR transfer. When
        omitted, the module-level axfr_transfer import is used. ZoneRecords
        passes its own axfr_transfer attribute so tests can monkeypatch it.

    Outputs:
      - None; mapping, name_index, zone_soa and dnssec_classified_axfr
        are updated in-place with transferred RRsets and DNSSEC state.
    """

    if not axfr_zones:
        return

    for zone_cfg in axfr_zones:
        zone_name = zone_cfg.get("zone")  # type: ignore[assignment]
        upstreams = zone_cfg.get("upstreams") or []  # type: ignore[assignment]
        if not zone_name or not isinstance(upstreams, list):
            continue

        zone_text = str(zone_name).rstrip(".").lower()
        if not zone_text:
            continue

        transferred, last_error = _axfr_transfer_for_zone(zone_text, upstreams, axfr_fn)
        if not transferred:
            if last_error is not None:
                logger.warning(
                    "ZoneRecords AXFR: giving up on %s after error: %s",
                    zone_text,
                    last_error,
                )
            continue

        _classify_axfr_zone_dnssec(
            zone_text, transferred, zone_cfg, dnssec_classified_axfr
        )
        _merge_transferred_rrs_into_mappings(
            mapping,
            name_index,
            zone_soa,
            soa_code,
            zone_text,
            transferred,
        )


def _axfr_transfer_for_zone(
    zone_text: str,
    upstreams: List[Dict[str, object]],
    axfr_fn: Optional[Callable[..., List[RR]]] = None,
) -> Tuple[Optional[List[RR]], Optional[Exception]]:
    """Brief: Attempt AXFR transfer for a single zone from configured upstreams.

    Inputs:
      - zone_text: Normalized zone name (no trailing dot, lowercased).
      - upstreams: List of upstream configuration mappings.

    Outputs:
      - (transferred_rrs, last_error): the first successful RR list or None
        when all upstreams fail, together with the last AXFRError raised.
    """

    transferred: Optional[List[RR]] = None
    last_error: Optional[Exception] = None

    # Prefer an injected axfr_fn (for example, ZoneRecords.axfr_transfer which
    # tests can monkeypatch); fall back to the module-level axfr_transfer
    # import when no callable is provided.
    fn: Callable[..., List[RR]] = axfr_fn or axfr_transfer

    for m in upstreams:
        if not isinstance(m, dict):
            continue
        host = m.get("host")
        port = m.get("port", 53)
        timeout_ms = m.get("timeout_ms", 5000)
        transport = str(m.get("transport", "tcp")).lower()
        server_name = m.get("server_name")
        verify_flag = m.get("verify", True)
        ca_file = m.get("ca_file")
        if not host:
            continue
        try:
            port_i = int(port)
            timeout_i = int(timeout_ms)
        except (TypeError, ValueError):
            continue

        try:
            logger.info(
                "ZoneRecords AXFR: transferring %s from %s:%d via %s",
                zone_text,
                host,
                port_i,
                transport,
            )
            transferred = fn(
                str(host),
                port_i,
                zone_text,
                transport=transport,
                server_name=(str(server_name) if server_name is not None else None),
                verify=bool(verify_flag),
                ca_file=str(ca_file) if ca_file is not None else None,
                connect_timeout_ms=timeout_i,
                read_timeout_ms=timeout_i,
            )
            break
        except AXFRError as exc:
            last_error = exc
            logger.warning(
                "ZoneRecords AXFR: failed transfer for %s from %s:%d via %s: %s",
                zone_text,
                host,
                port_i,
                transport,
                exc,
            )

    return transferred, last_error


def _classify_axfr_zone_dnssec(
    zone_text: str,
    transferred: List[RR],
    zone_cfg: Dict[str, object],
    dnssec_classified_axfr: Set[str],
) -> None:
    """Brief: Classify DNSSEC state for an AXFR-backed zone.

    Inputs:
      - zone_text: Normalized zone apex.
      - transferred: List of RRs returned by AXFR.
      - zone_cfg: Single axfr_zones entry used for allow_no_dnssec.
      - dnssec_classified_axfr: Set of already-classified AXFR apexes.

    Outputs:
      - None; logs dnssec_state and updates dnssec_classified_axfr.
    """

    try:
        apex_owner = zone_text.rstrip(".")
        has_dnskey = False
        has_rrsig = False
        try:
            dnskey_code = int(QTYPE.DNSKEY)
        except Exception:  # pragma: no cover - defensive
            dnskey_code = 48
        try:
            rrsig_code = int(QTYPE.RRSIG)
        except Exception:  # pragma: no cover - defensive
            rrsig_code = 46

        for rr in transferred:
            try:
                owner_norm = str(rr.rname).rstrip(".").lower()
            except Exception:  # pragma: no cover - defensive
                owner_norm = str(rr.rname).lower()
            if owner_norm != apex_owner:
                continue
            if int(rr.rtype) == int(dnskey_code):
                has_dnskey = True
            if int(rr.rtype) == int(rrsig_code):
                has_rrsig = True

        if has_dnskey and has_rrsig:
            dnssec_state = "present"
        elif has_dnskey or has_rrsig:
            dnssec_state = "partial"
        else:
            dnssec_state = "none"

        allow_no_dnssec = bool(zone_cfg.get("allow_no_dnssec", True))  # type: ignore[arg-type]
        if dnssec_state in {"none", "partial"}:
            if not allow_no_dnssec:
                logger.warning(
                    "ZoneRecords AXFR: zone %s has dnssec_state=%s with "
                    "allow_no_dnssec=False; loading anyway",
                    zone_text,
                    dnssec_state,
                )
            else:
                logger.info(
                    "ZoneRecords AXFR: zone %s has dnssec_state=%s; "
                    "proceeding (allow_no_dnssec=True)",
                    zone_text,
                    dnssec_state,
                )
        else:
            logger.info(
                "ZoneRecords AXFR: zone %s has dnssec_state=present",
                zone_text,
            )
        dnssec_classified_axfr.add(zone_text)
    except Exception:  # pragma: no cover - defensive logging only
        logger.warning(
            "ZoneRecords AXFR: failed to classify DNSSEC state for %s",
            zone_text,
            exc_info=True,
        )


def _merge_transferred_rrs_into_mappings(
    mapping: Dict[Tuple[str, int], Tuple[int, List[str]]],
    name_index: Dict[str, Dict[int, Tuple[int, List[str]]]],
    zone_soa: Dict[str, Tuple[int, List[str]]],
    soa_code: Optional[int],
    zone_text: str,
    transferred: List[RR],
) -> None:
    """Brief: Merge transferred AXFR RRs into mapping, name_index, and zone_soa.

    Inputs:
      - mapping: (owner, qtype) -> (ttl, [values]) mapping to update.
      - name_index: owner -> qtype -> (ttl, [values]) index.
      - zone_soa: zone apex -> (ttl, [soa_values]) mapping.
      - soa_code: Numeric QTYPE code for SOA, or None.
      - zone_text: Human-readable zone label used for logging.
      - transferred: List of RRs from AXFR.

    Outputs:
      - None; updates all three mappings in place.
    """

    for rr in transferred:
        try:
            owner = str(rr.rname).rstrip(".").lower()
            qtype_code = int(rr.rtype)
            ttl = int(rr.ttl)
            value = str(rr.rdata)
        except Exception as exc:  # pragma: no cover - defensive parsing
            logger.warning(
                "Skipping RR %r from AXFR zone %s due to parse error: %s",
                rr,
                zone_text,
                exc,
            )
            continue

        key = (owner, int(qtype_code))
        existing = mapping.get(key)

        if existing is None:
            stored_ttl = ttl
            values_ax: List[str] = []
        else:
            stored_ttl, values_ax = existing

        if value not in values_ax:
            values_ax.append(value)

        mapping[key] = (stored_ttl, values_ax)

        per_name_ax = name_index.setdefault(owner, {})
        per_name_ax[int(qtype_code)] = (stored_ttl, values_ax)

        if (
            soa_code is not None
            and int(qtype_code) == int(soa_code)
            and owner not in zone_soa
        ):
            zone_soa[owner] = (stored_ttl, values_ax)


def _classify_local_zones_dnssec(
    name_index: Dict[str, Dict[int, Tuple[int, List[str]]]],
    zone_soa: Dict[str, Tuple[int, List[str]]],
    dnssec_classified_axfr: Set[str],
) -> None:
    """Brief: Classify DNSSEC state for zones built from local sources.

    Inputs:
      - name_index: owner -> qtype -> (ttl, [values]) index.
      - zone_soa: zone apex -> (ttl, [soa_values]) mapping.
      - dnssec_classified_axfr: Set of apexes already classified via AXFR.

    Outputs:
      - None; logs dnssec_state for each local zone apex and updates no other
        state.
    """

    try:
        try:
            dnskey_code_all = int(QTYPE.DNSKEY)
        except Exception:  # pragma: no cover - defensive
            dnskey_code_all = 48
        try:
            rrsig_code_all = int(QTYPE.RRSIG)
        except Exception:  # pragma: no cover - defensive
            rrsig_code_all = 46

        for apex_owner in list(zone_soa.keys()):
            if apex_owner in dnssec_classified_axfr:
                continue
            owner_rrsets = name_index.get(apex_owner, {}) or {}
            has_dnskey = int(dnskey_code_all) in owner_rrsets
            has_rrsig = int(rrsig_code_all) in owner_rrsets
            if has_dnskey and has_rrsig:
                dnssec_state = "present"
            elif has_dnskey or has_rrsig:
                dnssec_state = "partial"
            else:
                dnssec_state = "none"
            logger.info(
                "ZoneRecords zone %s has dnssec_state=%s (file/bind/inline)",
                apex_owner,
                dnssec_state,
            )
    except Exception:  # pragma: no cover - defensive logging only
        logger.warning(
            "ZoneRecords: failed to classify DNSSEC state for local zones",
            exc_info=True,
        )


def dnssec_postprocess_zones(
    mapping: Dict[Tuple[str, int], Tuple[int, List[str]]],
    name_index: Dict[str, Dict[int, Tuple[int, List[str]]]],
    zone_soa: Dict[str, Tuple[int, List[str]]],
    dnssec_classified_axfr: Set[str],
    dnssec_cfg_raw: Optional[dict],
) -> Dict[int, Dict[str, List[RR]]]:
    # Brief: Classify and optionally auto-sign zones, then build DNSSEC helpers.
    #
    # Inputs:
    #   - mapping: (owner, qtype) -> (ttl, [values]) mapping.
    #   - name_index: owner -> qtype -> (ttl, [values]) index.
    #   - zone_soa: zone apex -> (ttl, [soa_values]) mapping.
    #   - dnssec_classified_axfr: Set of apexes already classified via AXFR.
    #   - dnssec_cfg_raw: Raw dnssec_signing config dict (or None).
    #
    # Outputs:
    #   - mapping_by_qtype: qtype -> owner -> list[RR] helper mapping including
    #     attached RRSIGs, suitable for use at query time.

    _classify_local_zones_dnssec(name_index, zone_soa, dnssec_classified_axfr)

    enabled = False
    if isinstance(dnssec_cfg_raw, dict):
        enabled = bool(dnssec_cfg_raw.get("enabled", False))
    if enabled and isinstance(dnssec_cfg_raw, dict):
        _zone_helpers.auto_sign_zones(
            mapping,
            name_index,
            zone_soa,
            dnssec_cfg_raw,
            log=logger,
        )

    return _zone_helpers.build_dnssec_helper_mapping(mapping, log=logger)
