"""Brief: Query resolution and reply building for zone records.

Inputs/Outputs:
  - DNS query handling with authoritative zone semantics and DNSSEC support.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from dnslib import OPCODE, QTYPE, RCODE, DNSHeader, DNSRecord

from foghorn.plugins.resolve.base import PluginContext, PluginDecision

from . import dnssec, helpers, update_processor

logger = logging.getLogger(__name__)


def _entry_has_update_source(entry: object) -> bool:
    """Brief: Determine whether an RRset entry is tagged as update-sourced.

    Inputs:
      - entry: RRset tuple in either 2-tuple or 3-tuple form.

    Outputs:
      - bool: True when the entry has "update" in its sources list/set.
    """
    try:
        _ttl, _values, sources = entry  # type: ignore[misc]
    except (ValueError, TypeError):
        return False
    if not isinstance(sources, (list, set)):
        return False
    return "update" in sources


def handle_opcode(
    plugin: object,
    opcode: int,
    qname: str,
    qtype: int,
    req: bytes,
    ctx: PluginContext,
) -> Optional[PluginDecision]:
    """Brief: Handle DNS UPDATE opcode for ZoneRecords.

    Inputs:
      - plugin: ZoneRecords plugin instance.
      - opcode: Numeric opcode from the DNS request header.
      - qname: Normalized zone name from the query.
      - qtype: Query type from the opcode dispatch path.
      - req: Raw wire-format request bytes.
      - ctx: PluginContext with client_ip, listener, etc.

    Outputs:
      - For NOTIFY opcodes: Delegates to ZoneRecords module-level
        _handle_notify_opcode() and returns its PluginDecision (or None).
      - For UPDATE opcodes: PluginDecision("override") with the wire response
        produced by update_processor.process_update_message(), when DNS UPDATE
        is enabled and the queried zone matches a configured update zone.
      - For all other opcodes: None.
    """
    if (
        int(opcode)
        == int(getattr(OPCODE, "NOTIFY", 4) if hasattr(OPCODE, "get") else 4)
        or int(opcode) == 4
    ):
        try:
            from foghorn.plugins.resolve.zone_records import _handle_notify_opcode
        except Exception:
            return None
        return _handle_notify_opcode(plugin, opcode, qname, qtype, req, ctx)
    # DNS UPDATE (RFC 2136)
    if (
        int(opcode)
        == int(getattr(OPCODE, "UPDATE", 5) if hasattr(OPCODE, "get") else 5)
        or int(opcode) == 5
    ):
        dns_update_cfg = getattr(plugin, "_dns_update_config", None)
        if not isinstance(dns_update_cfg, dict) or not bool(
            dns_update_cfg.get("enabled", False)
        ):
            return None

        zone_norm = str(qname).rstrip(".").lower()
        zone_cfg = None
        for z in dns_update_cfg.get("zones", []) or []:
            if not isinstance(z, dict):
                continue
            apex = str(z.get("zone", "")).rstrip(".").lower()
            if apex and apex == zone_norm:
                zone_cfg = z
                break

        if zone_cfg is None:
            return None

        try:
            listener = getattr(ctx, "listener", None)
        except Exception:
            listener = None

        try:
            client_ip = getattr(ctx, "client_ip", "")
        except Exception:
            client_ip = ""

        response_wire = update_processor.process_update_message(
            req,
            zone_apex=zone_norm,
            zone_config=zone_cfg,
            plugin=plugin,
            client_ip=str(client_ip),
            listener=str(listener) if listener is not None else None,
        )
        return PluginDecision(action="override", response=response_wire)

    return None


def pre_resolve(
    plugin: object,
    qname: str,
    qtype: int,
    req: bytes,
    ctx: PluginContext,
) -> Optional[PluginDecision]:
    """Brief: Decide whether to override resolution for a query.

    Inputs:
      - plugin: ZoneRecords plugin instance.
      - qname: Queried domain name.
      - qtype: DNS record type (numeric code).
      - req: Raw DNS request bytes.
      - ctx: Plugin context.

    Outputs:
      - PluginDecision("override") with an authoritative DNS response when
        this plugin should answer the query, or None to allow normal cache
        and upstream processing.

    Behaviour:
      - For names inside an authoritative zone (identified by SOA records
        in the records files), act as an authoritative server: apply
        correct CNAME and QTYPE.ANY semantics and synthesize NODATA and
        NXDOMAIN responses with SOA in the authority section.
      - For names outside any authoritative zone, preserve the historical
        behaviour by answering exact (name, qtype) entries and wildcard-owner
        matches from the in-memory name index, falling through to upstreams
        otherwise.
      - When nxdomain_zones is configured, names under matching suffixes are
        treated as authoritative even without an SOA, returning CNAME/positive
        answers, NODATA, or NXDOMAIN based on available RRsets.
      - When the client advertises EDNS(0) with DO=1, include RRSIG and
        DNSKEY RRsets from the zone data in positive answers.
    """
    # Normalize domain to a consistent lookup key.
    try:
        name = str(qname).rstrip(".").lower()
    except Exception:  # pragma: no cover - defensive
        name = str(qname).lower()

    qtype_int = int(qtype)
    type_name = QTYPE.get(qtype_int, str(qtype_int))

    # Attach qname to the context so BasePlugin can enforce domain-level
    # targeting (targets_domains/targets_domains_mode) via self.targets.
    try:
        if ctx is not None:
            setattr(ctx, "qname", qname)
    except Exception:  # pragma: no cover - defensive
        pass

    # Honour BasePlugin client/listener/domain targeting.
    try:
        if ctx is not None and not plugin.targets(ctx):
            return None
    except Exception:  # pragma: no cover - defensive
        logger.warning(
            "ZoneRecords: targets() evaluation failed; applying globally",
            exc_info=True,
        )
    logger.debug("pre-resolve zone-records %s %s", name, type_name)

    # Safe concurrent read from mappings when a watcher may be reloading.
    lock = getattr(plugin, "_records_lock", None)
    if lock is None:
        records = getattr(plugin, "records", {})
        name_index = getattr(plugin, "_name_index", {})
        zone_soa = getattr(plugin, "_zone_soa", {})
        mapping_by_qtype = getattr(plugin, "mapping", None)
        wildcard_owners = getattr(plugin, "_wildcard_owners", None)
    else:
        with lock:
            records = dict(getattr(plugin, "records", {}))
            name_index = dict(getattr(plugin, "_name_index", {}))
            zone_soa = dict(getattr(plugin, "_zone_soa", {}))
            mapping_by_qtype = dict(getattr(plugin, "mapping", {}) or {})
            wildcard_owners = list(getattr(plugin, "_wildcard_owners", []) or [])

    zone_apex = helpers.find_zone_for_name(name, zone_soa)

    # If this name is not covered by any authoritative zone, preserve the
    # legacy exact-match override behaviour keyed by (name, qtype), *unless*
    # nxdomain_zones is configured to force NXDOMAIN/NODATA under specific
    # suffixes.
    if zone_apex is None:
        key = (name, qtype_int)
        entry = records.get(key)

        # If entry has update source, return only update values
        if entry:
            try:
                ttl, values, sources = entry
            except (ValueError, TypeError):
                # Fallback to 2-tuple format for backward compatibility
                ttl, values = entry
                sources = set()
            # If "update" is in sources, filter to only update-sourced values
            if sources and "update" in (
                sources if isinstance(sources, (list, set)) else []
            ):
                # Keep all values since update source means all values from this RRset should be returned
                pass

        # If there's no exact match, try wildcard owners.
        if not entry:
            matched_owner, rrsets = helpers.find_best_rrsets_for_name(
                name, name_index, wildcard_patterns=wildcard_owners
            )
            if matched_owner is not None and qtype_int in (rrsets or {}):
                entry = rrsets[qtype_int]
                # Check sources in wildcard match entry too
                if entry:
                    try:
                        ttl, values, sources = entry
                    except (ValueError, TypeError):
                        ttl, values = entry
                        sources = set()
                    if sources and "update" in (
                        sources if isinstance(sources, (list, set)) else []
                    ):
                        # Only return update-sourced values
                        pass

        if not entry:
            # Optional: treat selected suffixes as authoritative NXDOMAIN/NODATA
            # zones even without an SOA.
            try:
                nxdomain_zones = list(getattr(plugin, "_nxdomain_zones", []) or [])
            except Exception:  # pragma: no cover - defensive
                nxdomain_zones = []

            matched_zone: Optional[str] = None
            if nxdomain_zones:
                for z in nxdomain_zones:
                    try:
                        zone_norm = str(z).rstrip(".").lower()
                    except Exception:
                        continue
                    if not zone_norm:
                        continue
                    if name == zone_norm or name.endswith("." + zone_norm):
                        matched_zone = zone_norm
                        break

            if matched_zone is None:
                return None

            try:
                request = DNSRecord.parse(req)
            except Exception as e:  # pragma: no cover - defensive parsing
                logger.warning("ZoneRecords parse failure (nxdomain_zones): %s", e)
                return None

            want_dnssec_nx = bool(dnssec.client_wants_dnssec(request))
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, ad=1), q=request.q
            )
            owner = str(request.q.qname).rstrip(".") + "."

            matched_owner_nx, rrsets = helpers.find_best_rrsets_for_name(
                name, name_index, wildcard_patterns=wildcard_owners
            )
            cname_code = int(QTYPE.CNAME)

            # CNAME at owner name: always answer with CNAME regardless of qtype.
            if cname_code in rrsets:
                ttl_cname, cname_values, _ = rrsets[cname_code]
                added = dnssec.add_rrset_to_reply(
                    reply,
                    owner,
                    cname_code,
                    ttl_cname,
                    list(cname_values),
                    include_dnssec=want_dnssec_nx,
                    mapping_by_qtype=mapping_by_qtype,
                )
                if not added:
                    return None
                if want_dnssec_nx:
                    dnssec.add_dnssec_rrsets(
                        reply,
                        owner,
                        rrsets,
                        matched_zone,
                        name_index,
                        mapping_by_qtype=mapping_by_qtype,
                    )
                return PluginDecision(action="override", response=reply.pack())

            if rrsets:
                # ANY query returns all RRsets at the owner.
                if qtype_int == int(QTYPE.ANY):
                    added_any = False
                    for rr_qtype, (ttl_rr, values_rr, _) in rrsets.items():
                        if not want_dnssec_nx and dnssec.is_dnssec_rrtype(rr_qtype):
                            continue
                        if dnssec.add_rrset_to_reply(
                            reply,
                            owner,
                            rr_qtype,
                            ttl_rr,
                            list(values_rr),
                            include_dnssec=want_dnssec_nx,
                            mapping_by_qtype=mapping_by_qtype,
                        ):
                            added_any = True
                    if not added_any:
                        return None
                    if want_dnssec_nx:
                        dnssec.add_dnssec_rrsets(
                            reply,
                            owner,
                            rrsets,
                            matched_zone,
                            name_index,
                            mapping_by_qtype=mapping_by_qtype,
                        )
                    return PluginDecision(action="override", response=reply.pack())

                # Exact qtype match.
                if qtype_int in rrsets:
                    ttl_rr, values_rr, _ = rrsets[qtype_int]
                    include_dnssec = want_dnssec_nx or dnssec.is_dnssec_rrtype(
                        qtype_int
                    )
                    if not dnssec.add_rrset_to_reply(
                        reply,
                        owner,
                        qtype_int,
                        ttl_rr,
                        list(values_rr),
                        include_dnssec=include_dnssec,
                        mapping_by_qtype=mapping_by_qtype,
                    ):
                        return None
                    if want_dnssec_nx:
                        dnssec.add_dnssec_rrsets(
                            reply,
                            owner,
                            rrsets,
                            matched_zone,
                            name_index,
                            mapping_by_qtype=mapping_by_qtype,
                        )
                    return PluginDecision(action="override", response=reply.pack())

                # Name exists under the configured suffix, but requested type is absent.
                reply.header.rcode = RCODE.NOERROR

                # DNSSEC denial-of-existence for wildcard-expanded answers is tricky,
                # and the NSEC3 proof logic assumes concrete owner names. Avoid
                # attaching NSEC3 when the rrsets came from a wildcard owner.
                if want_dnssec_nx and matched_owner_nx == name:
                    dnssec.add_nsec3_denial_of_existence(
                        reply,
                        name,
                        matched_zone,
                        records,
                        name_index,
                        mapping_by_qtype=mapping_by_qtype,
                    )

                return PluginDecision(action="override", response=reply.pack())

            # Name does not exist under the configured suffix.
            reply.header.rcode = RCODE.NXDOMAIN
            return PluginDecision(action="override", response=reply.pack())

        ttl, values, _ = entry
        logger.debug("ZoneRecords got entry for %s %s -> %s", name, type_name, values)

        try:
            request = DNSRecord.parse(req)
        except Exception as e:  # pragma: no cover - defensive parsing
            logger.warning("ZoneRecords parse failure: %s", e)
            return None

        want_dnssec_legacy = dnssec.client_wants_dnssec(request)

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, ad=1), q=request.q
        )
        owner = str(request.q.qname).rstrip(".") + "."
        # For update-sourced entries, bypass precomputed mapping_by_qtype because
        # it may still contain stale RR objects from file-based loads.
        effective_mapping_by_qtype = (
            None if _entry_has_update_source(entry) else mapping_by_qtype
        )

        added = dnssec.add_rrset_to_reply(
            reply,
            owner,
            qtype_int,
            ttl,
            list(values),
            include_dnssec=want_dnssec_legacy or False,
            mapping_by_qtype=effective_mapping_by_qtype,
        )
        if not added:
            return None

        return PluginDecision(action="override", response=reply.pack())

    # Authoritative path: name is inside a zone managed by this plugin.
    try:
        request = DNSRecord.parse(req)
    except Exception as e:  # pragma: no cover - defensive parsing
        logger.warning("ZoneRecords parse failure (authoritative path): %s", e)
        return None

    # Detect whether the client wants DNSSEC records via EDNS(0) DO bit.
    want_dnssec = bool(dnssec.client_wants_dnssec(request))

    owner = str(request.q.qname).rstrip(".") + "."
    reply = DNSRecord(
        DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, ad=1), q=request.q
    )

    matched_owner, rrsets = helpers.find_best_rrsets_for_name(
        name, name_index, wildcard_patterns=wildcard_owners
    )
    cname_code = int(QTYPE.CNAME)

    # CNAME at owner name: always answer with CNAME regardless of qtype.
    if cname_code in rrsets:
        ttl_cname, cname_values, _ = rrsets[cname_code]
        if len(rrsets) > 1:
            logger.warning(
                "CustomRecords zone %s has CNAME and other RRsets at %s; "
                "answering with CNAME only",
                zone_apex,
                name,
            )
        added = dnssec.add_rrset_to_reply(
            reply,
            owner,
            cname_code,
            ttl_cname,
            list(cname_values),
            include_dnssec=want_dnssec,
            mapping_by_qtype=mapping_by_qtype,
        )
        if not added:
            return None
        if want_dnssec:
            dnssec.add_dnssec_rrsets(
                reply,
                owner,
                rrsets,
                zone_apex,
                name_index,
                mapping_by_qtype=mapping_by_qtype,
            )
        return PluginDecision(action="override", response=reply.pack())

    # No CNAME at this owner; distinguish positive, NODATA, and NXDOMAIN.
    if rrsets:
        # Check if any RRset at this owner has update source - prioritize those
        update_sourced_rrsets = {}
        for qtype_key, (ttl_val, values_val, sources) in rrsets.items():
            if sources and "update" in (
                sources if isinstance(sources, (list, set)) else []
            ):
                update_sourced_rrsets[qtype_key] = rrsets[qtype_key]

        # Use only update-sourced RRsets if they exist for this owner
        if update_sourced_rrsets:
            rrsets = update_sourced_rrsets
        effective_mapping_by_qtype = None if update_sourced_rrsets else mapping_by_qtype

        # Positive answers for specific qtypes.
        if qtype_int == int(QTYPE.ANY):
            added_any = False
            for rr_qtype, (ttl_rr, values_rr, _) in rrsets.items():
                # For QTYPE=ANY with DO=0, suppress DNSSEC-only RR types
                if not want_dnssec and dnssec.is_dnssec_rrtype(rr_qtype):
                    continue
                if dnssec.add_rrset_to_reply(
                    reply,
                    owner,
                    rr_qtype,
                    ttl_rr,
                    list(values_rr),
                    include_dnssec=want_dnssec,
                    mapping_by_qtype=effective_mapping_by_qtype,
                ):
                    added_any = True
            if not added_any:
                return None
            if want_dnssec:
                dnssec.add_dnssec_rrsets(
                    reply,
                    owner,
                    rrsets,
                    zone_apex,
                    name_index,
                    mapping_by_qtype=effective_mapping_by_qtype,
                )
            return PluginDecision(action="override", response=reply.pack())

        if qtype_int in rrsets:
            ttl_rr, values_rr, _ = rrsets[qtype_int]
            # For DNSSEC RR types queried directly, always allow signatures.
            include_dnssec = want_dnssec or dnssec.is_dnssec_rrtype(qtype_int)
            if not dnssec.add_rrset_to_reply(
                reply,
                owner,
                qtype_int,
                ttl_rr,
                list(values_rr),
                include_dnssec=include_dnssec,
                mapping_by_qtype=effective_mapping_by_qtype,
            ):
                return None
            if want_dnssec:
                dnssec.add_dnssec_rrsets(
                    reply,
                    owner,
                    rrsets,
                    zone_apex,
                    name_index,
                    mapping_by_qtype=effective_mapping_by_qtype,
                )
            return PluginDecision(action="override", response=reply.pack())

        # NODATA: name exists in zone but requested type is absent.
        reply.header.rcode = RCODE.NOERROR
        soa_entry = zone_soa.get(zone_apex)
        if soa_entry is not None:
            soa_ttl, soa_values, _ = soa_entry
            soa_owner = zone_apex.rstrip(".") + "."

            if want_dnssec:
                dnssec.add_rrset_to_reply(
                    reply,
                    soa_owner,
                    int(QTYPE.SOA),
                    int(soa_ttl),
                    list(soa_values),
                    include_dnssec=True,
                    mapping_by_qtype=mapping_by_qtype,
                    section="auth",
                )

                # Avoid NSEC3 proofs for wildcard-expanded names (see note above).
                if matched_owner == name:
                    dnssec.add_nsec3_denial_of_existence(
                        reply,
                        name,
                        qtype_int,
                        zone_apex,
                        records,
                        name_index,
                        mapping_by_qtype=mapping_by_qtype,
                    )
            else:
                for value in list(soa_values):
                    zone_line = f"{soa_owner} {soa_ttl} IN SOA {value}"
                    try:
                        from dnslib import RR

                        rrs = RR.fromZone(zone_line)
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.warning(
                            "ZoneRecords invalid SOA value %r for zone %s: %s",
                            value,
                            zone_apex,
                            exc,
                        )
                        continue
                    for rr in rrs:
                        reply.add_auth(rr)

        return PluginDecision(action="override", response=reply.pack())

    # NXDOMAIN: no RRsets at this owner name within the authoritative zone.
    reply.header.rcode = RCODE.NXDOMAIN
    soa_entry = zone_soa.get(zone_apex)
    if soa_entry is not None:
        soa_ttl, soa_values, _ = soa_entry
        soa_owner = zone_apex.rstrip(".") + "."

        if want_dnssec:
            dnssec.add_rrset_to_reply(
                reply,
                soa_owner,
                int(QTYPE.SOA),
                int(soa_ttl),
                list(soa_values),
                include_dnssec=True,
                mapping_by_qtype=mapping_by_qtype,
                section="auth",
            )
            dnssec.add_nsec3_denial_of_existence(
                reply,
                name,
                qtype_int,
                zone_apex,
                records,
                name_index,
                mapping_by_qtype=mapping_by_qtype,
            )
        else:
            for value in list(soa_values):
                zone_line = f"{soa_owner} {soa_ttl} IN SOA {value}"
                try:
                    from dnslib import RR

                    rrs = RR.fromZone(zone_line)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "ZoneRecords invalid SOA value %r for zone %s: %s",
                        value,
                        zone_apex,
                        exc,
                    )
                    continue
                for rr in rrs:
                    reply.add_auth(rr)

    return PluginDecision(action="override", response=reply.pack())
