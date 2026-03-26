"""Brief: Query resolution and reply building for zone records.

Inputs/Outputs:
  - DNS query handling with authoritative zone semantics and DNSSEC support.
"""

from __future__ import annotations

import contextlib
import logging
from typing import List, Optional, Tuple

from dnslib import OPCODE, QTYPE, RCODE, DNSHeader, DNSRecord

from foghorn.plugins.resolve.base import PluginContext, PluginDecision

from . import dnssec, helpers, update_processor

logger = logging.getLogger(__name__)
_DEFAULT_ANY_ANSWER_RRSET_LIMIT = 16
_DEFAULT_ANY_ANSWER_RECORD_LIMIT = 64


def _get_any_query_policy(plugin: object) -> Tuple[bool, int, int]:
    """Brief: Resolve ZoneRecords QTYPE=ANY policy and limits from plugin state.

    Inputs:
      - plugin: ZoneRecords plugin instance.

    Outputs:
      - Tuple of (enabled, rrset_limit, record_limit).
    """
    config = getattr(plugin, "config", {}) or {}
    enabled = bool(
        getattr(plugin, "_any_query_enabled", config.get("any_query_enabled", False))
    )
    rrset_limit = getattr(
        plugin,
        "_any_answer_rrset_limit",
        config.get("any_answer_rrset_limit", _DEFAULT_ANY_ANSWER_RRSET_LIMIT),
    )
    record_limit = getattr(
        plugin,
        "_any_answer_record_limit",
        config.get("any_answer_record_limit", _DEFAULT_ANY_ANSWER_RECORD_LIMIT),
    )
    try:
        rrset_limit_int = max(1, int(rrset_limit))
    except (TypeError, ValueError):
        rrset_limit_int = _DEFAULT_ANY_ANSWER_RRSET_LIMIT
    try:
        record_limit_int = max(1, int(record_limit))
    except (TypeError, ValueError):
        record_limit_int = _DEFAULT_ANY_ANSWER_RECORD_LIMIT
    return enabled, rrset_limit_int, record_limit_int


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


def _get_reverse_ptr_values(
    plugin: object,
    reverse_owner: str,
    ptr_qtype: int,
) -> List[str]:
    """Brief: Read PTR values for one reverse owner from ZoneRecords state.

    Inputs:
      - plugin: ZoneRecords plugin instance.
      - reverse_owner: Normalized reverse owner (in-addr.arpa/ip6.arpa).
      - ptr_qtype: Numeric PTR qtype code.

    Outputs:
      - list[str]: PTR rdata values for the owner, or an empty list.
    """
    lock = getattr(plugin, "_records_lock", None)
    lock_context = lock if lock is not None else contextlib.nullcontext()
    with lock_context:
        records = getattr(plugin, "records", {}) or {}
        entry = records.get((reverse_owner, int(ptr_qtype)))

    if entry is None:
        return []

    try:
        _ttl, values, _sources = entry
    except (ValueError, TypeError):
        try:
            _ttl, values = entry
        except (ValueError, TypeError):
            return []

    if isinstance(values, (list, tuple, set)):
        items = list(values)
    else:
        items = [values]

    out: List[str] = []
    for item in items:
        text = str(item).strip()
        if text:
            out.append(text)
    return out


def _targets_match_reverse_ptr_hostname(
    plugin: object,
    ctx: PluginContext,
    reverse_owner: str,
    qtype: int,
) -> bool:
    """Brief: Check domain targeting against PTR target hostnames.

    Inputs:
      - plugin: ZoneRecords plugin instance.
      - ctx: PluginContext for the active query.
      - reverse_owner: Queried reverse owner name.
      - qtype: Query qtype integer.

    Outputs:
      - bool: True when any PTR target hostname satisfies plugin targets().
    """
    from foghorn.utils import dns_names

    try:
        ptr_code = int(QTYPE.PTR)
    except Exception:  # pragma: no cover - defensive
        ptr_code = 12

    if int(qtype) != int(ptr_code):
        return False

    reverse_name = dns_names.normalize_name(reverse_owner)
    if not (
        reverse_name.endswith(".in-addr.arpa") or reverse_name.endswith(".ip6.arpa")
    ):
        return False

    domains_cfg = list(getattr(plugin, "_targets_domains", []) or [])
    domains_mode = str(getattr(plugin, "_targets_domains_mode", "any") or "any")
    if not domains_cfg or domains_mode == "any":
        return False

    ptr_values = _get_reverse_ptr_values(plugin, reverse_name, int(ptr_code))
    if not ptr_values:
        return False

    original_qname = getattr(ctx, "qname", None)
    try:
        for value in ptr_values:
            target_name = dns_names.normalize_name(value)
            if not target_name:
                continue
            setattr(ctx, "qname", target_name)
            if bool(plugin.targets(ctx)):
                return True
    except Exception:
        return False
    finally:
        try:
            setattr(ctx, "qname", original_qname)
        except Exception:  # pragma: no cover - defensive
            pass
    return False


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

        from foghorn.utils import dns_names

        zone_norm = dns_names.normalize_name(qname)
        zone_cfg = None
        for z in dns_update_cfg.get("zones", []) or []:
            if not isinstance(z, dict):
                continue
            apex = dns_names.normalize_name(z.get("zone", ""))
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
    from foghorn.utils import dns_names

    name = dns_names.normalize_name(qname)

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
            if not _targets_match_reverse_ptr_hostname(plugin, ctx, name, qtype_int):
                return None
    except Exception:  # pragma: no cover - defensive
        logger.warning(
            "ZoneRecords: targets() evaluation failed; skipping plugin for safety",
            exc_info=True,
        )
        return None
    logger.debug("pre-resolve zone-records %s %s", name, type_name)
    any_queries_enabled, any_rrset_limit, any_record_limit = _get_any_query_policy(
        plugin
    )

    # Safe concurrent read from mappings when a watcher may be reloading.
    lock = getattr(plugin, "_records_lock", None)
    lock_context = lock if lock is not None else contextlib.nullcontext()

    with lock_context:
        records = getattr(plugin, "records", {})
        name_index = getattr(plugin, "_name_index", {})
        zone_soa = getattr(plugin, "_zone_soa", {})
        mapping_by_qtype = getattr(plugin, "mapping", None)
        nsec3_index = getattr(plugin, "_nsec3_index", None)
        wildcard_owners = getattr(plugin, "_wildcard_owners", None)
        zone_suffix_index = getattr(plugin, "_zone_suffix_index", None)

        zone_apex = helpers.find_zone_for_name(
            name, zone_soa, zone_index=zone_suffix_index
        )

        # If this name is not covered by any authoritative zone, preserve the
        # legacy exact-match override behaviour keyed by (name, qtype), *unless*
        # nxdomain_zones is configured to force NXDOMAIN/NODATA under specific
        # suffixes.
        if zone_apex is None:
            key = (name, qtype_int)
            entry = records.get(key)

            # If there's no exact match, try wildcard owners.
            if not entry:
                matched_owner, rrsets = helpers.find_best_rrsets_for_name(
                    name, name_index, wildcard_patterns=wildcard_owners
                )
                if matched_owner is not None and qtype_int in (rrsets or {}):
                    entry = rrsets[qtype_int]

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
                        zone_norm = dns_names.normalize_name(z)
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
                    DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, ad=0),
                    q=request.q,
                )
                owner = f"{dns_names.normalize_name(request.q.qname)}."

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
                        if not any_queries_enabled:
                            reply.header.rcode = RCODE.REFUSED
                            return PluginDecision(
                                action="override", response=reply.pack()
                            )
                        added_any = False
                        rrset_count = 0
                        record_count = 0
                        truncated = False
                        for rr_qtype, (ttl_rr, values_rr, _) in rrsets.items():
                            if not want_dnssec_nx and dnssec.is_dnssec_rrtype(rr_qtype):
                                continue
                            if (
                                rrset_count >= any_rrset_limit
                                or record_count >= any_record_limit
                            ):
                                truncated = True
                                break
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
                                rrset_count += 1
                                record_count += len(list(values_rr))
                        if truncated:
                            reply.header.tc = 1
                        if not added_any and not truncated:
                            return None
                        if want_dnssec_nx and not truncated:
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
                            qtype_int,
                            matched_zone,
                            records,
                            name_index,
                            mapping_by_qtype=mapping_by_qtype,
                            nsec3_index=nsec3_index,
                        )

                    return PluginDecision(action="override", response=reply.pack())

                # Name does not exist under the configured suffix.
                reply.header.rcode = RCODE.NXDOMAIN
                return PluginDecision(action="override", response=reply.pack())

            ttl, values, _ = entry
            logger.debug(
                "ZoneRecords got entry for %s %s -> %s", name, type_name, values
            )

            try:
                request = DNSRecord.parse(req)
            except Exception as e:  # pragma: no cover - defensive parsing
                logger.warning("ZoneRecords parse failure: %s", e)
                return None

            want_dnssec_legacy = dnssec.client_wants_dnssec(request)

            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, ad=0), q=request.q
            )
            owner = f"{dns_names.normalize_name(request.q.qname)}."
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

        owner = f"{dns_names.normalize_name(request.q.qname)}."
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, ad=0), q=request.q
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
            effective_mapping_by_qtype = (
                None if update_sourced_rrsets else mapping_by_qtype
            )

            # Positive answers for specific qtypes.
            if qtype_int == int(QTYPE.ANY):
                if not any_queries_enabled:
                    reply.header.rcode = RCODE.REFUSED
                    return PluginDecision(action="override", response=reply.pack())
                added_any = False
                rrset_count = 0
                record_count = 0
                truncated = False
                for rr_qtype, (ttl_rr, values_rr, _) in rrsets.items():
                    # For QTYPE=ANY with DO=0, suppress DNSSEC-only RR types
                    if not want_dnssec and dnssec.is_dnssec_rrtype(rr_qtype):
                        continue
                    if (
                        rrset_count >= any_rrset_limit
                        or record_count >= any_record_limit
                    ):
                        truncated = True
                        break
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
                        rrset_count += 1
                        record_count += len(list(values_rr))
                if truncated:
                    reply.header.tc = 1
                if not added_any and not truncated:
                    return None
                if want_dnssec and not truncated:
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
                soa_owner = f"{dns_names.normalize_name(zone_apex)}."

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
                            nsec3_index=nsec3_index,
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
            soa_owner = f"{dns_names.normalize_name(zone_apex)}."

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
                    nsec3_index=nsec3_index,
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
