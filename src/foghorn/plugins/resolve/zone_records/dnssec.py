"""Brief: DNSSEC query-time helpers for zone records replies.

Inputs/Outputs:
  - Client DNSSEC capability detection, RRset reply building with DNSSEC material.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set, Tuple

from dnslib import QTYPE, RR, DNSRecord

logger = logging.getLogger(__name__)


def client_wants_dnssec(request: object) -> bool:
    """Brief: Detect whether the client wants DNSSEC records via EDNS(0) DO bit.

    Inputs:
      - request: Parsed DNSRecord or raw bytes from the client query.

    Outputs:
      - bool: True if the client sent an OPT RR with DO=1, False otherwise.
    """
    try:
        # Support both parsed DNSRecord and raw bytes.
        if isinstance(request, (bytes, bytearray)):
            request = DNSRecord.parse(request)

        for rr in getattr(request, "ar", None) or []:
            if getattr(rr, "rtype", None) != QTYPE.OPT:
                continue
            # EDNS flags are encoded in the TTL field of the OPT RR.
            # DO bit is bit 15 (0x8000) of the flags portion (lower 16 bits).
            ttl_val = int(getattr(rr, "ttl", 0) or 0)
            flags = ttl_val & 0xFFFF
            if flags & 0x8000:
                return True
    except Exception:  # pragma: no cover - defensive
        pass
    return False


def add_rrset_to_reply(
    reply: DNSRecord,
    owner_name: str,
    rr_qtype: int,
    ttl: int,
    values: List[str],
    include_dnssec: bool,
    mapping_by_qtype: Optional[Dict[int, Dict[str, List[RR]]]] = None,
    *,
    section: str = "answer",
) -> bool:
    """Brief: Append an RRset (and any attached RRSIGs) to a DNS reply.

    Inputs:
      - reply: DNSRecord being built.
      - owner_name: Owner name (with trailing dot preferred but not required).
      - rr_qtype: Numeric RR type code for the RRset.
      - ttl: TTL to apply to constructed RRs.
      - values: List of presentation-format rdata strings.
      - include_dnssec: When False, suppress RRSIGs unless the caller
        explicitly handles DNSSEC-only queries.
      - mapping_by_qtype: Optional pre-built mapping of qtype -> owner -> [RRs]
        for DNSSEC material. When present, used instead of textual fallback.

    Outputs:
      - bool: True when at least one RR was added to the reply.
    """
    owner_key = str(owner_name).rstrip(".").lower()
    added_any = False

    # Determine the numeric RRSIG type code once so we can reliably
    # distinguish signature RRs from their covered RRsets when adding
    # them to the reply sections.
    try:
        rrsig_code_local = int(QTYPE.RRSIG)
    except Exception:  # pragma: no cover - defensive
        rrsig_code_local = 46

    def _add_rr_to_reply(rr: RR) -> None:
        """Append RR to the selected reply section, optionally filtering RRSIGs.

        Inputs:
          - rr: Fully constructed dnslib.RR instance.

        Outputs:
          - None; mutates ``reply`` in-place by appending to the selected
            section (answer/authority/additional). RRSIGs are suppressed
            entirely when DNSSEC is not requested via the DO bit.
        """
        try:
            rr_type_int = int(getattr(rr, "rtype", 0))
        except Exception:  # pragma: no cover - defensive
            rr_type_int = 0

        # When the client has not requested DNSSEC (DO=0) and the RR is
        # an RRSIG, suppress the signature entirely in order to comply
        # with RFC 4035 section 3.2. We still honour explicit DNSSEC
        # queries (for example, QTYPE=RRSIG) by passing
        # include_dnssec=True from the call site in those cases.
        if rr_type_int == rrsig_code_local and not include_dnssec:
            return

        if section == "answer":
            reply.add_answer(rr)
        elif section in {"auth", "authority"}:
            reply.add_auth(rr)
        elif section in {"ar", "additional"}:
            reply.add_ar(rr)
        else:  # pragma: no cover - defensive
            reply.add_answer(rr)

    # Prefer the helper mapping constructed at load time when present.
    if isinstance(mapping_by_qtype, dict):
        by_name = mapping_by_qtype.get(int(rr_qtype), {}) or {}
        rrs = by_name.get(owner_key)
        if rrs:
            for rr in list(rrs):
                _add_rr_to_reply(rr)
                added_any = True

    if added_any:
        return True

    # Fallback: construct RRs from textual TTL/value pairs as before.
    rr_type_name = QTYPE.get(rr_qtype, str(rr_qtype))
    for value in values:
        zone_line = f"{owner_name} {ttl} IN {rr_type_name} {value}"
        try:
            rrs = RR.fromZone(zone_line)
        except Exception as exc:  # pragma: no cover - invalid record value
            logger.warning(
                "ZoneRecords invalid value %r for qtype %s: %s",
                value,
                rr_type_name,
                exc,
            )
            continue
        for rr in rrs:
            _add_rr_to_reply(rr)
            added_any = True
    return added_any


def _find_closest_encloser(
    qname: str,
    zone_apex: str,
    name_index: Dict[str, Dict[int, Tuple[int, List[str], Set[str]]]],
) -> str:
    """Brief: Find the closest existing ancestor name inside a zone.

    Inputs:
      - qname: Normalized queried name (no trailing dot, lowercased).
      - zone_apex: Normalized zone apex (no trailing dot, lowercased).
      - name_index: Mapping of existing owner names -> RRsets.

    Outputs:
      - Closest encloser name inside the zone (at minimum the zone apex).
    """

    candidate = str(qname).rstrip(".").lower()
    apex = str(zone_apex).rstrip(".").lower()

    while candidate and candidate != apex:
        if candidate in name_index:
            return candidate
        if "." not in candidate:
            break
        candidate = candidate.split(".", 1)[1]

    return apex


def add_nsec3_denial_of_existence(
    reply: DNSRecord,
    qname: str,
    zone_apex: str,
    records: Dict[Tuple[str, int], Tuple[int, List[str], Set[str]]],
    name_index: Dict[str, Dict[int, Tuple[int, List[str], Set[str]]]],
    mapping_by_qtype: Optional[Dict[int, Dict[str, List[RR]]]] = None,
) -> None:
    """Brief: Add NSEC3 proof material to an authoritative negative response.

    Inputs:
      - reply: DNS reply to mutate (adds records to the authority section).
      - qname: Normalized queried name (no trailing dot, lowercased).
      - zone_apex: Normalized zone apex (no trailing dot, lowercased).
      - records: (owner,qtype)->(ttl,[values]) mapping used by ZoneRecords.
      - name_index: owner->qtype->(ttl,[values]) index used by ZoneRecords.
      - mapping_by_qtype: Optional helper mapping with pre-built dnslib RR
        instances (base RRsets + covering RRSIGs).

    Outputs:
      - None; appends NSEC3 (and their RRSIGs) into ``reply.auth``.

    Notes:
      - This function is only meaningful when the zone has NSEC3PARAM and NSEC3
        RRsets (e.g. from DNSSEC auto-signing).
      - We include a minimal RFC 5155 proof set: closest encloser match, and
        covering NSEC3 for the next-closer name and for the wildcard under the
        closest encloser.
    """

    if not isinstance(mapping_by_qtype, dict):
        return

    try:
        nsec3_code = int(QTYPE.NSEC3)
    except Exception:  # pragma: no cover - defensive
        nsec3_code = 50
    try:
        nsec3param_code = int(QTYPE.NSEC3PARAM)
    except Exception:  # pragma: no cover - defensive
        nsec3param_code = 51

    nsec3_by_name = mapping_by_qtype.get(int(nsec3_code), {}) or {}
    if not nsec3_by_name:
        return

    # Extract hashing parameters from apex-level NSEC3PARAM.
    param_entry = records.get((str(zone_apex), int(nsec3param_code)))
    if not param_entry:
        return

    try:
        _ttl_param, param_vals, _sources = param_entry
    except (ValueError, TypeError):
        # Legacy 2-tuple format
        _ttl_param, param_vals = param_entry
    if not param_vals:
        return

    try:
        p = str(param_vals[0]).split()
        alg = int(p[0])
        _flags = int(p[1])
        iterations = int(p[2])
        salt_text = str(p[3])
        if salt_text in {"", "-"}:
            salt_hash = ""
        else:
            # NSEC3PARAM salt is hex in presentation form.
            try:
                salt_hash = bytes.fromhex(salt_text)
            except Exception:
                salt_hash = str(salt_text)
    except Exception:
        return

    # Compute closest encloser and derived names.
    qn = str(qname).rstrip(".").lower()
    apex = str(zone_apex).rstrip(".").lower()

    is_nodata = qn in name_index

    if is_nodata:
        closest = qn
        next_closer = None
        wildcard = None
    else:
        closest = _find_closest_encloser(qn, apex, name_index)

        labels_q = qn.split(".") if qn else []
        labels_c = closest.split(".") if closest else []
        if len(labels_q) <= len(labels_c):
            return

        diff = len(labels_q) - len(labels_c)
        next_label = labels_q[diff - 1]
        next_closer = f"{next_label}.{closest}"
        wildcard = f"*.{closest}"

    try:
        import dns.dnssec as _dns_dnssec

        h_closest = _dns_dnssec.nsec3_hash(f"{closest}.", salt_hash, iterations, alg)
        h_next = (
            _dns_dnssec.nsec3_hash(f"{next_closer}.", salt_hash, iterations, alg)
            if next_closer
            else None
        )
        h_wc = (
            _dns_dnssec.nsec3_hash(f"{wildcard}.", salt_hash, iterations, alg)
            if wildcard
            else None
        )
    except Exception:
        return

    # Build sorted list of available hashes in this zone from the NSEC3 owner
    # names (first label is the hash).
    hash_to_owner: Dict[str, str] = {}
    for owner in nsec3_by_name.keys():
        try:
            owner_norm = str(owner).rstrip(".").lower()
        except Exception:
            continue
        if not owner_norm.endswith("." + apex):
            continue
        first = owner_norm.split(".", 1)[0]
        if first:
            hash_to_owner[first.upper()] = owner_norm

    if not hash_to_owner:
        return

    hashes_sorted = sorted(hash_to_owner.keys())

    def _covering_owner(target_hash: str) -> str:
        """Return the NSEC3 owner name whose interval covers target_hash.

        Inputs:
          - target_hash: Uppercase base32hex digest.

        Outputs:
          - Owner name (normalized, no trailing dot) of the covering NSEC3 RRset.
        """

        # Find the greatest hash <= target_hash; wrap to last on underflow.
        idx = 0
        for i, h in enumerate(hashes_sorted):
            if h <= target_hash:
                idx = i
            else:
                break
        return hash_to_owner[hashes_sorted[idx]]

    owners_to_add: List[str] = []

    exact_closest_owner = f"{str(h_closest).lower()}.{apex}"
    if exact_closest_owner in nsec3_by_name:
        owners_to_add.append(exact_closest_owner)
    else:
        owners_to_add.append(_covering_owner(str(h_closest).upper()))

    if h_next is not None:
        owners_to_add.append(_covering_owner(str(h_next).upper()))
    if h_wc is not None:
        owners_to_add.append(_covering_owner(str(h_wc).upper()))

    # De-dup while preserving order.
    seen: set[str] = set()
    for nsec3_owner in owners_to_add:
        if nsec3_owner in seen:
            continue
        seen.add(nsec3_owner)

        entry = records.get((nsec3_owner, int(nsec3_code)))
        if not entry:
            continue
        try:
            ttl, vals, _sources = entry
        except (ValueError, TypeError):
            # Legacy 2-tuple format
            ttl, vals = entry
        add_rrset_to_reply(
            reply,
            nsec3_owner + ".",
            int(nsec3_code),
            int(ttl),
            list(vals),
            include_dnssec=True,
            mapping_by_qtype=mapping_by_qtype,
            section="auth",
        )


def is_dnssec_rrtype(code: int) -> bool:
    """Brief: Return True when *code* represents a DNSSEC-related RR type.

    Inputs:
      - code: Numeric QTYPE code to classify.

    Outputs:
      - bool: True when *code* is one of the core DNSSEC RR types
        (DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, DS).
    """
    try:
        c = int(code)
    except Exception:  # pragma: no cover - defensive
        return False

    codes: List[int] = []
    try:
        codes.append(int(QTYPE.DNSKEY))
    except Exception:  # pragma: no cover - defensive
        codes.append(48)
    try:
        codes.append(int(QTYPE.RRSIG))
    except Exception:  # pragma: no cover - defensive
        codes.append(46)
    try:
        codes.append(int(QTYPE.NSEC))
    except Exception:  # pragma: no cover - defensive
        codes.append(47)
    try:
        codes.append(int(QTYPE.NSEC3))
    except Exception:  # pragma: no cover - defensive
        codes.append(50)
    try:
        codes.append(int(QTYPE.NSEC3PARAM))
    except Exception:  # pragma: no cover - defensive
        codes.append(51)
    try:
        codes.append(int(QTYPE.DS))
    except Exception:  # pragma: no cover - defensive
        codes.append(43)

    return c in set(codes)


def add_dnssec_rrsets(
    reply: DNSRecord,
    owner_name: str,
    owner_rrsets: Dict[int, Tuple[int, List[str], Set[str]]],
    zone_apex_name: str,
    name_index: Dict[str, Dict[int, Tuple[int, List[str], Set[str]]]],
    mapping_by_qtype: Optional[Dict[int, Dict[str, List[RR]]]] = None,
) -> None:
    """Brief: Append DNSSEC RRsets (DNSKEY/RRSIG) when present for an owner.

    Inputs:
      - reply: DNSRecord being built.
      - owner_name: Owner name with trailing dot.
      - owner_rrsets: RRsets dict for this owner.
      - zone_apex_name: Apex of the authoritative zone (no trailing dot).
      - name_index: Global name index used to look up apex-level DNSKEY RRsets.
      - mapping_by_qtype: Optional pre-built mapping used to attach RRSIGs to
        DNSKEY RRsets when available.

    Outputs:
      - None; mutates reply by adding DNSKEY (and their RRSIGs) when
        appropriate. Per-RRset RRSIGs for other types are attached via
        add_rrset_to_reply using the pre-built helper mapping.
    """
    owner_normalized = owner_name.rstrip(".").lower()

    # DNSKEY code is looked up defensively so tests that monkeypatch QTYPE
    # continue to behave as expected.
    try:
        dnskey_code = int(QTYPE.DNSKEY)
    except Exception:  # pragma: no cover - defensive
        dnskey_code = 48

    # At the zone apex, include DNSKEY RRsets when present; their
    # signatures will be attached by add_rrset_to_reply using the
    # pre-built mapping where available.
    if owner_normalized == zone_apex_name:
        apex_rrsets = name_index.get(zone_apex_name, {})
        if dnskey_code in apex_rrsets:
            try:
                ttl_dk, vals_dk, _sources = apex_rrsets[dnskey_code]
            except (ValueError, TypeError):
                ttl_dk, vals_dk = apex_rrsets[dnskey_code]
            add_rrset_to_reply(
                reply,
                owner_name,
                dnskey_code,
                ttl_dk,
                list(vals_dk),
                include_dnssec=True,
                mapping_by_qtype=mapping_by_qtype,
            )
