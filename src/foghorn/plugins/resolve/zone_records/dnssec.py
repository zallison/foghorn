"""Brief: DNSSEC query-time helpers for zone records replies.

Inputs/Outputs:
  - Client DNSSEC capability detection, RRset reply building with DNSSEC material.
"""

from __future__ import annotations

import bisect
import logging
from typing import Dict, List, Optional, Tuple

from dnslib import QTYPE, RR, DNSRecord
from foghorn.utils import dns_names
from foghorn.utils.register_caches import registered_lru_cache

try:  # pragma: no cover - optional dependency
    import dns.dnssec as _dns_dnssec
except Exception:  # pragma: no cover - optional dependency
    _dns_dnssec = None

logger = logging.getLogger(__name__)

NSEC3_MAX_ITERATIONS_SHA1 = 100
NSEC3_MAX_ITERATIONS_OTHER = 500
NSEC3_HASH_CACHE_SIZE = 2048
NSEC3_MAX_PROOF_RRSETS = 3


def _cap_nsec3_iterations(iterations: int, alg: int) -> tuple[int, bool]:
    """Brief: Clamp NSEC3 iterations to a safe upper bound per algorithm.

    Inputs:
      - iterations: Raw NSEC3 iteration count from zone data.
      - alg: NSEC3 hash algorithm number (RFC 5155).

    Outputs:
      - tuple[int, bool]: (capped_iterations, was_capped) where was_capped is
        True when the input exceeded the configured limit.
    """
    max_allowed = (
        int(NSEC3_MAX_ITERATIONS_SHA1)
        if int(alg) == 1
        else int(NSEC3_MAX_ITERATIONS_OTHER)
    )
    if iterations < 0:
        return 0, True
    if iterations > max_allowed:
        return max_allowed, True
    return iterations, False


@registered_lru_cache(maxsize=NSEC3_HASH_CACHE_SIZE)
def _nsec3_hash_cached(
    name_text: str,
    salt_value: object,
    iterations: int,
    alg: int,
) -> Optional[str]:
    """Brief: Compute (and cache) an NSEC3 hash for a given name.

    Inputs:
      - name_text: Absolute owner name with trailing dot.
      - salt_value: NSEC3 salt in bytes or presentation form string.
      - iterations: NSEC3 iteration count.
      - alg: NSEC3 hash algorithm number (RFC 5155).

    Outputs:
      - Optional[str]: Base32hex hash string, or None on failure.
    """
    if _dns_dnssec is None:
        return None
    return _dns_dnssec.nsec3_hash(name_text, salt_value, iterations, alg)


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
    owner_key = dns_names.normalize_name(owner_name)
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
    name_index: Dict[str, Dict[int, Tuple[int, List[str], object]]],
) -> str:
    """Brief: Find the closest existing ancestor name inside a zone.

    Inputs:
      - qname: Normalized queried name (no trailing dot, lowercased).
      - zone_apex: Normalized zone apex (no trailing dot, lowercased).
      - name_index: Mapping of existing owner names -> RRsets.

    Outputs:
      - Closest encloser name inside the zone (at minimum the zone apex).
    """

    candidate = dns_names.normalize_name(qname)
    apex = dns_names.normalize_name(zone_apex)

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
    qtype: int,
    zone_apex: str,
    records: Dict[Tuple[str, int], Tuple[int, List[str], object]],
    name_index: Dict[str, Dict[int, Tuple[int, List[str], object]]],
    mapping_by_qtype: Optional[Dict[int, Dict[str, List[RR]]]] = None,
    nsec3_index: Optional[Dict[str, Dict[str, object]]] = None,
) -> None:
    """Brief: Add NSEC3 proof material to an authoritative negative response.

    Inputs:
      - reply: DNS reply to mutate (adds records to the authority section).
      - qname: Normalized queried name (no trailing dot, lowercased).
      - qtype: Numeric RR type code from the original query.
      - zone_apex: Normalized zone apex (no trailing dot, lowercased).
      - records: (owner,qtype)->(ttl,[values]) mapping used by ZoneRecords.
      - name_index: owner->qtype->(ttl,[values]) index used by ZoneRecords.
      - mapping_by_qtype: Optional helper mapping with pre-built dnslib RR
        instances (base RRsets + covering RRSIGs).
      - nsec3_index: Optional precomputed NSEC3 owner/hash index keyed by apex.

    Outputs:
      - None; appends NSEC3 (and their RRSIGs) into ``reply.auth``.

    Notes:
      - For NXDOMAIN we include a minimal RFC 5155 proof set: closest encloser
        match, and covering NSEC3 for the next-closer name and for the wildcard
        under the closest encloser.
      - For NOERROR/NODATA we only include the *exact* NSEC3 for the queried
        name's hash (when present), and only when its type bitmap does not
        contain the queried RR type.
    """

    if not isinstance(mapping_by_qtype, dict):
        return

    def _nsec3_value_denies_qtype(value: str) -> bool:
        """Brief: Return True if an NSEC3 presentation value denies *qtype*.

        Inputs:
          - value: NSEC3 RDATA in presentation format.

        Outputs:
          - bool: True when we can parse the type bitmap and it does not contain
            the queried qtype; False when qtype appears in the bitmap or when
            parsing is inconclusive.
        """

        try:
            qtype_name = str(QTYPE.get(int(qtype), str(qtype))).upper()
        except Exception:  # pragma: no cover - defensive
            return False

        # If we cannot represent the queried type as a mnemonic, we cannot
        # reliably compare against the bitmap.
        if not qtype_name or qtype_name.isdigit():
            return False

        try:
            parts = str(value).split()
        except Exception:  # pragma: no cover - defensive
            return False

        # NSEC3 presentation format:
        #   alg flags iter salt next-hash type...
        if len(parts) < 6:
            return False

        bitmap_types = {p.upper() for p in parts[5:]}
        return qtype_name not in bitmap_types

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
    param_entry = records.get(
        (dns_names.normalize_name(zone_apex), int(nsec3param_code))
    )
    if not param_entry:
        return

    param_vals = param_entry[1]
    if not param_vals:
        return

    try:
        p = str(param_vals[0]).split()
        alg = int(p[0])
        _flags = int(p[1])
        iterations_input = p[2]
        iterations = int(iterations_input)
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
        logger.debug(
            "ZoneRecords: failed to parse NSEC3PARAM for zone %s",
            zone_apex,
            exc_info=True,
        )
        return

    iterations, was_capped = _cap_nsec3_iterations(int(iterations), int(alg))
    if was_capped:
        logger.warning(
            "ZoneRecords: NSEC3 iterations capped for zone %s (alg=%s): %s -> %s",
            zone_apex,
            alg,
            iterations_input if "iterations_input" in locals() else iterations,
            iterations,
        )

    # Compute closest encloser and derived names.
    qn = dns_names.normalize_name(qname)
    apex = dns_names.normalize_name(zone_apex)

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

    if _dns_dnssec is None:
        logger.debug("ZoneRecords: dnspython dnssec unavailable; skipping NSEC3 proofs")
        return

    try:
        h_closest = _nsec3_hash_cached(f"{closest}.", salt_hash, iterations, int(alg))
        h_next = (
            _nsec3_hash_cached(f"{next_closer}.", salt_hash, iterations, int(alg))
            if next_closer
            else None
        )
        h_wc = (
            _nsec3_hash_cached(f"{wildcard}.", salt_hash, iterations, int(alg))
            if wildcard
            else None
        )
    except Exception:
        logger.debug(
            "ZoneRecords: failed to compute NSEC3 hashes for zone %s",
            zone_apex,
            exc_info=True,
        )
        return

    if h_closest is None:
        return

    cache_entry = None
    if isinstance(nsec3_index, dict):
        cache_entry = nsec3_index.get(apex)

    if isinstance(cache_entry, dict):
        hash_to_owner = cache_entry.get("hash_to_owner")
        hashes_sorted = cache_entry.get("hashes_sorted")
    else:
        hash_to_owner = None
        hashes_sorted = None

    if not isinstance(hash_to_owner, dict) or not isinstance(hashes_sorted, list):
        # Build sorted list of available hashes in this zone from the NSEC3 owner
        # names (first label is the hash).
        hash_to_owner = {}
        for owner in nsec3_by_name.keys():
            owner_norm = dns_names.normalize_name(owner)
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
        idx = bisect.bisect_right(hashes_sorted, target_hash) - 1
        if idx < 0:
            idx = len(hashes_sorted) - 1
        return hash_to_owner[hashes_sorted[idx]]

    # For NOERROR/NODATA, only the *exact* NSEC3 RRset at the hashed owner name
    # can prove that a specific RRtype does not exist at an existing name.
    if is_nodata:
        exact_owner = f"{str(h_closest).lower()}.{apex}"
        if exact_owner not in nsec3_by_name:
            return

        entry_exact = records.get((exact_owner, int(nsec3_code)))
        if not entry_exact:
            return

        vals_exact = entry_exact[1] or []
        if not any(_nsec3_value_denies_qtype(v) for v in list(vals_exact)):
            return

        owners_to_add: List[str] = [exact_owner]
    else:
        owners_to_add = []

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
        if len(seen) >= int(NSEC3_MAX_PROOF_RRSETS):
            logger.debug(
                "ZoneRecords: NSEC3 proof owner cap reached for zone %s",
                zone_apex,
            )
            break
        seen.add(nsec3_owner)

        entry = records.get((nsec3_owner, int(nsec3_code)))
        if not entry:
            continue
        ttl = int(entry[0])
        vals = entry[1]
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
    owner_rrsets: Dict[int, Tuple[int, List[str], object]],
    zone_apex_name: str,
    name_index: Dict[str, Dict[int, Tuple[int, List[str], object]]],
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
    owner_normalized = dns_names.normalize_name(owner_name)

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
            entry = apex_rrsets[dnskey_code]
            ttl_dk = int(entry[0])
            vals_dk = entry[1]
            add_rrset_to_reply(
                reply,
                owner_name,
                dnskey_code,
                ttl_dk,
                list(vals_dk),
                include_dnssec=True,
                mapping_by_qtype=mapping_by_qtype,
            )
