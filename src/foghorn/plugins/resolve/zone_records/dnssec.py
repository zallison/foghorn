"""Brief: DNSSEC query-time helpers for zone records replies.

Inputs/Outputs:
  - Client DNSSEC capability detection, RRset reply building with DNSSEC material.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

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
        """Append RR to the answer section, optionally filtering RRSIGs.

        Inputs:
          - rr: Fully constructed dnslib.RR instance.

        Outputs:
          - None; mutates ``reply`` in-place by appending to the answer
            section. RRSIGs are suppressed entirely when DNSSEC is not
            requested via the DO bit.
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
    owner_rrsets: Dict[int, Tuple[int, List[str]]],
    zone_apex_name: str,
    name_index: Dict[str, Dict[int, Tuple[int, List[str]]]],
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
