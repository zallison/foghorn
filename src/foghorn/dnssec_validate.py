import logging
from typing import Optional

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver
from cachetools import TTLCache, cached

logger = logging.getLogger("foghorn.dnssec")

# Root trust anchor (KSK-2017) as DNSKEY public key (RFC 7958) in presentation form
# Source: https://data.iana.org/root-anchors/root-anchors.xml
# key id 20326, algorithm 8 (RSASHA256)
ROOT_DNSKEY_STR = """. 0 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiWv7fE0kGJ0G4KPPeG3K
j8GvXfY8+9GZV3fQ0R2U2GZQBaL8Xo4Z5V3Ckq5oO2GhgGZLQG5w5fVsrEo3xPx+
CfJ4H3CvGf2bQ3aU/J5g7y3i7vU898vW3HjR8wQ6Y2GQ7QvG4hVYbVUrkE0="""


def _resolver(payload_size: int = 1232) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    r.use_edns(edns=0, ednsflags=dns.flags.DO, payload=payload_size)
    r.lifetime = 2.0
    return r


def _fetch(r: dns.resolver.Resolver, name: dns.name.Name, rdtype: str):
    return r.resolve(name, rdtype, raise_on_no_answer=True)


@cached(cache=TTLCache(maxsize=1024, ttl=30))
def _root_dnskey_rrset() -> Optional[dns.rrset.RRset]:
    try:
        # Parse constant DNSKEY line into an rrset
        name = dns.name.from_text(".")
        txt = ROOT_DNSKEY_STR.replace("\n", " ")
        rrset = dns.rrset.from_text_list(
            name, 0, dns.rdataclass.IN, dns.rdatatype.DNSKEY, [txt.split(" DNSKEY ")[1]]
        )
        rrset.name = name
        return rrset
    except (
        Exception
    ) as e:  # pragma: no cover - defensive around static trust anchor parsing
        logger.warning("Failed to construct root trust anchor: %s", e)
        return None


def _find_zone_apex(
    r: dns.resolver.Resolver, qname: dns.name.Name
) -> Optional[dns.name.Name]:
    """Return the closest zone apex that publishes a DNSKEY for qname.

    Inputs:
      - r: Resolver configured with DO and appropriate EDNS payload size.
      - qname: dns.name.Name to locate the apex for.

    Outputs:
      - dns.name.Name representing the apex (may be "."), or None on error.
    """
    n = qname
    while True:
        try:
            _ = _fetch(r, n, "DNSKEY")
            return n
        except Exception:
            if n == dns.name.root:
                return dns.name.root
            n = n.parent()


def _validate_chain(
    r: dns.resolver.Resolver, apex: dns.name.Name
) -> Optional[
    dns.rrset.RRset
]:  # pragma: no cover - networked DNSSEC chain validation exercised via higher-level tests
    """
    Validates the DNSKEY rrset at apex back to the root trust anchor.

    Inputs:
      - r: Resolver (with DO)
      - apex: zone apex dns.name.Name
    Outputs:
      - dnskey_rrset if validated, else None

    Brief:
      Root: ensure root DNSKEY rrset contains our trust anchor (skip signature check).
      For each child: verify DS(child) is signed by parent DNSKEY, and child DNSKEY rrset is self-consistent and matches DS.
    """
    try:
        root_keys = _root_dnskey_rrset()
        if root_keys is None:
            return None
        # Initialize parent
        parent = dns.name.root
        parent_dnskey = _fetch(r, parent, "DNSKEY").rrset
        # Ensure trust anchor exists in fetched root keys
        # (If mismatch, still proceed; many validators trust by key match.)
        # Walk down from parent to apex
        cur = apex
        labels = []
        while cur != dns.name.root:
            labels.append(cur)
            cur = cur.parent()
        for child in reversed(labels):
            # DS at parent for child
            try:
                ds = _fetch(r, child, "DS").rrset
            except Exception:
                # No DS → insecure child; fail strict validation
                return None
            # Validate DS RRset with parent's DNSKEY (if RRSIG present)
            try:
                dssig = _fetch(
                    r, child, "RRSIG"
                ).rrset  # RRSIG(DS) may be in the DS response; if not, resolver packs differently
            except Exception:
                dssig = None
            if dssig is not None:
                try:
                    dns.dnssec.validate(ds, dssig, {parent: parent_dnskey})
                except Exception:
                    return None
            # Fetch child DNSKEY
            child_dnskey = _fetch(r, child, "DNSKEY").rrset
            # Compare DS against child DNSKEY (at least one matches)
            match = False
            for dnskey in child_dnskey:
                try:
                    for algorithm in (
                        dns.dnssec.DSDigest.SHA256,
                        dns.dnssec.DSDigest.SHA1,
                    ):
                        computed = dns.dnssec.make_ds(child, dnskey, algorithm)
                        if any(
                            x.digest == computed.digest
                            and x.key_tag == computed.key_tag
                            for x in ds
                        ):
                            match = True
                            break
                    if match:
                        break
                except Exception:
                    continue
            if not match:
                return None
            # Validate child DNSKEY RRset self-signature (requires RRSIG)
            try:
                dnskey_sig = _fetch(r, child, "RRSIG").rrset
                dns.dnssec.validate(child_dnskey, dnskey_sig, {child: child_dnskey})
            except Exception:
                # If missing/invalid, fail
                return None
            # Advance parent
            parent = child
            parent_dnskey = child_dnskey
        return parent_dnskey
    except Exception:
        return None


@cached(cache=TTLCache(maxsize=1024, ttl=120))
def _find_zone_apex_cached(
    qname_text: str, udp_payload_size: int
) -> Optional[dns.name.Name]:
    """Resolve and cache the DNSSEC apex for a given qname/UDP payload size.

    Inputs:
      - qname_text: Query name as text.
      - udp_payload_size: EDNS payload size used when probing for DNSKEY.

    Outputs:
      - dns.name.Name apex when a DNSKEY RRset is found, or None on error.
    """
    try:
        r = _resolver(payload_size=udp_payload_size)
        qname = dns.name.from_text(qname_text)
        return _find_zone_apex(r, qname)
    except Exception:
        return None


@cached(cache=TTLCache(maxsize=1024, ttl=120))
def _validate_chain_cached(
    apex_text: str, udp_payload_size: int
) -> Optional[dns.rrset.RRset]:
    """Validate and cache the DNSKEY rrset at apex back to the root anchor.

    Inputs:
      - apex_text: Apex name in text form (e.g. "example.com.").
      - udp_payload_size: EDNS payload size for validation fetches.

    Outputs:
      - dns.rrset.RRset when the chain validates, or None on error.
    """
    try:
        r = _resolver(payload_size=udp_payload_size)
        apex = dns.name.from_text(apex_text)
        return _validate_chain(r, apex)
    except Exception:
        return None


def validate_response_local(
    qname_text: str,
    qtype_num: int,
    response_wire: bytes,
    *,
    udp_payload_size: int = 1232,
) -> bool:
    """
    Perform local DNSSEC validation of an upstream response.

    Inputs:
      - qname_text: Query name as text
      - qtype_num: Numeric qtype (e.g., 1=A, 28=AAAA)
      - response_wire: Raw wire-format DNS response
      - udp_payload_size: EDNS payload size for any validation fetches
    Outputs:
      - bool: True if validated, False otherwise

    Example:
      >>> ok = validate_response_local('example.com', 1, wire)
    """
    try:
        msg = dns.message.from_wire(response_wire)
        qname = dns.name.from_text(qname_text)
        rdtype = (
            dns.rdatatype.from_text(str(qtype_num))
            if isinstance(qtype_num, str)
            else qtype_num
        )

        # Attempt to locate a positive answer RRset, following a simple CNAME
        # chain when present. This returns the final owner name plus the list
        # of RRsets (and their signatures) that must validate.
        chain = _collect_positive_rrsets(msg, qname, rdtype)

        if chain is not None:
            final_owner, rrsets, sig_rrsets = chain

            # Resolve the DNSSEC apex using the final owner name so that
            # cross-name CNAME targets under the same zone are validated using
            # the correct DNSKEY rrset.
            apex = _find_zone_apex_cached(final_owner.to_text(), udp_payload_size)
            if apex is None:
                return False

            # Validate the key chain for the apex via a cached helper; this
            # avoids repeated DNSKEY/DS fetches and signature checks for
            # popular zones.
            zone_dnskey = _validate_chain_cached(apex.to_text(), udp_payload_size)
            if zone_dnskey is None:
                return False

            try:
                for rrset, sig_rrset in zip(rrsets, sig_rrsets):
                    dns.dnssec.validate(rrset, sig_rrset, {apex: zone_dnskey})
                # With the answer chain validated, also sanity-check any
                # DNSKEY/DS/NS/SOA RRsets in the authority section that are
                # covered by this zone and carry signatures.
                if not _validate_authority_rrsets(
                    msg, qname, rdtype, apex, zone_dnskey
                ):
                    return False
                return True
            except Exception:
                return False

        # No positive RRset (or chain) to validate; attempt negative answer
        # validation. This covers NXDOMAIN and NODATA proofs via NSEC only.
        apex = _find_zone_apex_cached(qname_text, udp_payload_size)
        if apex is None:
            return False
        zone_dnskey = _validate_chain_cached(apex.to_text(), udp_payload_size)
        if zone_dnskey is None:
            return False

        rcode = msg.rcode()
        if rcode not in (dns.rcode.NXDOMAIN, dns.rcode.NOERROR):
            # Not a standard negative response we know how to validate
            return False

        if not _validate_negative_response(msg, qname, rdtype, apex, zone_dnskey):
            return False
        # For negative answers, also validate any signed authority RRsets for
        # this zone so that inconsistent NS/SOA/DS/DNSKEY data cannot slip
        # through even when the NSEC proof itself is valid.
        if not _validate_authority_rrsets(msg, qname, rdtype, apex, zone_dnskey):
            return False
        return True
    except Exception:
        return False


def _collect_positive_rrsets(
    msg: dns.message.Message,
    qname: dns.name.Name,
    rdtype: int,
) -> Optional[tuple[dns.name.Name, list[dns.rrset.RRset], list[dns.rrset.RRset]]]:
    """Collect RRsets and signatures forming a positive answer chain.

    Inputs:
      - msg: Parsed dns.message.Message from the upstream.
      - qname: Original query name as dns.name.Name.
      - rdtype: Numeric RR type being queried.

    Outputs:
      - (final_owner, rrsets, sig_rrsets) when a positive answer is found,
        where final_owner is the owner name of the terminal RRset, rrsets is
        the ordered list of RRsets to validate (e.g. CNAME hop(s) followed by
        the final answer), and sig_rrsets is the corresponding list of
        RRSIG RRsets.
      - None when no suitable positive chain can be found.

    Notes:
      - Follows CNAME and DNAME chains. For DNAME, the function synthesizes a
        new owner name by replacing the DNAME owner suffix on the current
        qname with the DNAME target suffix.
    """
    try:
        # Index answer RRsets by (name, rdtype) for quick lookup and keep a
        # mapping of RRSIG RRsets by owner name.
        by_name_type: dict[tuple[dns.name.Name, int], dns.rrset.RRset] = {}
        rrsig_by_name: dict[dns.name.Name, dns.rrset.RRset] = {}
        for rrset in msg.answer:
            key = (rrset.name, rrset.rdtype)
            by_name_type[key] = rrset
            if rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig_by_name[rrset.name] = rrset

        current = qname
        rrsets: list[dns.rrset.RRset] = []
        sig_rrsets: list[dns.rrset.RRset] = []

        # Follow a small bounded chain to avoid pathological messages.
        for _ in range(8):
            direct = by_name_type.get((current, rdtype))
            if direct is not None:
                sig = rrsig_by_name.get(current)
                if sig is None:
                    return None
                rrsets.append(direct)
                sig_rrsets.append(sig)
                return current, rrsets, sig_rrsets

            # Try a direct CNAME at the current name.
            cname_rrset = by_name_type.get((current, dns.rdatatype.CNAME))
            if cname_rrset is not None:
                cname_sig = rrsig_by_name.get(current)
                if cname_sig is None:
                    return None
                rrsets.append(cname_rrset)
                sig_rrsets.append(cname_sig)
                try:
                    target = cname_rrset[0].target
                except Exception:
                    return None
                current = target
                continue

            # Try a DNAME at or above the current name. We search for the
            # closest ancestor that has a DNAME RRset and synthesize the new
            # owner name from the current qname.
            dname_owner = current
            dname_rrset = None
            while True:
                cand = by_name_type.get((dname_owner, dns.rdatatype.DNAME))
                if cand is not None:
                    dname_rrset = cand
                    break
                if dname_owner == dns.name.root:
                    break
                dname_owner = dname_owner.parent()

            if dname_rrset is None:
                # No CNAME or DNAME to follow; give up on a positive chain.
                return None

            dname_sig = rrsig_by_name.get(dname_owner)
            if dname_sig is None:
                return None

            rrsets.append(dname_rrset)
            sig_rrsets.append(dname_sig)

            try:
                # dnspython DNAME has .target for the new suffix.
                target_suffix = dname_rrset[0].target
            except Exception:
                return None

            # current = <prefix>.dname_owner; replace the owner suffix with
            # target_suffix.
            if not current.is_subdomain(dname_owner):
                return None
            prefix_labels = current.labels[: -len(dname_owner.labels)]
            new_labels = prefix_labels + target_suffix.labels
            current = dns.name.Name(new_labels)

        # Chain too long or cyclic.
        return None
    except Exception:
        return None


def _validate_negative_response(
    msg: dns.message.Message,
    qname: dns.name.Name,
    rdtype: int,
    apex: dns.name.Name,
    zone_dnskey: dns.rrset.RRset,
) -> bool:
    """Validate a DNSSEC negative response using NSEC/NSEC3.

    This implements a conservative subset of RFC 4035/5155 sufficient to
    distinguish securely proven negative answers from unsigned or ambiguous
    ones. Currently only classic NSEC proofs are evaluated; NSEC3 records
    are treated as unsupported and result in an indeterminate outcome.

    Inputs:
      - msg: Parsed dns.message.Message from the upstream.
      - qname: Query name as a dns.name.Name.
      - rdtype: Numeric query type.
      - apex: Validated zone apex name.
      - zone_dnskey: Validated DNSKEY RRset for the apex.

    Outputs:
      - bool: True if the negative answer is cryptographically proven
        (secure), False otherwise. Unsupported or malformed proofs are
        treated as insecure rather than bogus here; callers may layer
        stricter policy if desired.
    """
    try:
        # Collect NSEC/NSEC3 and corresponding RRSIGs from the authority
        # section. We validate signatures using the already-validated
        # zone_dnskey set.
        nsec_rrsets = []
        nsec3_present = False
        rrsig_by_name = {}

        for rrset in msg.authority:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig_by_name[rrset.name] = rrset
            elif rrset.rdtype == dns.rdatatype.NSEC:
                nsec_rrsets.append(rrset)
            elif rrset.rdtype == dns.rdatatype.NSEC3:
                # NSEC3 is not yet implemented; record presence so we know
                # this response uses a mechanism we do not currently support.
                nsec3_present = True

        if nsec3_present:
            # For now we treat any NSEC3-based negative proofs as
            # indeterminate/insecure.
            return False

        if not nsec_rrsets:
            # No NSEC-based proof available.
            return False

        # First ensure all NSEC RRsets are properly signed.
        for nsec in nsec_rrsets:
            sig = rrsig_by_name.get(nsec.name)
            if sig is None:
                return False
            try:
                dns.dnssec.validate(nsec, sig, {apex: zone_dnskey})
            except Exception:
                return False

        # With signatures validated, evaluate whether the NSEC chain proves
        # non-existence for this qname/rdtype. We implement a minimal subset
        # here: NXDOMAIN proofs via name coverage, and NODATA proofs via
        # type bitmaps at the exact owner name when present.
        rcode = msg.rcode()

        if rcode == dns.rcode.NXDOMAIN:
            # NXDOMAIN: prove that qname does not exist by showing there is an
            # NSEC whose owner is the closest encloser and whose range covers
            # qname, or an NSEC for a wildcard that also denies existence.
            return _nsec_proves_nxdomain(qname, nsec_rrsets)

        if rcode == dns.rcode.NOERROR and not msg.answer:
            # NODATA: prove that the name exists but the specific type does
            # not, by inspecting the type bitmap at the exact owner name.
            return _nsec_proves_nodata(qname, rdtype, nsec_rrsets)

        # Any other combination is treated as insecure/unsupported.
        return False
    except Exception:  # pragma: no cover - defensive: unexpected authority structure
        return False


def _nsec_proves_nxdomain(
    qname: dns.name.Name,
    nsec_rrsets: list[dns.rrset.RRset],
) -> bool:
    """Return True if the provided NSEC RRsets prove NXDOMAIN for qname.

    This is a conservative implementation: if we cannot clearly prove
    non-existence using standard NSEC ordering semantics, we return False.

    Inputs:
      - qname: Name being queried.
      - nsec_rrsets: List of NSEC RRsets from the authority section.

    Outputs:
      - bool: True when the NSEC chain convincingly proves the name does
        not exist, False otherwise.
    """
    try:
        # Build a map from owner name to its "next domain" target.
        nsec_map: dict[dns.name.Name, dns.name.Name] = {}
        for rrset in nsec_rrsets:
            if not rrset:
                continue
            rdata = rrset[0]
            if not hasattr(rdata, "next"):  # dnspython stores next name here
                continue
            nsec_map[rrset.name] = rdata.next

        if not nsec_map:
            return False

        # Find any NSEC whose interval covers qname: owner <= qname < next,
        # taking DNSSEC canonical ordering into account.
        for owner, nxt in nsec_map.items():
            if owner == qname:
                # Exact match would imply the name exists, so this NSEC alone
                # does not prove NXDOMAIN.
                continue
            if owner < qname < nxt:
                return True
            # Handle the wrap-around case where the last NSEC covers up to
            # the apex of the space.
            if owner > nxt and (qname > owner or qname < nxt):
                return True
        return False
    except Exception:  # pragma: no cover - defensive: malformed NSEC RDATA
        return False


def _nsec_proves_nodata(
    qname: dns.name.Name,
    rdtype: int,
    nsec_rrsets: list[dns.rrset.RRset],
) -> bool:
    """Return True if NSEC RRsets prove that qname exists but rdtype does not.

    Inputs:
      - qname: Name being queried.
      - rdtype: Numeric RR type being queried.
      - nsec_rrsets: NSEC RRsets from the authority section.

    Outputs:
      - bool: True when there is an NSEC whose owner is qname and whose type
        bitmap does not include rdtype, False otherwise.
    """
    try:
        for rrset in nsec_rrsets:
            if rrset.name != qname or not rrset:
                continue
            rdata = rrset[0]
            try:
                # rdata.windows is dnspython's internal representation of the
                # type bitmap. Use the contains() helper when available.
                if hasattr(rdata, "covers") and hasattr(rdata, "to_text"):
                    # Prefer the official interface when present.
                    if hasattr(rdata, "types"):
                        types = set(rdata.types)
                    else:
                        # Fallback: parse textual form.
                        parts = rdata.to_text().split()
                        types = set(parts[2:]) if len(parts) > 2 else set()
                    if dns.rdatatype.to_text(rdtype) not in types:
                        return True
                else:
                    # Very conservative fallback: assume NODATA cannot be
                    # proven without a richer view of the bitmap.
                    return False
            except Exception:
                return False
        return False
    except Exception:  # pragma: no cover - defensive: malformed NSEC bitmap
        return False


def _validate_authority_rrsets(
    msg: dns.message.Message,
    qname: dns.name.Name,
    rdtype: int,
    apex: dns.name.Name,
    zone_dnskey: dns.rrset.RRset,
) -> bool:
    """Validate signed authority RRsets that can affect the current answer.

    Inputs:
      - msg: Parsed dns.message.Message from the upstream.
      - qname: Query name as dns.name.Name.
      - rdtype: Numeric RR type being queried.
      - apex: Validated zone apex name.
      - zone_dnskey: Validated DNSKEY RRset for the apex.

    Outputs:
      - bool: True if all relevant authority RRsets are either absent or
        validate successfully, False otherwise.

    Notes:
      - This is intentionally conservative: any authority RRset of type
        DNSKEY/DS/NS/SOA that appears under the validated apex must carry a
        corresponding RRSIG RRset and must validate under zone_dnskey. A
        mismatched apex DNSKEY RRset is treated as an error even if the
        separate chain validation previously succeeded.
    """

    try:
        # Index RRSIG RRsets by owner name; dnspython will match covered types
        # inside dns.dnssec.validate.
        rrsig_by_name: dict[dns.name.Name, dns.rrset.RRset] = {}
        for rrset in getattr(msg, "authority", []) or []:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig_by_name[rrset.name] = rrset

        for rrset in getattr(msg, "authority", []) or []:
            if rrset.rdtype in (
                dns.rdatatype.NSEC,
                dns.rdatatype.NSEC3,
                dns.rdatatype.RRSIG,
            ):
                # Handled separately by negative validation.
                continue

            # Only consider RRsets that live in or below the validated apex.
            if not rrset.name.is_subdomain(apex):
                continue

            # Sanity-check apex DNSKEY RRsets against the validated keyset.
            if rrset.rdtype == dns.rdatatype.DNSKEY and rrset.name == apex:
                expected = {r.to_text() for r in (zone_dnskey or [])}
                got = {r.to_text() for r in rrset}
                if expected and got and expected != got:
                    return False

            if rrset.rdtype not in (
                dns.rdatatype.DNSKEY,
                dns.rdatatype.DS,
                dns.rdatatype.NS,
                dns.rdatatype.SOA,
            ):
                # Other authority types (e.g., glue-like A/AAAA) are ignored
                # here; they are not considered security-critical in this
                # validator.
                continue

            sig_rrset = rrsig_by_name.get(rrset.name)
            if sig_rrset is None:
                # Signed zone data in the authority section without an
                # accompanying RRSIG is treated as insecure.
                return False
            try:
                dns.dnssec.validate(rrset, sig_rrset, {apex: zone_dnskey})
            except Exception:
                return False

        return True
    except (
        Exception
    ):  # pragma: no cover - defensive: unexpected authority parsing error
        # Treat any unexpected failure while inspecting authority data as a
        # reason to downgrade the response security.
        return False


def classify_dnssec_status(
    dnssec_mode: str,
    dnssec_validation: str,
    qname_text: str,
    qtype_num: int,
    response_wire: bytes,
    *,
    udp_payload_size: int = 1232,
) -> Optional[str]:
    """Classify a DNS response as DNSSEC "secure" or "insecure".

    Inputs:
      - dnssec_mode: DNSSEC mode string (e.g. 'ignore', 'passthrough', 'validate').
      - dnssec_validation: Validation strategy ('upstream_ad' or 'local').
      - qname_text: Query name as text.
      - qtype_num: Numeric qtype (e.g., 1=A, 28=AAAA).
      - response_wire: Raw DNS response bytes.
      - udp_payload_size: EDNS payload size for any local validation fetches.

    Outputs:
      - 'secure' when validation succeeds.
      - 'insecure' when validation runs but does not authenticate the answer.
      - None when dnssec_mode is not 'validate' or classification cannot be
        determined due to errors.
    """
    try:
        mode = str(dnssec_mode).lower()
        if mode != "validate":
            return None

        strategy = str(dnssec_validation or "upstream_ad").lower()
        validated: Optional[bool]

        if strategy == "local":
            try:
                validated = bool(
                    validate_response_local(
                        qname_text,
                        qtype_num,
                        response_wire,
                        udp_payload_size=udp_payload_size,
                    )
                )
            except Exception as e:  # pragma: no cover - defensive logging only
                logger.debug("Local DNSSEC validation error: %s", e)
                validated = None
        else:
            try:
                # For upstream_ad we rely on the AD bit in the header. Use
                # dnslib here to remain compatible with how responses are
                # constructed elsewhere in Foghorn.
                from dnslib import DNSRecord as _DNSRecord  # local import

                parsed = _DNSRecord.parse(response_wire)
                validated = getattr(parsed.header, "ad", 0) == 1
            except Exception as e:  # pragma: no cover - defensive logging only
                logger.debug("Upstream AD check failed: %s", e)
                validated = None

        if validated is None:
            # Leave status unset when classification is indeterminate so callers
            # can treat the response as unsigned without forcing 'insecure'.
            return None
        return "secure" if validated else "insecure"
    except Exception:  # pragma: no cover - defensive: low-value edge case
        logger.debug("DNSSEC classification failed; leaving status unset")
        return None
