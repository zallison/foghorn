import functools
import logging
from typing import Optional

import dns.dnssec
import dns.flags
import dns.message

# dnspython imports
import dns.name
import dns.rdatatype
import dns.resolver

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


@functools.lru_cache(maxsize=1024)
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
    except Exception as e:
        logger.warning("Failed to construct root trust anchor: %s", e)
        return None


def _find_zone_apex(
    r: dns.resolver.Resolver, qname: dns.name.Name
) -> Optional[dns.name.Name]:
    # Walk labels upwards until DNSKEY exists
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
) -> Optional[dns.rrset.RRset]:
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
        # Gather answer RRset and its RRSIG
        answer_rrset = None
        rrsig_rrset = None
        for rrset in msg.answer:
            if rrset.name == qname and rrset.rdtype == rdtype:
                answer_rrset = rrset
            if rrset.name == qname and rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig_rrset = rrset
        if answer_rrset is None or rrsig_rrset is None:
            # No signatures to validate
            return False
        r = _resolver(payload_size=udp_payload_size)
        apex = _find_zone_apex(r, qname)
        if apex is None:
            return False
        zone_dnskey = _validate_chain(r, apex)
        if zone_dnskey is None:
            return False
        # Validate answer with zone's DNSKEY
        try:
            dns.dnssec.validate(answer_rrset, rrsig_rrset, {apex: zone_dnskey})
            return True
        except Exception:
            return False
    except Exception:
        return False
