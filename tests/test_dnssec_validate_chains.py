import dns.dnssec
import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import pytest

from foghorn.dnssec.dnssec_validate import (
    classify_dnssec_status,
    validate_response_local,
)


def _make_dnskey_rrset(name: str) -> dns.rrset.RRset:
    """Create a placeholder DNSKEY RRset for tests.

    Inputs:
      - name: Owner name of the DNSKEY RRset.

    Outputs:
      - dns.rrset.RRset with a dummy DNSKEY; material isn't used because
        dns.dnssec.validate is monkeypatched.
    """
    owner = dns.name.from_text(name)
    dnskey = dns.rdtypes.ANY.DNSKEY.DNSKEY(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        257,
        3,
        dns.dnssec.Algorithm.RSASHA256,
        b"",
    )
    rrset = dns.rrset.RRset(owner, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    rrset.add(dnskey)
    return rrset


@pytest.fixture
def apex_name() -> str:
    """Return the test apex used for CNAME-chain validations.

    Outputs:
      - str apex name.
    """
    return "example.test."


@pytest.fixture
def monkeypatched_validate(monkeypatch):
    """Monkeypatch dns.dnssec.validate to a no-op for deterministic tests.

    Outputs:
      - None; dns.dnssec.validate is replaced during the test.
    """

    def _noop_validate(*args, **kwargs):  # noqa: D401 - simple stub
        """Stub validator that always succeeds."""
        return None

    monkeypatch.setattr(dns.dnssec, "validate", _noop_validate)


def test_dnssec_cname_chain_secure(monkeypatch, monkeypatched_validate, apex_name):
    """Follow a simple CNAME -> A chain and treat it as secure.

    Ensures that validate_response_local() follows a CNAME from the original
    qname to the final owner and that classify_dnssec_status() reports 'secure'
    when all RRsets in the chain are signed.
    """
    import foghorn.dnssec.dnssec_validate as dv

    def fake_find_zone_apex_cached(qname_text: str, udp_payload_size: int):
        return dns.name.from_text(apex_name)

    def fake_validate_chain_cached(apex_text: str, udp_payload_size: int):
        return _make_dnskey_rrset(apex_name)

    monkeypatch.setattr(dv, "_find_zone_apex_cached", fake_find_zone_apex_cached)
    monkeypatch.setattr(dv, "_validate_chain_cached", fake_validate_chain_cached)

    qname = dns.name.from_text("www.example.test.")
    target = dns.name.from_text("a.example.test.")

    msg = dns.message.Message()

    # CNAME at qname pointing to target.
    cname_rrset = dns.rrset.from_text(
        qname.to_text(),
        300,
        "IN",
        "CNAME",
        target.to_text(),
    )
    cname_rrsig = dns.rrset.from_text(
        qname.to_text(),
        300,
        "IN",
        "RRSIG",
        "CNAME 8 3 300 20300101000000 20000101000000 0 example.test. "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )

    # Final A RRset at target.
    a_rrset = dns.rrset.from_text(
        target.to_text(),
        300,
        "IN",
        "A",
        "192.0.2.1",
    )
    a_rrsig = dns.rrset.from_text(
        target.to_text(),
        300,
        "IN",
        "RRSIG",
        "A 8 3 300 20300101000000 20000101000000 0 example.test. "
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    )

    msg.answer.extend([cname_rrset, cname_rrsig, a_rrset, a_rrsig])
    wire = msg.to_wire()

    ok = validate_response_local(qname.to_text(), dns.rdatatype.A, wire)
    assert ok is True

    status = classify_dnssec_status(
        "validate",
        "local",
        qname.to_text(),
        dns.rdatatype.A,
        wire,
    )
    assert status == "dnssec_secure"


def test_dnssec_cname_chain_missing_rrsig(
    monkeypatch, monkeypatched_validate, apex_name
):
    """CNAME chain without signatures is not considered secure.

    If either the CNAME or the final answer lacks an RRSIG, the chain should
    not validate and should be classified as 'insecure'.
    """
    import foghorn.dnssec.dnssec_validate as dv

    def fake_find_zone_apex_cached(qname_text: str, udp_payload_size: int):
        return dns.name.from_text(apex_name)

    def fake_validate_chain_cached(apex_text: str, udp_payload_size: int):
        return _make_dnskey_rrset(apex_name)

    monkeypatch.setattr(dv, "_find_zone_apex_cached", fake_find_zone_apex_cached)
    monkeypatch.setattr(dv, "_validate_chain_cached", fake_validate_chain_cached)

    qname = dns.name.from_text("www.example.test.")
    target = dns.name.from_text("a.example.test.")

    msg = dns.message.Message()

    # CNAME without any RRSIG.
    cname_rrset = dns.rrset.from_text(
        qname.to_text(),
        300,
        "IN",
        "CNAME",
        target.to_text(),
    )

    # Final A RRset with its own RRSIG only.
    a_rrset = dns.rrset.from_text(
        target.to_text(),
        300,
        "IN",
        "A",
        "192.0.2.1",
    )
    a_rrsig = dns.rrset.from_text(
        target.to_text(),
        300,
        "IN",
        "RRSIG",
        "A 8 3 300 20300101000000 20000101000000 0 example.test. "
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    )

    msg.answer.extend([cname_rrset, a_rrset, a_rrsig])
    wire = msg.to_wire()

    ok = validate_response_local(qname.to_text(), dns.rdatatype.A, wire)
    assert ok is False

    status = classify_dnssec_status(
        "validate",
        "local",
        qname.to_text(),
        dns.rdatatype.A,
        wire,
    )
    # Chain is incomplete and carries DNSSEC material, so this should be
    # classified as 'dnssec_bogus' rather than 'dnssec_unsigned'.
    assert status == "dnssec_bogus"


def test_dnssec_dname_chain_secure(monkeypatch, monkeypatched_validate, apex_name):
    """Follow a DNAME-induced redirection and treat it as secure.

    Verifies that when a DNAME + its RRSIG are present and the synthesized
    target owner has a signed answer RRset, local validation succeeds and the
    response is classified as 'secure'.
    """
    import foghorn.dnssec.dnssec_validate as dv

    def fake_find_zone_apex_cached(qname_text: str, udp_payload_size: int):
        return dns.name.from_text(apex_name)

    def fake_validate_chain_cached(apex_text: str, udp_payload_size: int):
        return _make_dnskey_rrset(apex_name)

    monkeypatch.setattr(dv, "_find_zone_apex_cached", fake_find_zone_apex_cached)
    monkeypatch.setattr(dv, "_validate_chain_cached", fake_validate_chain_cached)

    # Query name under sub.example.test., while DNAME lives at example.test.
    qname = dns.name.from_text("www.sub.example.test.")
    dname_owner = dns.name.from_text("example.test.")
    dname_target = dns.name.from_text("example.org.")

    # Synthesized target should be www.sub.example.org.
    target = dns.name.from_text("www.sub.example.org.")

    msg = dns.message.Message()

    # DNAME at example.test. pointing to example.org.
    dname_rrset = dns.rrset.from_text(
        dname_owner.to_text(),
        300,
        "IN",
        "DNAME",
        dname_target.to_text(),
    )
    dname_rrsig = dns.rrset.from_text(
        dname_owner.to_text(),
        300,
        "IN",
        "RRSIG",
        "DNAME 8 2 300 20300101000000 20000101000000 0 example.test. "
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    )

    # Final A RRset at synthesized target.
    a_rrset = dns.rrset.from_text(
        target.to_text(),
        300,
        "IN",
        "A",
        "192.0.2.2",
    )
    a_rrsig = dns.rrset.from_text(
        target.to_text(),
        300,
        "IN",
        "RRSIG",
        "A 8 3 300 20300101000000 20000101000000 0 example.test. "
        "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=",
    )

    msg.answer.extend([dname_rrset, dname_rrsig, a_rrset, a_rrsig])
    wire = msg.to_wire()

    ok = validate_response_local(qname.to_text(), dns.rdatatype.A, wire)
    assert ok is True

    status = classify_dnssec_status(
        "validate",
        "local",
        qname.to_text(),
        dns.rdatatype.A,
        wire,
    )
    assert status == "dnssec_secure"
