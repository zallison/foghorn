import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from foghorn.dnssec_validate import (
    classify_dnssec_status,
    validate_response_local,
)


def _make_dnskey_rrset(name: str) -> dns.rrset.RRset:
    """Build a minimal DNSKEY RRset used only as a placeholder.

    Inputs:
      - name: Owner name of the DNSKEY RRset.

    Outputs:
      - dns.rrset.RRset containing a single dummy DNSKEY RDATA. The actual
        key material is not used because dns.dnssec.validate is monkeypatched
        in tests.
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


def _make_dummy_rrsig(rrset: dns.rrset.RRset, signer_name: str) -> dns.rrset.RRset:
    """Return a dummy RRSIG RRset for rrset.

    Inputs:
      - rrset: RRset to attach a signature to.
      - signer_name: Name of the signer (zone apex).

    Outputs:
      - dns.rrset.RRset containing a single RRSIG RDATA with placeholder
        fields. Signature contents are not verified because dns.dnssec.validate
        is monkeypatched in tests.
    """
    signer = dns.name.from_text(signer_name)
    inception = 0
    expiration = 2**31
    rrsig_rdata = dns.rdtypes.ANY.RRSIG.RRSIG(
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        rrset.rdtype,
        dns.dnssec.Algorithm.RSASHA256,
        len(rrset.name.labels),
        300,
        expiration,
        inception,
        0,
        signer,
        b"",
    )
    sig_rrset = dns.rrset.RRset(rrset.name, rrset.rdclass, dns.rdatatype.RRSIG)
    sig_rrset.add(rrsig_rdata)
    return sig_rrset


def _wire_message(msg: dns.message.Message) -> bytes:
    """Serialize a dns.message.Message to wire format.

    Inputs:
      - msg: dns.message.Message instance.

    Outputs:
      - bytes containing the wire-format DNS message.
    """
    return msg.to_wire()


@pytest.fixture
def apex_name() -> str:
    """Return the test apex name used for DNSSEC chain stubs.

    Outputs:
      - str representing the apex in textual form.
    """
    return "example.test."


@pytest.fixture
def monkeypatched_validate(monkeypatch):
    """Monkeypatch dns.dnssec.validate to a no-op for deterministic tests.

    Outputs:
      - None; the global dns.dnssec.validate is replaced during the test.
    """

    def _noop_validate(*args, **kwargs):  # noqa: D401 - simple stub
        """Stub validator that always succeeds."""
        return None

    monkeypatch.setattr(dns.dnssec, "validate", _noop_validate)


def test_dnssec_negative_secure_nxdomain(
    monkeypatch, monkeypatched_validate, apex_name
):
    """NXDOMAIN with signed NSEC range covering qname is treated as secure.

    Validates that local DNSSEC validation returns True and classification is
    'secure' for an NXDOMAIN response that carries a correct NSEC-based proof
    of non-existence.
    """
    from foghorn import dnssec_validate as dv

    # Stub chain helpers to avoid network I/O.
    def fake_find_zone_apex_cached(qname_text: str, udp_payload_size: int):
        return dns.name.from_text(apex_name)

    def fake_validate_chain_cached(apex_text: str, udp_payload_size: int):
        return _make_dnskey_rrset(apex_name)

    monkeypatch.setattr(dv, "_find_zone_apex_cached", fake_find_zone_apex_cached)
    monkeypatch.setattr(dv, "_validate_chain_cached", fake_validate_chain_cached)

    qname = dns.name.from_text("nonexistent.example.test.")
    msg = dns.message.Message()
    msg.set_rcode(dns.rcode.NXDOMAIN)

    # Construct an NSEC that covers qname in its interval.
    owner = dns.name.from_text("example.test.")
    next_name = dns.name.from_text("zzz.example.test.")
    nsec_rrset = dns.rrset.from_text(
        owner.to_text(),
        300,
        "IN",
        "NSEC",
        f"{next_name.to_text()} SOA",
    )
    nsec_rrsig = _make_dummy_rrsig(nsec_rrset, apex_name)
    msg.authority.append(nsec_rrset)
    msg.authority.append(nsec_rrsig)

    wire = _wire_message(msg)
    ok = validate_response_local(qname.to_text(), dns.rdatatype.A, wire)
    assert ok is True

    status = classify_dnssec_status(
        "validate",
        "local",
        qname.to_text(),
        dns.rdatatype.A,
        wire,
    )
    assert status == "secure"


def test_dnssec_negative_secure_nodata(monkeypatch, monkeypatched_validate, apex_name):
    """NODATA with NSEC bitmap lacking queried type is treated as secure.

    Ensures that when an NSEC at the exact owner shows the queried RR type is
    absent from the bitmap, local validation marks the response as secure.
    """
    from foghorn import dnssec_validate as dv

    def fake_find_zone_apex_cached(qname_text: str, udp_payload_size: int):
        return dns.name.from_text(apex_name)

    def fake_validate_chain_cached(apex_text: str, udp_payload_size: int):
        return _make_dnskey_rrset(apex_name)

    monkeypatch.setattr(dv, "_find_zone_apex_cached", fake_find_zone_apex_cached)
    monkeypatch.setattr(dv, "_validate_chain_cached", fake_validate_chain_cached)

    qname = dns.name.from_text("www.example.test.")
    msg = dns.message.Message()
    msg.set_rcode(dns.rcode.NOERROR)

    # NSEC at the exact owner, listing only A in the bitmap.
    nsec_rrset = dns.rrset.from_text(
        qname.to_text(),
        300,
        "IN",
        "NSEC",
        "zzz.example.test. A",
    )
    nsec_rrsig = _make_dummy_rrsig(nsec_rrset, apex_name)
    msg.authority.append(nsec_rrset)
    msg.authority.append(nsec_rrsig)

    wire = _wire_message(msg)
    ok = validate_response_local(qname.to_text(), dns.rdatatype.AAAA, wire)
    assert ok is True

    status = classify_dnssec_status(
        "validate",
        "local",
        qname.to_text(),
        dns.rdatatype.AAAA,
        wire,
    )
    assert status == "secure"


def test_dnssec_negative_nxdomain_without_nsec(
    monkeypatch, monkeypatched_validate, apex_name
):
    """NXDOMAIN without NSEC proof is not considered secure.

    Verifies that in the absence of any NSEC-based proof, local validation
    returns False and classification is 'insecure'.
    """
    from foghorn import dnssec_validate as dv

    def fake_find_zone_apex_cached(qname_text: str, udp_payload_size: int):
        return dns.name.from_text(apex_name)

    def fake_validate_chain_cached(apex_text: str, udp_payload_size: int):
        return _make_dnskey_rrset(apex_name)

    monkeypatch.setattr(dv, "_find_zone_apex_cached", fake_find_zone_apex_cached)
    monkeypatch.setattr(dv, "_validate_chain_cached", fake_validate_chain_cached)

    qname = dns.name.from_text("nonexistent.example.test.")
    msg = dns.message.Message()
    msg.set_rcode(dns.rcode.NXDOMAIN)

    wire = _wire_message(msg)
    ok = validate_response_local(qname.to_text(), dns.rdatatype.A, wire)
    assert ok is False

    status = classify_dnssec_status(
        "validate",
        "local",
        qname.to_text(),
        dns.rdatatype.A,
        wire,
    )
    assert status == "insecure"


def test_validate_negative_response_missing_rrsig_and_validate_error(
    apex_name, monkeypatch
):
    """Brief: _validate_negative_response fails on missing RRSIG or bad validate().

    Inputs:
      - apex_name: zone apex fixture.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts False when NSEC lacks RRSIG and when validate() raises.
    """

    class _RRset(list):
        def __init__(self, name, rdtype, records):
            super().__init__(records)
            self.name = name
            self.rdtype = rdtype

    class _Msg:
        def __init__(self, authority, rcode_value):
            self.authority = authority
            self._rcode = rcode_value
            self.answer = []

        def rcode(self):
            return self._rcode

    apex = dns.name.from_text(apex_name)
    zone_dnskey = _make_dnskey_rrset(apex_name)

    owner = apex
    nxt = dns.name.from_text("zzz.example.test.")
    # NSEC without any corresponding RRSIG -> False.
    nsec_only = _RRset(
        owner,
        dns.rdatatype.NSEC,
        [
            dns.rrset.from_text(
                owner.to_text(), 300, "IN", "NSEC", f"{nxt.to_text()} SOA"
            )[0]
        ],
    )
    msg = _Msg([nsec_only], dns.rcode.NXDOMAIN)
    from foghorn import dnssec_validate as dv

    assert (
        dv._validate_negative_response(msg, owner, dns.rdatatype.A, apex, zone_dnskey)
        is False
    )

    # Now provide RRSIG but make dns.dnssec.validate raise.
    nsec_rr = dns.rrset.from_text(
        owner.to_text(),
        300,
        "IN",
        "NSEC",
        f"{nxt.to_text()} SOA",
    )
    nsec_sig = _make_dummy_rrsig(nsec_rr, apex_name)
    msg2 = _Msg([nsec_rr, nsec_sig], dns.rcode.NXDOMAIN)

    def _boom_validate(*_a, **_k):  # pragma: no cover - simple error stub
        raise RuntimeError("boom")

    monkeypatch.setattr("foghorn.dnssec_validate.dns.dnssec.validate", _boom_validate)
    assert (
        dv._validate_negative_response(msg2, owner, dns.rdatatype.A, apex, zone_dnskey)
        is False
    )


def test_dnssec_negative_nodata_with_type_present(
    monkeypatch, monkeypatched_validate, apex_name
):
    """NODATA where NSEC bitmap includes queried type is not secure.

    Checks that when the NSEC bitmap lists the queried type, the response is
    not treated as a secure NODATA proof.
    """
    from foghorn import dnssec_validate as dv

    def fake_find_zone_apex_cached(qname_text: str, udp_payload_size: int):
        return dns.name.from_text(apex_name)

    def fake_validate_chain_cached(apex_text: str, udp_payload_size: int):
        return _make_dnskey_rrset(apex_name)

    monkeypatch.setattr(dv, "_find_zone_apex_cached", fake_find_zone_apex_cached)
    monkeypatch.setattr(dv, "_validate_chain_cached", fake_validate_chain_cached)

    qname = dns.name.from_text("www.example.test.")
    msg = dns.message.Message()
    msg.set_rcode(dns.rcode.NOERROR)

    # NSEC at exact owner listing both A and AAAA, so AAAA cannot be proven
    # absent.
    nsec_rrset = dns.rrset.from_text(
        qname.to_text(),
        300,
        "IN",
        "NSEC",
        "zzz.example.test. A AAAA",
    )
    nsec_rrsig = _make_dummy_rrsig(nsec_rrset, apex_name)
    msg.authority.append(nsec_rrset)
    msg.authority.append(nsec_rrsig)

    wire = _wire_message(msg)
    ok = validate_response_local(qname.to_text(), dns.rdatatype.AAAA, wire)
    assert ok is False

    status = classify_dnssec_status(
        "validate",
        "local",
        qname.to_text(),
        dns.rdatatype.AAAA,
        wire,
    )
    assert status == "insecure"


def test_dnssec_negative_apex_dnskey_mismatch_in_authority(
    monkeypatch, monkeypatched_validate, apex_name
):
    """Apex DNSKEY RRset in authority that conflicts with validated chain is insecure.

    Builds an NXDOMAIN response with a valid NSEC proof but a DNSKEY RRset at
    the apex whose contents differ from the chain-validated DNSKEY set.
    validate_response_local() should return False and classification should be
    'insecure'.
    """
    from foghorn import dnssec_validate as dv

    def fake_find_zone_apex_cached(qname_text: str, udp_payload_size: int):
        return dns.name.from_text(apex_name)

    # Chain validation returns a single-key DNSKEY rrset.
    zone_dnskey = _make_dnskey_rrset(apex_name)

    def fake_validate_chain_cached(apex_text: str, udp_payload_size: int):
        return zone_dnskey

    monkeypatch.setattr(dv, "_find_zone_apex_cached", fake_find_zone_apex_cached)
    monkeypatch.setattr(dv, "_validate_chain_cached", fake_validate_chain_cached)

    qname = dns.name.from_text("nonexistent.example.test.")
    msg = dns.message.Message()
    msg.set_rcode(dns.rcode.NXDOMAIN)

    # Valid-looking NSEC proof covering qname so that the negative validator
    # itself succeeds.
    owner = dns.name.from_text("example.test.")
    next_name = dns.name.from_text("zzz.example.test.")
    nsec_rrset = dns.rrset.from_text(
        owner.to_text(),
        300,
        "IN",
        "NSEC",
        f"{next_name.to_text()} SOA",
    )
    nsec_rrsig = _make_dummy_rrsig(nsec_rrset, apex_name)
    msg.authority.append(nsec_rrset)
    msg.authority.append(nsec_rrsig)

    # Add an apex DNSKEY RRset whose contents differ from zone_dnskey.
    mismatched = _make_dnskey_rrset(apex_name)
    # Append a second DNSKEY record with different flags so the to_text() set
    # differs from zone_dnskey.
    extra_dnskey = dns.rdtypes.ANY.DNSKEY.DNSKEY(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        256,  # different flags
        3,
        dns.dnssec.Algorithm.RSASHA256,
        b"\x00",
    )
    mismatched.add(extra_dnskey)
    mismatched_sig = _make_dummy_rrsig(mismatched, apex_name)
    msg.authority.append(mismatched)
    msg.authority.append(mismatched_sig)

    wire = _wire_message(msg)

    ok = validate_response_local(qname.to_text(), dns.rdatatype.A, wire)
    assert ok is False

    status = classify_dnssec_status(
        "validate",
        "local",
        qname.to_text(),
        dns.rdatatype.A,
        wire,
    )
    assert status == "insecure"
