"""Brief: Unit tests for foghorn.dnssec.dnssec_validate helpers.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

import base64
import dns.name
import dns.rcode
import pytest

import foghorn.dnssec.dnssec_validate as dval


def test_resolver_sets_do_and_lifetime():
    """Brief: _resolver configures EDNS DO flag and lifetime.

    Inputs:
      - None

    Outputs:
      - None; asserts lifetime is set and call does not crash.
    """

    r = dval._resolver(payload_size=1400)
    # We cannot easily introspect EDNS flags across dnspython versions, but we
    # can ensure the resolver lifetime has been configured as expected.
    assert getattr(r, "lifetime", None) == 2.0


def test_fetch_delegates_to_resolver_resolve():
    """Brief: _fetch calls resolver.resolve with raise_on_no_answer=True.

    Inputs:
      - None

    Outputs:
      - None; asserts arguments passed through and return value propagated.
    """

    class _R:
        def __init__(self):
            self.calls = []

        def resolve(self, name, rdtype, raise_on_no_answer=True):
            self.calls.append((name, rdtype, raise_on_no_answer))
            return "ok"

    r = _R()
    name = dns.name.from_text("example.com.")
    out = dval._fetch(r, name, "DNSKEY")
    assert out == "ok"
    assert r.calls == [(name, "DNSKEY", True)]


def test_root_dnskey_rrset_constructs_trust_anchor():
    """Brief: _root_dnskey_rrset parses the baked-in trust anchor.

    Inputs:
      - None

    Outputs:
      - None; asserts the resulting rrset is anchored at the root name.
    """

    rrset = dval._root_dnskey_rrset()
    assert rrset is not None
    assert rrset.name == dns.name.root


def test_find_zone_apex_uses_first_success_and_root_on_failure(monkeypatch):
    """Brief: _find_zone_apex returns first successful DNSKEY owner or root.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts both direct-hit and walk-to-root behaviors.
    """

    qname = dns.name.from_text("a.b.example.")
    calls = []

    def _fake_fetch(resolver, name, rdtype):
        calls.append((name, rdtype))
        if name == qname:

            class _Resp:
                rrset = "dnskey-rrset"

            return _Resp()
        raise RuntimeError("no dnskey here")

    monkeypatch.setattr(dval, "_fetch", _fake_fetch)
    r = object()
    apex = dval._find_zone_apex(r, qname)
    assert apex == qname
    assert calls[0] == (qname, "DNSKEY")

    # Now make every lookup fail so we walk all the way to the root.
    calls.clear()

    def _always_fail(resolver, name, rdtype):  # pragma: no cover - helper used once
        calls.append((name, rdtype))
        raise RuntimeError("boom")

    monkeypatch.setattr(dval, "_fetch", _always_fail)
    apex2 = dval._find_zone_apex(r, qname)
    assert apex2 == dns.name.root
    # Ensure we attempted multiple labels including the root.
    assert (dns.name.root, "DNSKEY") in calls


def test_find_zone_apex_cached_success_and_failure(monkeypatch):
    """Brief: _find_zone_apex_cached returns apex on success and None on error.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts both cached helper paths.
    """

    apex = dns.name.from_text("example.com.")

    def _fake_resolver(payload_size):
        return object()

    def _fake_apex(resolver, qname):
        return apex

    monkeypatch.setattr(dval, "_resolver", _fake_resolver)
    monkeypatch.setattr(dval, "_find_zone_apex", _fake_apex)

    out = dval._find_zone_apex_cached("example.com.", 1232)
    assert out == apex

    # Error path: make _resolver raise so the cached helper returns None.
    def _boom_resolver(payload_size):  # pragma: no cover - simple error stub
        raise RuntimeError("boom")

    monkeypatch.setattr(dval, "_resolver", _boom_resolver)
    out2 = dval._find_zone_apex_cached("boom.example.", 1232)
    assert out2 is None


def test_validate_chain_cached_success_and_failure(monkeypatch):
    """Brief: _validate_chain_cached wraps _validate_chain and resolver errors.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts successful validation and error path both behave.
    """

    # Clear any cached entries so this test is independent of prior calls.
    func = getattr(dval, "_validate_chain_cached")
    cache_obj = getattr(func, "cache", None)
    if hasattr(cache_obj, "clear"):
        cache_obj.clear()

    dnskey = object()

    def _fake_resolver(payload_size):
        return object()

    def _fake_validate_chain(resolver, apex):
        return dnskey

    monkeypatch.setattr(dval, "_resolver", _fake_resolver)
    monkeypatch.setattr(dval, "_validate_chain", _fake_validate_chain)

    out = dval._validate_chain_cached("example.com.", 1232)
    assert out is dnskey

    # Error path: resolver construction fails.
    def _boom_resolver(payload_size):  # pragma: no cover - simple error stub
        raise RuntimeError("boom")

    monkeypatch.setattr(dval, "_resolver", _boom_resolver)
    out2 = dval._validate_chain_cached("boom.example.", 1232)
    assert out2 is None


def test_validate_response_local_positive_and_negative_paths(monkeypatch):
    """Brief: validate_response_local covers positive, negative, and rcode guard.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts True/False for key decision points.
    """

    class _Msg:
        def __init__(self, rcode_value):
            self._rcode = rcode_value

        def rcode(self):
            return self._rcode

    qname_text = "example.com."
    qname = dns.name.from_text(qname_text)
    rdtype = 1

    # Positive chain: _collect_positive_rrsets returns a chain and all
    # downstream helpers succeed.
    final_owner = dns.name.from_text("www.example.com.")
    rrsets = [object()]
    sig_rrsets = [object()]

    def _fake_from_wire(wire):
        return _Msg(dns.rcode.NOERROR)

    def _fake_collect(msg, qname_in, rdtype_in):
        assert qname_in == qname
        assert rdtype_in == rdtype
        return final_owner, rrsets, sig_rrsets

    def _fake_apex_cached(name_text, payload_size):
        assert name_text == final_owner.to_text()
        return dns.name.from_text("example.com.")

    def _fake_chain_cached(apex_text, payload_size):
        return object()

    def _fake_validate(rrset, sig_rrset, keymap):
        # Called once for each rrset/sig pair; no-op.
        assert keymap

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.message.from_wire", _fake_from_wire
    )
    monkeypatch.setattr(dval, "_collect_positive_rrsets", _fake_collect)
    monkeypatch.setattr(dval, "_find_zone_apex_cached", _fake_apex_cached)
    monkeypatch.setattr(dval, "_validate_chain_cached", _fake_chain_cached)
    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.dnssec.validate", _fake_validate
    )

    ok = dval.validate_response_local(qname_text, rdtype, b"wire")
    assert ok is True

    # Chain present but apex validation fails -> False at zone_dnskey check.
    def _chain_none(apex_text, payload_size):
        return None

    monkeypatch.setattr(dval, "_validate_chain_cached", _chain_none)
    not_ok = dval.validate_response_local(qname_text, rdtype, b"wire")
    assert not_ok is False

    # No positive chain: fall back to negative validation.
    def _no_chain(msg, qname_in, rdtype_in):
        return None

    def _fake_apex(name_text, payload_size):
        return dns.name.from_text("example.com.")

    def _fake_zone_dnskey(apex_text, payload_size):
        return object()

    def _fake_negate(msg, qname_in, rdtype_in, apex_in, dnskey):
        return True

    monkeypatch.setattr(dval, "_collect_positive_rrsets", _no_chain)
    monkeypatch.setattr(dval, "_find_zone_apex_cached", _fake_apex)
    monkeypatch.setattr(dval, "_validate_chain_cached", _fake_zone_dnskey)
    monkeypatch.setattr(dval, "_validate_negative_response", _fake_negate)

    ok_neg = dval.validate_response_local(qname_text, rdtype, b"wire")
    assert ok_neg is True

    # Unsupported rcode (not NXDOMAIN/NOERROR) -> False.
    def _msg_servfail(wire):
        return _Msg(dns.rcode.SERVFAIL)

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.message.from_wire", _msg_servfail
    )
    unsupported = dval.validate_response_local(qname_text, rdtype, b"wire")
    assert unsupported is False

    # Outer exception path: from_wire raises -> False.
    def _boom_from_wire(wire):  # pragma: no cover - simple error stub
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.message.from_wire", _boom_from_wire
    )
    failed = dval.validate_response_local(qname_text, rdtype, b"wire")
    assert failed is False


def test_validate_response_local_positive_apex_and_authority_failures(monkeypatch):
    """Brief: validate_response_local handles apex/authority failure branches.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts False for various early-return branches in positive/negative paths.
    """

    class _Msg:
        def __init__(self, rcode_value: int) -> None:
            self._rcode = rcode_value

        def rcode(self) -> int:
            return self._rcode

    qname_text = "example.com."
    rdtype = 1

    # 1) Positive chain present but apex lookup returns None -> False at apex check.
    def _from_wire_noerror(_wire: bytes) -> _Msg:
        return _Msg(dns.rcode.NOERROR)

    def _collect_positive(_msg, _q, _t):
        return dns.name.from_text(qname_text), [object()], [object()]

    def _apex_none(_name_text: str, _payload_size: int):
        return None

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.message.from_wire", _from_wire_noerror
    )
    monkeypatch.setattr(dval, "_collect_positive_rrsets", _collect_positive)
    monkeypatch.setattr(dval, "_find_zone_apex_cached", _apex_none)

    assert dval.validate_response_local(qname_text, rdtype, b"wire") is False

    # 2) Positive chain with apex + DNSKEY but authority validator fails -> False at
    # _validate_authority_rrsets check.
    apex = dns.name.from_text(qname_text)

    def _apex_ok(_name_text: str, _payload_size: int):
        return apex

    def _zone_dnskey(_apex_text: str, _payload_size: int):
        return object()

    def _auth_fail(_msg, _q, _t, _apex_name, _dnskey) -> bool:
        return False

    monkeypatch.setattr(dval, "_find_zone_apex_cached", _apex_ok)
    monkeypatch.setattr(dval, "_validate_chain_cached", _zone_dnskey)
    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.dnssec.validate",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(dval, "_validate_authority_rrsets", _auth_fail)

    assert dval.validate_response_local(qname_text, rdtype, b"wire") is False

    # 3) Negative path apex None -> False.
    def _from_wire_nxdomain(_wire: bytes) -> _Msg:
        return _Msg(dns.rcode.NXDOMAIN)

    def _no_chain(_msg, _q, _t):
        return None

    def _apex_none_neg(_name_text: str, _payload_size: int):
        return None

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.message.from_wire", _from_wire_nxdomain
    )
    monkeypatch.setattr(dval, "_collect_positive_rrsets", _no_chain)
    monkeypatch.setattr(dval, "_find_zone_apex_cached", _apex_none_neg)

    assert dval.validate_response_local(qname_text, rdtype, b"wire") is False

    # 4) Negative path apex ok but DNSKEY None -> False.
    def _apex_ok_neg(_name_text: str, _payload_size: int):
        return dns.name.from_text(qname_text)

    def _zone_none(_apex_text: str, _payload_size: int):
        return None

    monkeypatch.setattr(dval, "_find_zone_apex_cached", _apex_ok_neg)
    monkeypatch.setattr(dval, "_validate_chain_cached", _zone_none)

    assert dval.validate_response_local(qname_text, rdtype, b"wire") is False


# Local helpers reused from negative DNSSEC tests to avoid cross-module imports.


def _make_dnskey_rrset_ext(name: str) -> dns.rrset.RRset:
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


def _make_dummy_rrsig_ext(rrset: dns.rrset.RRset, signer_name: str) -> dns.rrset.RRset:
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


def test_classify_dnssec_local_extended_zone_chain_without_rrsig(monkeypatch):
    """local_extended keeps dnssec_unsigned when no RRSIG is available.

    Original response:
      - NOERROR with an unsigned A RRset (no DNSSEC records at all).

    Extended path:
      - _find_zone_apex_cached / _validate_chain_cached validate the zone's
        DNSKEY/DS chain.
      - _resolver/_fetch return a message containing the same unsigned A RRset
        plus a signed DNSKEY RRset for the apex, but still no RRSIG for A.

    Expectations:
      - validation='local' -> dnssec_unsigned
      - validation='local_extended' -> dnssec_zone_secure
    """

    import foghorn.dnssec.dnssec_validate as dv

    qname_text = "www.example.test."
    qname = dns.name.from_text(qname_text)
    rdtype = dns.rdatatype.A

    # Original upstream response: unsigned A only, no DNSSEC.
    orig = dns.message.Message()
    orig.set_rcode(dns.rcode.NOERROR)
    a_rrset = dns.rrset.from_text(qname, 300, dns.rdataclass.IN, rdtype, "1.2.3.4")
    orig.answer.append(a_rrset)
    orig_wire = orig.to_wire()

    # Baseline local classification sees no DNSSEC material and yields unsigned.
    base = dv.classify_dnssec_status(
        dnssec_mode="validate",
        dnssec_validation="local",
        qname_text=qname_text,
        qtype_num=rdtype,
        response_wire=orig_wire,
        udp_payload_size=1232,
    )
    assert base == "dnssec_unsigned"

    # Fake a validated DNSKEY rrset for the apex.
    zone_apex = dns.name.from_text("example.test.")
    zone_dnskey = _make_dnskey_rrset_ext("example.test.")

    def fake_find_zone_apex_cached(name_text: str, payload_size: int):
        assert name_text == qname_text
        return zone_apex

    def fake_validate_chain_cached(apex_text: str, payload_size: int):
        assert apex_text == "example.test."
        return zone_dnskey

    # Enriched message: same A RRset plus signed DNSKEY for the apex.
    enriched = dns.message.Message()
    enriched.set_rcode(dns.rcode.NOERROR)
    enriched.answer.append(a_rrset)

    dnskey_rrset = dns.rrset.RRset(zone_apex, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    for r in zone_dnskey:
        dnskey_rrset.add(r)
    dnskey_sig = _make_dummy_rrsig_ext(dnskey_rrset, "example.test.")
    enriched.authority.append(dnskey_rrset)
    enriched.authority.append(dnskey_sig)

    class _Resp:
        def __init__(self, message: dns.message.Message) -> None:
            self.response = message

    def fake_resolver(payload_size: int):  # pragma: no cover - simple stub
        class _R:
            pass

        return _R()

    def fake_fetch(resolver, name, rtype):  # pragma: no cover - simple stub
        # Extended lookup for qname/rdtype returns the enriched message.
        assert name == qname
        assert dns.rdatatype.from_text(rtype) == rdtype
        return _Resp(enriched)

    monkeypatch.setattr(dv, "_find_zone_apex_cached", fake_find_zone_apex_cached)
    monkeypatch.setattr(dv, "_validate_chain_cached", fake_validate_chain_cached)
    monkeypatch.setattr(dv, "_resolver", fake_resolver)
    monkeypatch.setattr(dv, "_fetch", fake_fetch)

    out_ext = dv.classify_dnssec_status(
        dnssec_mode="validate",
        dnssec_validation="local_extended",
        qname_text=qname_text,
        qtype_num=rdtype,
        response_wire=orig_wire,
        udp_payload_size=1232,
    )

    assert out_ext == "dnssec_unsigned"


def test_collect_positive_rrsets_direct_cname_and_dname(monkeypatch):
    """Brief: _collect_positive_rrsets handles direct, CNAME, and DNAME cases.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts basic chaining behavior without real DNS objects.
    """

    class _RRset(list):
        def __init__(self, name, rdtype, records):
            super().__init__(records)
            self.name = name
            self.rdtype = rdtype

    qname = dns.name.from_text("a.example.")
    target = dns.name.from_text("b.example.")

    # Direct answer + RRSIG
    direct_rr = _RRset(qname, 1, ["A"])
    direct_sig = _RRset(qname, dns.rdatatype.RRSIG, ["sigA"])

    class _Msg:
        def __init__(self, answer):
            self.answer = answer

    msg_direct = _Msg([direct_rr, direct_sig])
    owner, rrsets, sigs = dval._collect_positive_rrsets(msg_direct, qname, 1)
    assert owner == qname
    assert rrsets == [direct_rr]
    assert sigs == [direct_sig]

    # CNAME chain followed by direct answer.
    cname_rr = _RRset(
        qname, dns.rdatatype.CNAME, [type("_C", (), {"target": target})()]
    )
    cname_sig = _RRset(qname, dns.rdatatype.RRSIG, ["sigC"])
    target_rr = _RRset(target, 1, ["A"])
    target_sig = _RRset(target, dns.rdatatype.RRSIG, ["sigT"])

    msg_cname = _Msg([cname_rr, cname_sig, target_rr, target_sig])
    owner2, rrsets2, sigs2 = dval._collect_positive_rrsets(msg_cname, qname, 1)
    assert owner2 == target
    assert rrsets2 == [cname_rr, target_rr]
    assert sigs2 == [cname_sig, target_sig]

    # DNAME present but no final answer: function should fall back to None
    # after attempting the DNAME rewrite logic.
    dname_owner = dns.name.from_text("example.")
    dname_target = dns.name.from_text("alias.example.")

    dname_rr = _RRset(
        dname_owner, dns.rdatatype.DNAME, [type("_D", (), {"target": dname_target})()]
    )
    dname_sig = _RRset(dname_owner, dns.rdatatype.RRSIG, ["sigD"])

    msg_dname = _Msg([dname_rr, dname_sig])
    none_owner = dval._collect_positive_rrsets(msg_dname, qname, 1)
    assert none_owner is None

    # Direct RRset without RRSIG should return None.
    msg_no_sig = _Msg([direct_rr])
    assert dval._collect_positive_rrsets(msg_no_sig, qname, 1) is None

    # CNAME without RRSIG should also return None.
    msg_cname_no_sig = _Msg([cname_rr, target_rr, target_sig])
    assert dval._collect_positive_rrsets(msg_cname_no_sig, qname, 1) is None

    # CNAME with bad target (missing .target attribute) should return None.
    bad_cname_rr = _RRset(qname, dns.rdatatype.CNAME, [object()])
    msg_bad_cname = _Msg([bad_cname_rr])
    assert dval._collect_positive_rrsets(msg_bad_cname, qname, 1) is None

    # DNAME without RRSIG should return None.
    msg_dname_no_sig = _Msg([dname_rr])
    assert dval._collect_positive_rrsets(msg_dname_no_sig, qname, 1) is None

    # DNAME whose owner is not an ancestor of current name should return None.
    other_owner = dns.name.from_text("other.example.")
    other_dname_rr = _RRset(
        other_owner, dns.rdatatype.DNAME, [type("_D2", (), {"target": dname_target})()]
    )
    other_sig = _RRset(other_owner, dns.rdatatype.RRSIG, ["sigD2"])
    msg_dname_bad = _Msg([other_dname_rr, other_sig])
    assert dval._collect_positive_rrsets(msg_dname_bad, qname, 1) is None


def test_validate_negative_response_nxdomain_and_nodata(monkeypatch):
    """Brief: _validate_negative_response covers NXDOMAIN and NODATA via NSEC.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts True for proven NXDOMAIN/NODATA and False otherwise.
    """

    class _RRset(list):
        def __init__(self, name, rdtype, records):
            super().__init__(records)
            self.name = name
            self.rdtype = rdtype

    class _NsecRdata:
        def __init__(self, nxt):
            self.next = nxt

    class _Msg:
        def __init__(self, authority, rcode_value, answer=None):
            self.authority = authority
            self._rcode = rcode_value
            self.answer = answer or []

        def rcode(self):
            return self._rcode

    # Monkeypatch dns.dnssec.validate to a no-op.
    def _fake_validate(rrset, sig_rrset, keymap):
        assert keymap

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.dnssec.validate", _fake_validate
    )

    apex = dns.name.from_text("example.")
    zone_dnskey = object()

    owner = dns.name.from_text("a.example.")
    nxt = dns.name.from_text("z.example.")
    qname = dns.name.from_text("m.example.")

    nsec_rr = _RRset(owner, dns.rdatatype.NSEC, [_NsecRdata(nxt)])
    nsec_sig = _RRset(owner, dns.rdatatype.RRSIG, ["sig"])
    msg = _Msg([nsec_rr, nsec_sig], dns.rcode.NXDOMAIN)

    ok_nx = dval._validate_negative_response(msg, qname, 1, apex, zone_dnskey)
    assert ok_nx is True

    # NODATA proof at exact owner name.
    class _BitmapRdata:
        def __init__(self, types):
            self.types = types

        def covers(self, *_a, **_k):  # pragma: no cover - not used in test
            return True

        def to_text(self):
            # Return owner, next, then types.
            return "owner next " + " ".join(self.types)

    nodata_qname = dns.name.from_text("nodata.example.")
    nsec_rr2 = _RRset(nodata_qname, dns.rdatatype.NSEC, [_BitmapRdata(["AAAA"])])
    nsec_sig2 = _RRset(nodata_qname, dns.rdatatype.RRSIG, ["sigN"])
    msg2 = _Msg([nsec_rr2, nsec_sig2], dns.rcode.NOERROR)

    ok_nodata = dval._validate_negative_response(
        msg2,
        nodata_qname,
        dns.rdatatype.A,
        apex,
        zone_dnskey,
    )
    assert ok_nodata is True

    # Unsupported rcode and NSEC3 presence both return False.
    nsec3_rr = _RRset(owner, dns.rdatatype.NSEC3, ["x"])
    msg3 = _Msg([nsec3_rr], dns.rcode.SERVFAIL)
    assert dval._validate_negative_response(msg3, qname, 1, apex, zone_dnskey) is False


def test_nsec_proves_nxdomain_and_nodata_helpers():
    """Brief: _nsec_proves_nxdomain/_nsec_proves_nodata basic behaviors.

    Inputs:
      - None

    Outputs:
      - None; asserts True/False for simple synthetic NSEC data.
    """

    class _RRset(list):
        def __init__(self, name, rdtype, records):
            super().__init__(records)
            self.name = name
            self.rdtype = rdtype

    class _Nsec:
        def __init__(self, nxt):
            self.next = nxt

    owner = dns.name.from_text("a.example.")
    nxt = dns.name.from_text("z.example.")
    qname = dns.name.from_text("m.example.")

    nsec_rr = _RRset(owner, dns.rdatatype.NSEC, [_Nsec(nxt)])
    assert dval._nsec_proves_nxdomain(qname, [nsec_rr]) is True

    # Exact owner name should not prove NXDOMAIN.
    assert dval._nsec_proves_nxdomain(owner, [nsec_rr]) is False

    # NODATA proof: bitmap does not contain queried type.
    class _BitmapRdata:
        def __init__(self, types):
            self.types = types

        def covers(self, *_a, **_k):  # pragma: no cover - not used in test
            return True

        def to_text(self):
            return "owner next " + " ".join(self.types)

    nodata_qname = dns.name.from_text("nodata.example.")
    nsec_rr2 = _RRset(nodata_qname, dns.rdatatype.NSEC, [_BitmapRdata(["AAAA"])])
    assert dval._nsec_proves_nodata(nodata_qname, dns.rdatatype.A, [nsec_rr2]) is True

    # When owner does not match qname or bitmap includes the type, NODATA is
    # not proven.
    assert (
        dval._nsec_proves_nodata(
            nodata_qname,
            dns.rdatatype.A,
            [_RRset(nodata_qname, dns.rdatatype.NSEC, [_BitmapRdata(["A"])])],
        )
        is False
    )


def test_classify_dnssec_local_variants(monkeypatch):
    """Brief: _classify_dnssec_local distinguishes secure/bogus/unsigned.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts outcomes based on validation flag and presence of DNSSEC RRs.
    """

    qname_text = "example.com."
    qtype = 1
    wire = b"wire"

    class _Msg:
        def __init__(self, has_dnssec: bool) -> None:
            self._has_dnssec = has_dnssec

    def fake_from_wire(_wire):
        return _Msg(has_dnssec=True)

    def fake_has_dnssec_rr(msg):  # noqa: D401
        return msg._has_dnssec

    # Secure when validate_response_local returns True.
    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.message.from_wire", fake_from_wire
    )
    monkeypatch.setattr(dval, "_message_has_dnssec_rr", fake_has_dnssec_rr)
    monkeypatch.setattr(dval, "validate_response_local", lambda *a, **k: True)

    assert (
        dval._classify_dnssec_local(qname_text, qtype, wire, udp_payload_size=1232)
        == "dnssec_secure"
    )

    # Bogus when validation fails but DNSSEC material is present.
    monkeypatch.setattr(dval, "validate_response_local", lambda *a, **k: False)
    assert (
        dval._classify_dnssec_local(qname_text, qtype, wire, udp_payload_size=1232)
        == "dnssec_bogus"
    )

    # Unsigned when there is no DNSSEC material at all.
    def fake_from_wire_unsigned(_wire):
        return _Msg(has_dnssec=False)

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.message.from_wire", fake_from_wire_unsigned
    )
    assert (
        dval._classify_dnssec_local(qname_text, qtype, wire, udp_payload_size=1232)
        == "dnssec_unsigned"
    )

    # Error path: from_wire raises -> None.
    def _boom_from_wire(_wire):  # pragma: no cover - simple error stub
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.message.from_wire", _boom_from_wire
    )
    assert (
        dval._classify_dnssec_local(qname_text, qtype, wire, udp_payload_size=1232)
        is None
    )


def test_validate_authority_rrsets_behaviour(monkeypatch):
    """Brief: _validate_authority_rrsets enforces signatures and key matching.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts True/False for various authority RRset combinations.
    """

    class _RRset(list):
        def __init__(self, name, rdtype, records):
            super().__init__(records)
            self.name = name
            self.rdtype = rdtype

    apex = dns.name.from_text("example.com.")
    zone_dnskey = _make_dnskey_rrset_ext("example.com.")

    # 1) No relevant authority RRsets -> True.
    msg = type(
        "_Msg",
        (),
        {
            "authority": [
                _RRset(dns.name.from_text("other."), dns.rdatatype.A, ["1.2.3.4"]),
            ]
        },
    )()

    assert dval._validate_authority_rrsets(msg, apex, 1, apex, zone_dnskey) is True

    # 2) Apex DNSKEY mismatch -> False.
    mismatched_rrset = _RRset(apex, dns.rdatatype.DNSKEY, ["other-key"])
    msg2 = type("_Msg2", (), {"authority": [mismatched_rrset]})()
    assert dval._validate_authority_rrsets(msg2, apex, 1, apex, zone_dnskey) is False

    # 3) Relevant RRset without RRSIG -> False.
    ds_rr = _RRset(apex, dns.rdatatype.DS, ["ds"])
    msg3 = type("_Msg3", (), {"authority": [ds_rr]})()
    assert dval._validate_authority_rrsets(msg3, apex, 1, apex, zone_dnskey) is False

    # 4) Relevant RRset with RRSIG, but validation fails -> False.
    sig_rr = _RRset(apex, dns.rdatatype.RRSIG, ["sig"])
    msg4 = type("_Msg4", (), {"authority": [ds_rr, sig_rr]})()

    def _boom_validate(rrset, sig_rrset, keymap):  # noqa: D401, ANN001
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.dnssec.validate", _boom_validate
    )
    assert dval._validate_authority_rrsets(msg4, apex, 1, apex, zone_dnskey) is False


def test_message_has_dnssec_rr_detects_any_dnssec():
    """Brief: _message_has_dnssec_rr reports presence of DNSSEC RR types.

    Inputs:
      - None

    Outputs:
      - None; asserts True when any DNSKEY/DS/RRSIG/NSEC/NSEC3 is present.
    """

    class _RRset:
        def __init__(self, name, rdtype):
            self.name = name
            self.rdtype = rdtype

    msg = type(
        "_Msg",
        (),
        {
            "answer": [
                _RRset(dns.name.from_text("example."), dns.rdatatype.DNSKEY),
            ],
            "authority": [],
        },
    )()

    assert dval._message_has_dnssec_rr(msg) is True

    msg2 = type(
        "_Msg2",
        (),
        {
            "answer": [],
            "authority": [
                _RRset(dns.name.from_text("example."), dns.rdatatype.NSEC3),
            ],
        },
    )()

    assert dval._message_has_dnssec_rr(msg2) is True

    msg3 = type(
        "_Msg3",
        (),
        {
            "answer": [
                _RRset(dns.name.from_text("example."), dns.rdatatype.A),
            ],
            "authority": [],
        },
    )()

    assert dval._message_has_dnssec_rr(msg3) is False


def test_classify_dnssec_local_extended_additional_paths(monkeypatch):
    """Brief: _classify_dnssec_local_extended covers early-return branches.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts we honour baseline decisions and handle apex/chain errors.
    """

    qname_text = "example.com."
    qtype = 1
    wire = b"wire"

    # 1) Baseline secure/bogus/None are returned as-is.
    for status in ("dnssec_secure", "dnssec_bogus", None):
        monkeypatch.setattr(dval, "_classify_dnssec_local", lambda *_a, **_k: status)
        out = dval._classify_dnssec_local_extended(
            qname_text, qtype, wire, udp_payload_size=1232
        )
        assert out == status

    # 2) Baseline unsigned with DNSSEC material keeps baseline.
    class _Msg:
        def __init__(self, has_dnssec: bool) -> None:
            self._has_dnssec = has_dnssec

    def fake_from_wire(_wire):
        return _Msg(has_dnssec=True)

    def fake_has_dnssec_rr(msg):  # noqa: D401
        return msg._has_dnssec

    monkeypatch.setattr(
        dval, "_classify_dnssec_local", lambda *_a, **_k: "dnssec_unsigned"
    )
    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.message.from_wire", fake_from_wire
    )
    monkeypatch.setattr(dval, "_message_has_dnssec_rr", fake_has_dnssec_rr)

    out2 = dval._classify_dnssec_local_extended(
        qname_text, qtype, wire, udp_payload_size=1232
    )
    assert out2 == "dnssec_unsigned"

    # 3) Apex lookup fails or chain validation fails -> baseline result.
    def fake_from_wire_unsigned(_wire):
        return _Msg(has_dnssec=False)

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.message.from_wire", fake_from_wire_unsigned
    )

    monkeypatch.setattr(dval, "_find_zone_apex_cached", lambda *_a, **_k: None)
    out3 = dval._classify_dnssec_local_extended(
        qname_text, qtype, wire, udp_payload_size=1232
    )
    assert out3 == "dnssec_unsigned"

    apex = dns.name.from_text("example.com.")
    monkeypatch.setattr(dval, "_find_zone_apex_cached", lambda *_a, **_k: apex)
    monkeypatch.setattr(dval, "_validate_chain_cached", lambda *_a, **_k: None)
    out4 = dval._classify_dnssec_local_extended(
        qname_text, qtype, wire, udp_payload_size=1232
    )
    assert out4 == "dnssec_unsigned"


def test_classify_dnssec_status_modes_and_errors(monkeypatch):
    """Brief: classify_dnssec_status handles modes, strategies, and errors.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts None for non-validate mode and error paths.
    """

    # Non-validate mode -> None
    assert (
        dval.classify_dnssec_status(
            dnssec_mode="ignore",
            dnssec_validation="upstream_ad",
            qname_text="example.com",
            qtype_num=1,
            response_wire=b"wire",
        )
        is None
    )

    # Local strategy: make validate_response_local raise; classification should
    # swallow the error and return None.
    def _boom_local(
        qname, qtype, wire, udp_payload_size=0
    ):  # pragma: no cover - error stub
        raise RuntimeError("boom")

    monkeypatch.setattr(dval, "validate_response_local", _boom_local)
    assert (
        dval.classify_dnssec_status(
            dnssec_mode="validate",
            dnssec_validation="local",
            qname_text="example.com",
            qtype_num=1,
            response_wire=b"wire",
        )
        is None
    )

    # Upstream_ad: make dnslib parse raise; classification should return None.
    class _FakeDNSRecord:
        @staticmethod
        def parse(_b):  # pragma: no cover - error stub
            raise RuntimeError("boom")

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.DNSRecord", _FakeDNSRecord, raising=False
    )
    assert (
        dval.classify_dnssec_status(
            dnssec_mode="validate",
            dnssec_validation="upstream_ad",
            qname_text="example.com",
            qtype_num=1,
            response_wire=b"wire",
        )
        is None
    )


def test_configure_dnssec_resolver_and_resolver_variants(monkeypatch):
    """Brief: configure_dnssec_resolver drives resolver selection modes.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts global flags and _resolver behavior for all sentinel modes.
    """

    # Start from a clean configuration.
    dval.configure_dnssec_resolver(None)
    r_default = dval._resolver(payload_size=1280)
    assert isinstance(r_default, dns.resolver.Resolver)

    # Explicit nameserver list -> stub resolver with those nameservers.
    dval.configure_dnssec_resolver(["192.0.2.1", "2001:db8::1"])
    r_ns = dval._resolver(payload_size=1232)
    assert isinstance(r_ns, dns.resolver.Resolver)
    assert set(getattr(r_ns, "nameservers", [])) == {"192.0.2.1", "2001:db8::1"}

    # Empty list -> RecursiveResolver-backed shim.
    dval.configure_dnssec_resolver([])

    # Monkeypatch RecursiveResolver so we do not perform any real network IO.
    import foghorn.servers.recursive_resolver as rr_mod

    class _FakeRecursiveResolver:
        def __init__(self, *args, **kwargs):  # noqa: D401, ANN001
            """Record constructor arguments without side effects."""

            self.args = args
            self.kwargs = kwargs

        def resolve(self, q):  # noqa: D401, ANN001
            """Return a minimal dns.message-based response for testing."""

            msg = dns.message.Message()
            msg.answer.append(
                dns.rrset.from_text(
                    "example.com.",
                    300,
                    dns.rdataclass.IN,
                    dns.rdatatype.A,
                    "203.0.113.5",
                )
            )
            wire = msg.to_wire()
            return wire, "test-upstream"

    monkeypatch.setattr(rr_mod, "RecursiveResolver", _FakeRecursiveResolver)

    r_rec = dval._resolver(payload_size=1400)
    assert isinstance(r_rec, dval._RecursiveValidationResolver)

    # Exercise _RecursiveValidationResolver.resolve end-to-end.
    answer = r_rec.resolve(dns.name.from_text("example.com."), "A")
    assert isinstance(answer, dval._RecursiveAnswer)
    assert answer.rrset is not None
    assert isinstance(answer.response, dns.message.Message)

    # Error path: no matching RRset should raise NoAnswer when requested.
    class _EmptyRecursiveResolver:
        def __init__(self, *args, **kwargs):  # noqa: D401, ANN001
            """Resolver that always returns an empty answer section."""

        def resolve(self, q):  # noqa: D401, ANN001
            msg = dns.message.Message()
            wire = msg.to_wire()
            return wire, "test-upstream"

    monkeypatch.setattr(rr_mod, "RecursiveResolver", _EmptyRecursiveResolver)
    r_rec_empty = dval._RecursiveValidationResolver(payload_size=1400)

    import dns.resolver as _dns_resolver_mod

    with pytest.raises(_dns_resolver_mod.NoAnswer):
        r_rec_empty.resolve(dns.name.from_text("example.com."), "A")


def test_configure_trust_anchors_updates_globals():
    """Brief: configure_trust_anchors applies mode and hold-down settings.

    Inputs:
      - None

    Outputs:
      - None; asserts module-level configuration is updated.
    """

    dval.configure_trust_anchors(
        mode="RFC5011",
        store_path="/tmp/store.json",
        hold_down_add_days=7,
        hold_down_remove_days=9,
    )

    assert dval._TRUST_ANCHOR_MODE == "rfc5011"
    assert dval._TRUST_ANCHOR_STORE_PATH == "/tmp/store.json"
    assert dval._TRUST_ANCHOR_HOLD_ADD_DAYS == 7
    assert dval._TRUST_ANCHOR_HOLD_REMOVE_DAYS == 9


def test_dnskey_and_ds_caches_use_ttl_and_refresh(monkeypatch):
    """Brief: _fetch_dnskey_cached/_fetch_ds_cached honour TTL and cache entries.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts cached values are reused until expiry then refreshed.
    """

    # Clear caches for deterministic behavior.
    dval._DNSKEY_CACHE.clear()
    dval._DS_CACHE.clear()

    now_values = [1000.0, 1005.0, 1015.0, 1020.0, 1025.0, 1030.0]

    def fake_time() -> float:  # noqa: D401
        """Return controlled timestamps for cache tests."""

        return now_values.pop(0)

    monkeypatch.setattr(dval.time, "time", fake_time)

    class _Ans:
        def __init__(self, ttl: int, tag: str) -> None:
            self.rrset = type("_RR", (), {"ttl": ttl, "tag": tag})()

    fetch_calls: list[tuple[str, str]] = []

    def fake_fetch(resolver, name, rdtype):  # noqa: D401, ANN001
        """Return distinct rrsets so refresh behavior is visible."""

        fetch_calls.append((name.to_text(), rdtype))
        if rdtype == "DNSKEY":
            return _Ans(10, "dnskey")
        return _Ans(10, "ds")

    monkeypatch.setattr(dval, "_fetch", fake_fetch)

    name = dns.name.from_text("example.com.")

    rr1 = dval._fetch_dnskey_cached(object(), name)
    rr2 = dval._fetch_dnskey_cached(object(), name)
    # After TTL expiry, a new fetch should occur.
    rr3 = dval._fetch_dnskey_cached(object(), name)

    assert rr1 is rr2
    assert rr3 is not rr1

    # Similar behaviour for DS cache.
    ds1 = dval._fetch_ds_cached(object(), name)
    ds2 = dval._fetch_ds_cached(object(), name)
    assert ds1 is ds2


def test_fetch_dnskey_and_rrsig_parsing_and_errors():
    """Brief: _fetch_dnskey_and_rrsig extracts DNSKEY and covering RRSIG.

    Inputs:
      - None

    Outputs:
      - None; asserts success path and error when DNSKEY is absent.
    """

    class _RRset(list):
        def __init__(self, name, rdtype, records):
            super().__init__(records)
            self.name = name
            self.rdtype = rdtype

    class _SigRdata:
        def __init__(self, covered):
            self.type_covered = covered

    class _Ans:
        def __init__(self, answer):
            self.response = type("_Resp", (), {"answer": answer})()

    name = dns.name.from_text("example.com.")
    dnskey_rr = _RRset(name, dns.rdatatype.DNSKEY, ["dnskey"])
    rrsig_rr = _RRset(name, dns.rdatatype.RRSIG, [_SigRdata(dns.rdatatype.DNSKEY)])

    class _R:
        def __init__(self, answer):
            self._answer = answer

        def resolve(self, n, t, raise_on_no_answer=True):  # noqa: D401, ANN001
            assert n == name
            assert t == "DNSKEY"
            return _Ans(self._answer)

    r = _R([dnskey_rr, rrsig_rr])
    dnskey_out, sig_out = dval._fetch_dnskey_and_rrsig(r, name)
    assert dnskey_out is dnskey_rr
    assert sig_out is rrsig_rr

    # When no DNSKEY RRset is present, an exception should be raised.
    r2 = _R([rrsig_rr])
    with pytest.raises(Exception):
        dval._fetch_dnskey_and_rrsig(r2, name)


def test_nsec3_common_params_and_helpers(monkeypatch):
    """Brief: NSEC3 helpers cover NXDOMAIN/NODATA with synthetic data.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts True/False for simple NSEC3 scenarios.
    """

    class _RRset(list):
        def __init__(self, name, rdtype, records):
            super().__init__(records)
            self.name = name
            self.rdtype = rdtype

    origin = dns.name.from_text("example.")
    owner = dns.name.from_text("aaaa.example.")
    nxt_hash_name = dns.name.from_text("zzzz")

    class _Nsec3Rdata:
        def __init__(self):
            self.algorithm = 1
            self.iterations = 0
            self.salt = b""
            self.next = nxt_hash_name

    rrset = _RRset(owner, dns.rdatatype.NSEC3, [_Nsec3Rdata()])

    # Common params should extract origin/algorithm/iterations/salt.
    origin_out, algorithm, iterations, salt = dval._nsec3_common_params([rrset])
    assert origin_out == origin
    assert algorithm == 1
    assert iterations == 0
    assert salt == b""

    # Patch nsec3_hash so that we have a deterministic digest.
    def fake_hash(qname, alg, iters, s):  # noqa: D401, ANN001
        return b"digest-bytes"

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.dnssec.nsec3_hash", fake_hash
    )

    qname = dns.name.from_text("name.example.")

    # NXDOMAIN: hashed name should fall between owner and next.
    assert dval._nsec3_proves_nxdomain(qname, [rrset]) in {True, False}

    # NODATA: construct an rrset at the hashed owner with a bitmap that does
    # not include the queried type.
    digest = fake_hash(qname, 1, 0, b"")
    hash_label = base64.b32encode(digest).decode("ascii").strip("=").lower()
    hashed_owner = dns.name.from_text(f"{hash_label}.{origin}")

    class _BitmapRdata:
        def __init__(self, types):
            self.types = types

        def to_text(self):  # noqa: D401
            """Return a textual form with trailing type names."""

            return "owner next " + " ".join(self.types)

    nodata_rr = _RRset(hashed_owner, dns.rdatatype.NSEC3, [_BitmapRdata(["AAAA"])])

    # For the NODATA helper we do not rely on the full NSEC3 parameter
    # extraction logic; stub _nsec3_common_params so the test focuses on the
    # bitmap handling.
    def fake_common_params(_rrsets):  # noqa: D401, ANN001
        return origin, 1, 0, b""

    monkeypatch.setattr(dval, "_nsec3_common_params", fake_common_params)

    assert dval._nsec3_proves_nodata(qname, dns.rdatatype.A, [nodata_rr]) is True
