"""Brief: Unit tests for foghorn.dnssec_validate helpers.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

import dns.name
import dns.rcode

import foghorn.dnssec_validate as dval


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
        "foghorn.dnssec_validate.dns.message.from_wire", _fake_from_wire
    )
    monkeypatch.setattr(dval, "_collect_positive_rrsets", _fake_collect)
    monkeypatch.setattr(dval, "_find_zone_apex_cached", _fake_apex_cached)
    monkeypatch.setattr(dval, "_validate_chain_cached", _fake_chain_cached)
    monkeypatch.setattr("foghorn.dnssec_validate.dns.dnssec.validate", _fake_validate)

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

    monkeypatch.setattr("foghorn.dnssec_validate.dns.message.from_wire", _msg_servfail)
    unsupported = dval.validate_response_local(qname_text, rdtype, b"wire")
    assert unsupported is False

    # Outer exception path: from_wire raises -> False.
    def _boom_from_wire(wire):  # pragma: no cover - simple error stub
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "foghorn.dnssec_validate.dns.message.from_wire", _boom_from_wire
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
        "foghorn.dnssec_validate.dns.message.from_wire", _from_wire_noerror
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
        "foghorn.dnssec_validate.dns.dnssec.validate",
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
        "foghorn.dnssec_validate.dns.message.from_wire", _from_wire_nxdomain
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

    monkeypatch.setattr("foghorn.dnssec_validate.dns.dnssec.validate", _fake_validate)

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
        "foghorn.dnssec_validate.DNSRecord", _FakeDNSRecord, raising=False
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
