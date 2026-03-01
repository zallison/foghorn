"""Brief: Additional coverage tests for foghorn.dnssec.dnssec_validate.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver

import foghorn.dnssec.dnssec_validate as dval


def test_parse_resolv_conf_nameservers_parses_nameservers(tmp_path) -> None:
    """Brief: _parse_resolv_conf_nameservers parses nameserver lines only.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - None: Asserts nameserver entries are extracted in-order.
    """
    p = tmp_path / "resolv.conf"
    p.write_text(
        "\n".join(
            [
                "# comment",
                "search example.com",
                "nameserver 192.0.2.1",
                "nameserver 2001:db8::1  # trailing",
                "options edns0",
                "nameserver 8.8.8.8",
                "",
            ]
        ),
        encoding="utf-8",
    )

    out = dval._parse_resolv_conf_nameservers(str(p))
    assert out == ["192.0.2.1", "2001:db8::1", "8.8.8.8"]


def test_recursive_validation_resolver_handles_int_rdtype(monkeypatch) -> None:
    """Brief: _RecursiveValidationResolver.resolve supports numeric rdtype inputs.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: Asserts a response is returned and the qtype conversion path is exercised.
    """

    import foghorn.servers.recursive_resolver as rr_mod

    class _FakeRecursiveResolver:
        def __init__(self, *args, **kwargs):  # noqa: ANN001
            self.args = args
            self.kwargs = kwargs

        def resolve(self, q):  # noqa: ANN001
            _ = q
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
            return msg.to_wire(), "upstream"

    monkeypatch.setattr(rr_mod, "RecursiveResolver", _FakeRecursiveResolver)

    r = dval._RecursiveValidationResolver(payload_size=1232)
    ans = r.resolve(dns.name.from_text("example.com."), dns.rdatatype.A)
    assert ans.rrset is not None


def _clear_root_dnskey_cache() -> None:
    """Brief: Clear the cache used by _root_dnskey_rrset.

    Inputs:
      - None

    Outputs:
      - None
    """
    func = getattr(dval, "_root_dnskey_rrset")
    cache_obj = getattr(func, "cache", None)
    if hasattr(cache_obj, "clear"):
        cache_obj.clear()


def test_root_dnskey_rrset_rfc5011_bootstraps_store(monkeypatch, tmp_path) -> None:
    """Brief: _root_dnskey_rrset bootstraps store when RFC5011 mode has no anchors.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - tmp_path: pytest temporary directory.

    Outputs:
      - None: Asserts save_store is called and rrset is returned.
    """
    _clear_root_dnskey_cache()

    monkeypatch.setattr(dval, "_TRUST_ANCHOR_MODE", "rfc5011")
    store_path = str(tmp_path / "anchors.json")
    monkeypatch.setattr(dval, "_TRUST_ANCHOR_STORE_PATH", store_path)

    import foghorn.dnssec.trust_anchors as ta

    calls: dict[str, object] = {}

    def fake_load_store(path: str) -> dict:  # noqa: ANN001
        calls["load"] = path
        return {"zones": {}}

    def fake_anchors_for_zone(store: dict, zone: str):  # noqa: ANN001
        calls["anchors_for_zone"] = (store, zone)
        return []

    def fake_bootstrap(store: dict, zone: str, rrset):  # noqa: ANN001
        calls["bootstrap"] = zone
        return store

    def fake_save_store(path: str, store: dict) -> None:  # noqa: ANN001
        calls["save"] = path

    monkeypatch.setattr(ta, "load_store", fake_load_store)
    monkeypatch.setattr(ta, "anchors_for_zone", fake_anchors_for_zone)
    monkeypatch.setattr(ta, "bootstrap_from_rrset", fake_bootstrap)
    monkeypatch.setattr(ta, "save_store", fake_save_store)

    rrset = dval._root_dnskey_rrset()
    assert rrset is not None
    assert calls.get("save") == store_path


def test_root_dnskey_rrset_rfc5011_uses_existing_anchors(monkeypatch, tmp_path) -> None:
    """Brief: _root_dnskey_rrset builds rrset from store-provided anchors.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - tmp_path: pytest temporary directory.

    Outputs:
      - None: Asserts rrset is built from the anchor set.
    """
    _clear_root_dnskey_cache()

    monkeypatch.setattr(dval, "_TRUST_ANCHOR_MODE", "rfc5011")
    monkeypatch.setattr(
        dval, "_TRUST_ANCHOR_STORE_PATH", str(tmp_path / "anchors.json")
    )

    # Build a real DNSKEY rdata from the baked-in constant without invoking
    # _root_dnskey_rrset (which would depend on RFC5011 store state).
    txt = dval.ROOT_DNSKEY_STR.replace("\n", " ")
    rdata = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        txt.split(" DNSKEY ")[1],
    )

    import foghorn.dnssec.trust_anchors as ta

    monkeypatch.setattr(ta, "load_store", lambda _p: {"zones": {}})
    monkeypatch.setattr(ta, "anchors_for_zone", lambda _s, _z: [rdata])

    rrset = dval._root_dnskey_rrset()
    assert rrset is not None
    assert len(list(rrset)) == 1


def test_fetch_dnskey_and_rrsig_skips_rrsig_without_type_covered() -> None:
    """Brief: _fetch_dnskey_and_rrsig ignores malformed RRSIG records.

    Inputs:
      - None

    Outputs:
      - None: Asserts the DNSKEY rrset is returned with no covering sig.
    """

    class _RRset(list):
        def __init__(self, name, rdtype, records):
            super().__init__(records)
            self.name = name
            self.rdtype = rdtype

    class _BadSigRdata:
        pass

    class _Ans:
        def __init__(self, answer):
            self.response = type("_Resp", (), {"answer": answer})()

    name = dns.name.from_text("example.com.")
    dnskey_rr = _RRset(name, dns.rdatatype.DNSKEY, ["dnskey"])
    bad_sig_rr = _RRset(name, dns.rdatatype.RRSIG, [_BadSigRdata()])

    class _R:
        def resolve(self, n, t, raise_on_no_answer=True):  # noqa: ANN001
            assert n == name
            assert t == "DNSKEY"
            assert raise_on_no_answer is True
            return _Ans([dnskey_rr, bad_sig_rr])

    dnskey_out, sig_out = dval._fetch_dnskey_and_rrsig(_R(), name)
    assert dnskey_out is dnskey_rr
    assert sig_out is None


def test_validate_response_local_positive_chain_validate_error_returns_false(
    monkeypatch,
) -> None:
    """Brief: validate_response_local returns False when answer RRset validation errors.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None: Asserts False when dns.dnssec.validate raises in positive path.
    """

    class _Msg:
        def rcode(self):  # noqa: D401
            return dns.rcode.NOERROR

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.message.from_wire", lambda _b: _Msg()
    )

    final_owner = dns.name.from_text("example.com.")
    rrset = object()
    sig_rrset = object()
    monkeypatch.setattr(
        dval,
        "_collect_positive_rrsets",
        lambda *_a, **_k: (final_owner, [rrset], [sig_rrset]),
    )
    monkeypatch.setattr(dval, "_find_zone_apex_cached", lambda *_a, **_k: dns.name.root)
    monkeypatch.setattr(dval, "_validate_chain_cached", lambda *_a, **_k: object())

    def boom_validate(*_a, **_k):  # noqa: ANN001
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.dnssec.validate", boom_validate
    )

    assert dval.validate_response_local("example.com.", 1, b"wire") is False


def test_collect_positive_rrsets_cname_target_missing_returns_none() -> None:
    """Brief: _collect_positive_rrsets returns None on malformed CNAME rdata.

    Inputs:
      - None

    Outputs:
      - None: Asserts None when CNAME rrset lacks a usable target.
    """

    class _BadCnameRRset:
        def __init__(self, name):
            self.name = name
            self.rdtype = dns.rdatatype.CNAME

        def __getitem__(self, idx: int):  # noqa: D401
            _ = idx
            raise ValueError("no target")

    class _RRsigRRset:
        def __init__(self, name):
            self.name = name
            self.rdtype = dns.rdatatype.RRSIG

    qname = dns.name.from_text("www.example.com.")

    msg = type("_Msg", (), {"answer": [_BadCnameRRset(qname), _RRsigRRset(qname)]})()
    out = dval._collect_positive_rrsets(msg, qname, dns.rdatatype.A)
    assert out is None


def test_collect_positive_rrsets_dname_target_missing_returns_none() -> None:
    """Brief: _collect_positive_rrsets returns None on malformed DNAME rdata.

    Inputs:
      - None

    Outputs:
      - None: Asserts None when DNAME rrset lacks a usable target.
    """

    class _BadDnameRRset:
        def __init__(self, name):
            self.name = name
            self.rdtype = dns.rdatatype.DNAME

        def __getitem__(self, idx: int):  # noqa: D401
            _ = idx
            raise ValueError("no target")

    class _RRsigRRset:
        def __init__(self, name):
            self.name = name
            self.rdtype = dns.rdatatype.RRSIG

    qname = dns.name.from_text("www.example.com.")
    msg = type("_Msg", (), {"answer": [_BadDnameRRset(qname), _RRsigRRset(qname)]})()
    out = dval._collect_positive_rrsets(msg, qname, dns.rdatatype.A)
    assert out is None


def test_collect_positive_rrsets_defensive_error_returns_none() -> None:
    """Brief: _collect_positive_rrsets returns None on unexpected message structures.

    Inputs:
      - None

    Outputs:
      - None: Asserts None for objects without an answer section.
    """
    qname = dns.name.from_text("example.com.")
    out = dval._collect_positive_rrsets(object(), qname, dns.rdatatype.A)  # type: ignore[arg-type]
    assert out is None


def test_nsec_helpers_cover_edge_paths() -> None:
    """Brief: NSEC helpers cover low-level edge/corner cases.

    Inputs:
      - None

    Outputs:
      - None: Asserts conservative False/True outcomes for tricky cases.
    """

    class _NsecRRset(list):
        def __init__(self, name, records):
            super().__init__(records)
            self.name = name

    class _NoNext:
        pass

    # Empty rrset and rrset without .next -> map remains empty -> False.
    qname = dns.name.from_text("missing.example.")
    empty = _NsecRRset(dns.name.from_text("a.example."), [])
    no_next = _NsecRRset(dns.name.from_text("b.example."), [_NoNext()])
    assert dval._nsec_proves_nxdomain(qname, [empty, no_next]) is False

    # Wrap-around interval: owner > next and qname in wrap -> True.
    class _WithNext:
        def __init__(self, nxt):
            self.next = nxt

    owner = dns.name.from_text("zzzz.example.")
    nxt = dns.name.from_text("bbbb.example.")
    rr = _NsecRRset(owner, [_WithNext(nxt)])
    qname2 = dns.name.from_text("aaaa.example.")
    assert dval._nsec_proves_nxdomain(qname2, [rr]) is True

    # _nsec_proves_nodata skips non-matching rrsets.
    q = dns.name.from_text("name.example.")
    mismatch = _NsecRRset(dns.name.from_text("other.example."), [_WithNext(nxt)])
    assert dval._nsec_proves_nodata(q, dns.rdatatype.A, [mismatch]) is False

    # _nsec_proves_nodata conservative fallback when bitmap is unavailable.
    class _Bitmapless:
        pass

    nodata_rr = _NsecRRset(q, [_Bitmapless()])
    assert dval._nsec_proves_nodata(q, dns.rdatatype.A, [nodata_rr]) is False


def test_nsec3_common_params_negative_cases() -> None:
    """Brief: _nsec3_common_params returns None for inconsistent/malformed rrsets.

    Inputs:
      - None

    Outputs:
      - None
    """

    class _RRset(list):
        def __init__(self, name, records):
            super().__init__(records)
            self.name = name

    class _R:
        def __init__(self, alg, iters, salt):
            self.algorithm = alg
            self.iterations = iters
            self.salt = salt

    origin_owner = dns.name.from_text("aaaa.example.")

    assert dval._nsec3_common_params([]) is None
    assert dval._nsec3_common_params([_RRset(origin_owner, [])]) is None
    assert dval._nsec3_common_params([_RRset(origin_owner, [_R(None, 0, b"")])]) is None

    # Parameter mismatch between rrsets.
    a = _RRset(origin_owner, [_R(1, 0, b"")])
    b = _RRset(dns.name.from_text("bbbb.example."), [_R(2, 0, b"")])
    assert dval._nsec3_common_params([a, b]) is None

    # Defensive exception path.
    class _Boom:
        def __len__(self):
            raise RuntimeError("boom")

    assert dval._nsec3_common_params([_Boom()]) is None  # type: ignore[list-item]


def test_nsec3_proves_nxdomain_and_nodata_additional_branches(monkeypatch) -> None:
    """Brief: NSEC3 helpers cover additional branches (skips, wrap-around, bitmap parse).

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    class _RRset(list):
        def __init__(self, name, records):
            super().__init__(records)
            self.name = name

    class _R:
        def __init__(self, origin, nxt=None):
            self.algorithm = 1
            self.iterations = 0
            self.salt = b""
            self.next = nxt
            self._origin = origin

    qname = dns.name.from_text("name.example.")
    origin = dns.name.from_text("example.")

    # params None -> False.
    assert dval._nsec3_proves_nxdomain(qname, []) is False
    assert dval._nsec3_proves_nodata(qname, dns.rdatatype.A, []) is False

    # Skip empty rrset and rrset with next=None -> map empty -> False.
    empty = _RRset(dns.name.from_text("aaaa.example."), [])
    no_next = _RRset(dns.name.from_text("bbbb.example."), [_R(origin, nxt=None)])
    monkeypatch.setattr(dval, "_nsec3_common_params", lambda _rrs: (origin, 1, 0, b""))
    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.dnssec.nsec3_hash", lambda *_a, **_k: b"x"
    )
    assert dval._nsec3_proves_nxdomain(qname, [empty, no_next]) is False

    # Force hash_label to 'mmmm' so we can deterministically hit ordering logic.
    monkeypatch.setattr(dval.base64, "b32encode", lambda _b: b"MMMM")

    class _NextName:
        def __init__(self, label: str):
            self.labels = (label.encode("ascii"),)

    # Include an entry with owner == hashed_qname to cover the skip.
    hashed_qname = dns.name.from_text("mmmm.example.")
    rr_equal = _RRset(hashed_qname, [_R(origin, nxt=_NextName("zzzz"))])

    # Wrap-around entry: owner > nxt and hashed_qname < nxt -> True.
    owner = dns.name.from_text("zzzz.example.")
    # Choose next='nnnn' so that hashed_qname ('mmmm') is < next, triggering the
    # wrap-around coverage branch (owner='zzzz' > next='nnnn').
    rr_wrap = _RRset(owner, [_R(origin, nxt=_NextName("nnnn"))])

    assert dval._nsec3_proves_nxdomain(qname, [rr_equal, rr_wrap]) is True

    # NODATA: cover the to_text() bitmap parse path when rdata has no .types.
    class _BitmapRdata:
        def __init__(self):
            self.algorithm = 1
            self.iterations = 0
            self.salt = b""

        def to_text(self):
            return "1 0 0 0 0 AAAA"

    rr_nodata = _RRset(hashed_qname, [_BitmapRdata()])
    assert dval._nsec3_proves_nodata(qname, dns.rdatatype.A, [rr_nodata]) is True

    # Inner exception -> False.
    class _BoomText(_BitmapRdata):
        def to_text(self):
            raise RuntimeError("boom")

    rr_boom = _RRset(hashed_qname, [_BoomText()])
    assert dval._nsec3_proves_nodata(qname, dns.rdatatype.A, [rr_boom]) is False

    # Outer exception -> False.
    monkeypatch.setattr(
        dval,
        "_nsec3_common_params",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert dval._nsec3_proves_nodata(qname, dns.rdatatype.A, [rr_nodata]) is False


def test_validate_negative_response_additional_branches(monkeypatch) -> None:
    """Brief: _validate_negative_response covers return-false branches for rcode/answer combos.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    class _RRset(list):
        def __init__(self, name, rdtype):
            super().__init__([object()])
            self.name = name
            self.rdtype = rdtype

    apex = dns.name.from_text("example.")
    zone_dnskey = object()
    owner = dns.name.from_text("owner.example.")

    # Skip cryptographic validation.
    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.dnssec.validate", lambda *_a, **_k: None
    )

    nsec = _RRset(owner, dns.rdatatype.NSEC)
    sig = _RRset(owner, dns.rdatatype.RRSIG)

    class _MsgNsec:
        authority = [nsec, sig]
        answer = [object()]

        def rcode(self):
            return dns.rcode.SERVFAIL

    assert (
        dval._validate_negative_response(
            _MsgNsec(), owner, dns.rdatatype.A, apex, zone_dnskey
        )
        is False
    )

    nsec3 = _RRset(owner, dns.rdatatype.NSEC3)
    sig3 = _RRset(owner, dns.rdatatype.RRSIG)

    class _MsgNsec3:
        authority = [nsec3, sig3]
        answer = [object()]

        def rcode(self):
            return dns.rcode.NOERROR

    assert (
        dval._validate_negative_response(
            _MsgNsec3(), owner, dns.rdatatype.A, apex, zone_dnskey
        )
        is False
    )


def test_validate_authority_rrsets_ignores_glue_under_apex() -> None:
    """Brief: _validate_authority_rrsets ignores non-critical A/AAAA under the apex.

    Inputs:
      - None

    Outputs:
      - None: Asserts True when only glue-like RRsets are present.
    """

    class _RRset(list):
        def __init__(self, name, rdtype, records):
            super().__init__(records)
            self.name = name
            self.rdtype = rdtype

    apex = dns.name.from_text("example.com.")
    msg = type(
        "_Msg",
        (),
        {
            "authority": [
                _RRset(
                    dns.name.from_text("ns1.example.com."),
                    dns.rdatatype.A,
                    ["192.0.2.1"],
                ),
            ]
        },
    )()

    # zone_dnskey is unused in this branch, but must be present.
    assert dval._validate_authority_rrsets(msg, apex, 1, apex, []) is True


def test_classify_dnssec_local_extended_parse_failure_returns_baseline(
    monkeypatch,
) -> None:
    """Brief: _classify_dnssec_local_extended keeps baseline when wire re-parse fails.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    monkeypatch.setattr(
        dval, "_classify_dnssec_local", lambda *_a, **_k: "dnssec_unsigned"
    )

    def from_wire(_wire):  # noqa: ANN001
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.message.from_wire", from_wire
    )

    out = dval._classify_dnssec_local_extended("example.com.", 1, b"wire", 1232)
    assert out == "dnssec_unsigned"


def test_classify_dnssec_local_extended_enriched_rrsig_secure_and_bogus(
    monkeypatch,
) -> None:
    """Brief: _classify_dnssec_local_extended can upgrade to zone-secure or mark bogus.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    qname_text = "example.com."
    qname = dns.name.from_text(qname_text)

    monkeypatch.setattr(
        dval, "_classify_dnssec_local", lambda *_a, **_k: "dnssec_unsigned"
    )
    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.message.from_wire", lambda _b: object()
    )
    monkeypatch.setattr(dval, "_message_has_dnssec_rr", lambda _m: False)

    apex = dns.name.from_text("example.com.")
    monkeypatch.setattr(dval, "_find_zone_apex_cached", lambda *_a, **_k: apex)
    zone_dnskey = object()
    monkeypatch.setattr(dval, "_validate_chain_cached", lambda *_a, **_k: zone_dnskey)

    class _RR:
        def __init__(self, name, rdtype):
            self.name = name
            self.rdtype = rdtype

    enriched = type(
        "_Enriched",
        (),
        {"answer": [_RR(qname, dns.rdatatype.A), _RR(qname, dns.rdatatype.RRSIG)]},
    )()

    class _Ans:
        response = enriched

    monkeypatch.setattr(dval, "_resolver", lambda *_a, **_k: object())
    monkeypatch.setattr(dval, "_fetch", lambda *_a, **_k: _Ans())

    # Secure path.
    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.dnssec.validate", lambda *_a, **_k: None
    )
    assert (
        dval._classify_dnssec_local_extended(qname_text, 1, b"wire", 1232)
        == "dnssec_zone_secure"
    )

    # Bogus path.
    def boom_validate(*_a, **_k):  # noqa: ANN001
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.dnssec.validate", boom_validate
    )
    assert (
        dval._classify_dnssec_local_extended(qname_text, 1, b"wire", 1232)
        == "dnssec_bogus"
    )


def test_classify_dnssec_status_upstream_ad_success_paths() -> None:
    """Brief: classify_dnssec_status upstream_ad distinguishes AD=1 vs AD=0.

    Inputs:
      - None

    Outputs:
      - None
    """

    from dnslib import DNSHeader, DNSRecord

    msg_ad = DNSRecord(DNSHeader(ad=1))
    msg_no_ad = DNSRecord(DNSHeader(ad=0))

    assert (
        dval.classify_dnssec_status(
            dnssec_mode="validate",
            dnssec_validation="upstream_ad",
            qname_text="example.com",
            qtype_num=1,
            response_wire=msg_ad.pack(),
        )
        == "dnssec_secure"
    )

    assert (
        dval.classify_dnssec_status(
            dnssec_mode="validate",
            dnssec_validation="upstream_ad",
            qname_text="example.com",
            qtype_num=1,
            response_wire=msg_no_ad.pack(),
        )
        == "dnssec_unsigned"
    )


def test_validate_negative_response_nsec3_nodata_branch(monkeypatch) -> None:
    """Brief: _validate_negative_response uses NSEC3 NODATA proof when appropriate.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    class _RRset(list):
        def __init__(self, name, rdtype):
            super().__init__([object()])
            self.name = name
            self.rdtype = rdtype

    apex = dns.name.from_text("example.")
    zone_dnskey = object()
    owner = dns.name.from_text("owner.example.")

    # Make signature checks succeed.
    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.dnssec.validate", lambda *_a, **_k: None
    )
    monkeypatch.setattr(dval, "_nsec3_proves_nodata", lambda *_a, **_k: True)

    nsec3 = _RRset(owner, dns.rdatatype.NSEC3)
    sig = _RRset(owner, dns.rdatatype.RRSIG)

    class _Msg:
        authority = [nsec3, sig]
        answer = []

        def rcode(self):
            return dns.rcode.NOERROR

    assert (
        dval._validate_negative_response(
            _Msg(), owner, dns.rdatatype.A, apex, zone_dnskey
        )
        is True
    )


def test_nsec_proves_nodata_inner_exception_returns_false() -> None:
    """Brief: _nsec_proves_nodata returns False on bitmap parsing exceptions.

    Inputs:
      - None

    Outputs:
      - None
    """

    class _RRset(list):
        def __init__(self, name, records):
            super().__init__(records)
            self.name = name

    class _Rdata:
        covers = True

        def to_text(self):
            raise RuntimeError("boom")

    q = dns.name.from_text("name.example.")
    rr = _RRset(q, [_Rdata()])
    assert dval._nsec_proves_nodata(q, dns.rdatatype.A, [rr]) is False


def test_nsec3_common_params_subsequent_empty_rrset_returns_none() -> None:
    """Brief: _nsec3_common_params returns None when any rrset beyond the first is empty.

    Inputs:
      - None

    Outputs:
      - None
    """

    class _RRset(list):
        def __init__(self, name, records):
            super().__init__(records)
            self.name = name

    class _R:
        def __init__(self):
            self.algorithm = 1
            self.iterations = 0
            self.salt = b""

    a = _RRset(dns.name.from_text("aaaa.example."), [_R()])
    b = _RRset(dns.name.from_text("bbbb.example."), [])
    assert dval._nsec3_common_params([a, b]) is None


def test_nsec3_proves_nxdomain_interval_and_fallthrough(monkeypatch) -> None:
    """Brief: _nsec3_proves_nxdomain covers interval match and fall-through False.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    class _RRset(list):
        def __init__(self, name, records):
            super().__init__(records)
            self.name = name

    class _Next:
        def __init__(self, label: str):
            self.labels = (label.encode("ascii"),)

    class _R:
        algorithm = 1
        iterations = 0
        salt = b""

        def __init__(self, nxt: _Next):
            self.next = nxt

    origin = dns.name.from_text("example.")
    qname = dns.name.from_text("name.example.")

    monkeypatch.setattr(dval, "_nsec3_common_params", lambda _rrs: (origin, 1, 0, b""))
    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.dnssec.nsec3_hash", lambda *_a, **_k: b"x"
    )
    monkeypatch.setattr(dval.base64, "b32encode", lambda _b: b"MMMM")

    # Interval match: owner 'aaaa' < hashed 'mmmm' < next 'zzzz' -> True.
    rr_match = _RRset(dns.name.from_text("aaaa.example."), [_R(_Next("zzzz"))])
    assert dval._nsec3_proves_nxdomain(qname, [rr_match]) is True

    # Fall-through: hashed 'mmmm' not covered by 'aaaa'..'bbbb' -> False.
    rr_nomatch = _RRset(dns.name.from_text("aaaa.example."), [_R(_Next("bbbb"))])
    assert dval._nsec3_proves_nxdomain(qname, [rr_nomatch]) is False


def test_nsec3_proves_nodata_no_matching_hashed_owner_returns_false(
    monkeypatch,
) -> None:
    """Brief: _nsec3_proves_nodata returns False when no rrset matches hashed_qname.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    class _RRset(list):
        def __init__(self, name, records):
            super().__init__(records)
            self.name = name

    class _R:
        algorithm = 1
        iterations = 0
        salt = b""

        def to_text(self):
            return "1 0 0 0 0 AAAA"

    origin = dns.name.from_text("example.")
    qname = dns.name.from_text("name.example.")

    monkeypatch.setattr(dval, "_nsec3_common_params", lambda _rrs: (origin, 1, 0, b""))
    monkeypatch.setattr(
        "foghorn.dnssec.dnssec_validate.dns.dnssec.nsec3_hash", lambda *_a, **_k: b"x"
    )
    monkeypatch.setattr(dval.base64, "b32encode", lambda _b: b"MMMM")

    # rrset name != hashed owner -> continue -> final False.
    rr = _RRset(dns.name.from_text("aaaa.example."), [_R()])
    assert dval._nsec3_proves_nodata(qname, dns.rdatatype.A, [rr]) is False
