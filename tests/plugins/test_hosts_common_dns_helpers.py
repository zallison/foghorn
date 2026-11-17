"""Brief: Tests for pure DNS answer helpers in hosts_common.

Inputs/Outputs:
  - Exercises parse/reply packing helpers used by EtcHosts, MdnsBridge, and
    DynamicHostsPlugin without requiring plugin setup.
"""

from __future__ import annotations

from dnslib import AAAA, PTR, QTYPE, A, DNSRecord

from foghorn.plugins.resolve import hosts_common

_V4 = ".".join(map(str, (127, 0, 0, 1)))
_V6 = "::1"
_REV4 = ".".join(map(str, (1, 0, 0, 127))) + ".in-addr.arpa"


def test_ptr_owner_and_reverse_name_helpers() -> None:
    """Brief: ptr_owner and is_reverse_ptr_name cover basic edge cases."""

    assert hosts_common.ptr_owner("host.example") == "host.example."
    assert hosts_common.ptr_owner("host.example.") == "host.example."
    assert hosts_common.ptr_owner("") == "."
    assert hosts_common.is_reverse_ptr_name(_REV4)
    assert hosts_common.is_reverse_ptr_name("x.ip6.arpa.")
    assert not hosts_common.is_reverse_ptr_name("host.example")


def test_ip_matches_qtype_family_gate() -> None:
    """Brief: A/AAAA family mismatch detection matches historical EtcHosts rules."""

    assert hosts_common.ip_matches_qtype(_V4, QTYPE.A)
    assert not hosts_common.ip_matches_qtype(_V4, QTYPE.AAAA)
    assert hosts_common.ip_matches_qtype(_V6, QTYPE.AAAA)
    assert not hosts_common.ip_matches_qtype(_V6, QTYPE.A)


def test_make_a_aaaa_and_ptr_responses() -> None:
    """Brief: Packed A/AAAA/PTR responses parse and carry expected rdata."""

    a_req = DNSRecord.question("web.example.", qtype="A").pack()
    a_wire = hosts_common.make_a_aaaa_response(a_req, QTYPE.A, [_V4], 42)
    assert a_wire is not None
    a_reply = DNSRecord.parse(a_wire)
    assert len(a_reply.rr) == 1
    assert a_reply.rr[0].rtype == QTYPE.A
    assert str(a_reply.rr[0].rdata) == _V4
    assert int(a_reply.rr[0].ttl) == 42

    aaaa_req = DNSRecord.question("web.example.", qtype="AAAA").pack()
    aaaa_wire = hosts_common.make_a_aaaa_response(aaaa_req, QTYPE.AAAA, [_V6], 60)
    assert aaaa_wire is not None
    aaaa_reply = DNSRecord.parse(aaaa_wire)
    assert aaaa_reply.rr[0].rtype == QTYPE.AAAA
    assert isinstance(aaaa_reply.rr[0].rdata, AAAA)

    empty = hosts_common.make_a_aaaa_response(a_req, QTYPE.A, [], 30)
    assert empty is not None
    assert DNSRecord.parse(empty).rr == []

    ptr_req = DNSRecord.question(_REV4 + ".", qtype="PTR").pack()
    ptr_wire = hosts_common.make_ptr_response(ptr_req, "host.example", 99)
    assert ptr_wire is not None
    ptr_reply = DNSRecord.parse(ptr_wire)
    assert ptr_reply.rr[0].rtype == QTYPE.PTR
    assert isinstance(ptr_reply.rr[0].rdata, PTR)
    assert str(ptr_reply.rr[0].rdata).rstrip(".") == "host.example"
    assert int(ptr_reply.rr[0].ttl) == 99

    assert hosts_common.make_a_aaaa_response(b"bad", QTYPE.A, [_V4], 1) is None
    assert hosts_common.make_ptr_response(b"bad", "host", 1) is None


def test_limit_txt_values_and_sanitize() -> None:
    """Brief: TXT helpers clamp count/bytes and strip control characters."""

    limited = hosts_common.limit_txt_values(
        ["a", "bb", "ccc"], max_strings=2, max_bytes=0, sanitize=False
    )
    assert limited == ["a", "bb"]

    limited_bytes = hosts_common.limit_txt_values(
        ["aa", "bbb"], max_strings=0, max_bytes=3, sanitize=False
    )
    assert limited_bytes == ["aa"]

    dirty = "hi" + chr(0) + "there"
    cleaned = hosts_common.sanitize_txt_chunk(dirty)
    assert chr(0) not in cleaned
    dirty2 = "x" + chr(1) + "y"
    assert hosts_common.limit_txt_values([dirty2], sanitize=True) == [
        hosts_common.sanitize_txt_chunk(dirty2)
    ]


def test_rr_builders() -> None:
    """Brief: rr_a/rr_aaaa/rr_ptr/rr_txt produce the expected QTYPEs."""

    assert hosts_common.rr_a("web.", _V4, 10).rtype == QTYPE.A
    assert isinstance(hosts_common.rr_a("web.", _V4, 10).rdata, A)
    assert hosts_common.rr_aaaa("web.", _V6, 10).rtype == QTYPE.AAAA
    assert hosts_common.rr_ptr(_REV4 + ".", "h.example", 10).rtype == QTYPE.PTR
    txt = hosts_common.rr_txt("web.", ["k=v"], 10, sanitize=True)
    assert txt.rtype == QTYPE.TXT


def test_format_exception_brief_handles_empty_message() -> None:
    """Brief: bare NotImplementedError still yields a useful type name."""

    assert (
        hosts_common.format_exception_brief(NotImplementedError())
        == "NotImplementedError"
    )
    assert (
        hosts_common.format_exception_brief(RuntimeError("boom"))
        == "RuntimeError: boom"
    )


def test_dns_names_from_labels_parses_and_validates() -> None:
    """Brief: dns_names_from_labels splits, normalizes, and drops invalid tokens.

    Inputs:
      - None.

    Outputs:
      - None; asserts parsing, multi-label keep, invalid drop.
    """

    assert hosts_common.dns_names_from_labels({"dns_name": "api, web"}) == [
        "api",
        "web",
    ]
    assert hosts_common.dns_names_from_labels(
        {"DNS_NAME": "Api.Internal"}, "dns_name"
    ) == ["api.internal"]
    assert hosts_common.dns_names_from_labels({"dns_name": "_bad,ok"}) == ["ok"]
    assert hosts_common.dns_names_from_labels({}, "dns_name") == []
    assert hosts_common.is_valid_dns_hostname("api.internal") is True
    assert hosts_common.is_valid_dns_hostname("_x") is False
