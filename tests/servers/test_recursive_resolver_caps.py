"""Regression tests for RecursiveResolver DoS hardening caps.

Brief:
  Ensure referral processing in RecursiveResolver is bounded:
  - NS names processed are capped
  - glue records processed are capped
  - next-hop server list is capped

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from dnslib import NS, QTYPE, RR, A, DNSRecord

from foghorn.servers.recursive_resolver import RecursiveResolver


def _make_referral_with_glue(*, ns_count: int, glue_rrs: list[RR]) -> DNSRecord:
    """Brief: Build a referral-style response with NS in auth and glue in ar.

    Inputs:
      - ns_count: Number of NS records to include under auth.
      - glue_rrs: Additional-section glue RRs.

    Outputs:
      - DNSRecord with auth NS records and additional glue records.
    """

    q = DNSRecord.question("example.com.", qtype="A")
    resp = q.reply()

    for i in range(1, ns_count + 1):
        resp.add_auth(
            RR("example.com.", QTYPE.NS, rdata=NS(f"ns{i}.example.com."), ttl=60)
        )

    for rr in glue_rrs:
        resp.add_ar(rr)

    return resp


def test_extract_next_servers_caps_ns_names() -> None:
    """Brief: _extract_next_servers caps NS names processed to 20.

    Inputs:
      - None.

    Outputs:
      - None; asserts returned next servers <= 20 when glue is present.
    """

    glue = [
        RR(f"ns{i}.example.com.", QTYPE.A, rdata=A(f"192.0.2.{i % 250 + 1}"), ttl=60)
        for i in range(1, 40)
    ]
    resp = _make_referral_with_glue(ns_count=40, glue_rrs=glue)

    r = RecursiveResolver(cache=None, stats=None)
    servers = r._extract_next_servers(resp)

    assert len(servers) == 20


def test_extract_next_servers_caps_glue_records_processed() -> None:
    """Brief: _extract_next_servers ignores glue records after the first 50.

    Inputs:
      - None.

    Outputs:
      - None; asserts NS names whose glue appears only after 50 are not returned.
    """

    # NS ns1..ns20
    # Provide glue for ns1..ns10 in the first 10 glue records, then pad out
    # to 50+ with unrelated glue, then provide glue for ns11..ns20 only after 60.
    glue: list[RR] = []

    for i in range(1, 11):
        glue.append(
            RR(f"ns{i}.example.com.", QTYPE.A, rdata=A(f"198.51.100.{i}"), ttl=60)
        )

    for i in range(1, 60):
        glue.append(
            RR(
                f"pad{i}.example.com.",
                QTYPE.A,
                rdata=A(f"203.0.113.{i % 250 + 1}"),
                ttl=60,
            )
        )

    for i in range(11, 21):
        glue.append(
            RR(f"ns{i}.example.com.", QTYPE.A, rdata=A(f"198.51.100.{i}"), ttl=60)
        )

    resp = _make_referral_with_glue(ns_count=20, glue_rrs=glue)

    r = RecursiveResolver(cache=None, stats=None)
    servers = r._extract_next_servers(resp)

    assert len(servers) == 10
    assert {s.host for s in servers} == {f"198.51.100.{i}" for i in range(1, 11)}
