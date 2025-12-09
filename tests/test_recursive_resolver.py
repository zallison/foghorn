"""
Brief: Tests for the RecursiveResolver iterative recursion logic.

Inputs:
  - None (pytest harness)

Outputs:
  - None (pytest assertions on resolution behaviour).
"""

from typing import Any

import pytest
from dnslib import A, NS, QTYPE, RCODE, RR, SOA, DNSRecord

from foghorn.cache import FoghornTTLCache
from foghorn.recursive_resolver import RecursiveResolver


def _make_nxdomain_with_soa(qname: str) -> bytes:
    """Brief: Helper to build NXDOMAIN response with SOA for qname.

    Inputs:
      - qname: Query name as text.

    Outputs:
      - Wire-format DNS response bytes with NXDOMAIN and SOA authority.
    """

    q = DNSRecord.question(qname, "A")
    r = q.reply()
    r.header.rcode = RCODE.NXDOMAIN
    r.add_auth(
        RR(
            qname,
            QTYPE.SOA,
            rdata=SOA(
                f"ns.{qname}.",
                f"hostmaster.{qname}.",
                (1, 300, 300, 300, 300),
            ),
            ttl=300,
        )
    )
    return r.pack()


def test_recursive_resolver_positive_referral_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: RecursiveResolver walks root -> TLD -> auth using NS+glue.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture to stub udp_query.

    Outputs:
      - Final NOERROR answer for www.example.com and upstream id of auth server.
    """

    # Synthetic authorities used in the referral chain. We patch the
    # initial server list to contain a single synthetic root so the test is
    # deterministic and does not depend on the baked-in root hints.
    import foghorn.recursive_resolver as rr_mod

    root_ip = "192.0.2.1"
    tld_ip = "203.0.113.10"
    auth_ip = "203.0.113.20"

    def fake_choose_initial_servers(self):  # noqa: D401
        """Return a single synthetic root server for deterministic tests."""

        return [rr_mod._Server(root_ip, 53)]

    monkeypatch.setattr(
        RecursiveResolver, "_choose_initial_servers", fake_choose_initial_servers
    )

    def fake_udp_query(
        host: str, port: int, wire: bytes, timeout_ms: int = 0
    ) -> bytes:  # noqa: D401, ANN001
        """Return synthetic responses for root, TLD, and auth servers."""

        q = DNSRecord.parse(wire)
        qname = str(q.questions[0].qname).rstrip(".")

        if host == root_ip:
            # Root: refer to .com with NS and glue
            r = q.reply()
            r.add_auth(RR("com", QTYPE.NS, rdata=NS("ns1.com."), ttl=300))
            r.add_ar(RR("ns1.com.", QTYPE.A, rdata=A(tld_ip), ttl=300))
            return r.pack()

        if host == tld_ip:
            # TLD: refer to example.com with NS and glue
            r = q.reply()
            r.add_auth(
                RR("example.com", QTYPE.NS, rdata=NS("ns1.example.com."), ttl=300)
            )
            r.add_ar(RR("ns1.example.com.", QTYPE.A, rdata=A(auth_ip), ttl=300))
            return r.pack()

        if host == auth_ip:
            # Authoritative: final A answer
            r = q.reply()
            r.add_answer(RR(qname, QTYPE.A, rdata=A("93.184.216.34"), ttl=300))
            return r.pack()

        # Unexpected host: treat as NXDOMAIN to fail clearly in tests.
        return _make_nxdomain_with_soa(qname)

    # Patch the udp_query used inside recursive_resolver.
    monkeypatch.setattr(rr_mod, "udp_query", fake_udp_query)

    # Ensure TCP is never required in this happy-path test.
    def _boom_tcp(*_a: Any, **_k: Any) -> bytes:  # noqa: ANN001
        raise AssertionError("tcp_query should not be used in this test")

    monkeypatch.setattr(rr_mod, "tcp_query", _boom_tcp)

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=8,
        timeout_ms=5000,
        per_try_timeout_ms=1000,
    )

    req = DNSRecord.question("www.example.com.", "A")
    wire, upstream = resolver.resolve(req)

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR
    assert any(rr.rdata == A("93.184.216.34") for rr in resp.rr)
    assert upstream == f"{auth_ip}:53"


def test_recursive_resolver_nxdomain_terminates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: RecursiveResolver returns NXDOMAIN directly from first authority.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture to stub udp_query.

    Outputs:
      - NXDOMAIN reply and upstream id for the first authority.
    """

    # Use a fixed synthetic root for determinism.
    root_ip = "192.0.2.1"

    import foghorn.recursive_resolver as rr_mod

    def fake_choose_initial_servers(self):  # noqa: D401
        """Return a single synthetic root server for NXDOMAIN test."""

        return [rr_mod._Server(root_ip, 53)]

    monkeypatch.setattr(
        RecursiveResolver, "_choose_initial_servers", fake_choose_initial_servers
    )

    def fake_udp_query(
        host: str, port: int, wire: bytes, timeout_ms: int = 0
    ) -> bytes:  # noqa: D401, ANN001
        """Return NXDOMAIN with SOA for any root hit."""

        q = DNSRecord.parse(wire)
        qname = str(q.questions[0].qname).rstrip(".")

        if host == root_ip:
            return _make_nxdomain_with_soa(qname)

        return _make_nxdomain_with_soa(qname)

    monkeypatch.setattr(rr_mod, "udp_query", fake_udp_query)

    def _noop_tcp(*_a: Any, **_k: Any) -> bytes:  # noqa: ANN001
        return _make_nxdomain_with_soa("nxdomain.example")

    monkeypatch.setattr(rr_mod, "tcp_query", _noop_tcp)

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=4,
        timeout_ms=2000,
        per_try_timeout_ms=500,
    )

    req = DNSRecord.question("nxdomain.example.", "A")
    wire, upstream = resolver.resolve(req)

    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NXDOMAIN
    assert upstream is not None


def test_recursive_resolver_qname_minimization(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: RecursiveResolver uses minimized QNAMEs for NS lookups.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that root is queried for "com." NS and TLD for
        "example.com." NS before the final full QNAME A lookup.
    """

    import foghorn.recursive_resolver as rr_mod

    root_ip = "192.0.2.1"
    tld_ip = "203.0.113.10"
    auth_ip = "203.0.113.20"

    def fake_choose_initial_servers(self):  # noqa: D401
        """Return a single synthetic root server for deterministic tests."""

        return [rr_mod._Server(root_ip, 53)]

    monkeypatch.setattr(
        RecursiveResolver, "_choose_initial_servers", fake_choose_initial_servers
    )

    seen = {"root": None, "tld": None, "auth": None}

    def fake_udp_query(
        host: str, port: int, wire: bytes, timeout_ms: int = 0
    ) -> bytes:  # noqa: D401, ANN001
        """Inspect QNAME/QTYPE at each stage and return synthetic responses."""

        q = DNSRecord.parse(wire)
        qn = str(q.questions[0].qname)
        qt = q.questions[0].qtype

        if host == root_ip:
            seen["root"] = (qn, qt)
            # Root referral to .com
            r = q.reply()
            r.add_auth(RR("com.", QTYPE.NS, rdata=NS("ns1.com."), ttl=300))
            r.add_ar(RR("ns1.com.", QTYPE.A, rdata=A(tld_ip), ttl=300))
            return r.pack()

        if host == tld_ip:
            seen["tld"] = (qn, qt)
            # TLD referral to example.com
            r = q.reply()
            r.add_auth(
                RR("example.com.", QTYPE.NS, rdata=NS("ns1.example.com."), ttl=300)
            )
            r.add_ar(RR("ns1.example.com.", QTYPE.A, rdata=A(auth_ip), ttl=300))
            return r.pack()

        if host == auth_ip:
            seen["auth"] = (qn, qt)
            # Final A answer
            r = q.reply()
            r.add_answer(
                RR("www.example.com.", QTYPE.A, rdata=A("93.184.216.34"), ttl=300)
            )
            return r.pack()

        return _make_nxdomain_with_soa(qn)

    monkeypatch.setattr(rr_mod, "udp_query", fake_udp_query)

    def _boom_tcp(*_a: Any, **_k: Any) -> bytes:  # noqa: ANN001
        raise AssertionError("tcp_query should not be used in qname minimization test")

    monkeypatch.setattr(rr_mod, "tcp_query", _boom_tcp)

    resolver = RecursiveResolver(
        cache=FoghornTTLCache(),
        stats=None,
        max_depth=8,
        timeout_ms=5000,
        per_try_timeout_ms=1000,
    )

    req = DNSRecord.question("www.example.com.", "A")
    wire, upstream = resolver.resolve(req)
    resp = DNSRecord.parse(wire)

    # Ensure final answer is correct.
    assert resp.header.rcode == RCODE.NOERROR
    assert any(rr.rdata == A("93.184.216.34") for rr in resp.rr)
    assert upstream == f"{auth_ip}:53"

    # Check QNAME minimization stages.
    assert seen["root"] is not None
    root_qname, root_qtype = seen["root"]
    assert root_qname == "com."
    assert root_qtype == QTYPE.NS

    assert seen["tld"] is not None
    tld_qname, tld_qtype = seen["tld"]
    assert tld_qname == "example.com."
    assert tld_qtype == QTYPE.NS

    assert seen["auth"] is not None
    auth_qname, auth_qtype = seen["auth"]
    assert auth_qname == "www.example.com."
    assert auth_qtype == QTYPE.A
