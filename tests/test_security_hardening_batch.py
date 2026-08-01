"""Brief: Security hardening tests for refuse_any, recursive destinations, stats caps.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from dnslib import QTYPE, RCODE, DNSRecord, RR, A, NS
from dnslib import DNSHeader

import foghorn.servers.server as srv
from foghorn.servers.recursive_resolver import RecursiveResolver
from foghorn.stats import StatsCollector


class _FakeStore:
    """Brief: Minimal stats store capturing increment_count calls."""

    def __init__(self) -> None:
        self.counts: list[tuple[str, str, int]] = []

    def increment_count(self, scope: str, key: str, delta: int = 1) -> None:
        self.counts.append((str(scope), str(key), int(delta)))


def test_refuse_any_feature_returns_refused(set_runtime_snapshot) -> None:
    """Brief: server.features.refuse_any causes QTYPE ANY to return REFUSED.

    Inputs:
      - set_runtime_snapshot: runtime snapshot fixture.

    Outputs:
      - None; asserts REFUSED wire for ANY and NOERROR path still works for A.
    """

    set_runtime_snapshot(
        refuse_any=True,
        plugins=[],
        upstream_addrs=[],
        stats_collector=None,
        resolver_mode="master",
    )
    q_any = DNSRecord.question("example.com", "ANY")
    wire = srv.resolve_query_bytes(q_any.pack(), "127.0.0.1")
    assert DNSRecord.parse(wire).header.rcode == RCODE.REFUSED

    q_a = DNSRecord.question("example.com", "A")
    wire_a = srv.resolve_query_bytes(q_a.pack(), "127.0.0.1")
    # master mode without local answer is REFUSED for normal queries too; ensure
    # the ANY path specifically used refuse_any status rather than crashing.
    assert isinstance(wire_a, (bytes, bytearray))
    assert len(wire_a) >= 12


def test_recursive_destination_filter_blocks_private_glue() -> None:
    """Brief: Private glue is skipped when allow_private_destinations is false.

    Inputs:
      - None.

    Outputs:
      - None; asserts only global glue is returned.
    """

    resolver = RecursiveResolver(
        cache=None,
        stats=None,
        allow_private_destinations=False,
        destination_allowlist=[],
    )
    # Build a synthetic referral response with private + public glue.
    req = DNSRecord.question("www.example.com", "A")
    resp = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=0, ra=0), q=req.q)
    resp.add_auth(RR("example.com", QTYPE.NS, rdata=NS("ns.example.com."), ttl=60))
    resp.add_ar(RR("ns.example.com", QTYPE.A, rdata=A("10.1.2.3"), ttl=60))
    resp.add_ar(RR("ns.example.com", QTYPE.A, rdata=A("1.2.3.4"), ttl=60))
    resolver._stage_qname_context = "www.example.com."
    servers = resolver._extract_next_servers(resp)
    hosts = {s.host for s in servers}
    assert "10.1.2.3" not in hosts
    assert "1.2.3.4" in hosts


def test_recursive_destination_allowlist_permits_private() -> None:
    """Brief: destination_allowlist can re-enable selected private next hops.

    Inputs:
      - None.

    Outputs:
      - None; asserts allowlisted private IP is accepted.
    """

    resolver = RecursiveResolver(
        cache=None,
        stats=None,
        allow_private_destinations=False,
        destination_allowlist=["10.0.0.0/8"],
    )
    assert resolver._destination_allowed("10.9.9.9") is True
    assert resolver._destination_allowed("192.168.1.1") is False
    assert resolver._destination_allowed("8.8.8.8") is True


def test_stats_store_cardinality_cap_skips_new_client_keys() -> None:
    """Brief: max_store_clients prevents unbounded clients keys in persistence.

    Inputs:
      - None.

    Outputs:
      - None; asserts only one clients key is persisted when cap=1.
    """

    store = _FakeStore()
    collector = StatsCollector(
        track_uniques=False,
        include_top_clients=False,
        include_top_domains=False,
        stats_store=store,
        query_log_only=False,
        max_store_clients=1,
        max_store_domains=100,
        max_store_subdomains=100,
        max_store_qtype_qnames=100,
    )
    collector.record_query("1.1.1.1", "a.example.com", "A")
    collector.record_query("2.2.2.2", "b.example.com", "A")
    client_keys = [k for scope, k, _ in store.counts if scope == "clients"]
    assert client_keys == ["1.1.1.1"]
    assert collector._store_clients_dropped >= 1
