"""Brief: Tests ignore filters for top clients, domains, and subdomains.

Inputs:
  - None

Outputs:
  - None (pytest assertions on StatsCollector top-list behavior).
"""

from __future__ import annotations

from typing import Dict

from foghorn.stats import StatsCollector


def _snapshot_dict(collector: StatsCollector) -> Dict[str, object]:
    """Brief: Helper to take a snapshot and convert key fields to a dict.

    Inputs:
      - collector: StatsCollector instance.

    Outputs:
      - Dict containing selected snapshot attributes.
    """

    snap = collector.snapshot(reset=False)
    return {
        "top_clients": snap.top_clients,
        "top_domains": snap.top_domains,
        "top_subdomains": snap.top_subdomains,
        "totals": snap.totals,
    }


def test_ignore_top_clients_cidr() -> None:
    """Brief: Clients matching an IP/CIDR ignore rule do not appear in top_clients.

    Inputs:
      - None (uses in-memory StatsCollector only).

    Outputs:
      - Asserts that ignored clients are absent from top_clients but counted in totals.
    """

    collector = StatsCollector(
        include_top_clients=True,
        include_top_domains=False,
        ignore_top_clients=["10.0.0.0/8"],
    )

    # First query from an ignored CIDR, second from allowed IP
    collector.record_query("10.1.2.3", "example.com", "A")
    collector.record_query("1.2.3.4", "example.com", "A")

    snap = collector.snapshot(reset=False)
    assert snap.totals["total_queries"] == 2

    # Only the non-ignored client should appear in top_clients
    assert snap.top_clients is not None
    clients = {c for c, _ in snap.top_clients}
    assert "1.2.3.4" in clients
    assert "10.1.2.3" not in clients


def test_ignore_top_subdomains_suffix() -> None:
    """Brief: Subdomains matching ignore suffixes are omitted from top_subdomains.

    Inputs:
      - None.

    Outputs:
      - Asserts that names with ignored suffixes are excluded from top_subdomains.
    """

    collector = StatsCollector(
        include_top_domains=True,
        ignore_top_subdomains=["example.com"],
    )

    collector.record_query("192.0.2.1", "example.com", "A")
    collector.record_query("192.0.2.1", "a.Example.com.", "A")
    collector.record_query("192.0.2.1", "allowed.test", "A")

    snap = collector.snapshot(reset=False)

    assert snap.top_subdomains is not None
    subs = {d for d, _ in snap.top_subdomains}
    # Both example.com and a.example.com should be filtered out
    assert "example.com" not in subs
    assert "a.example.com" not in subs
    assert "allowed.test" in subs


def test_ignore_top_domains_suffix() -> None:
    """Brief: Base domains matching ignore suffixes are omitted from top_domains.

    Inputs:
      - None.

    Outputs:
      - Asserts that ignored base domains (and subdomains mapping to them) are excluded.
    """

    collector = StatsCollector(
        include_top_domains=True,
        ignore_top_domains=["example.com"],
    )

    collector.record_query("192.0.2.1", "a.Example.com.", "A")
    collector.record_query("192.0.2.1", "example.com", "A")
    collector.record_query("192.0.2.1", "b.example.net", "A")

    snap = collector.snapshot(reset=False)

    assert snap.top_domains is not None
    domains = {d for d, _ in snap.top_domains}
    # example.com (and a.example.com base) should be ignored
    assert "example.com" not in domains
    # example.net should still be present
    assert "example.net" in domains


def test_set_ignore_filters_at_runtime() -> None:
    """Brief: Updating ignore filters at runtime affects only subsequent top-list updates.

    Inputs:
      - None.

    Outputs:
      - Asserts that counters remain monotonic while top lists reflect new filters.
    """

    collector = StatsCollector(include_top_clients=True, include_top_domains=True)

    # Initial queries without ignore filters
    collector.record_query("10.1.2.3", "example.com", "A")
    collector.record_query("1.2.3.4", "example.net", "A")
    snap1 = collector.snapshot(reset=False)
    assert snap1.totals["total_queries"] == 2

    # Apply ignore filters and send more queries
    collector.set_ignore_filters(
        ["10.0.0.0/8"],
        ["example.com"],
        ["example.com"],
    )

    collector.record_query("10.1.2.3", "example.com", "A")
    collector.record_query("1.2.3.4", "example.net", "A")

    snap2 = collector.snapshot(reset=False)
    # Totals include all four queries
    assert snap2.totals["total_queries"] == 4

    # Top clients: 10.1.2.3 remains from pre-filter queries but is not
    # incremented for post-filter queries; 1.2.3.4 continues to accumulate.
    assert snap2.top_clients is not None
    client_counts = {c: n for c, n in snap2.top_clients}
    assert client_counts["1.2.3.4"] >= 2

    # Top domains: example.com should be ignored for new updates, while
    # example.net remains present.
    if snap2.top_domains is not None:
        domains = {d for d, _ in snap2.top_domains}
        assert "example.net" in domains
