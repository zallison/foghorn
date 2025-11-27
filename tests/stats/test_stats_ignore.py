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


def test_ignore_top_subdomains_exact_match_and_fallback() -> None:
    """Brief: Subdomains are ignored only on exact match; domains list is a fallback when subdomains list is empty.

    Inputs:
      - None.

    Outputs:
      - Asserts that names with ignored suffixes are excluded from top_subdomains
      - and that only true subdomains (at least three labels) appear in the
      - subdomain stats.
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
    # Only the exact example.com entry should be filtered out; a.example.com
    # must still be present because ignores are exact-match only. Names with
    # fewer than three labels (e.g., allowed.test) are not treated as
    # subdomains and therefore never appear in this list.
    assert "example.com" not in subs
    assert "a.example.com" in subs
    assert "allowed.test" not in subs

    # When ignore_top_subdomains is empty, ignore_top_domains acts as fallback
    collector = StatsCollector(
        include_top_domains=True,
        ignore_top_domains=["example.com"],
        ignore_top_subdomains=[],
    )
    collector.record_query("192.0.2.1", "example.com", "A")
    collector.record_query("192.0.2.1", "a.example.com", "A")
    snap2 = collector.snapshot(reset=False)
    assert snap2.top_subdomains is not None
    subs2 = {d for d, _ in snap2.top_subdomains}
    # Fallback uses exact-match semantics as well: example.com is hidden,
    # a.example.com remains visible.
    assert "example.com" not in subs2
    assert "a.example.com" in subs2


def test_ignore_top_domains_exact_match() -> None:
    """Brief: Base domains are ignored only on exact match in top_domains.

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
    # example.com should be ignored, but example.net (and any other domain)
    # must still be present.
    assert "example.com" not in domains
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


def test_suffix_mode_for_domains_and_subdomains() -> None:
    """Brief: When suffix modes are enabled, ignore lists act on suffix matches.

    Inputs:
      - None.

    Outputs:
      - Asserts that names ending in ignored suffixes are excluded from
      - top_domains and top_subdomains while totals still count all queries.
    """

    collector = StatsCollector(
        include_top_domains=True,
        ignore_top_domains=["example.com"],
        ignore_top_subdomains=[],
        ignore_domains_as_suffix=True,
        ignore_subdomains_as_suffix=True,
    )

    collector.record_query("192.0.2.1", "example.com", "A")
    collector.record_query("192.0.2.1", "a.example.com", "A")
    collector.record_query("192.0.2.1", "b.a.example.com", "A")

    snap = collector.snapshot(reset=False)
    assert snap.totals["total_queries"] == 3

    assert snap.top_domains is not None
    domains = {d for d, _ in snap.top_domains}
    # All base domains that collapse to example.com should be hidden
    assert "example.com" not in domains

    assert snap.top_subdomains is not None
    subs = {d for d, _ in snap.top_subdomains}
    # With suffix mode active and no explicit subdomain list, the domain set is
    # reused as suffix ignore set for subdomains.
    assert "example.com" not in subs
    assert "a.example.com" not in subs
    assert "b.a.example.com" not in subs


def test_ignore_single_host_hides_single_label_domains() -> None:
    """Brief: ignore_single_host hides single-label hostnames from top lists.

    Inputs:
      - None.

    Outputs:
      - Asserts that single-label names (e.g., "web") are absent from
      - top_domains/top_subdomains when ignore_single_host is enabled, while
      - fully-qualified names remain visible and totals still count all queries.
    """

    collector = StatsCollector(
        include_top_domains=True,
        ignore_single_host=True,
    )

    # Single-label hostnames
    collector.record_query("192.0.2.1", "web", "A")
    collector.record_query("192.0.2.1", "databases", "A")

    # Fully-qualified domains
    collector.record_query("192.0.2.1", "web.example.com", "A")
    collector.record_query("192.0.2.1", "databases.internal", "A")

    snap = collector.snapshot(reset=False)
    assert snap.totals["total_queries"] == 4

    # top_subdomains includes only true subdomains (at least three labels)
    assert snap.top_subdomains is not None
    subdomains = {d for d, _ in snap.top_subdomains}
    assert "web" not in subdomains
    assert "databases" not in subdomains
    assert "web.example.com" in subdomains
    # "databases.internal" has only two labels and is treated as a base
    # domain, so it must not appear in subdomain stats.
    assert "databases.internal" not in subdomains

    # top_domains aggregates by base domain (last two labels) and should only
    # see real domains. "databases.internal" remains visible while single-label
    # hosts are hidden.
    assert snap.top_domains is not None
    domains = {d for d, _ in snap.top_domains}
    assert "web" not in domains
    assert "databases" not in domains
    assert "example.com" in domains
    assert "databases.internal" in domains


def test_co_uk_subdomain_label_rules() -> None:
    """Brief: Subdomain stats require four labels under *.co.uk and three labels otherwise.

    Inputs:
      - None.

    Outputs:
      - Asserts that example.co.uk (3 labels) is treated as a base domain, while
      - www.example.co.uk (4 labels) is treated as a subdomain for top_subdomains.
    """

    collector = StatsCollector(
        include_top_domains=True,
    )

    # Base domains
    collector.record_query("192.0.2.1", "example.com", "A")
    collector.record_query("192.0.2.1", "example.co.uk", "A")

    # True subdomains
    collector.record_query("192.0.2.2", "www.example.com", "A")
    collector.record_query("192.0.2.2", "www.example.co.uk", "A")

    snap = collector.snapshot(reset=False)

    assert snap.top_subdomains is not None
    subs = {d for d, _ in snap.top_subdomains}

    # example.com and example.co.uk are bases, not subdomains
    assert "example.com" not in subs
    assert "example.co.uk" not in subs

    # www.example.com (3 labels) and www.example.co.uk (4 labels) are subdomains
    assert "www.example.com" in subs
    assert "www.example.co.uk" in subs


def test_set_ignore_filters_skips_empty_entries() -> None:
    """Brief: set_ignore_filters ignores empty client/domain/subdomain strings.

    Inputs:
      - None.

    Outputs:
      - None; asserts no crash and ignore filters still apply to non-empty values.
    """

    collector = StatsCollector(include_top_clients=True, include_top_domains=True)

    # Include empty strings that should be skipped by the parser.
    collector.set_ignore_filters(
        clients=["", "10.0.0.0/8"],
        domains=["", "example.com"],
        subdomains=["", "www.example.com"],
    )

    collector.record_query("10.1.2.3", "example.com", "A")
    collector.record_query("1.2.3.4", "www.example.com", "A")
    collector.record_query("1.2.3.5", "other.com", "A")
    collector.record_query("1.2.3.6", "notexample.com", "A")
    collector.record_query("1.2.3.7", "fakeexample.com", "A")

    snap = collector.snapshot(reset=False)
    assert snap.totals["total_queries"] == 3

    # Ignored client and domains should be filtered from top lists, ensuring
    # only the non-ignored entries remain visible.
    assert snap.top_clients is not None
    clients = {c for c, _ in snap.top_clients}
    assert "10.1.2.3" not in clients

    assert snap.top_domains is not None
    domains = {d for d, _ in snap.top_domains}
    assert "example.com" not in domains
    assert "other.com" in domains
    assert "notexample.com" in domains
    assert "fakeexample.com" in domains
