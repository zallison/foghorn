"""Integration tests for statistics collection in server."""

from unittest.mock import Mock, patch

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache
from foghorn.plugins.resolve import base as plugin_base
from foghorn.servers.udp_server import DNSUDPHandler
from foghorn.stats import StatsCollector


def test_stats_collected_on_query(set_runtime_snapshot):
    """Verify stats are collected when handling a query."""
    # Create a stats collector
    collector = StatsCollector(track_latency=True)

    plugin_base.DNS_CACHE = InMemoryTTLCache()  # Clear cache
    set_runtime_snapshot(
        stats_collector=collector,
        upstream_addrs=[{"host": "8.8.8.8", "port": 53}],
        plugins=[],
        resolver_mode="forward",
        forward_local=False,
    )

    # Create a DNS query
    query = DNSRecord.question("example.com", "A")
    query_wire = query.pack()

    # Mock the socket
    mock_sock = Mock()

    # Mock upstream response
    response = query.reply()
    response_wire = response.pack()

    # Create handler without calling __init__ (which calls handle())
    handler = DNSUDPHandler.__new__(DNSUDPHandler)
    handler.request = (query_wire, mock_sock)
    handler.client_address = ("192.0.2.1", 12345)

    with patch.object(DNSRecord, "send", return_value=response_wire):
        try:
            handler.handle()
        except Exception:  # pragma: no cover
            # Socket operations may fail in test, that's OK
            pass  # pragma: no cover

    # Verify stats were collected
    snapshot = collector.snapshot()

    assert (
        snapshot.totals["total_queries"] >= 1
    ), "Should have recorded at least 1 query"
    assert "A" in snapshot.qtypes, "Should have recorded query type"
    assert (
        snapshot.totals.get("cache_misses", 0) >= 1
    ), "Should have recorded cache miss"

    # Verify latency was recorded
    if snapshot.latency_stats:
        assert snapshot.latency_stats["count"] >= 1, "Should have recorded latency"

    # Verify upstream statistics were populated for the configured upstream.
    assert snapshot.upstreams is not None
    assert "8.8.8.8:53" in snapshot.upstreams
    assert snapshot.upstream_rcodes is not None
    # At least one NOERROR from the single upstream should be recorded.
    assert snapshot.upstream_rcodes["8.8.8.8:53"]["NOERROR"] >= 1


def test_stats_cache_hit(set_runtime_snapshot):
    """Verify cache hits are recorded."""
    collector = StatsCollector()
    plugin_base.DNS_CACHE = InMemoryTTLCache()  # Clear cache
    set_runtime_snapshot(
        stats_collector=collector,
        upstream_addrs=[{"host": "8.8.8.8", "port": 53}],
        plugins=[],
        resolver_mode="forward",
        forward_local=False,
    )

    # Pre-populate cache
    query = DNSRecord.question("cached.example.com", "A")
    response = query.reply()
    response_wire = response.pack()
    cache_key = ("cached.example.com", QTYPE.A)
    plugin_base.DNS_CACHE.set(cache_key, 300, response_wire)

    # Create handler without calling __init__
    handler = DNSUDPHandler.__new__(DNSUDPHandler)
    query_wire = query.pack()
    mock_sock = Mock()
    handler.request = (query_wire, mock_sock)
    handler.client_address = ("192.0.2.1", 12345)

    try:
        handler.handle()
    except Exception:  # pragma: no cover
        pass  # pragma: no cover

    # Verify cache hit was recorded
    snapshot = collector.snapshot()
    assert snapshot.totals.get("cache_hits", 0) >= 1, "Should have recorded cache hit"


def test_stats_disabled_no_overhead(set_runtime_snapshot):
    """Verify no errors when stats collector is None."""
    plugin_base.DNS_CACHE = InMemoryTTLCache()  # Clear cache
    set_runtime_snapshot(
        stats_collector=None,
        upstream_addrs=[{"host": "8.8.8.8", "port": 53}],
        plugins=[],
        resolver_mode="forward",
        forward_local=False,
    )

    handler = DNSUDPHandler.__new__(DNSUDPHandler)
    query = DNSRecord.question("example.com", "A")
    query_wire = query.pack()
    mock_sock = Mock()
    handler.request = (query_wire, mock_sock)
    handler.client_address = ("192.0.2.1", 12345)

    response = query.reply()
    response_wire = response.pack()

    with patch.object(DNSRecord, "send", return_value=response_wire):
        try:
            handler.handle()
            # Should complete without errors even with no stats collector
        except Exception as e:
            # Socket errors are OK in test
            if "send" not in str(e).lower():
                raise
