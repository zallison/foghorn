"""Brief: Unit tests for the dns_prefetch plugin.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from typing import List, Optional, Tuple

import pytest

from foghorn.plugins.resolve.base import PluginContext
from foghorn.stats import StatsCollector, StatsSnapshot


def _make_snapshot(
    *,
    cache_hit_domains: Optional[List[Tuple[str, int]]] = None,
    top_domains: Optional[List[Tuple[str, int]]] = None,
) -> StatsSnapshot:
    """Brief: Create a minimal StatsSnapshot for dns_prefetch unit tests.

    Inputs:
      - cache_hit_domains: Optional list of (domain, count) tuples.
      - top_domains: Optional list of (domain, count) tuples.

    Outputs:
      - StatsSnapshot with empty/None values for unrelated fields.
    """

    return StatsSnapshot(
        created_at=0.0,
        totals={},
        rcodes={},
        qtypes={},
        decisions={},
        upstreams={},
        uniques=None,
        top_clients=None,
        top_subdomains=None,
        top_domains=top_domains,
        latency_stats=None,
        cache_hit_domains=cache_hit_domains,
    )


def test_dns_prefetch_setup_starts_thread_once_and_sigusr2_stops(monkeypatch) -> None:
    """Brief: setup() starts a daemon thread once and SIGUSR2 stops the loop.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts thread is started once and stop event is set.
    """

    from foghorn.plugins.resolve.dns_prefetch import DnsPrefetchPlugin
    import foghorn.plugins.resolve.dns_prefetch as mod

    created = {"count": 0}

    class DummyThread:
        def __init__(self, *, target, name: str, daemon: bool) -> None:
            created["count"] += 1
            self._target = target
            self.name = name
            self.daemon = daemon
            self._started = False

        def start(self) -> None:
            self._started = True

        def is_alive(self) -> bool:
            return self._started

    monkeypatch.setattr(mod.threading, "Thread", DummyThread)

    plugin = DnsPrefetchPlugin(interval_seconds=60)
    plugin.setup()
    plugin.setup()  # should be idempotent

    assert created["count"] == 1
    assert plugin._thread is not None
    assert plugin._thread.name == "DnsPrefetchPlugin"
    assert plugin._thread.daemon is True

    assert plugin._stop_event.is_set() is False
    plugin.handle_sigusr2()
    assert plugin._stop_event.is_set() is True


def test_dns_prefetch_get_stats_collector_requires_statscollector(monkeypatch) -> None:
    """Brief: _get_stats_collector returns None unless a StatsCollector is present.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts type gating around DNSUDPHandler.stats_collector.
    """

    from foghorn.plugins.resolve.dns_prefetch import DnsPrefetchPlugin
    from foghorn.servers.udp_server import DNSUDPHandler

    plugin = DnsPrefetchPlugin(interval_seconds=60)
    # Prevent starting a real background thread during unit tests.
    plugin.interval_seconds = 0
    plugin.setup()

    monkeypatch.setattr(DNSUDPHandler, "stats_collector", object(), raising=False)
    assert plugin._get_stats_collector() is None

    collector = StatsCollector()
    monkeypatch.setattr(DNSUDPHandler, "stats_collector", collector, raising=False)
    assert plugin._get_stats_collector() is collector


def test_dns_prefetch_run_single_cycle_prefers_cache_hit_domains_and_limits(
    monkeypatch,
) -> None:
    """Brief: _run_single_cycle prefers cache_hit_domains and limits/sorts candidates.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts only the top-N cache-hit domains are prefetched.
    """

    from foghorn.plugins.resolve.dns_prefetch import DnsPrefetchPlugin
    from foghorn.servers.udp_server import DNSUDPHandler

    plugin = DnsPrefetchPlugin(interval_seconds=60, prefetch_top_n=2)
    plugin.interval_seconds = 0
    plugin.setup()

    collector = StatsCollector()

    snap = _make_snapshot(
        cache_hit_domains=[("b.example", 1), ("a.example", 10), ("c.example", 2)],
        top_domains=[("should.not", 999)],
    )

    def _snapshot(reset: bool = False):  # type: ignore[no-untyped-def]
        assert reset is False
        return snap

    monkeypatch.setattr(collector, "snapshot", _snapshot)
    monkeypatch.setattr(DNSUDPHandler, "stats_collector", collector, raising=False)

    seen: List[str] = []

    def _prefetch_domain(domain: str) -> None:
        seen.append(domain)

    monkeypatch.setattr(plugin, "_prefetch_domain", _prefetch_domain)

    plugin._run_single_cycle()

    # Sorted by count desc, then limited to top 2.
    assert seen == ["a.example", "c.example"]


def test_dns_prefetch_run_single_cycle_falls_back_to_top_domains(monkeypatch) -> None:
    """Brief: _run_single_cycle falls back to top_domains when cache_hit_domains is empty.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts top_domains are used as candidates.
    """

    from foghorn.plugins.resolve.dns_prefetch import DnsPrefetchPlugin
    from foghorn.servers.udp_server import DNSUDPHandler

    plugin = DnsPrefetchPlugin(interval_seconds=60, prefetch_top_n=1)
    plugin.interval_seconds = 0
    plugin.setup()

    collector = StatsCollector()
    snap = _make_snapshot(cache_hit_domains=None, top_domains=[("x.example", 5)])

    monkeypatch.setattr(collector, "snapshot", lambda reset=False: snap)
    monkeypatch.setattr(DNSUDPHandler, "stats_collector", collector, raising=False)

    seen: List[str] = []
    monkeypatch.setattr(plugin, "_prefetch_domain", lambda d: seen.append(d))

    plugin._run_single_cycle()
    assert seen == ["x.example"]


def test_dns_prefetch_run_single_cycle_skips_after_max_misses_until_hit_increases(
    monkeypatch,
) -> None:
    """Brief: Domains are skipped after max_consecutive_misses until hit count rises.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts skip behavior and streak reset when hits increase.
    """

    from foghorn.plugins.resolve.dns_prefetch import DnsPrefetchPlugin
    from foghorn.servers.udp_server import DNSUDPHandler

    plugin = DnsPrefetchPlugin(
        interval_seconds=60,
        prefetch_top_n=1,
        max_consecutive_misses=2,
    )
    plugin.interval_seconds = 0
    plugin.setup()

    collector = StatsCollector()
    monkeypatch.setattr(DNSUDPHandler, "stats_collector", collector, raising=False)

    seen: List[str] = []
    monkeypatch.setattr(plugin, "_prefetch_domain", lambda d: seen.append(d))

    # Cycle 1: hits go 0 -> 1 (resets streak) => prefetch.
    monkeypatch.setattr(
        collector,
        "snapshot",
        lambda reset=False: _make_snapshot(cache_hit_domains=[("a.example", 1)]),
    )
    plugin._run_single_cycle()

    # Cycle 2: no new hits => streak 1 => still prefetch.
    plugin._run_single_cycle()

    # Cycle 3: still no new hits => streak 2 => skip.
    plugin._run_single_cycle()

    # Cycle 4: hits increase => streak reset => prefetch resumes.
    monkeypatch.setattr(
        collector,
        "snapshot",
        lambda reset=False: _make_snapshot(cache_hit_domains=[("a.example", 2)]),
    )
    plugin._run_single_cycle()

    assert seen == ["a.example", "a.example", "a.example"]


def test_dns_prefetch_prefetch_domain_continues_on_error(monkeypatch) -> None:
    """Brief: _prefetch_domain continues to next qtype when a single prefetch fails.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts later qtypes still run.
    """

    from foghorn.plugins.resolve.dns_prefetch import DnsPrefetchPlugin

    plugin = DnsPrefetchPlugin(interval_seconds=60, qtypes=["A", "AAAA"])
    plugin.interval_seconds = 0
    plugin.setup()

    called: List[Tuple[str, str]] = []

    def _prefetch_single(domain: str, qtype_name: str) -> None:
        if qtype_name == "A":
            raise RuntimeError("boom")
        called.append((domain, qtype_name))

    monkeypatch.setattr(plugin, "_prefetch_single", _prefetch_single)

    plugin._prefetch_domain("example.com")
    plugin._prefetch_domain("")

    assert called == [("example.com", "AAAA")]


def test_dns_prefetch_prefetch_single_sets_and_resets_threadlocal(monkeypatch) -> None:
    """Brief: _prefetch_single sets threadlocal marker only during resolver call.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts threadlocal marker is reset even on exceptions.
    """

    from foghorn.plugins.resolve.dns_prefetch import DnsPrefetchPlugin, _PREFETCH_LOCAL
    import foghorn.plugins.resolve.dns_prefetch as mod

    plugin = DnsPrefetchPlugin(interval_seconds=60)
    plugin.interval_seconds = 0
    plugin.setup()

    # Success path: local flag is True during resolver call.
    def _resolver_ok(wire: bytes, client_ip: str) -> bytes:  # type: ignore[no-untyped-def]
        assert getattr(_PREFETCH_LOCAL, "in_prefetch", False) is True
        assert client_ip == "127.0.0.1"
        return b""

    monkeypatch.setattr(mod, "resolve_query_bytes", _resolver_ok)

    assert getattr(_PREFETCH_LOCAL, "in_prefetch", False) is False
    plugin._prefetch_single("example.com", "A")
    assert getattr(_PREFETCH_LOCAL, "in_prefetch", False) is False

    # Error path: must still reset local flag.
    def _resolver_err(wire: bytes, client_ip: str) -> bytes:  # type: ignore[no-untyped-def]
        assert getattr(_PREFETCH_LOCAL, "in_prefetch", False) is True
        raise RuntimeError("resolver failed")

    monkeypatch.setattr(mod, "resolve_query_bytes", _resolver_err)
    with pytest.raises(RuntimeError):
        plugin._prefetch_single("example.com", "A")
    assert getattr(_PREFETCH_LOCAL, "in_prefetch", False) is False


def test_dns_prefetch_hooks_are_noops() -> None:
    """Brief: pre_resolve/post_resolve always return None.

    Inputs:
      - None.

    Outputs:
      - None; asserts hook return values.
    """

    from foghorn.plugins.resolve.dns_prefetch import DnsPrefetchPlugin

    plugin = DnsPrefetchPlugin(interval_seconds=60)
    plugin.interval_seconds = 0
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    assert plugin.pre_resolve("example.com", 1, b"", ctx) is None
    assert plugin.post_resolve("example.com", 1, b"", ctx) is None
