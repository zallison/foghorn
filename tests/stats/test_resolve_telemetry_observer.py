"""Unit tests for resolve telemetry bus and StatsCollectorObserver.

Inputs:
    - Synthetic ResolveEvent values.
    - In-memory StatsCollector.

Outputs:
    - Assertions that observer mapping matches prior pipeline counters.
"""

from __future__ import annotations

import time

from foghorn.servers.resolve_telemetry import (
    ResolveEvent,
    ResolveEventKind,
    ResolveTelemetry,
    telemetry_from_stats,
)
from foghorn.stats import StatsCollector
from foghorn.stats.observer import StatsCollectorObserver


def _totals(collector: StatsCollector) -> dict:
    snap = collector.snapshot(reset=False)
    return dict(snap.totals or {})


def test_telemetry_from_stats_empty_when_none() -> None:
    """Brief: None stats yields inactive bus.

    Inputs: none
    Outputs: inactive ResolveTelemetry.
    """
    tel = telemetry_from_stats(None)
    assert tel.active is False


def test_telemetry_from_stats_caches_on_collector() -> None:
    """Brief: Observer bus is cached on the collector instance.

    Inputs: StatsCollector
    Outputs: Same ResolveTelemetry instance on second call.
    """
    c = StatsCollector()
    a = telemetry_from_stats(c)
    b = telemetry_from_stats(c)
    assert a is b
    assert a.active is True


def test_observer_query_received() -> None:
    """Brief: query_received increments total_queries.

    Inputs: QUERY_RECEIVED event
    Outputs: totals.total_queries == 1
    """
    c = StatsCollector()
    StatsCollectorObserver(c).on_event(
        ResolveEvent(
            kind=ResolveEventKind.QUERY_RECEIVED,
            client_ip="10.0.0.1",
            qname="example.com",
            qtype_label="A",
        )
    )
    assert _totals(c).get("total_queries") == 1


def test_observer_pre_deny_fanout() -> None:
    """Brief: pre deny maps to cache_null, pre_deny_*, rcode, EDE.

    Inputs: PRE_PLUGIN_DECISION deny
    Outputs: Expected totals keys incremented.
    """
    c = StatsCollector(track_latency=True)
    t0 = time.perf_counter()
    StatsCollectorObserver(c).on_event(
        ResolveEvent(
            kind=ResolveEventKind.PRE_PLUGIN_DECISION,
            action="deny",
            client_ip="10.0.0.1",
            qname="blocked.example",
            qtype_label="A",
            plugin_label="filter",
            stat_label="blocklist",
            ede_code=15,
            ede_text="blocked by policy",
            t0=t0,
        )
    )
    totals = _totals(c)
    assert totals.get("cache_null") == 1
    assert totals.get("cache_deny_pre") == 1
    assert totals.get("pre_deny_filter") == 1
    assert totals.get("cache_stat_blocklist") == 1
    assert totals.get("ede_15") == 1


def test_observer_pre_deny_suppress_query_log() -> None:
    """Brief: suppress_query_log still updates counters without requiring store.

    Inputs: deny with suppress_query_log=True
    Outputs: counters updated; no exception without store.
    """
    c = StatsCollector()
    StatsCollectorObserver(c).on_event(
        ResolveEvent(
            kind=ResolveEventKind.PRE_PLUGIN_DECISION,
            action="deny",
            client_ip="10.0.0.1",
            qname="flood.example",
            qtype_label="A",
            plugin_label="rate_limit",
            suppress_query_log=True,
            ede_code=14,
            ede_text="rate limit exceeded",
            stat_label="rate_limit",
        )
    )
    totals = _totals(c)
    assert totals.get("cache_null") == 1
    assert totals.get("pre_deny_rate_limit") == 1


def test_observer_pre_override() -> None:
    """Brief: pre override records override_pre and pre_override label.

    Inputs: PRE_PLUGIN_DECISION override
    Outputs: cache_override_pre and pre_override_* totals.
    """
    c = StatsCollector()
    StatsCollectorObserver(c).on_event(
        ResolveEvent(
            kind=ResolveEventKind.PRE_PLUGIN_DECISION,
            action="override",
            client_ip="10.0.0.1",
            qname="local.example",
            qtype_label="A",
            plugin_label="etc_hosts",
            rcode_name="NOERROR",
            answers=[
                {"name": "local.example", "type": "A", "ttl": 60, "rdata": "127.0.0.1"}
            ],
            first="127.0.0.1",
        )
    )
    totals = _totals(c)
    assert totals.get("cache_null") == 1
    assert totals.get("cache_override_pre") == 1
    assert totals.get("pre_override_etc_hosts") == 1


def test_observer_cache_hit_and_miss() -> None:
    """Brief: cache lookup hit/miss map to collector counters.

    Inputs: CACHE_LOOKUP hit and miss
    Outputs: cache_hits and cache_misses.
    """
    c = StatsCollector(track_latency=True)
    obs = StatsCollectorObserver(c)
    obs.on_event(
        ResolveEvent(
            kind=ResolveEventKind.CACHE_LOOKUP,
            cache_outcome="hit",
            client_ip="10.0.0.1",
            qname="cached.example",
            qtype_label="A",
            rcode_name="NOERROR",
            answers=[],
            t0=time.perf_counter(),
        )
    )
    obs.on_event(
        ResolveEvent(
            kind=ResolveEventKind.CACHE_LOOKUP,
            cache_outcome="miss",
            qname="miss.example",
        )
    )
    totals = _totals(c)
    assert totals.get("cache_hits") == 1
    assert totals.get("cache_misses") == 1


def test_observer_upstream_failure() -> None:
    """Brief: total upstream failure records SERVFAIL path.

    Inputs: UPSTREAM_ATTEMPT total_failure=True
    Outputs: upstream counters and response rcode path without error.
    """
    c = StatsCollector(track_latency=True)
    StatsCollectorObserver(c).on_event(
        ResolveEvent(
            kind=ResolveEventKind.UPSTREAM_ATTEMPT,
            upstream_id="1.1.1.1:53",
            upstream_outcome="timeout",
            total_failure=True,
            client_ip="10.0.0.1",
            qname="fail.example",
            qtype_label="A",
            rcode_name="SERVFAIL",
            status="timeout",
            error="all_upstreams_failed",
            ede_code=23,
            ede_text="all upstreams failed",
            result={
                "source": "upstream",
                "status": "timeout",
                "error": "all_upstreams_failed",
                "ede_code": 23,
                "ede_text": "all upstreams failed",
            },
            t0=time.perf_counter(),
        )
    )
    totals = _totals(c)
    assert totals.get("ede_23") == 1


def test_observer_response_finalized_dnssec_recorded() -> None:
    """Brief: dnssec_recorded drives totals; dnssec_status goes to query path.

    Inputs: RESPONSE_FINALIZED with distinct dnssec fields
    Outputs: dnssec totals key from dnssec_recorded.
    """
    c = StatsCollector()
    StatsCollectorObserver(c).on_event(
        ResolveEvent(
            kind=ResolveEventKind.RESPONSE_FINALIZED,
            client_ip="10.0.0.1",
            qname="secure.example",
            qtype_label="A",
            rcode_name="NOERROR",
            status="ok",
            upstream_id="8.8.8.8:53",
            dnssec_status="dnssec_zone_secure",
            dnssec_recorded="dnssec_unsigned",
            answers=[],
        )
    )
    totals = _totals(c)
    assert totals.get("dnssec_unsigned") == 1
    assert totals.get("dnssec_zone_secure") in (0, None)


def test_observer_errors_do_not_raise() -> None:
    """Brief: Bad collector methods are swallowed by bus emit.

    Inputs: Observer that raises
    Outputs: emit completes without raising.
    """

    class Boom:
        def on_event(self, event):
            raise RuntimeError("boom")

    ResolveTelemetry((Boom(),)).emit(
        ResolveEvent(kind=ResolveEventKind.QUERY_RECEIVED, qname="x")
    )


def test_gate_short_circuit() -> None:
    """Brief: gate short circuit records rcode path.

    Inputs: GATE_SHORT_CIRCUIT
    Outputs: no exception; latency optional.
    """
    c = StatsCollector(track_latency=True)
    StatsCollectorObserver(c).on_event(
        ResolveEvent(
            kind=ResolveEventKind.GATE_SHORT_CIRCUIT,
            client_ip="10.0.0.1",
            qname="any.example",
            qtype_label="ANY",
            rcode_name="REFUSED",
            status="refuse_any",
            result={"source": "refuse_any", "action": "refuse"},
            t0=time.perf_counter(),
        )
    )
