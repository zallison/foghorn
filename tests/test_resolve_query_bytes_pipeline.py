"""
Brief: Tests resolve_query_bytes pipeline for deny/override and cache hit.

Inputs:
  - None

Outputs:
  - None
"""

import pytest
from dnslib import QTYPE, RCODE, RR, A, DNSRecord

import foghorn.servers.server as server_mod
from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache
from foghorn.plugins.resolve import base as plugin_base
from foghorn.plugins.resolve.base import BasePlugin, PluginContext, PluginDecision
from foghorn.runtime_config import parse_upstream_health_config
from foghorn.servers.dns_runtime_state import DNSRuntimeState
from foghorn.servers.server import resolve_query_bytes


class _DenyPlugin(BasePlugin):
    def pre_resolve(self, qname, qtype, data, ctx: PluginContext):
        return PluginDecision(action="deny")


class _OverridePlugin(BasePlugin):
    def pre_resolve(self, qname, qtype, data, ctx: PluginContext):
        r = DNSRecord.question(qname, "A").reply()
        return PluginDecision(action="override", response=r.pack())


class _Stats:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[tuple, dict]]] = []

    def __getattr__(self, name: str):
        def _rec(*a, **k):
            self.calls.append((name, (a, k)))

        return _rec


def test_resolve_query_bytes_deny_and_override(set_runtime_snapshot):
    set_runtime_snapshot(plugins=[_DenyPlugin()])
    q = DNSRecord.question("deny.example", "A")
    resp = resolve_query_bytes(q.pack(), "127.0.0.1")
    assert DNSRecord.parse(resp).header.rcode == RCODE.NXDOMAIN

    set_runtime_snapshot(plugins=[_OverridePlugin()])
    q2 = DNSRecord.question("override.example", "A")
    resp2 = resolve_query_bytes(q2.pack(), "127.0.0.1")
    assert DNSRecord.parse(resp2).header.rcode == RCODE.NOERROR


def test_resolve_query_bytes_cache_hit(set_runtime_snapshot):
    set_runtime_snapshot(plugins=[])
    q = DNSRecord.question("cache.example", "A")
    r = q.reply()
    plugin_base.DNS_CACHE.set(("cache.example", QTYPE.A), 10, r.pack())
    resp = resolve_query_bytes(q.pack(), "127.0.0.1")
    out = DNSRecord.parse(resp)
    assert out.header.rcode == RCODE.NOERROR


def test_resolve_query_bytes_qdcount_zero_returns_formerr(set_runtime_snapshot) -> None:
    """Brief: QDCOUNT=0 packets should not crash and should return FORMERR.

    Inputs:
      - Minimal DNS wire header with QDCOUNT=0.

    Outputs:
      - None; asserts QR=1 and RCODE=FORMERR.
    """

    set_runtime_snapshot(plugins=[])

    # 12-byte DNS header only (QDCOUNT=0).
    # ID=0xBEEF, RD=1.
    query = (
        b"\xbe\xef"  # ID
        + b"\x01\x00"  # flags (RD=1)
        + b"\x00\x00"  # QDCOUNT
        + b"\x00\x00"  # ANCOUNT
        + b"\x00\x00"  # NSCOUNT
        + b"\x00\x00"  # ARCOUNT
    )

    resp = resolve_query_bytes(query, "127.0.0.1")

    assert isinstance(resp, (bytes, bytearray))
    assert len(resp) == 12
    assert resp[:2] == b"\xbe\xef"

    flags = int.from_bytes(resp[2:4], "big")
    assert (flags & 0x8000) == 0x8000  # QR=1
    assert (flags & 0x0100) == 0x0100  # RD mirrored
    assert (flags & 0x000F) == int(RCODE.FORMERR)


def test_resolve_query_bytes_worst_case_fallback_never_reflects_query(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: Worst-case fallback must never return the original query bytes.

    Inputs:
      - monkeypatch: Forces DNSRecord.parse to fail in both main and exception paths.

    Outputs:
      - None; asserts header-only SERVFAIL with preserved ID.
    """

    set_runtime_snapshot(plugins=[])

    # Minimal header-only query; actual content doesn't matter because parse is patched.
    query = (
        b"\x12\x34"  # ID
        + b"\x01\x00"  # flags (RD=1)
        + b"\x00\x01"  # QDCOUNT=1 (nominal)
        + b"\x00\x00"  # ANCOUNT
        + b"\x00\x00"  # NSCOUNT
        + b"\x00\x00"  # ARCOUNT
    )

    def _boom(_wire):
        raise Exception("parse failed")

    monkeypatch.setattr(server_mod.DNSRecord, "parse", _boom)

    resp = resolve_query_bytes(query, "127.0.0.1")

    assert isinstance(resp, (bytes, bytearray))
    assert len(resp) == 12
    assert resp[:2] == b"\x12\x34"
    assert bytes(resp) != bytes(query)

    flags = int.from_bytes(resp[2:4], "big")
    assert (flags & 0x8000) == 0x8000  # QR=1
    assert (flags & 0x0100) == 0x0100  # RD mirrored
    assert (flags & 0x000F) == int(RCODE.SERVFAIL)


def test_resolve_query_bytes_stats_pre_deny_and_override(set_runtime_snapshot):
    """Brief: resolve_query_bytes records stats for pre deny and override paths.

    Inputs:
      - None

    Outputs:
      - None; asserts key stats hooks are called for deny/override.
    """

    plugin_base.DNS_CACHE = InMemoryTTLCache()

    stats = _Stats()

    set_runtime_snapshot(stats_collector=stats, plugins=[_DenyPlugin()])
    q1 = DNSRecord.question("deny-stats.example", "A")
    resolve_query_bytes(q1.pack(), "127.0.0.1")

    set_runtime_snapshot(stats_collector=stats, plugins=[_OverridePlugin()])
    q2 = DNSRecord.question("override-stats.example", "A")
    resolve_query_bytes(q2.pack(), "127.0.0.1")

    kinds = [k for k, _ in stats.calls]
    assert "record_query" in kinds
    assert "record_cache_null" in kinds
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds
    assert "record_latency" in kinds


def test_resolve_query_bytes_marks_upstream_health_on_failure(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: resolve_query_bytes increments upstream fail_count on forward failure.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts DNSRuntimeState.upstream_health fail_count increments.
    """

    q = DNSRecord.question("health-fail.example", "A")
    up = {"host": "2.2.2.2", "port": 53}
    up_id = DNSRuntimeState._upstream_id(up)

    def _forward_fail(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        return None, None, "all_failed"

    monkeypatch.setattr(server_mod, "send_query_with_failover", _forward_fail)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[up],
    )

    DNSRuntimeState.upstream_health.clear()
    try:
        wire = resolve_query_bytes(q.pack(), "127.0.0.1")
        resp = DNSRecord.parse(wire)
        assert resp.header.rcode == RCODE.SERVFAIL

        entry = DNSRuntimeState.upstream_health.get(up_id)
        assert isinstance(entry, dict)
        assert float(entry.get("fail_count", 0.0) or 0.0) >= 1.0
        assert float(entry.get("down_until", 0.0) or 0.0) > 0.0
    finally:
        DNSRuntimeState.upstream_health.clear()


def test_resolve_query_bytes_uses_backup_when_all_primaries_degraded(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: resolve_query_bytes forwards to backups only when all primaries are degraded.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts backup upstream is selected when primary is in backoff.
    """

    q = DNSRecord.question("backup-failover.example", "A")
    primary = {"host": "1.1.1.1", "port": 53}
    backup = {"host": "9.9.9.9", "port": 53}
    chosen = {"host": None}

    r_ok = q.reply()

    def _forward_capture(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        assert upstreams, "expected at least one upstream candidate"
        chosen["host"] = upstreams[0].get("host")
        return r_ok.pack(), upstreams[0], "ok"

    monkeypatch.setattr(server_mod, "send_query_with_failover", _forward_capture)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[primary],
        upstream_backup_addrs=[backup],
    )

    primary_id = DNSRuntimeState._upstream_id(primary)
    DNSRuntimeState.upstream_health.clear()
    try:
        import time as _time

        DNSRuntimeState.upstream_health[primary_id] = {
            "fail_count": 2.0,
            "down_until": _time.time() + 60.0,
        }

        wire = resolve_query_bytes(q.pack(), "127.0.0.1")
        resp = DNSRecord.parse(wire)
        assert resp.header.rcode == RCODE.NOERROR
        assert chosen["host"] == "9.9.9.9"
    finally:
        DNSRuntimeState.upstream_health.clear()


def test_resolve_query_bytes_skips_backup_when_any_primary_healthy(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: Backup upstreams are skipped when at least one primary is healthy.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts primary upstream is selected when any primary is healthy.
    """

    q = DNSRecord.question("primary-still-healthy.example", "A")
    primary_healthy = {"host": "1.1.1.1", "port": 53}
    primary_degraded = {"host": "1.0.0.1", "port": 53}
    backup = {"host": "9.9.9.9", "port": 53}
    chosen = {"host": None}
    r_ok = q.reply()

    monkeypatch.setattr(server_mod.random, "random", lambda: 1.0)

    def _forward_capture(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        assert upstreams, "expected at least one upstream candidate"
        chosen["host"] = upstreams[0].get("host")
        return r_ok.pack(), upstreams[0], "ok"

    monkeypatch.setattr(server_mod, "send_query_with_failover", _forward_capture)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[primary_healthy, primary_degraded],
        upstream_backup_addrs=[backup],
    )

    primary_id = DNSRuntimeState._upstream_id(primary_degraded)
    DNSRuntimeState.upstream_health.clear()
    try:
        import time as _time

        DNSRuntimeState.upstream_health[primary_id] = {
            "fail_count": 2.0,
            "down_until": _time.time() + 60.0,
        }

        wire = resolve_query_bytes(q.pack(), "127.0.0.1")
        resp = DNSRecord.parse(wire)
        assert resp.header.rcode == RCODE.NOERROR
        assert chosen["host"] == "1.1.1.1"
    finally:
        DNSRuntimeState.upstream_health.clear()


def test_resolve_query_bytes_probes_unhealthy_primary_by_probe_percent(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: Probe traffic can target unhealthy primaries when probe_percent allows it.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts unhealthy primary can be included for probing in primary list order.
    """

    q = DNSRecord.question("probe-primary.example", "A")
    primary_unhealthy = {"host": "1.1.1.1", "port": 53}
    primary_healthy = {"host": "1.0.0.1", "port": 53}
    chosen = {"host": None}
    r_ok = q.reply()

    monkeypatch.setattr(server_mod.random, "random", lambda: 0.0)

    def _forward_capture(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        assert upstreams, "expected at least one upstream candidate"
        chosen["host"] = upstreams[0].get("host")
        return r_ok.pack(), upstreams[0], "ok"

    monkeypatch.setattr(server_mod, "send_query_with_failover", _forward_capture)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[primary_unhealthy, primary_healthy],
        upstream_health=parse_upstream_health_config(
            {"health": {"probe_percent": 100.0, "probe_max_percent": 100.0}}
        ),
    )
    primary_id = DNSRuntimeState._upstream_id(primary_unhealthy)
    DNSRuntimeState.upstream_health.clear()
    try:
        import time as _time

        DNSRuntimeState.upstream_health[primary_id] = {
            "fail_count": 3.0,
            "down_until": _time.time() + 60.0,
        }

        wire = resolve_query_bytes(q.pack(), "127.0.0.1")
        resp = DNSRecord.parse(wire)
        assert resp.header.rcode == RCODE.NOERROR
        assert chosen["host"] == "1.1.1.1"
    finally:
        DNSRuntimeState.upstream_health.clear()


def test_resolve_query_bytes_adapts_probe_percent_on_failure_and_success(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: Probe percent adapts using probe_increase/probe_decrease knobs.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts adaptive probe percentage is increased on failure and decreased on success.
    """

    q = DNSRecord.question("probe-adapt.example", "A")
    upstream = {"host": "2.2.2.2", "port": 53}
    r_ok = q.reply()
    DNSRuntimeState.upstream_probe_percent = None

    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[upstream],
        upstream_health=parse_upstream_health_config(
            {
                "health": {
                    "probe_percent": 10.0,
                    "probe_min_percent": 1.0,
                    "probe_max_percent": 50.0,
                    "probe_increase": 1.0,
                    "probe_decrease": 2.0,
                }
            }
        ),
    )

    try:
        monkeypatch.setattr(
            server_mod,
            "send_query_with_failover",
            lambda *a, **k: (None, None, "all_failed"),
        )
        resolve_query_bytes(q.pack(), "127.0.0.1")
        assert DNSRuntimeState.upstream_probe_percent == 11.0

        monkeypatch.setattr(
            server_mod,
            "send_query_with_failover",
            lambda *a, **k: (r_ok.pack(), upstream, "ok"),
        )
        resolve_query_bytes(q.pack(), "127.0.0.1")
        assert DNSRuntimeState.upstream_probe_percent == 9.0
    finally:
        DNSRuntimeState.upstream_probe_percent = None


def test_resolve_query_bytes_round_robin_rotates_upstream_order(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: round_robin strategy rotates upstream ordering between queries.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts first candidate rotates according to _upstream_rr_index.
    """

    q = DNSRecord.question("rr-order.example", "A")
    upstreams = [
        {"host": "1.1.1.1", "port": 53},
        {"host": "2.2.2.2", "port": 53},
        {"host": "3.3.3.3", "port": 53},
    ]
    seen: list[str] = []

    def _forward_capture(
        req,
        candidates,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        seen.append(str(candidates[0].get("host")))
        r = q.reply()
        return r.pack(), candidates[0], "ok"

    monkeypatch.setattr(server_mod, "send_query_with_failover", _forward_capture)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=upstreams,
        upstream_strategy="round_robin",
    )

    DNSRuntimeState._upstream_rr_index = 0
    resolve_query_bytes(q.pack(), "127.0.0.1")
    resolve_query_bytes(q.pack(), "127.0.0.1")
    assert seen[:2] == ["1.1.1.1", "2.2.2.2"]


def test_resolve_query_bytes_random_strategy_shuffles_candidates(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: random strategy shuffles upstream list before forwarding.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts shuffled ordering is used for forwarding attempts.
    """

    q = DNSRecord.question("rnd-order.example", "A")
    upstreams = [
        {"host": "1.1.1.1", "port": 53},
        {"host": "2.2.2.2", "port": 53},
    ]
    chosen = {"host": None}

    def _shuffle_reverse(seq):  # noqa: ANN001
        seq[:] = list(reversed(seq))

    def _forward_capture(
        req,
        candidates,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        chosen["host"] = candidates[0].get("host")
        r = q.reply()
        return r.pack(), candidates[0], "ok"

    monkeypatch.setattr(server_mod.random, "shuffle", _shuffle_reverse)
    monkeypatch.setattr(server_mod, "send_query_with_failover", _forward_capture)
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=upstreams,
        upstream_strategy="random",
    )

    resolve_query_bytes(q.pack(), "127.0.0.1")
    assert chosen["host"] == "2.2.2.2"


def test_resolve_query_bytes_stats_cache_and_no_upstreams(set_runtime_snapshot):
    """Brief: resolve_query_bytes records stats for cache hit and no upstreams paths.

    Inputs:
      - None

    Outputs:
      - None; asserts cache and no_upstreams stats hooks are invoked.
    """

    stats = _Stats()

    # Cache hit
    set_runtime_snapshot(stats_collector=stats, plugins=[])
    q = DNSRecord.question("cache-stats.example", "A")
    r = q.reply()
    plugin_base.DNS_CACHE.set(("cache-stats.example", QTYPE.A), 10, r.pack())
    resolve_query_bytes(q.pack(), "127.0.0.1")

    # No upstreams: clear cache and ensure no upstreams configured
    plugin_base.DNS_CACHE = InMemoryTTLCache()
    set_runtime_snapshot(stats_collector=stats, upstream_addrs=[], plugins=[])
    q2 = DNSRecord.question("no-upstreams-stats.example", "A")
    resolve_query_bytes(q2.pack(), "127.0.0.1")

    kinds = [k for k, _ in stats.calls]
    assert "record_cache_hit" in kinds
    assert "record_cache_miss" in kinds
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds
    assert "record_latency" in kinds


def test_resolve_query_bytes_stats_upstream_success_and_failure(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: resolve_query_bytes records upstream stats for success and all_failed cases.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts upstream_result and upstream_rcode stats are recorded.
    """

    stats = _Stats()

    q = DNSRecord.question("upstream-stats.example", "A")
    r_ok = q.reply()

    def _forward_ok(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        return r_ok.pack(), {"host": "1.1.1.1", "port": 53}, "ok"

    def _forward_fail(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        return None, {"host": "2.2.2.2", "port": 53}, "all_failed"

    # Success case
    monkeypatch.setattr(server_mod, "send_query_with_failover", _forward_ok)
    set_runtime_snapshot(
        stats_collector=stats,
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
    )
    resolve_query_bytes(q.pack(), "127.0.0.1")

    # Failure case
    monkeypatch.setattr(server_mod, "send_query_with_failover", _forward_fail)
    set_runtime_snapshot(
        stats_collector=stats,
        plugins=[],
        upstream_addrs=[{"host": "2.2.2.2", "port": 53}],
    )
    resolve_query_bytes(q.pack(), "127.0.0.1")

    kinds = [k for k, _ in stats.calls]
    assert "record_upstream_result" in kinds
    assert "record_upstream_rcode" in kinds
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds
    assert "record_latency" in kinds


def test_resolve_query_bytes_stats_outer_exception(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: resolve_query_bytes outer exception path records SERVFAIL and latency stats.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts response_rcode, query_result, and latency are recorded.
    """

    stats = _Stats()
    plugin_base.DNS_CACHE = InMemoryTTLCache()
    set_runtime_snapshot(
        stats_collector=stats,
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
    )

    def _boom_send(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        raise RuntimeError("boom")

    monkeypatch.setattr(server_mod, "send_query_with_failover", _boom_send)

    q = DNSRecord.question("outer-stats.example", "A")
    wire = resolve_query_bytes(q.pack(), "127.0.0.1")

    # Response should be SERVFAIL synthesized by the outer exception handler
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.SERVFAIL

    kinds = [k for k, _ in stats.calls]
    assert "record_response_rcode" in kinds
    assert "record_query_result" in kinds
    assert "record_latency" in kinds


def test_resolve_query_bytes_query_context_includes_listener_secure(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: resolve_query_bytes records listener and secure flags in query context.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that record_query_result receives listener='udp' and
        secure=False in its result payload for UDP queries.
    """

    stats = _Stats()

    # Configure a fake upstream so the shared resolver takes the normal
    # forwarder path and exercises the upstream statistics branch.
    q = DNSRecord.question("ctx-listener.example", "A")
    r_ok = q.reply()

    def _forward_ok(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        return r_ok.pack(), {"host": "1.1.1.1", "port": 53}, "ok"

    monkeypatch.setattr(server_mod, "send_query_with_failover", _forward_ok)
    set_runtime_snapshot(
        stats_collector=stats,
        plugins=[],
        upstream_addrs=[{"host": "1.1.1.1", "port": 53}],
    )

    resolve_query_bytes(q.pack(), "127.0.0.1", listener="udp", secure=False)

    # Extract the result payloads from record_query_result calls.
    results = [
        kwargs.get("result")
        for name, (_args, kwargs) in stats.calls
        if name == "record_query_result"
    ]
    assert results, "expected at least one record_query_result call"
    for ctx in results:
        assert isinstance(ctx, dict)
        assert ctx.get("listener") == "udp"
        # secure is expected to be the boolean False for UDP/TCP listeners.
        assert ctx.get("secure") is False


def test_resolve_query_bytes_recursive_mode_uses_recursive_resolver(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: recursive resolver mode uses RecursiveResolver and still caches.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures RecursiveResolver.resolve() is called once and results are
        cached so the second query does not invoke it again.
    """

    calls = {"n": 0}

    class _FakeRecursiveResolver:
        def __init__(
            self,
            *,
            cache,
            stats,
            max_depth: int = 16,
            timeout_ms: int = 2000,
            per_try_timeout_ms: int = 2000,
        ) -> None:
            self.cache = cache
            self.stats = stats
            self.max_depth = max_depth
            self.timeout_ms = timeout_ms
            self.per_try_timeout_ms = per_try_timeout_ms

        def resolve(self, req: DNSRecord):  # noqa: D401
            """Resolve via fake recursive path, returning a fixed A answer."""

            calls["n"] += 1
            r = req.reply()
            r.add_answer(RR("rec.example.", QTYPE.A, rdata=A("192.0.2.1"), ttl=60))
            return r.pack(), "fake-auth:53"

    # Patch RecursiveResolver used inside foghorn.servers.server._resolve_core
    monkeypatch.setattr(server_mod, "RecursiveResolver", _FakeRecursiveResolver)

    # Blow up if the forwarder path is accidentally used in recursive mode.
    def _boom_send_recursive(*_a, **_k):  # noqa: ANN001
        raise AssertionError(
            "send_query_with_failover should not be called in recursive mode"
        )

    monkeypatch.setattr(server_mod, "send_query_with_failover", _boom_send_recursive)

    # Configure runtime snapshot for recursive mode.
    plugin_base.DNS_CACHE = InMemoryTTLCache()
    set_runtime_snapshot(
        plugins=[],
        resolver_mode="recursive",
        upstream_addrs=[{"host": "8.8.8.8", "port": 53}],
    )

    q = DNSRecord.question("rec.example.", "A")

    # First query should go through the fake resolver.
    resp1 = resolve_query_bytes(q.pack(), "127.0.0.1")
    out1 = DNSRecord.parse(resp1)
    assert out1.header.rcode == RCODE.NOERROR
    assert any(rr.rdata == A("192.0.2.1") for rr in out1.rr)

    # Second query should be served from cache with no extra resolver calls.
    resp2 = resolve_query_bytes(q.pack(), "127.0.0.1")
    out2 = DNSRecord.parse(resp2)
    assert out2.header.rcode == RCODE.NOERROR
    assert any(rr.rdata == A("192.0.2.1") for rr in out2.rr)

    assert calls["n"] == 1


def test_resolve_query_bytes_master_mode_refuses_without_forwarding(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: master resolver mode returns REFUSED without contacting upstreams.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts REFUSED and that forwarding helpers are not invoked.
    """

    def _boom_send(*_a, **_k):  # noqa: ANN001
        raise AssertionError("send_query_with_failover should not be called")

    monkeypatch.setattr(server_mod, "send_query_with_failover", _boom_send)

    plugin_base.DNS_CACHE = InMemoryTTLCache()
    set_runtime_snapshot(
        plugins=[],
        resolver_mode="master",
        upstream_addrs=[{"host": "8.8.8.8", "port": 53}],
    )

    q = DNSRecord.question("no-forward.example.", "A")
    resp = resolve_query_bytes(q.pack(), "127.0.0.1")
    out = DNSRecord.parse(resp)
    assert out.header.rcode == RCODE.REFUSED


def test_resolve_query_bytes_none_alias_behaves_like_master(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: resolver mode alias 'none' behaves like master.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts REFUSED and no upstream calls.
    """

    def _boom_send(*_a, **_k):  # noqa: ANN001
        raise AssertionError("send_query_with_failover should not be called")

    monkeypatch.setattr(server_mod, "send_query_with_failover", _boom_send)

    plugin_base.DNS_CACHE = InMemoryTTLCache()
    set_runtime_snapshot(
        plugins=[],
        resolver_mode="none",
        upstream_addrs=[{"host": "8.8.8.8", "port": 53}],
    )

    q = DNSRecord.question("no-forward-alias.example.", "A")
    resp = resolve_query_bytes(q.pack(), "127.0.0.1")
    out = DNSRecord.parse(resp)
    assert out.header.rcode == RCODE.REFUSED


def test_forward_local_false_blocks_local_queries(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: .local queries return NXDOMAIN when forward_local is false.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that .local queries return NXDOMAIN without contacting
        upstreams when forward_local is false (the default).
    """

    # Track whether upstreams are contacted.
    upstream_calls = {"n": 0}

    def _fail_send(*_a, **_k):  # noqa: ANN001
        upstream_calls["n"] += 1
        raise AssertionError("send_query_with_failover should not be called")

    monkeypatch.setattr(server_mod, "send_query_with_failover", _fail_send)

    plugin_base.DNS_CACHE = InMemoryTTLCache()
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "8.8.8.8", "port": 53}],
        forward_local=False,
    )

    # Query for a .local name should be blocked.
    q = DNSRecord.question("myhost.local.", "A")
    resp = resolve_query_bytes(q.pack(), "127.0.0.1")
    out = DNSRecord.parse(resp)
    assert out.header.rcode == RCODE.NXDOMAIN
    assert upstream_calls["n"] == 0

    # Also test bare "local" TLD.
    q2 = DNSRecord.question("local", "A")
    resp2 = resolve_query_bytes(q2.pack(), "127.0.0.1")
    out2 = DNSRecord.parse(resp2)
    assert out2.header.rcode == RCODE.NXDOMAIN
    assert upstream_calls["n"] == 0


def test_forward_local_true_allows_local_queries(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: .local queries are forwarded when forward_local is true.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that .local queries are forwarded to upstreams when
        forward_local is true.
    """

    # Fake upstream response.
    q = DNSRecord.question("myhost.local.", "A")
    r_ok = q.reply()
    r_ok.add_answer(RR("myhost.local.", QTYPE.A, rdata=A("192.168.1.1"), ttl=60))

    upstream_calls = {"n": 0}

    def _forward_ok(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        upstream_calls["n"] += 1
        return r_ok.pack(), {"host": "8.8.8.8", "port": 53}, "ok"

    monkeypatch.setattr(server_mod, "send_query_with_failover", _forward_ok)

    plugin_base.DNS_CACHE = InMemoryTTLCache()
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "8.8.8.8", "port": 53}],
        forward_local=True,
    )

    resp = resolve_query_bytes(q.pack(), "127.0.0.1")
    out = DNSRecord.parse(resp)
    assert out.header.rcode == RCODE.NOERROR
    assert upstream_calls["n"] == 1
    assert any(rr.rdata == A("192.168.1.1") for rr in out.rr)


def test_forward_local_blocking_does_not_affect_non_local_queries(
    monkeypatch: pytest.MonkeyPatch,
    set_runtime_snapshot,
) -> None:
    """Brief: Non-.local queries are forwarded regardless of forward_local.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that .com queries are still forwarded when
        forward_local is false.
    """

    q = DNSRecord.question("example.com.", "A")
    r_ok = q.reply()
    r_ok.add_answer(RR("example.com.", QTYPE.A, rdata=A("93.184.216.34"), ttl=60))

    upstream_calls = {"n": 0}

    def _forward_ok(
        req,
        upstreams,
        timeout_ms,
        qname,
        qtype,
        max_concurrent=None,
        on_attempt_result=None,
    ):
        upstream_calls["n"] += 1
        return r_ok.pack(), {"host": "8.8.8.8", "port": 53}, "ok"

    monkeypatch.setattr(server_mod, "send_query_with_failover", _forward_ok)

    plugin_base.DNS_CACHE = InMemoryTTLCache()
    set_runtime_snapshot(
        plugins=[],
        upstream_addrs=[{"host": "8.8.8.8", "port": 53}],
        forward_local=False,
    )

    resp = resolve_query_bytes(q.pack(), "127.0.0.1")
    out = DNSRecord.parse(resp)
    assert out.header.rcode == RCODE.NOERROR
    assert upstream_calls["n"] == 1
