"""Brief: Regression tests for throttling aggregate all-upstreams-failed warnings.

Inputs:
  - None.

Outputs:
  - None.
"""

from __future__ import annotations

import errno
import logging

from dnslib import QTYPE, RR, A, DNSRecord

from foghorn.servers import server_failover
from foghorn.servers.dns_runtime_state import DNSRuntimeState
from foghorn.servers.server_failover import _send_query_with_failover_impl


def _clear_all_failed_warned_state() -> None:
    """Brief: Reset module-level all-failed warning de-dupe state for isolation.

    Inputs:
      - None.

    Outputs:
      - None.
    """

    with server_failover._UPSTREAM_SKIP_LOCK:
        server_failover._ALL_UPSTREAMS_FAILED_WARNED.clear()
        server_failover._UPSTREAM_SKIP_WARNED.clear()


def _seed_fail_count(upstream: dict, fail_count: float) -> None:
    """Brief: Seed DNSRuntimeState.upstream_health fail_count for warning gate.

    Inputs:
      - upstream: Upstream mapping used by the failover call.
      - fail_count: Value that should pass all_failed_should_warn (fc > 1).

    Outputs:
      - None.
    """

    up_id = DNSRuntimeState._upstream_id(upstream)
    DNSRuntimeState.upstream_health[up_id] = {
        "fail_count": float(fail_count),
        "down_until": 0.0,
        "state": "down",
    }


def test_all_upstreams_failed_warning_is_throttled_until_success(caplog):
    """Brief: Aggregate all-failed WARNING emits once until an upstream recovers.

    Inputs:
      - caplog: pytest log capture fixture.

    Outputs:
      - None.

    Scenario:
      - Repeated TCP connection-refused failures with fail_count high enough to
        qualify for WARNING must log "All upstreams failed" only once.
      - A later successful query clears de-dupe state so a subsequent outage
        logs WARNING again.
    """

    _clear_all_failed_warned_state()
    q = DNSRecord.question("example.com", "A")
    upstreams = [{"host": "127.0.0.1", "port": 53, "transport": "tcp", "id": "u1"}]
    _seed_fail_count(upstreams[0], fail_count=5.0)

    class _RefusingPool:
        def set_limits(self, *args, **kwargs):
            return None

        def send(self, *args, **kwargs):
            raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")

    class _OkPool:
        def set_limits(self, *args, **kwargs):
            return None

        def send(self, *args, **kwargs):
            reply = q.reply()
            reply.add_answer(
                RR("example.com", QTYPE.A, rdata=A("203.0.113.10"), ttl=60)
            )
            return reply.pack()

    def _refusing_pool(host: str, port: int):
        return _RefusingPool()

    def _ok_pool(host: str, port: int):
        return _OkPool()

    with caplog.at_level(logging.WARNING, logger="foghorn.server"):
        for _ in range(3):
            resp, used, reason = _send_query_with_failover_impl(
                q,
                upstreams,
                200,
                "example.com",
                QTYPE.A,
                max_concurrent=1,
                get_tcp_pool_fn=_refusing_pool,
            )
            assert resp is None
            assert used is None
            assert reason == "all_failed"

        first_outage_warnings = [
            r
            for r in caplog.records
            if r.levelno >= logging.WARNING and "All upstreams failed" in r.getMessage()
        ]
        assert len(first_outage_warnings) == 1

        # Recovery clears throttle state.
        resp, used, reason = _send_query_with_failover_impl(
            q,
            upstreams,
            200,
            "example.com",
            QTYPE.A,
            max_concurrent=1,
            get_tcp_pool_fn=_ok_pool,
        )
        assert reason == "ok"
        assert resp is not None
        assert used is not None

        caplog.clear()

        # New outage after recovery should warn once again.
        resp, used, reason = _send_query_with_failover_impl(
            q,
            upstreams,
            200,
            "example.com",
            QTYPE.A,
            max_concurrent=1,
            get_tcp_pool_fn=_refusing_pool,
        )
        assert reason == "all_failed"

        second_outage_warnings = [
            r
            for r in caplog.records
            if r.levelno >= logging.WARNING and "All upstreams failed" in r.getMessage()
        ]
        assert len(second_outage_warnings) == 1
