"""Brief: Regression test for sequential failover on connection-refused upstreams.

Inputs:
  - None.

Outputs:
  - None.
"""

from __future__ import annotations

import errno

from dnslib import QTYPE, DNSRecord

from foghorn.servers.server_failover import _send_query_with_failover_impl


def test_failover_connection_refused_does_not_crash_sequential_mode():
    """Brief: Connection-refused upstream must not raise inside failover except block.

    Inputs:
      - None.

    Outputs:
      - None.

    Scenario:
      - A single TCP upstream attempt raises ConnectionRefusedError.
      - Failover runs in sequential mode (max_concurrent=1).
      - The call should return all_failed (None response) without propagating a
        TypeError from the warning rate-limit guard.
    """

    q = DNSRecord.question("example.com", "A")

    class _RefusingPool:
        def set_limits(self, *args, **kwargs):
            return None

        def send(self, *args, **kwargs):
            raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")

    def _fake_get_tcp_pool(host: str, port: int):
        return _RefusingPool()

    upstreams = [{"host": "127.0.0.1", "port": 53, "transport": "tcp"}]

    resp, used, reason = _send_query_with_failover_impl(
        q,
        upstreams,
        200,
        "example.com",
        QTYPE.A,
        max_concurrent=1,
        get_tcp_pool_fn=_fake_get_tcp_pool,
    )

    assert resp is None
    assert used is None
    assert reason == "all_failed"
