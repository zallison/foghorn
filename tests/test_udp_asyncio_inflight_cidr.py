"""Tests for CIDR-bucketed in-flight limiting in asyncio UDP server.

Inputs:
  - dnslib DNSRecord queries.
  - Synthetic client IPs.

Outputs:
  - Verifies most-specific matching CIDR rule selection.
  - Verifies overload shedding occurs when a CIDR bucket limit is reached.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

from dnslib import DNSRecord


def test_udp_asyncio_select_cidr_bucket_most_specific_wins() -> None:
    """Brief: When multiple CIDRs match, the most specific prefix wins.

    Inputs:
      - CIDR rules: overlapping /8 and /16.
      - client_ip: '10.1.2.3' (matches both).

    Outputs:
      - Asserts the /16 rule is selected even when it has a higher limit.
    """

    from foghorn.servers.udp_asyncio_server import _UDPProtocol

    proto = _UDPProtocol(
        lambda _q, _ip: b"",
        executor=None,
        max_inflight=100,
        max_inflight_per_ip=100,
        max_query_bytes=4096,
        max_inflight_by_cidr=[
            {"cidr": "10.0.0.0/8", "max_inflight": 5},
            {"cidr": "10.1.0.0/16", "max_inflight": 100},
        ],
    )

    bucket_key, limit = proto._select_cidr_bucket("10.1.2.3")
    assert bucket_key == "10.1.0.0/16"
    assert limit == 100


def test_udp_asyncio_cidr_bucket_limit_sheds_overload() -> None:
    """Brief: CIDR bucket limit sheds excess queries with SERVFAIL.

    Inputs:
      - max_inflight_by_cidr: /16 bucket with max_inflight=1.
      - Two datagrams from the same client IP before the first resolves.

    Outputs:
      - Asserts one overload (SERVFAIL) response is sent.
    """

    from foghorn.servers.udp_asyncio_server import _UDPProtocol

    query = DNSRecord.question("example.com").pack()
    release = threading.Event()

    def resolver(_q: bytes, _ip: str) -> bytes:
        release.wait(timeout=2.0)
        r = DNSRecord.parse(query).reply()
        return r.pack()

    class DummyTransport:
        def __init__(self) -> None:
            self.sent: list[tuple[bytes, Any]] = []

        def sendto(self, data: bytes, addr: Any) -> None:  # noqa: ANN401
            self.sent.append((data, addr))

    async def _run() -> None:
        proto = _UDPProtocol(
            resolver,
            executor=None,
            max_inflight=100,
            max_inflight_per_ip=100,
            max_query_bytes=4096,
            max_inflight_by_cidr=[{"cidr": "10.1.0.0/16", "max_inflight": 1}],
        )
        dummy = DummyTransport()
        proto._transport = dummy  # type: ignore[assignment]

        addr = ("10.1.2.3", 12345)
        proto.datagram_received(query, addr)

        # Give the first task a chance to start and occupy the CIDR bucket.
        await asyncio.sleep(0)

        proto.datagram_received(query, addr)

        assert len(dummy.sent) == 1
        resp_wire = dummy.sent[0][0]
        assert len(resp_wire) == 12
        assert resp_wire[0:2] == query[0:2]
        assert resp_wire[2] == 0x80
        assert (resp_wire[3] & 0x0F) == 2

        release.set()
        await asyncio.sleep(0.05)
        assert proto._inflight_total == 0

    asyncio.run(_run())
