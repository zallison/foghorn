"""Additional tests for src/foghorn/servers/udp_asyncio_server.py.

Brief:
  Focuses on unit-level coverage for edge/corner cases and defensive branches in
  the asyncio UDP server implementation.

Inputs:
  - pytest fixtures (monkeypatch).
  - dnslib DNSRecord queries.

Outputs:
  - Assertions covering overload shedding, CIDR rule parsing, counter cleanup,
    and shutdown plumbing.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from typing import Any

import pytest
from dnslib import DNSRecord

from foghorn.servers import udp_asyncio_server as udp_mod


def test_make_overloaded_response_returns_none_when_too_short_for_txid() -> None:
    """Brief: Too-short query bytes yield None.

    Inputs:
      - Invalid wire bytes.

    Outputs:
      - None; asserts helper returns None.
    """

    assert udp_mod._make_overloaded_response(b"\x00") is None


def test_make_overloaded_response_sets_servfail_and_preserves_txid() -> None:
    """Brief: Overload response is a minimal SERVFAIL with matching TXID.

    Inputs:
      - Valid DNS query bytes.

    Outputs:
      - None; asserts TXID matches and header indicates SERVFAIL.

    Notes:
      - The overload response is intentionally a minimal 12-byte header. It does
        not include a question section, so dnslib parsing is not expected to
        succeed.
    """

    q = DNSRecord.question("example.com")
    q.header.id = 0xBEEF
    query_wire = q.pack()

    resp_wire = udp_mod._make_overloaded_response(query_wire)
    assert resp_wire is not None

    assert len(resp_wire) == 12
    assert resp_wire[0:2] == query_wire[0:2]
    assert resp_wire[2] == 0x80
    assert (resp_wire[3] & 0x0F) == 2


def test_udp_protocol_init_filters_invalid_cidr_rules() -> None:
    """Brief: Invalid CIDR rule entries are ignored.

    Inputs:
      - Mixed valid/invalid rule entries.

    Outputs:
      - None; asserts only valid rules are retained.
    """

    proto = udp_mod._UDPProtocol(
        lambda _q, _ip: b"",
        executor=None,
        max_inflight=10,
        max_inflight_per_ip=10,
        max_query_bytes=4096,
        max_inflight_by_cidr=[
            "not-a-dict",
            {"cidr": "10.0.0.0/8", "max_inflight": 5},
            {"cidr": "bad-cidr", "max_inflight": 2},
            {"cidr": "192.0.2.0/24", "max_inflight": 0},
            {"cidr": "2001:db8::/32", "max_inflight": "3"},
            {"cidr": None, "max_inflight": 1},
            {"cidr": "10.0.0.0/8", "max_inflight": None},
        ],
    )

    # Only the valid entries should remain.
    assert [str(n) for (n, _lim, _p) in proto._cidr_rules_v4] == ["10.0.0.0/8"]
    assert [int(lim) for (_n, lim, _p) in proto._cidr_rules_v4] == [5]

    assert [str(n) for (n, _lim, _p) in proto._cidr_rules_v6] == ["2001:db8::/32"]
    assert [int(lim) for (_n, lim, _p) in proto._cidr_rules_v6] == [3]


def test_select_cidr_bucket_returns_none_when_no_rules() -> None:
    """Brief: No CIDR rules => (None, None).

    Inputs:
      - protocol without CIDR rules.

    Outputs:
      - None; asserts (None, None).
    """

    proto = udp_mod._UDPProtocol(
        lambda _q, _ip: b"",
        executor=None,
        max_inflight=10,
        max_inflight_per_ip=10,
        max_query_bytes=4096,
        max_inflight_by_cidr=None,
    )
    assert proto._select_cidr_bucket("10.1.2.3") == (None, None)


def test_select_cidr_bucket_returns_none_for_invalid_client_ip() -> None:
    """Brief: Invalid client_ip is handled and yields (None, None).

    Inputs:
      - client_ip string which cannot be parsed.

    Outputs:
      - None; asserts (None, None).
    """

    proto = udp_mod._UDPProtocol(
        lambda _q, _ip: b"",
        executor=None,
        max_inflight=10,
        max_inflight_per_ip=10,
        max_query_bytes=4096,
        max_inflight_by_cidr=[{"cidr": "10.0.0.0/8", "max_inflight": 5}],
    )
    assert proto._select_cidr_bucket("not-an-ip") == (None, None)


def test_select_cidr_bucket_most_specific_wins_over_higher_parent_limit() -> None:
    """Brief: More-specific CIDR wins even when it has a higher limit.

    Inputs:
      - Overlapping CIDRs with identical max_inflight.

    Outputs:
      - None; asserts /16 is chosen over /8.
    """

    proto = udp_mod._UDPProtocol(
        lambda _q, _ip: b"",
        executor=None,
        max_inflight=10,
        max_inflight_per_ip=10,
        max_query_bytes=4096,
        max_inflight_by_cidr=[
            {"cidr": "10.0.0.0/8", "max_inflight": 5},
            {"cidr": "10.1.0.0/16", "max_inflight": 100},
        ],
    )

    bucket, limit = proto._select_cidr_bucket("10.1.2.3")
    assert bucket == "10.1.0.0/16"
    assert limit == 100


def test_connection_made_records_transport_only_for_datagram_transport() -> None:
    """Brief: connection_made only stores DatagramTransport instances.

    Inputs:
      - Dummy DatagramTransport.
      - Non-datagram object.

    Outputs:
      - None; asserts transport is stored only for the right type.
    """

    class DummyDatagramTransport(asyncio.DatagramTransport):
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

        def is_closing(self) -> bool:
            return self.closed

        def get_extra_info(self, name: str, default=None):  # noqa: ANN001
            return default

        def sendto(self, data: bytes, addr=None) -> None:  # noqa: ANN001
            return None

        def abort(self) -> None:
            self.closed = True

    proto = udp_mod._UDPProtocol(
        lambda _q, _ip: b"",
        executor=None,
        max_inflight=10,
        max_inflight_per_ip=10,
        max_query_bytes=4096,
    )

    t = DummyDatagramTransport()
    proto.connection_made(t)
    assert proto._transport is t

    proto.connection_made(object())
    assert proto._transport is t


def test_datagram_received_size_gate_drops_too_small_and_oversized_packets() -> None:
    """Brief: Datagram size gate drops undersized/oversized packets silently.

    Inputs:
      - undersized payload (< 12 bytes).
      - oversized payload (> max_query_bytes).

    Outputs:
      - None; asserts no counters are incremented and no response is sent.
    """

    def resolver(_q: bytes, _ip: str) -> bytes:
        raise AssertionError("resolver should not be called for dropped packets")

    sent: list[bytes] = []

    class DummyTransport:
        def sendto(self, data: bytes, addr: Any) -> None:  # noqa: ANN401
            sent.append(data)

    proto = udp_mod._UDPProtocol(
        resolver,
        executor=None,
        max_inflight=10,
        max_inflight_per_ip=10,
        max_query_bytes=32,
    )
    proto._transport = DummyTransport()  # type: ignore[assignment]

    proto.datagram_received(b"\x00" * 11, ("127.0.0.1", 12345))
    proto.datagram_received(b"\x00" * 33, ("127.0.0.1", 12345))

    assert proto._inflight_total == 0
    assert proto._inflight_per_ip == {}
    assert sent == []


def test_datagram_received_ignores_empty_data() -> None:
    """Brief: Empty datagrams are ignored.

    Inputs:
      - data=b''.

    Outputs:
      - None; asserts counters are unchanged.
    """

    proto = udp_mod._UDPProtocol(
        lambda _q, _ip: b"",
        executor=None,
        max_inflight=1,
        max_inflight_per_ip=1,
        max_query_bytes=4096,
    )
    proto._transport = SimpleNamespace(sendto=lambda *_a, **_k: None)

    proto.datagram_received(b"", ("127.0.0.1", 12345))
    assert proto._inflight_total == 0
    assert proto._inflight_per_ip == {}


def test_datagram_received_global_overload_sheds_with_servfail() -> None:
    """Brief: Global inflight limit triggers overload shedding.

    Inputs:
      - inflight_total at max_inflight.

    Outputs:
      - None; asserts a SERVFAIL response is sent.
    """

    query = DNSRecord.question("example.com").pack()

    sent: list[bytes] = []

    class DummyTransport:
        def sendto(self, data: bytes, addr: Any) -> None:  # noqa: ANN401
            sent.append(data)

    proto = udp_mod._UDPProtocol(
        lambda _q, _ip: b"",
        executor=None,
        max_inflight=1,
        max_inflight_per_ip=10,
        max_query_bytes=4096,
    )
    proto._transport = DummyTransport()  # type: ignore[assignment]
    proto._inflight_total = 1

    proto.datagram_received(query, ("127.0.0.1", 12345))
    assert sent
    resp_wire = sent[0]
    assert len(resp_wire) == 12
    assert resp_wire[0:2] == query[0:2]
    assert resp_wire[2] == 0x80
    assert (resp_wire[3] & 0x0F) == 2


def test_datagram_received_per_ip_overload_sheds_and_sendto_errors_are_swallowed() -> (
    None
):
    """Brief: Per-IP limit triggers overload shedding and sendto errors are ignored.

    Inputs:
      - inflight_per_ip at max_inflight_per_ip.
      - transport.sendto raises.

    Outputs:
      - None; asserts no exception escapes.
    """

    query = DNSRecord.question("example.com").pack()

    class DummyTransport:
        def sendto(self, data: bytes, addr: Any) -> None:  # noqa: ANN401
            raise RuntimeError("sendto failed")

    proto = udp_mod._UDPProtocol(
        lambda _q, _ip: b"",
        executor=None,
        max_inflight=100,
        max_inflight_per_ip=1,
        max_query_bytes=4096,
    )
    proto._transport = DummyTransport()  # type: ignore[assignment]
    proto._inflight_per_ip["127.0.0.1"] = 1

    # Should not raise.
    proto.datagram_received(query, ("127.0.0.1", 12345))


def test_handle_one_empty_response_decrements_counters() -> None:
    """Brief: Empty resolver responses still decrement inflight counters.

    Inputs:
      - resolver returns b''.

    Outputs:
      - None; asserts counters are decremented and response is not sent.
    """

    async def _run() -> None:
        query = DNSRecord.question("example.com").pack()

        def resolver(_q: bytes, _ip: str) -> bytes:
            return b""

        class DummyTransport:
            def __init__(self) -> None:
                self.sent: list[tuple[bytes, Any]] = []

            def sendto(self, data: bytes, addr: Any) -> None:  # noqa: ANN401
                self.sent.append((data, addr))

        proto = udp_mod._UDPProtocol(
            resolver,
            executor=None,
            max_inflight=10,
            max_inflight_per_ip=10,
            max_query_bytes=4096,
        )
        proto._transport = DummyTransport()  # type: ignore[assignment]

        proto._inflight_total = 1
        proto._inflight_per_ip["127.0.0.1"] = 1
        proto._inflight_per_cidr["10.0.0.0/8"] = 1

        await proto._handle_one(query, ("127.0.0.1", 12345), "127.0.0.1", "10.0.0.0/8")

        assert proto._inflight_total == 0
        assert proto._inflight_per_ip == {}
        assert proto._inflight_per_cidr == {}
        assert proto._transport.sent == []

    asyncio.run(_run())


def test_handle_one_sendto_exception_falls_back_to_overload_response(
    monkeypatch: Any,
) -> None:
    """Brief: sendto exceptions trigger best-effort overload response.

    Inputs:
      - resolver returns bytes.
      - transport.sendto raises on first call.

    Outputs:
      - None; asserts fallback response is attempted.
    """

    async def _run() -> None:
        query = DNSRecord.question("example.com").pack()

        def resolver(_q: bytes, _ip: str) -> bytes:
            return b"normal"

        sent: list[bytes] = []

        class DummyTransport:
            def __init__(self) -> None:
                self.calls = 0

            def sendto(self, data: bytes, addr: Any) -> None:  # noqa: ANN401
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("boom")
                sent.append(data)

        monkeypatch.setattr(udp_mod, "_make_overloaded_response", lambda _b: b"ovl")

        proto = udp_mod._UDPProtocol(
            resolver,
            executor=None,
            max_inflight=10,
            max_inflight_per_ip=10,
            max_query_bytes=4096,
        )
        proto._transport = DummyTransport()  # type: ignore[assignment]
        proto._inflight_total = 1
        proto._inflight_per_ip["127.0.0.1"] = 2

        await proto._handle_one(query, ("127.0.0.1", 12345), "127.0.0.1", None)

        assert sent == [b"ovl"]
        assert proto._inflight_total == 0
        assert proto._inflight_per_ip["127.0.0.1"] == 1

    asyncio.run(_run())


def test_handle_one_resolver_exception_sends_overload_response(
    monkeypatch: Any,
) -> None:
    """Brief: Resolver exceptions cause SERVFAIL fallback.

    Inputs:
      - resolver raises.

    Outputs:
      - None; asserts overload response is sent.
    """

    async def _run() -> None:
        query = DNSRecord.question("example.com").pack()

        def resolver(_q: bytes, _ip: str) -> bytes:
            raise RuntimeError("resolver died")

        sent: list[bytes] = []

        class DummyTransport:
            def sendto(self, data: bytes, addr: Any) -> None:  # noqa: ANN401
                sent.append(data)

        monkeypatch.setattr(udp_mod, "_make_overloaded_response", lambda _b: b"ovl")

        proto = udp_mod._UDPProtocol(
            resolver,
            executor=None,
            max_inflight=10,
            max_inflight_per_ip=10,
            max_query_bytes=4096,
        )
        proto._transport = DummyTransport()  # type: ignore[assignment]
        proto._inflight_total = 1
        proto._inflight_per_ip["127.0.0.1"] = 1

        await proto._handle_one(query, ("127.0.0.1", 12345), "127.0.0.1", None)

        assert sent == [b"ovl"]
        assert proto._inflight_total == 0
        assert proto._inflight_per_ip == {}

    asyncio.run(_run())


def test_serve_udp_asyncio_stops_on_stop_event_and_closes_transport(
    monkeypatch: Any,
) -> None:
    """Brief: serve_udp_asyncio closes transport on stop_event.

    Inputs:
      - monkeypatch: patches loop.create_datagram_endpoint.

    Outputs:
      - None; asserts started is set, transport_out populated, and close() called.
    """

    async def _run() -> None:
        loop = asyncio.get_running_loop()

        class DummyTransport:
            def __init__(self) -> None:
                self.closed = False

            def close(self) -> None:
                self.closed = True

        dummy = DummyTransport()

        async def _fake_create_datagram_endpoint(
            factory, local_addr=None
        ):  # noqa: ANN001
            proto = factory()
            assert isinstance(proto, udp_mod._UDPProtocol)
            return dummy, proto

        monkeypatch.setattr(
            loop, "create_datagram_endpoint", _fake_create_datagram_endpoint
        )

        stop_event = asyncio.Event()
        started = threading.Event()
        holder: dict[str, object] = {}

        async def _stop_soon() -> None:
            await asyncio.sleep(0)
            stop_event.set()

        asyncio.create_task(_stop_soon())

        await udp_mod.serve_udp_asyncio(
            "127.0.0.1",
            0,
            lambda _q, _ip: b"",
            stop_event=stop_event,
            started=started,
            transport_out=holder,
        )

        assert started.is_set() is True
        assert holder.get("transport") is dummy
        assert dummy.closed is True

    asyncio.run(_run())


def test_serve_udp_asyncio_stop_event_none_can_be_cancelled_and_closes_transport(
    monkeypatch: Any,
) -> None:
    """Brief: Cancellation triggers transport.close() when stop_event is None.

    Inputs:
      - monkeypatch: patches loop.create_datagram_endpoint.

    Outputs:
      - None; asserts close() is called in finally.
    """

    async def _run() -> None:
        loop = asyncio.get_running_loop()

        class DummyTransport:
            def __init__(self) -> None:
                self.closed = False

            def close(self) -> None:
                self.closed = True

        dummy = DummyTransport()

        async def _fake_create_datagram_endpoint(
            factory, local_addr=None
        ):  # noqa: ANN001
            proto = factory()
            assert isinstance(proto, udp_mod._UDPProtocol)
            return dummy, proto

        monkeypatch.setattr(
            loop, "create_datagram_endpoint", _fake_create_datagram_endpoint
        )

        t = asyncio.create_task(
            udp_mod.serve_udp_asyncio(
                "127.0.0.1",
                0,
                lambda _q, _ip: b"",
                stop_event=None,
            )
        )
        await asyncio.sleep(0)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

        assert dummy.closed is True

    asyncio.run(_run())


def test_udp_asyncio_server_handle_stop_is_noop_when_missing_loop_or_event() -> None:
    """Brief: stop() is a no-op when loop/stop_event are missing.

    Inputs:
      - Handle with loop=None/stop_event=None.

    Outputs:
      - None; asserts no exception.
    """

    h = udp_mod.UDPAsyncioServerHandle(
        thread=threading.Thread(),
        loop=None,
        stop_event=None,
        transport_holder={},
    )
    h.stop()


def test_udp_asyncio_server_handle_stop_swallow_call_soon_errors() -> None:
    """Brief: stop() swallows call_soon_threadsafe errors.

    Inputs:
      - Dummy loop raising on call_soon_threadsafe.

    Outputs:
      - None; asserts no exception.
    """

    class DummyLoop:
        def call_soon_threadsafe(self, _cb):  # noqa: ANN001
            raise RuntimeError("boom")

    h = udp_mod.UDPAsyncioServerHandle(
        thread=threading.Thread(),
        loop=DummyLoop(),
        stop_event=SimpleNamespace(set=lambda: None),
        transport_holder={},
    )
    h.stop()


def test_start_udp_asyncio_threaded_best_effort_when_thread_target_not_run(
    monkeypatch: Any,
) -> None:
    """Brief: If thread.start() never runs the target, handle has no loop/event.

    Inputs:
      - monkeypatch: replaces threading.Thread with a no-op start() implementation.

    Outputs:
      - None; asserts handle.loop and stop_event are None.
    """

    class DummyThread:
        def __init__(self, target=None, name=None, daemon=None) -> None:  # noqa: ANN001
            self._target = target
            self.name = name
            self.daemon = daemon

        def start(self) -> None:
            return None

    monkeypatch.setattr(udp_mod.threading, "Thread", DummyThread)

    h = udp_mod.start_udp_asyncio_threaded(
        "127.0.0.1",
        0,
        lambda _q, _ip: b"",
        startup_timeout_s=0.01,
    )

    assert h._loop is None
    assert h._stop_event is None


def test_start_udp_asyncio_threaded_surfaces_loop_creation_errors(
    monkeypatch: Any,
) -> None:
    """Brief: Exceptions during runner startup are raised to the caller.

    Inputs:
      - monkeypatch: forces asyncio.new_event_loop to raise.

    Outputs:
      - None; asserts PermissionError is raised.
    """

    monkeypatch.setattr(
        udp_mod.asyncio,
        "new_event_loop",
        lambda: (_ for _ in ()).throw(PermissionError("blocked")),
    )

    class DummyThread:
        def __init__(self, target=None, name=None, daemon=None) -> None:  # noqa: ANN001
            self._target = target

        def start(self) -> None:
            if self._target is not None:
                self._target()

    monkeypatch.setattr(udp_mod.threading, "Thread", DummyThread)

    with pytest.raises(PermissionError):
        udp_mod.start_udp_asyncio_threaded(
            "127.0.0.1",
            0,
            lambda _q, _ip: b"",
            startup_timeout_s=0.01,
        )


def test_start_udp_asyncio_threaded_happy_path_stops(monkeypatch: Any) -> None:
    """Brief: Threaded starter returns a handle that can stop the server.

    Inputs:
      - monkeypatch: replaces serve_udp_asyncio with a stub that waits on stop_event.

    Outputs:
      - None; asserts stop() stops the server thread.
    """

    async def fake_serve(
        host: str,
        port: int,
        resolver,  # noqa: ANN001
        *,
        stop_event: asyncio.Event,
        started: threading.Event,
        transport_out: dict[str, object],
        **_kw: Any,
    ) -> None:
        started.set()
        transport_out["transport"] = "dummy"
        await stop_event.wait()

    monkeypatch.setattr(udp_mod, "serve_udp_asyncio", fake_serve)

    h = udp_mod.start_udp_asyncio_threaded(
        "127.0.0.1",
        0,
        lambda _q, _ip: b"",
        startup_timeout_s=0.5,
        thread_name="foghorn-udp-test",
    )

    assert h.thread.is_alive() is True
    assert h._loop is not None
    assert h._stop_event is not None

    h.stop()
    h.thread.join(timeout=1.0)
    assert h.thread.is_alive() is False
