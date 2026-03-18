from __future__ import annotations

"""Asyncio-based DNS-over-UDP server.

Brief:
  Implements a UDP listener using asyncio DatagramProtocol. This is intended to
  be the default UDP listener path, with ThreadingUDPServer retained only as a
  fallback for restricted environments.

Inputs:
  - host/port: UDP bind address
  - resolver: callable (query_bytes, client_ip) -> response_bytes
  - max_inflight / max_inflight_per_ip: bounds on concurrent in-flight queries

Outputs:
  - serve_udp_asyncio(): coroutine that runs forever
"""

import asyncio
import ipaddress
import logging
import threading
from concurrent.futures import Executor
from typing import Callable
from foghorn.utils import ip_networks

logger = logging.getLogger("foghorn.udp_asyncio")

# RFC 1035 DNS header is 12 bytes.
_DNS_HEADER_BYTES = 12

# Default cap for UDP query payloads. This is intentionally conservative and is
# meant as a DoS guardrail rather than a protocol limit.
DEFAULT_MAX_UDP_QUERY_BYTES = 4096


def _make_overloaded_response(query_wire: bytes) -> bytes | None:
    """Brief: Build a minimal SERVFAIL response for overload shedding.

    Inputs:
      - query_wire: Wire-format DNS query bytes.

    Outputs:
      - bytes | None: A minimal SERVFAIL response (with matching TXID) when
        query_wire contains a transaction ID; otherwise None.

    Notes:
      - This function is used in hot overload paths. It intentionally avoids
        dnslib parsing and constructs only the 12-byte DNS header response.
      - The response sets:
          - QR=1 (response)
          - OPCODE=0
          - AA=0, TC=0, RD=0
          - RA=0, Z=0
          - RCODE=SERVFAIL (2)
          - QDCOUNT=1, ANCOUNT=NSCOUNT=ARCOUNT=0
    """

    if len(query_wire) < 2:
        return None

    txid = query_wire[0:2]
    return txid + b"\x80\x02" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"


class _UDPProtocol(asyncio.DatagramProtocol):
    """Brief: DatagramProtocol that runs the resolver with in-flight limits.

    Inputs:
      - resolver: callable mapping (query_bytes, client_ip) -> response_bytes
      - executor: optional executor to run resolver in
      - max_inflight: global cap on in-flight resolver calls
      - max_inflight_per_ip: per-source-IP cap on in-flight resolver calls
      - max_inflight_by_cidr: optional list of CIDR bucket limits.

    Outputs:
      - Async UDP handling via datagram_received.
    """

    def __init__(
        self,
        resolver: Callable[[bytes, str], bytes],
        *,
        executor: Executor | None,
        max_inflight: int,
        max_inflight_per_ip: int,
        max_query_bytes: int,
        max_inflight_by_cidr: list[dict[str, object]] | None = None,
    ) -> None:
        """Brief: Initialize protocol state.

        Inputs:
          - resolver: Callable (query_bytes, client_ip) -> response_bytes.
          - executor: Optional executor for running the resolver.
          - max_inflight: Global cap on concurrent resolver calls (min 1).
          - max_inflight_per_ip: Per-client cap on concurrent resolver calls (min 1).
          - max_query_bytes: Max UDP payload bytes accepted for a DNS query.
          - max_inflight_by_cidr: Optional list of dicts with keys:
              - cidr: CIDR string
              - max_inflight: positive integer limit for this CIDR bucket

        Outputs:
          - None; initializes counters and optional CIDR bucket rules.
        """
        self._resolver = resolver
        self._executor = executor
        self._max_inflight = max(1, int(max_inflight))
        self._max_inflight_per_ip = max(1, int(max_inflight_per_ip))
        self._max_query_bytes = max(_DNS_HEADER_BYTES, int(max_query_bytes))

        # Optional CIDR bucket limits: partitioned IPv4/IPv6 lists of
        # (network, max_inflight, prefixlen).
        self._cidr_rules_v4: list[tuple[ipaddress.IPv4Network, int, int]] = []
        self._cidr_rules_v6: list[tuple[ipaddress.IPv6Network, int, int]] = []
        if max_inflight_by_cidr:
            for entry in max_inflight_by_cidr:
                if not isinstance(entry, dict):
                    continue
                cidr = entry.get("cidr")
                limit = entry.get("max_inflight")
                if not cidr or limit is None:
                    continue
                net = ip_networks.parse_network(cidr, strict=False)
                if net is None:
                    continue
                try:
                    lim_i = int(limit)
                except Exception:
                    continue
                if lim_i < 1:
                    continue

                try:
                    prefixlen = int(getattr(net, "prefixlen", 0) or 0)
                except Exception:
                    prefixlen = 0

                if isinstance(net, ipaddress.IPv4Network):
                    self._cidr_rules_v4.append((net, lim_i, prefixlen))
                elif isinstance(net, ipaddress.IPv6Network):
                    self._cidr_rules_v6.append((net, lim_i, prefixlen))

        # Prefer most-specific matches (largest prefixlen) earlier.
        self._cidr_rules_v4.sort(key=lambda x: x[2], reverse=True)
        self._cidr_rules_v6.sort(key=lambda x: x[2], reverse=True)

        self._inflight_total = 0
        self._inflight_per_ip: dict[str, int] = {}
        self._inflight_per_cidr: dict[str, int] = {}

        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:  # noqa: D401
        """Brief: Record the datagram transport.

        Inputs:
          - transport: asyncio transport instance provided by the event loop.

        Outputs:
          - None; stores the transport when it is a DatagramTransport.
        """

        if isinstance(transport, asyncio.DatagramTransport):
            self._transport = transport

    def connection_lost(self, exc: Exception | None) -> None:  # noqa: D401
        """Brief: Drop the transport reference.

        Inputs:
          - exc: Optional exception (unused).

        Outputs:
          - None; clears the stored transport reference.
        """

        self._transport = None

    def _select_cidr_bucket(self, client_ip: str) -> tuple[str | None, int | None]:
        """Brief: Pick the most-specific matching CIDR bucket for client_ip.

        Inputs:
          - client_ip: Source IP string.

        Outputs:
          - (bucket_key, limit) where bucket_key is a stable string for
            bookkeeping (e.g. '10.0.0.0/8'). Returns (None, None) when no CIDR
            rules match.

        Notes:
          - "Most-specific wins": the matching rule with the largest prefixlen
            is chosen.
          - When multiple rules share the same prefixlen, the smallest
            max_inflight is chosen (stricter within equal specificity).

        Example:
          - Rules:
              - 10.0.0.0/8 => 5
              - 10.1.0.0/16 => 100
            For 10.1.2.3, the /16 rule is chosen and the limit is 100.
        """

        if not self._cidr_rules_v4 and not self._cidr_rules_v6:
            return None, None

        addr = ip_networks.parse_ip(client_ip)
        if addr is None:
            return None, None

        if isinstance(addr, ipaddress.IPv4Address):
            rules = self._cidr_rules_v4
        else:
            rules = self._cidr_rules_v6

        if not rules:
            return None, None

        best_net = None
        best_limit: int | None = None
        best_prefix = -1

        for net, limit, prefix in rules:
            try:
                if addr not in net:
                    continue
            except Exception:
                continue

            if prefix > best_prefix:
                best_prefix = prefix
                best_limit = int(limit)
                best_net = net
            elif prefix == best_prefix:
                if best_limit is None or int(limit) < int(best_limit):
                    best_limit = int(limit)
                    best_net = net

        if best_net is None or best_limit is None:
            return None, None
        return str(best_net), int(best_limit)

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: D401
        """Brief: Handle one UDP datagram.

        Inputs:
          - data: Raw UDP payload bytes (DNS message).
          - addr: Address tuple provided by asyncio (ip, port).

        Outputs:
          - None; schedules background resolver work or sheds load with SERVFAIL.
        """

        if len(data) < _DNS_HEADER_BYTES or len(data) > self._max_query_bytes:
            # Drop invalid/oversized packets silently (no response) to avoid
            # amplification and wasted work on attack traffic.
            return

        client_ip = addr[0] if isinstance(addr, tuple) and addr else "0.0.0.0"

        # All callbacks run on the event loop thread, so we can update counters
        # synchronously without additional locking.
        cur_ip = int(self._inflight_per_ip.get(client_ip, 0) or 0)

        bucket_key, bucket_limit = self._select_cidr_bucket(client_ip)
        cur_bucket = 0
        if bucket_key is not None and bucket_limit is not None:
            cur_bucket = int(self._inflight_per_cidr.get(bucket_key, 0) or 0)

        if self._inflight_total >= self._max_inflight:
            limited = True
        elif cur_ip >= self._max_inflight_per_ip:
            limited = True
        elif (
            bucket_key is not None
            and bucket_limit is not None
            and cur_bucket >= int(bucket_limit)
        ):
            limited = True
        else:
            limited = False

        if limited:
            resp = _make_overloaded_response(data)
            if resp and self._transport is not None:
                try:
                    self._transport.sendto(resp, addr)
                except Exception:
                    pass
            return

        self._inflight_total += 1
        self._inflight_per_ip[client_ip] = cur_ip + 1
        if bucket_key is not None and bucket_limit is not None:
            self._inflight_per_cidr[bucket_key] = cur_bucket + 1

        loop = asyncio.get_running_loop()
        loop.create_task(self._handle_one(data, addr, client_ip, bucket_key))

    async def _handle_one(
        self, data: bytes, addr, client_ip: str, bucket_key: str | None
    ) -> None:
        """Brief: Resolve a single datagram and reply (best-effort).

        Inputs:
          - data: DNS query wire bytes.
          - addr: UDP client address tuple.
          - client_ip: Normalized client IP string.
          - bucket_key: Optional CIDR bucket key for inflight accounting.

        Outputs:
          - None; sends a UDP response when available.

        Notes:
          - Errors are swallowed to avoid killing the datagram protocol.
          - Inflight counters are decremented in a finally block.
        """
        try:
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                self._executor, self._resolver, data, client_ip
            )
            if not resp:
                return
            if self._transport is not None:
                self._transport.sendto(resp, addr)
        except Exception as _exc:
            # Defensive: do not crash the protocol on resolver failures.
            logger.debug("Resolver error for %s: %s", client_ip, _exc, exc_info=True)
            try:
                resp = _make_overloaded_response(data)
                if resp and self._transport is not None:
                    self._transport.sendto(resp, addr)
            except Exception:
                pass
        finally:
            try:
                self._inflight_total = max(0, int(self._inflight_total) - 1)
                cur = int(self._inflight_per_ip.get(client_ip, 0) or 0)
                if cur <= 1:
                    self._inflight_per_ip.pop(client_ip, None)
                else:
                    self._inflight_per_ip[client_ip] = cur - 1

                if bucket_key:
                    cur_b = int(self._inflight_per_cidr.get(bucket_key, 0) or 0)
                    if cur_b <= 1:
                        self._inflight_per_cidr.pop(bucket_key, None)
                    else:
                        self._inflight_per_cidr[bucket_key] = cur_b - 1

                # Defensive recovery: if counter bookkeeping ever drifts and the
                # dict grows unexpectedly, reset it rather than leaking memory.
                if len(self._inflight_per_ip) > (self._max_inflight * 2):
                    logger.warning(
                        "inflight_per_ip size %d exceeds safety cap; clearing",
                        len(self._inflight_per_ip),
                    )
                    self._inflight_per_ip.clear()
            except (
                Exception
            ):  # pragma: nocover - defensive: counter bookkeeping should not raise
                # If counters drift due to an unexpected exception, keep going.
                pass


async def serve_udp_asyncio(
    host: str,
    port: int,
    resolver: Callable[[bytes, str], bytes],
    *,
    max_inflight: int = 1024,
    max_inflight_per_ip: int = 64,
    max_query_bytes: int = DEFAULT_MAX_UDP_QUERY_BYTES,
    max_inflight_by_cidr: list[dict[str, object]] | None = None,
    executor: Executor | None = None,
    stop_event: asyncio.Event | None = None,
    started: threading.Event | None = None,
    transport_out: dict[str, object] | None = None,
) -> None:
    """Brief: Serve DNS-over-UDP using asyncio.

    Inputs:
      - host: Bind address.
      - port: Bind port.
      - resolver: Callable (query_bytes, client_ip) -> response_bytes.
      - max_inflight: Global cap on concurrent in-flight resolver calls.
      - max_inflight_per_ip: Per-client-IP cap on in-flight resolver calls.
      - max_query_bytes: Max UDP payload bytes accepted for a DNS query.
      - max_inflight_by_cidr: Optional list of CIDR bucket limits.
      - executor: Optional executor used to run the synchronous resolver.
      - stop_event: Optional asyncio.Event used to request shutdown.
      - started: Optional threading.Event set after the UDP socket is bound.
      - transport_out: Optional dict used to expose the underlying transport.

    Outputs:
      - None (runs forever until stop_event is set or the event loop is stopped).
    """

    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: _UDPProtocol(
            resolver,
            executor=executor,
            max_inflight=max_inflight,
            max_inflight_per_ip=max_inflight_per_ip,
            max_query_bytes=max_query_bytes,
            max_inflight_by_cidr=max_inflight_by_cidr,
        ),
        local_addr=(host, int(port)),
    )

    if transport_out is not None:
        try:
            transport_out["transport"] = transport
        except (
            Exception
        ):  # pragma: nocover - defensive: transport_out may be a hostile mapping
            pass

    if started is not None:
        try:
            started.set()
        except (
            Exception
        ):  # pragma: nocover - defensive: threading.Event.set should not raise
            pass

    try:
        if stop_event is None:
            await asyncio.Future()
        else:
            await stop_event.wait()
    finally:
        try:
            transport.close()
        except (
            Exception
        ):  # pragma: nocover - defensive: transport.close() should not raise
            pass


class UDPAsyncioServerHandle:
    """Brief: Threaded handle for an asyncio-based UDP DNS listener.

    Inputs:
      - host/port/resolver/max_inflight/max_inflight_per_ip/executor: passed to serve_udp_asyncio.

    Outputs:
      - UDPAsyncioServerHandle with stop() and thread access.

    Notes:
      - This exists so foghorn.main can treat UDP like other listeners while still
        being able to stop the server during coordinated shutdown.
    """

    def __init__(
        self,
        *,
        thread: threading.Thread,
        loop: asyncio.AbstractEventLoop | None,
        stop_event: asyncio.Event | None,
        transport_holder: dict[str, object],
    ) -> None:
        """Brief: Create a handle to a threaded asyncio UDP listener.

        Inputs:
          - thread: Listener thread.
          - loop: Event loop running on the listener thread (or None).
          - stop_event: asyncio.Event used to request shutdown (or None).
          - transport_holder: Mapping that may contain the underlying transport.

        Outputs:
          - None; stores references for stop() and inspection.
        """
        self.thread = thread
        self._loop = loop
        self._stop_event = stop_event
        self._transport_holder = transport_holder

    def stop(self) -> None:
        """Brief: Request graceful shutdown of the asyncio UDP listener.

        Inputs:
          - None

        Outputs:
          - None; schedules stop_event on the server thread.
        """

        if self._loop is None or self._stop_event is None:
            return
        try:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        except Exception:
            return


def start_udp_asyncio_threaded(
    host: str,
    port: int,
    resolver: Callable[[bytes, str], bytes],
    *,
    max_inflight: int = 1024,
    max_inflight_per_ip: int = 64,
    max_query_bytes: int = DEFAULT_MAX_UDP_QUERY_BYTES,
    max_inflight_by_cidr: list[dict[str, object]] | None = None,
    executor: Executor | None = None,
    startup_timeout_s: float = 2.0,
    thread_name: str = "foghorn-udp",
) -> UDPAsyncioServerHandle:
    """Brief: Start an asyncio UDP DNS server on a dedicated daemon thread.

    Inputs:
      - host: Bind address.
      - port: Bind port.
      - resolver: Callable (query_bytes, client_ip) -> response_bytes.
      - max_inflight: Global cap on in-flight resolver calls.
      - max_inflight_per_ip: Per-client-IP cap on in-flight resolver calls.
      - max_query_bytes: Max UDP payload bytes accepted for a DNS query.
      - max_inflight_by_cidr: Optional list of CIDR bucket limits.
      - executor: Optional executor used to run resolver.
      - startup_timeout_s: Max seconds to wait for the socket bind to complete.
      - thread_name: Name assigned to the listener thread.

    Outputs:
      - UDPAsyncioServerHandle: Handle used to stop the listener.

    Raises:
      - PermissionError / OSError / Exception: When binding or event loop creation
        fails. Exceptions are surfaced synchronously after waiting for startup.
    """

    started = threading.Event()
    transport_holder: dict[str, object] = {}
    state: dict[str, object] = {"exc": None, "loop": None, "stop": None}

    def _runner() -> None:
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            stop_event = asyncio.Event()
            state["loop"] = loop
            state["stop"] = stop_event
            loop.run_until_complete(
                serve_udp_asyncio(
                    host,
                    int(port),
                    resolver,
                    max_inflight=max_inflight,
                    max_inflight_per_ip=max_inflight_per_ip,
                    max_query_bytes=max_query_bytes,
                    max_inflight_by_cidr=max_inflight_by_cidr,
                    executor=executor,
                    stop_event=stop_event,
                    started=started,
                    transport_out=transport_holder,
                )
            )
        except Exception as exc:
            state["exc"] = exc
            try:
                started.set()
            except (
                Exception
            ):  # pragma: nocover - defensive: threading.Event.set should not raise
                pass
        finally:
            try:
                loop = state.get("loop")
                if isinstance(loop, asyncio.AbstractEventLoop):
                    loop.close()
            except (
                Exception
            ):  # pragma: nocover - defensive: loop close may fail in unusual interpreter shutdown cases
                pass

    t = threading.Thread(target=_runner, name=str(thread_name), daemon=True)
    t.start()

    # Wait for the bind to complete (or fail) so callers can decide on fallbacks.
    try:
        started.wait(timeout=float(startup_timeout_s))
    except (
        Exception
    ):  # pragma: nocover - defensive: threading.Event.wait should not raise
        pass

    if not started.is_set():
        logger.warning(
            "UDP listener on %s:%d did not signal startup within %.1fs",
            host,
            int(port),
            float(startup_timeout_s),
        )

    exc = state.get("exc")
    if isinstance(exc, BaseException):
        raise exc

    loop = state.get("loop")
    stop_event = state.get("stop")

    # If the thread was started with a test stub that does not execute the
    # target, the loop/stop_event will not be populated. Treat this as a
    # best-effort start rather than failing hard so unit tests can stub
    # Thread.start() without binding real sockets.
    if not isinstance(loop, asyncio.AbstractEventLoop) or not isinstance(
        stop_event, asyncio.Event
    ):
        loop = None
        stop_event = None

    return UDPAsyncioServerHandle(
        thread=t,
        loop=loop,
        stop_event=stop_event,
        transport_holder=transport_holder,
    )
