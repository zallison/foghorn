import asyncio
import logging
import socketserver
from concurrent.futures import Executor
from typing import Callable

from foghorn.security_limits import MAX_DNS_TCP_MESSAGE_BYTES
from foghorn.servers.overload_response import (
    OVERLOAD_RESPONSE_DROP,
    build_overload_dns_response,
    normalize_overload_response,
)

logger = logging.getLogger("foghorn.servers.tcp_server")


class _TCPHandler(socketserver.BaseRequestHandler):
    """
    Blocking handler for DNS-over-TCP using length-prefixed frames.

    Inputs:
      - request: socket
      - client_address: tuple
    Outputs:
      - None (serves one connection)

    Example:
      See serve_tcp_threaded.
    """

    resolver: Callable[[bytes, str], bytes] = lambda b, ip: b

    def handle(self) -> None:
        peer_ip = (
            self.client_address[0]
            if isinstance(self.client_address, tuple)
            else "0.0.0.0"
        )
        try:
            from dnslib import QTYPE, DNSRecord

            from foghorn.servers import server as _server_mod

            sock = self.request  # type: ignore
            # Set a modest timeout to avoid permanent hangs
            sock.settimeout(15)
            while True:
                hdr = _recv_exact(sock, 2)
                if not hdr or len(hdr) != 2:
                    break
                ln = int.from_bytes(hdr, "big")
                if ln <= 0:  # pragma: no cover - network error
                    break
                if ln > int(MAX_DNS_TCP_MESSAGE_BYTES):
                    # Oversized DNS message; close connection to avoid memory DoS.
                    break
                body = _recv_exact(sock, ln)
                if body is None or len(body) != ln:  # pragma: no cover - network error
                    break

                is_transfer = False
                try:
                    req = DNSRecord.parse(body)
                    if getattr(req, "questions", None):
                        q = req.questions[0]
                        qtype = q.qtype
                        if qtype in (QTYPE.AXFR, QTYPE.IXFR):
                            is_transfer = True
                except Exception:  # pragma: no cover - defensive parse failure
                    req = None

                if is_transfer and req is not None:
                    # Stream AXFR/IXFR messages using the shared helper so TCP
                    # and DoT use the same zone-transfer semantics.
                    try:
                        messages = _server_mod.iter_axfr_messages(
                            req,
                            peer_ip,
                            body,
                        )
                    except TypeError:
                        messages = _server_mod.iter_axfr_messages(req)
                    for wire in messages:
                        if not wire:
                            continue
                        sock.sendall(len(wire).to_bytes(2, "big") + wire)
                    # AXFR/IXFR consumes this connection; do not process
                    # additional queries on the same TCP stream.
                    break

                resp = self.resolver(body, peer_ip)
                # Treat an empty response as an explicit drop/timeout request
                # from the shared resolver: do not send a DNS message so the
                # client observes a timeout at the TCP or application layer.
                if not resp:
                    break
                sock.sendall(len(resp).to_bytes(2, "big") + resp)
        except (ConnectionError, OSError, TimeoutError):
            return
        except Exception:  # pragma: no cover - defensive: unexpected transport failure
            logger.exception(
                "Unhandled error in threaded TCP handler for client %s",
                peer_ip,
            )


def serve_tcp_threaded(
    host: str, port: int, resolver: Callable[[bytes, str], bytes]
) -> None:
    """
    Serve DNS-over-TCP using socketserver.ThreadingTCPServer as a fallback when asyncio is unavailable.

    Inputs:
      - host: Listen address
      - port: Listen port
      - resolver: Callable mapping (query_bytes, client_ip) -> response_bytes
    Outputs:
      - None (runs forever)

    Example:
      >>> # In a thread
      >>> # serve_tcp_threaded('0.0.0.0', 5353, resolver)
    """
    # Bind handler with resolver
    handler_cls = _TCPHandler
    handler_cls.resolver = staticmethod(resolver)  # type: ignore
    server = socketserver.ThreadingTCPServer((host, port), handler_cls)
    server.daemon_threads = True
    try:
        server.serve_forever()
    finally:
        try:
            server.server_close()
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably


async def _read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    """
    Read exactly n bytes from an asyncio StreamReader.

    Inputs:
      - reader: asyncio.StreamReader
      - n: Number of bytes to read
    Outputs:
      - bytes: Exactly n bytes unless EOF occurs early.

    Example:
      >>> await _read_exact(reader, 2)
    """
    data = b""
    while len(data) < n:
        chunk = await reader.read(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _recv_exact(sock, length):
    """
    Receive exactly 'length' bytes from the given socket.
    This function blocks until the requested number of bytes is received
    or the connection is closed.

    Args:
        sock: A connected socket object.
        length (int): The number of bytes to receive.

    Returns:
        bytes | None: The received data, or None if the connection was closed.

    Raises:
        RuntimeError: If the connection is broken before receiving all data.
    """
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            # Connection closed by peer
            return None
        data.extend(chunk)
    return bytes(data)


async def _send_connection_overload_response(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    overload_response: str,
    idle_timeout: float,
) -> None:
    """Brief: Attempt to send one framed DNS overload response.

    Inputs:
      - reader/writer: asyncio stream objects for the rejected connection.
      - overload_response: Policy ('servfail'|'refused'|'drop').
      - idle_timeout: Idle timeout used to bound best-effort reads.

    Outputs:
      - None; writes at most one framed DNS response when policy permits.
    """

    policy = normalize_overload_response(
        overload_response, default=OVERLOAD_RESPONSE_DROP
    )
    if policy == OVERLOAD_RESPONSE_DROP:
        return

    timeout = min(1.0, max(0.05, float(idle_timeout or 0.0)))
    try:
        hdr = await asyncio.wait_for(_read_exact(reader, 2), timeout=timeout)
        if len(hdr) != 2:
            return
        ln = int.from_bytes(hdr, byteorder="big")
        if ln <= 0 or ln > int(MAX_DNS_TCP_MESSAGE_BYTES):
            return

        query = await asyncio.wait_for(_read_exact(reader, ln), timeout=timeout)
        if len(query) != ln:
            return

        response = build_overload_dns_response(query, policy)
        if not response:
            return

        writer.write(len(response).to_bytes(2, "big") + response)
        await writer.drain()
    except Exception:
        return


class _ConnLimiter:
    """Brief: Bound total and per-IP concurrent connections for asyncio servers.

    Inputs:
      - max_connections: Global concurrent connection cap.
      - max_per_ip: Per-client-IP concurrent connection cap.

    Outputs:
      - Instance with acquire/release coroutines.
    """

    def __init__(self, *, max_connections: int, max_per_ip: int) -> None:
        self._sem = asyncio.Semaphore(max(1, int(max_connections)))
        self._max_per_ip = max(1, int(max_per_ip))
        self._lock = asyncio.Lock()
        self._per_ip: dict[str, int] = {}

    async def acquire(self, client_ip: str) -> bool:
        await self._sem.acquire()
        ok = False
        try:
            async with self._lock:
                cur = int(self._per_ip.get(client_ip, 0) or 0)
                if cur >= self._max_per_ip:
                    ok = False
                else:
                    self._per_ip[client_ip] = cur + 1
                    ok = True
            return ok
        except Exception:
            ok = False
            return False
        finally:
            if not ok:
                try:
                    self._sem.release()
                except Exception:
                    pass

    async def release(self, client_ip: str) -> None:
        try:
            async with self._lock:
                cur = int(self._per_ip.get(client_ip, 0) or 0)
                if cur <= 1:
                    self._per_ip.pop(client_ip, None)
                else:
                    self._per_ip[client_ip] = cur - 1
        finally:
            try:
                self._sem.release()
            except Exception:
                pass


async def _handle_conn(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    resolver: Callable[[bytes, str], bytes],
    *,
    idle_timeout: float = 15.0,
    max_queries: int = 100,
    limiter: _ConnLimiter | None = None,
    executor: Executor | None = None,
    overload_response: str = OVERLOAD_RESPONSE_DROP,
) -> None:
    """
    Handle a single DNS-over-TCP connection.

    Inputs:
      - reader: asyncio StreamReader for the client
      - writer: asyncio StreamWriter for the client
      - resolver: Callable that takes (query_bytes, client_ip) and returns response_bytes
      - idle_timeout: Seconds before closing idle connection
      - overload_response: Overload handling policy for rejected connections.
    Outputs:
      - None

    Example:
      >>> await _handle_conn(reader, writer, resolver)
    """
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if isinstance(peer, tuple) else "0.0.0.0"

    acquired = True
    if limiter is not None:
        acquired = await limiter.acquire(client_ip)
        if not acquired:
            await _send_connection_overload_response(
                reader,
                writer,
                overload_response=overload_response,
                idle_timeout=float(idle_timeout),
            )
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

    writer.transport.set_write_buffer_limits(1 << 20)
    query_count = 0
    try:
        while True:
            if query_count >= max(1, int(max_queries)):
                break
            hdr = await asyncio.wait_for(_read_exact(reader, 2), timeout=idle_timeout)
            if len(hdr) != 2:
                break
            ln = int.from_bytes(hdr, byteorder="big")
            if ln <= 0:
                break
            if ln > int(MAX_DNS_TCP_MESSAGE_BYTES):
                break
            query = await asyncio.wait_for(
                _read_exact(reader, ln), timeout=idle_timeout
            )
            if len(query) != ln:
                break

            # Detect AXFR/IXFR and stream via shared helper when requested.
            is_transfer = False
            req = None
            try:
                from dnslib import (  # local import for parity with threaded handler
                    QTYPE,
                    DNSRecord,
                )

                from foghorn.servers import server as _server_mod

                req = DNSRecord.parse(query)
                if getattr(req, "questions", None):
                    q = req.questions[0]
                    qtype = q.qtype
                    if qtype in (QTYPE.AXFR, QTYPE.IXFR):
                        is_transfer = True
            except Exception:  # pragma: no cover - defensive parse failure
                req = None

            if is_transfer and req is not None:
                try:
                    try:
                        messages = _server_mod.iter_axfr_messages(
                            req,
                            client_ip,
                            query,
                        )
                    except TypeError:
                        messages = _server_mod.iter_axfr_messages(req)
                    for wire in messages:
                        if not wire:
                            continue
                        writer.write(len(wire).to_bytes(2, "big") + wire)
                        await writer.drain()
                except (
                    Exception
                ):  # pragma: no cover - defensive: AXFR failure falls back to closing
                    pass
                # AXFR/IXFR consumes this connection; do not process further
                # queries on the same TCP stream.
                break

            # Resolve normal (non-transfer) queries via the shared resolver.
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(executor, resolver, query, client_ip)
            # Treat an empty response as an explicit drop/timeout request from
            # the shared resolver: stop processing without writing a DNS
            # message so the client observes a timeout.
            if not response:
                break

            query_count += 1
            # Write back
            writer.write(len(response).to_bytes(2, "big") + response)
            await writer.drain()
    except asyncio.TimeoutError:
        pass  # pragma: no cover - defensive: idle timeout closes connection
    except (ConnectionError, OSError):
        pass  # pragma: no cover - defensive: expected network disconnect path
    except Exception:  # pragma: no cover - defensive: unexpected transport failure
        logger.exception(
            "Unhandled error in asyncio TCP handler for client %s",
            client_ip,
        )
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        if limiter is not None and acquired:
            try:
                await limiter.release(client_ip)
            except Exception:
                pass


async def serve_tcp(
    host: str,
    port: int,
    resolver: Callable[[bytes, str], bytes],
    *,
    max_connections: int = 1024,
    max_connections_per_ip: int = 64,
    max_queries_per_connection: int = 100,
    idle_timeout_seconds: float = 15.0,
    executor: Executor | None = None,
    overload_response: str = OVERLOAD_RESPONSE_DROP,
) -> None:
    """
    Serve DNS-over-TCP on host:port.

    Inputs:
      - host: Listen address
      - port: Listen port
      - resolver: Callable that maps (query_bytes, client_ip) -> response_bytes
      - overload_response: Overload handling policy for rejected connections.
    Outputs:
      - None (runs forever)

    Example:
      >>> asyncio.run(serve_tcp('0.0.0.0', 5353, resolver))
    """
    if executor is None:
        try:
            from .executors import get_resolver_executor

            executor = get_resolver_executor()
        except Exception:
            executor = None

    limiter = _ConnLimiter(
        max_connections=int(max_connections or 1),
        max_per_ip=int(max_connections_per_ip or 1),
    )

    server = await asyncio.start_server(
        lambda r, w: _handle_conn(
            r,
            w,
            resolver,
            idle_timeout=float(idle_timeout_seconds),
            max_queries=int(max_queries_per_connection),
            limiter=limiter,
            executor=executor,
            overload_response=overload_response,
        ),
        host,
        port,
    )
    async with server:
        await server.serve_forever()
