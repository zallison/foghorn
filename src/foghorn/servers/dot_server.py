import asyncio
import ssl
from concurrent.futures import Executor
from typing import Callable, Optional


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
) -> None:
    """
    Handle a single DNS-over-TLS connection (RFC 7858).

    Inputs:
      - reader: TLS-wrapped StreamReader.
      - writer: TLS-wrapped StreamWriter.
      - resolver: Callable that takes (query_bytes, client_ip) and returns
        response_bytes.
      - idle_timeout: Seconds before closing an idle connection.
      - max_queries: Maximum DNS frames to process before closing.
      - limiter: Optional _ConnLimiter for global/per-IP concurrent limits.
      - executor: Optional executor used for resolver calls.
    Outputs:
      - None; writes framed DNS responses and always closes the writer.

    Example:
      >>> await _handle_conn(reader, writer, resolver)

    Notes:
      - AXFR/IXFR requests stream multi-message responses from
        server.iter_axfr_messages().
      - Empty resolver responses are treated as intentional drops/timeouts and
        no DNS response frame is sent.
      - If peername is unavailable or malformed, client_ip defaults to 0.0.0.0.
    """
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if isinstance(peer, tuple) else "0.0.0.0"

    acquired = True
    if limiter is not None:
        acquired = await limiter.acquire(client_ip)
        if not acquired:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

    query_count = 0
    try:
        from dnslib import QTYPE, DNSRecord

        from foghorn.servers import server as _server_mod

        while True:
            if query_count >= max(1, int(max_queries)):
                break
            hdr = await asyncio.wait_for(_read_exact(reader, 2), timeout=idle_timeout)
            if len(hdr) != 2:
                break
            ln = int.from_bytes(hdr, byteorder="big")
            if ln <= 0:  # pragma: no cover - network error
                break
            query = await asyncio.wait_for(
                _read_exact(reader, ln), timeout=idle_timeout
            )
            if len(query) != ln:  # pragma: no cover - network error
                break

            is_transfer = False
            req: Optional[DNSRecord]
            try:
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
                    messages = _server_mod.iter_axfr_messages(req, client_ip, query)
                except TypeError:
                    messages = _server_mod.iter_axfr_messages(req)
                for wire in messages:
                    if not wire:
                        continue
                    writer.write(len(wire).to_bytes(2, "big") + wire)
                    await writer.drain()
                break

            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(executor, resolver, query, client_ip)
            # Interpret an empty response as an explicit drop/timeout request
            # from the shared resolver: do not send a DNS message so the
            # client-side DoT stack experiences a timeout.
            if not response:
                break
            query_count += 1
            writer.write(len(response).to_bytes(2, "big") + response)
            await writer.drain()
    except (
        asyncio.TimeoutError
    ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
    except (
        Exception
    ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
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


async def serve_dot(
    host: str,
    port: int,
    resolver: Callable[[bytes, str], bytes],
    *,
    cert_file: str,
    key_file: str,
    ca_file: Optional[str] = None,
    min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
    max_connections: int = 1024,
    max_connections_per_ip: int = 64,
    max_queries_per_connection: int = 100,
    idle_timeout_seconds: float = 15.0,
    executor: Executor | None = None,
    on_listen: Callable[[int], None] | None = None,
) -> None:
    """Brief: Serve DNS-over-TLS on host:port with the given certificate.

    Inputs:
      - host: Listen address.
      - port: Listen port (853 typical). When 0, the OS chooses an ephemeral port.
      - resolver: Callable mapping (query_bytes, client_ip) -> response_bytes.
      - cert_file: Path to PEM certificate.
      - key_file: Path to PEM private key.
      - ca_file: Optional client-auth CA (accepted for API compatibility;
        currently unused by this implementation).
      - min_version: Minimum TLS version (default TLS1.2).
      - max_connections / max_connections_per_ip: Connection limiting knobs.
      - max_queries_per_connection: Close after this many queries.
      - idle_timeout_seconds: Close idle connections after this many seconds.
      - executor: Optional executor for resolver work.
      - on_listen: Optional callback invoked with the bound port after the server
        starts listening.

    Outputs:
      - None (runs until cancelled/stopped).

    Example:
      >>> asyncio.run(serve_dot('0.0.0.0', 8853, resolver, cert_file='cert.pem', key_file='key.pem'))
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

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = min_version
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    server = await asyncio.start_server(
        lambda r, w: _handle_conn(
            r,
            w,
            resolver,
            idle_timeout=float(idle_timeout_seconds),
            max_queries=int(max_queries_per_connection),
            limiter=limiter,
            executor=executor,
        ),
        host,
        port,
        ssl=ctx,
    )

    if on_listen is not None:
        listen_port = int(port)
        try:
            if getattr(server, "sockets", None):
                listen_port = int(server.sockets[0].getsockname()[1])  # type: ignore[index]
        except Exception:
            listen_port = int(port)
        try:
            on_listen(int(listen_port))
        except Exception:
            pass

    async with server:
        await server.serve_forever()
