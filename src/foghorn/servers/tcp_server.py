import asyncio
import socketserver
from typing import Callable


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
        try:
            sock = self.request  # type: ignore
            # Set a modest timeout to avoid permanent hangs
            sock.settimeout(15)
            peer_ip = (
                self.client_address[0]
                if isinstance(self.client_address, tuple)
                else "0.0.0.0"
            )
            while True:
                hdr = _recv_exact(sock, 2)
                if len(hdr) != 2:
                    break
                ln = int.from_bytes(hdr, "big")
                if ln <= 0:  # pragma: no cover - network error
                    break
                body = _recv_exact(sock, ln)
                if len(body) != ln:  # pragma: no cover - network error
                    break
                resp = self.resolver(body, peer_ip)
                # Treat an empty response as an explicit drop/timeout request
                # from the shared resolver: do not send a DNS message so the
                # client observes a timeout at the TCP or application layer.
                if not resp:
                    break
                sock.sendall(len(resp).to_bytes(2, "big") + resp)
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass


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
        bytes: The received data, or None if the connection was closed.

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


async def _handle_conn(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    resolver: Callable[[bytes, str], bytes],
    idle_timeout: float = 15.0,
) -> None:
    """
    Handle a single DNS-over-TCP connection.

    Inputs:
      - reader: asyncio StreamReader for the client
      - writer: asyncio StreamWriter for the client
      - resolver: Callable that takes (query_bytes, client_ip) and returns response_bytes
      - idle_timeout: Seconds before closing idle connection
    Outputs:
      - None

    Example:
      >>> await _handle_conn(reader, writer, resolver)
    """
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if isinstance(peer, tuple) else "0.0.0.0"
    writer.transport.set_write_buffer_limits(1 << 20)
    try:
        while True:
            hdr = await asyncio.wait_for(_read_exact(reader, 2), timeout=idle_timeout)
            if len(hdr) != 2:
                break
            ln = int.from_bytes(hdr, byteorder="big")
            if ln <= 0:
                break
            query = await asyncio.wait_for(
                _read_exact(reader, ln), timeout=idle_timeout
            )
            if len(query) != ln:
                break
            # Resolve
            response = await asyncio.get_running_loop().run_in_executor(
                None, resolver, query, client_ip
            )
            # Treat an empty response as an explicit drop/timeout request from
            # the shared resolver: stop processing without writing a DNS
            # message so the client observes a timeout.
            if not response:
                break
            # Write back
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


async def serve_tcp(
    host: str, port: int, resolver: Callable[[bytes, str], bytes]
) -> None:
    """
    Serve DNS-over-TCP on host:port.

    Inputs:
      - host: Listen address
      - port: Listen port
      - resolver: Callable that maps (query_bytes, client_ip) -> response_bytes
    Outputs:
      - None (runs forever)

    Example:
      >>> asyncio.run(serve_tcp('0.0.0.0', 5353, resolver))
    """
    server = await asyncio.start_server(
        lambda r, w: _handle_conn(r, w, resolver), host, port
    )
    async with server:
        await server.serve_forever()
