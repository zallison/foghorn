import asyncio
from typing import Callable


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


async def _handle_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, resolver: Callable[[bytes, str], bytes], idle_timeout: float = 15.0) -> None:
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
            query = await asyncio.wait_for(_read_exact(reader, ln), timeout=idle_timeout)
            if len(query) != ln:
                break
            # Resolve
            response = await asyncio.get_running_loop().run_in_executor(None, resolver, query, client_ip)
            # Write back
            writer.write(len(response).to_bytes(2, "big") + response)
            await writer.drain()
    except asyncio.TimeoutError:
        pass
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def serve_tcp(host: str, port: int, resolver: Callable[[bytes, str], bytes]) -> None:
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
    server = await asyncio.start_server(lambda r, w: _handle_conn(r, w, resolver), host, port)
    async with server:
        await server.serve_forever()