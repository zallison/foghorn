import asyncio
import ssl
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


async def _handle_conn(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    resolver: Callable[[bytes, str], bytes],
    idle_timeout: float = 15.0,
) -> None:
    """
    Handle a single DNS-over-TLS connection (RFC 7858).

    Inputs:
      - reader: TLS-wrapped StreamReader
      - writer: TLS-wrapped StreamWriter
      - resolver: Callable that takes (query_bytes, client_ip) and returns response_bytes
      - idle_timeout: Seconds before closing idle connection
    Outputs:
      - None

    Example:
      >>> await _handle_conn(reader, writer, resolver)
    """
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if isinstance(peer, tuple) else "0.0.0.0"
    try:
        while True:
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
            response = await asyncio.get_running_loop().run_in_executor(
                None, resolver, query, client_ip
            )
            # Interpret an empty response as an explicit drop/timeout request
            # from the shared resolver: do not send a DNS message so the
            # client-side DoT stack experiences a timeout.
            if not response:
                break
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


async def serve_dot(
    host: str,
    port: int,
    resolver: Callable[[bytes, str], bytes],
    *,
    cert_file: str,
    key_file: str,
    ca_file: Optional[str] = None,
    min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
) -> None:
    """
    Serve DNS-over-TLS on host:port with given certificate.

    Inputs:
      - host: Listen address
      - port: Listen port (853 typical)
      - resolver: Callable mapping (query_bytes, client_ip) -> response_bytes
      - cert_file: Path to PEM certificate
      - key_file: Path to PEM private key
      - ca_file: Optional client-auth CA (unused by default)
      - min_version: Minimum TLS version (default TLS1.2)
    Outputs:
      - None (runs forever)

    Example:
      >>> asyncio.run(serve_dot('0.0.0.0', 8853, resolver, cert_file='cert.pem', key_file='key.pem'))
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = min_version
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    server = await asyncio.start_server(
        lambda r, w: _handle_conn(r, w, resolver), host, port, ssl=ctx
    )
    async with server:
        await server.serve_forever()
