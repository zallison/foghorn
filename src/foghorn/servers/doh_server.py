import asyncio
import base64
from typing import Callable

from foghorn.utils.register_caches import registered_lru_cached

_HTTP_OK = b"HTTP/1.1 200 OK\r\n"
_HTTP_BAD = b"HTTP/1.1 400 Bad Request\r\n"
_HTTP_UNSUPPORTED = b"HTTP/1.1 415 Unsupported Media Type\r\n"
_HTTP_NOTFOUND = b"HTTP/1.1 404 Not Found\r\n"
_CT_DNS = b"Content-Type: application/dns-message\r\n"
_CT_JSON = b"Content-Type: application/json\r\n"
_CONN_CLOSE = b"Connection: close\r\n"
_CRLF = b"\r\n"


@registered_lru_cached(maxsize=1024)
def _b64url_decode_nopad(s: str) -> bytes:
    """
    Brief: Decode base64url without padding.

    Inputs:
    - s: base64url string without '='

    Outputs:
    - bytes: decoded binary

    Example:
        >>> _b64url_decode_nopad('AQI')
        b'\x01\x02'
    """
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


async def _read_request(
    reader: asyncio.StreamReader,
) -> tuple[str, dict[str, str], bytes]:
    """
    Brief: Minimal HTTP/1.1 request parser for GET/POST.

    Inputs:
    - reader: asyncio StreamReader

    Outputs:
    - (request_line, headers, body)

    Example:
        >>> # used internally by serve_doh
    """
    # Read request line and headers
    headers: dict[str, str] = {}
    line = await reader.readline()
    if not line:
        return "", {}, b""
    req_line = line.decode("latin-1").rstrip("\r\n")
    # Headers
    while True:
        h = await reader.readline()
        if not h or h == _CRLF:
            break
        k, _, v = h.decode("latin-1").partition(":")
        headers[k.strip().lower()] = v.strip()
    # Body if present
    body = b""
    if headers.get("content-length"):
        try:
            ln = int(headers.get("content-length", "0"))
            body = await reader.readexactly(ln)
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            body = await reader.read(0)
    return req_line, headers, body


async def _handle_conn(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    resolver: Callable[[bytes, str], bytes],
    *,
    idle_timeout: float = 10.0,
) -> None:
    """
    Brief: Handle a single HTTP connection for DoH with minimal parsing.

    Inputs:
    - reader, writer: asyncio streams
    - resolver: callable (query_bytes, client_ip) -> response_bytes
    - idle_timeout: seconds to keep connection open while waiting

    Outputs:
    - None

    Example:
        >>> # internal use by serve_doh
    """
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if isinstance(peer, tuple) else "0.0.0.0"
    try:
        # Single request then close (keep simple)
        req_line, headers, body = await asyncio.wait_for(
            _read_request(reader), timeout=idle_timeout
        )
        if not req_line:
            writer.close()
            await writer.wait_closed()
            return
        try:
            method, target, _ = req_line.split(" ", 2)
        except ValueError:
            writer.write(_HTTP_BAD + _CONN_CLOSE + _CRLF)
            await writer.drain()
            return
        if not target.startswith("/dns-query"):
            writer.write(_HTTP_NOTFOUND + _CONN_CLOSE + _CRLF)
            await writer.drain()
            return
        # Extract DNS query
        if method.upper() == "POST":
            ctype = headers.get("content-type", "")
            if "application/dns-message" not in ctype:
                writer.write(_HTTP_UNSUPPORTED + _CONN_CLOSE + _CRLF)
                await writer.drain()
                return
            qbytes = body
        elif method.upper() == "GET":
            from urllib.parse import parse_qs, urlparse

            qs = parse_qs(urlparse(target).query)
            if "dns" not in qs:
                writer.write(_HTTP_BAD + _CONN_CLOSE + _CRLF)
                await writer.drain()
                return
            try:
                qbytes = _b64url_decode_nopad(qs["dns"][0])
            except Exception:
                writer.write(_HTTP_BAD + _CONN_CLOSE + _CRLF)
                await writer.drain()
                return
        else:
            writer.write(_HTTP_BAD + _CONN_CLOSE + _CRLF)
            await writer.drain()
            return

        # Resolve
        loop = asyncio.get_running_loop()
        resp = await loop.run_in_executor(None, resolver, qbytes, client_ip)
        # Reply
        writer.write(_HTTP_OK + _CT_DNS + _CONN_CLOSE + _CRLF)
        writer.write(resp)
        await writer.drain()
    except asyncio.TimeoutError:
        pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
    except Exception:
        try:
            writer.write(_HTTP_BAD + _CONN_CLOSE + _CRLF)
            await writer.drain()
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass
