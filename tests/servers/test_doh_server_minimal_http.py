"""
Brief: Unit tests for the minimal asyncio DoH HTTP server implementation in doh_server.

Inputs:
  - None

Outputs:
  - None
"""

import asyncio
import base64

import pytest

from foghorn.servers import doh_server


pytestmark = pytest.mark.slow


def test_b64url_decode_nopad_roundtrip() -> None:
    """Brief: _b64url_decode_nopad decodes base64url strings without padding.

    Inputs:
      - None.

    Outputs:
      - None; asserts that repeated decoding matches original bytes.
    """
    original = b"\x01\x02\xff"
    s = base64.urlsafe_b64encode(original).decode("ascii").rstrip("=")
    assert doh_server._b64url_decode_nopad(s) == original
    # Second call exercises the lru_cache path as well.
    assert doh_server._b64url_decode_nopad(s) == original


def test_read_request_no_data_returns_empty() -> None:
    """Brief: _read_request returns empty values when the stream yields no data.

    Inputs:
      - None.

    Outputs:
      - None; asserts that request line, headers, and body are empty.
    """

    async def _run() -> tuple[str, dict[str, str], bytes]:
        reader = asyncio.StreamReader()
        reader.feed_eof()
        return await doh_server._read_request(reader)

    req_line, headers, body = asyncio.run(_run())
    assert req_line == ""
    assert headers == {}
    assert body == b""


def test_read_request_parses_headers_and_body() -> None:
    """Brief: _read_request parses request line, headers, and body correctly.

    Inputs:
      - None.

    Outputs:
      - None; asserts that headers and body are decoded from the stream.
    """

    async def _run() -> tuple[str, dict[str, str], bytes]:
        reader = asyncio.StreamReader()
        raw = (
            b"POST /dns-query HTTP/1.1\r\n"
            b"Host: example.test\r\n"
            b"Content-Length: 5\r\n"
            b"X-Extra: value\r\n"
            b"\r\n"
            b"abcde"
        )
        reader.feed_data(raw)
        reader.feed_eof()
        return await doh_server._read_request(reader)

    req_line, headers, body = asyncio.run(_run())
    assert req_line == "POST /dns-query HTTP/1.1"
    assert headers["host"] == "example.test"
    assert headers["content-length"] == "5"
    assert headers["x-extra"] == "value"
    assert body == b"abcde"


class _FakeWriter:
    """Brief: Minimal fake StreamWriter for exercising _handle_conn.

    Inputs:
      - peer: optional peername used for get_extra_info("peername").

    Outputs:
      - Instances record writes and close calls for assertions.
    """

    def __init__(self, peer=("1.2.3.4", 5300)) -> None:
        self._peer = peer
        self.written: list[bytes] = []
        self.closed = False

    def get_extra_info(self, key: str):
        """Brief: Return stored peername for the given key.

        Inputs:
          - key: extra info key.

        Outputs:
          - peer tuple for "peername", else None.
        """
        if key == "peername":
            return self._peer
        return None

    def write(self, data: bytes) -> None:
        """Brief: Record written bytes for later inspection.

        Inputs:
          - data: bytes to write.

        Outputs:
          - None.
        """
        self.written.append(data)

    async def drain(self) -> None:
        """Brief: Async no-op drain implementation.

        Inputs:
          - None.

        Outputs:
          - None.
        """
        return None

    def close(self) -> None:
        """Brief: Mark writer as closed.

        Inputs:
          - None.

        Outputs:
          - None.
        """
        self.closed = True

    async def wait_closed(self) -> None:
        """Brief: Async no-op wait_closed implementation.

        Inputs:
          - None.

        Outputs:
          - None.
        """
        return None


def test_handle_conn_post_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _handle_conn handles POST /dns-query with valid content type.

    Inputs:
      - monkeypatch: used to stub _read_request.

    Outputs:
      - None; asserts resolver is called and 200 response is written.
    """
    writer = _FakeWriter()
    calls: dict[str, list[tuple[bytes, str]]] = {"calls": []}

    async def fake_read_request(reader):  # type: ignore[override]
        return (
            "POST /dns-query HTTP/1.1",
            {"content-type": "application/dns-message", "content-length": "3"},
            b"abc",
        )

    def resolver(q: bytes, ip: str) -> bytes:
        calls["calls"].append((q, ip))
        return b"resp"

    monkeypatch.setattr(doh_server, "_read_request", fake_read_request)

    async def _run() -> None:
        await doh_server._handle_conn(reader=object(), writer=writer, resolver=resolver)

    asyncio.run(_run())

    assert calls["calls"] == [(b"abc", "1.2.3.4")]
    assert writer.closed is True
    assert writer.written
    head = writer.written[0]
    assert head.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Type: application/dns-message\r\n" in head
    assert writer.written[1] == b"resp"


def test_handle_conn_post_wrong_content_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _handle_conn returns 415 for POST with wrong Content-Type.

    Inputs:
      - monkeypatch: used to stub _read_request.

    Outputs:
      - None; asserts resolver is not called and 415 is written.
    """
    writer = _FakeWriter()

    async def fake_read_request(reader):  # type: ignore[override]
        return (
            "POST /dns-query HTTP/1.1",
            {"content-type": "text/plain", "content-length": "1"},
            b"x",
        )

    def resolver(q: bytes, ip: str) -> bytes:  # pragma: no cover - defensive
        raise AssertionError("resolver should not be called")

    monkeypatch.setattr(doh_server, "_read_request", fake_read_request)

    async def _run() -> None:
        await doh_server._handle_conn(reader=object(), writer=writer, resolver=resolver)

    asyncio.run(_run())

    assert writer.closed is True
    assert len(writer.written) == 1
    assert writer.written[0].startswith(b"HTTP/1.1 415 Unsupported Media Type\r\n")


def test_handle_conn_get_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _handle_conn decodes GET /dns-query?dns=<b64> and returns 200.

    Inputs:
      - monkeypatch: used to stub _read_request.

    Outputs:
      - None; asserts decoded query and resolver response are used.
    """
    writer = _FakeWriter()
    calls: dict[str, list[tuple[bytes, str]]] = {"calls": []}

    q = b"payload"
    s = base64.urlsafe_b64encode(q).decode("ascii").rstrip("=")

    async def fake_read_request(reader):  # type: ignore[override]
        return (
            f"GET /dns-query?dns={s} HTTP/1.1",
            {},
            b"",
        )

    def resolver(qbytes: bytes, ip: str) -> bytes:
        calls["calls"].append((qbytes, ip))
        return b"resp2"

    monkeypatch.setattr(doh_server, "_read_request", fake_read_request)

    async def _run() -> None:
        await doh_server._handle_conn(reader=object(), writer=writer, resolver=resolver)

    asyncio.run(_run())

    assert calls["calls"] == [(q, "1.2.3.4")]
    assert writer.closed is True
    assert writer.written[0].startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Type: application/dns-message\r\n" in writer.written[0]
    assert writer.written[1] == b"resp2"


def test_handle_conn_get_missing_dns_param(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _handle_conn returns 400 for GET /dns-query without dns param.

    Inputs:
      - monkeypatch: used to stub _read_request.

    Outputs:
      - None; asserts 400 response and no resolver call.
    """
    writer = _FakeWriter()

    async def fake_read_request(reader):  # type: ignore[override]
        return (
            "GET /dns-query HTTP/1.1",
            {},
            b"",
        )

    def resolver(q: bytes, ip: str) -> bytes:  # pragma: no cover - defensive
        raise AssertionError("resolver should not be called")

    monkeypatch.setattr(doh_server, "_read_request", fake_read_request)

    async def _run() -> None:
        await doh_server._handle_conn(reader=object(), writer=writer, resolver=resolver)

    asyncio.run(_run())

    assert writer.closed is True
    assert len(writer.written) == 1
    assert writer.written[0].startswith(b"HTTP/1.1 400 Bad Request\r\n")


def test_handle_conn_get_invalid_base64(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _handle_conn returns 400 for GET with invalid base64 dns param.

    Inputs:
      - monkeypatch: used to stub _read_request.

    Outputs:
      - None; asserts 400 response and no resolver call.
    """
    writer = _FakeWriter()

    async def fake_read_request(reader):  # type: ignore[override]
        return (
            "GET /dns-query?dns=% HTTP/1.1",
            {},
            b"",
        )

    def resolver(q: bytes, ip: str) -> bytes:  # pragma: no cover - defensive
        raise AssertionError("resolver should not be called")

    monkeypatch.setattr(doh_server, "_read_request", fake_read_request)

    async def _run() -> None:
        await doh_server._handle_conn(reader=object(), writer=writer, resolver=resolver)

    asyncio.run(_run())

    assert writer.closed is True
    assert len(writer.written) == 1
    assert writer.written[0].startswith(b"HTTP/1.1 400 Bad Request\r\n")


def test_handle_conn_unsupported_method(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _handle_conn returns 400 for unsupported HTTP methods.

    Inputs:
      - monkeypatch: used to stub _read_request.

    Outputs:
      - None; asserts that 400 response is written and resolver is not called.
    """
    writer = _FakeWriter()

    async def fake_read_request(reader):  # type: ignore[override]
        return (
            "PUT /dns-query HTTP/1.1",
            {},
            b"",
        )

    def resolver(q: bytes, ip: str) -> bytes:  # pragma: no cover - defensive
        raise AssertionError("resolver should not be called")

    monkeypatch.setattr(doh_server, "_read_request", fake_read_request)

    async def _run() -> None:
        await doh_server._handle_conn(reader=object(), writer=writer, resolver=resolver)

    asyncio.run(_run())

    assert writer.closed is True
    assert len(writer.written) == 1
    assert writer.written[0].startswith(b"HTTP/1.1 400 Bad Request\r\n")


def test_handle_conn_invalid_request_line(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _handle_conn returns 400 when request line cannot be split.

    Inputs:
      - monkeypatch: used to stub _read_request.

    Outputs:
      - None; asserts 400 response and early return.
    """
    writer = _FakeWriter()

    async def fake_read_request(reader):  # type: ignore[override]
        return ("INVALID", {}, b"")

    def resolver(q: bytes, ip: str) -> bytes:  # pragma: no cover - defensive
        raise AssertionError("resolver should not be called")

    monkeypatch.setattr(doh_server, "_read_request", fake_read_request)

    async def _run() -> None:
        await doh_server._handle_conn(reader=object(), writer=writer, resolver=resolver)

    asyncio.run(_run())

    assert writer.closed is True
    assert len(writer.written) == 1
    assert writer.written[0].startswith(b"HTTP/1.1 400 Bad Request\r\n")


def test_handle_conn_wrong_path_404(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _handle_conn returns 404 when path does not start with /dns-query.

    Inputs:
      - monkeypatch: used to stub _read_request.

    Outputs:
      - None; asserts 404 response and no resolver call.
    """
    writer = _FakeWriter()

    async def fake_read_request(reader):  # type: ignore[override]
        return (
            "GET /other HTTP/1.1",
            {},
            b"",
        )

    def resolver(q: bytes, ip: str) -> bytes:  # pragma: no cover - defensive
        raise AssertionError("resolver should not be called")

    monkeypatch.setattr(doh_server, "_read_request", fake_read_request)

    async def _run() -> None:
        await doh_server._handle_conn(reader=object(), writer=writer, resolver=resolver)

    asyncio.run(_run())

    assert writer.closed is True
    assert len(writer.written) == 1
    assert writer.written[0].startswith(b"HTTP/1.1 404 Not Found\r\n")


def test_handle_conn_empty_request_line(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _handle_conn closes connection when request line is empty.

    Inputs:
      - monkeypatch: used to stub _read_request.

    Outputs:
      - None; asserts writer is closed and no response is written.
    """
    writer = _FakeWriter()

    async def fake_read_request(reader):  # type: ignore[override]
        return ("", {}, b"")

    def resolver(q: bytes, ip: str) -> bytes:  # pragma: no cover - defensive
        raise AssertionError("resolver should not be called")

    monkeypatch.setattr(doh_server, "_read_request", fake_read_request)

    async def _run() -> None:
        await doh_server._handle_conn(reader=object(), writer=writer, resolver=resolver)

    asyncio.run(_run())

    assert writer.closed is True
    # No HTTP status line is written for an empty request
    assert writer.written == []


def test_handle_conn_exception_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _handle_conn writes 400 when an internal exception is raised.

    Inputs:
      - monkeypatch: used to make _read_request raise an exception.

    Outputs:
      - None; asserts 400 response and connection close.
    """
    writer = _FakeWriter()

    async def fake_read_request(reader):  # type: ignore[override]
        raise RuntimeError("boom")

    def resolver(q: bytes, ip: str) -> bytes:  # pragma: no cover - defensive
        raise AssertionError("resolver should not be called")

    monkeypatch.setattr(doh_server, "_read_request", fake_read_request)

    async def _run() -> None:
        await doh_server._handle_conn(reader=object(), writer=writer, resolver=resolver)

    asyncio.run(_run())

    assert writer.closed is True
    assert len(writer.written) == 1
    assert writer.written[0].startswith(b"HTTP/1.1 400 Bad Request\r\n")


def test_handle_conn_uses_default_client_ip_when_peer_not_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _handle_conn falls back to 0.0.0.0 when peername is not a tuple.

    Inputs:
      - monkeypatch: used to stub _read_request.

    Outputs:
      - None; asserts resolver sees 0.0.0.0 as client_ip.
    """
    writer = _FakeWriter(peer="not-a-tuple")
    seen: dict[str, list[str]] = {"ips": []}

    async def fake_read_request(reader):  # type: ignore[override]
        return (
            "POST /dns-query HTTP/1.1",
            {"content-type": "application/dns-message", "content-length": "1"},
            b"z",
        )

    def resolver(q: bytes, ip: str) -> bytes:
        seen["ips"].append(ip)
        return b"ok"

    monkeypatch.setattr(doh_server, "_read_request", fake_read_request)

    async def _run() -> None:
        await doh_server._handle_conn(reader=object(), writer=writer, resolver=resolver)

    asyncio.run(_run())

    assert seen["ips"] == ["0.0.0.0"]
    assert writer.closed is True
    assert writer.written[0].startswith(b"HTTP/1.1 200 OK\r\n")
