"""
Brief: Unit tests for internal behaviors of foghorn.doh_api.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import base64
import subprocess
from io import BytesIO
from typing import Any

import pytest

try:  # FastAPI is an optional dependency; skip these tests if unavailable.
    from fastapi.testclient import TestClient
except (
    ModuleNotFoundError
):  # pragma: no cover - environment-dependent optional dependency
    TestClient = None
    pytest.skip(
        "fastapi not installed; skipping DoH FastAPI unit tests",
        allow_module_level=True,
    )

import foghorn.servers.doh_api as doh_api


def test_b64url_decode_nopad_non_str_raises_valueerror() -> None:
    """Brief: Ensure _b64url_decode_nopad rejects non-str input.

    Inputs:
      - None

    Outputs:
      - Raises ValueError when input is not a str.
    """

    with pytest.raises(ValueError):
        doh_api._b64url_decode_nopad(b"not-a-string")  # type: ignore[arg-type]


def test_doh_get_bad_base64_returns_400(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: GET /dns-query returns 400 when base64 decode fails.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Response status 400 from FastAPI doh_get handler.
    """

    def boom_decode(s: str) -> bytes:  # pragma: no cover - exercised via handler
        raise ValueError("bad b64")

    monkeypatch.setattr(doh_api, "_b64url_decode_nopad", boom_decode)

    app = doh_api.create_doh_app(lambda q, ip: q)
    client = TestClient(app)

    resp = client.get("/dns-query", params={"dns": "ignored"})
    assert resp.status_code == 400


def test_doh_get_resolver_exception_returns_400() -> None:
    """Brief: GET /dns-query returns 400 when resolver raises.

    Inputs:
      - None

    Outputs:
      - Response status 400 from FastAPI doh_get handler.
    """

    def bad_resolver(
        q: bytes, client_ip: str
    ) -> bytes:  # pragma: no cover - exercised via handler
        raise RuntimeError("resolver boom")

    app = doh_api.create_doh_app(bad_resolver)
    client = TestClient(app)

    query = b"\x01\x02test"
    s = base64.urlsafe_b64encode(query).decode("ascii").rstrip("=")
    resp = client.get("/dns-query", params={"dns": s})
    assert resp.status_code == 400


def test_doh_post_resolver_exception_returns_400() -> None:
    """Brief: POST /dns-query returns 400 when resolver raises.

    Inputs:
      - None

    Outputs:
      - Response status 400 from FastAPI doh_post handler.
    """

    def bad_resolver(
        q: bytes, client_ip: str
    ) -> bytes:  # pragma: no cover - exercised via handler
        raise RuntimeError("resolver boom")

    app = doh_api.create_doh_app(bad_resolver)
    client = TestClient(app)

    resp = client.post(
        "/dns-query",
        data=b"\x00\x01body",
        headers={"Content-Type": "application/dns-message"},
    )
    assert resp.status_code == 400


def test_threaded_client_ip_fallback_to_default() -> None:
    """Brief: _ThreadedDoHRequestHandler._client_ip falls back to 0.0.0.0.

    Inputs:
      - None

    Outputs:
      - Returns "0.0.0.0" when client_address is missing or not a tuple.
    """

    handler = doh_api._ThreadedDoHRequestHandler.__new__(
        doh_api._ThreadedDoHRequestHandler
    )
    handler.client_address = None  # type: ignore[assignment]
    assert handler._client_ip() == "0.0.0.0"


def test_threaded_send_empty_delegates_to_send_bytes() -> None:
    """Brief: _send_empty uses _send_bytes with expected arguments.

    Inputs:
      - None

    Outputs:
      - _send_bytes called with status, empty body, and text/plain content-type.
    """

    handler = doh_api._ThreadedDoHRequestHandler.__new__(
        doh_api._ThreadedDoHRequestHandler
    )
    captured: dict[str, Any] = {}

    def fake_send_bytes(status: int, body: bytes, ctype: str) -> None:
        captured["args"] = (status, body, ctype)

    handler._send_bytes = fake_send_bytes  # type: ignore[assignment]

    handler._send_empty(418)
    assert captured["args"] == (418, b"", "text/plain; charset=utf-8")


def test_threaded_get_non_doh_path_404() -> None:
    """Brief: do_GET sends 404 when path is not /dns-query.

    Inputs:
      - None

    Outputs:
      - _send_empty called with 404.
    """

    handler = doh_api._ThreadedDoHRequestHandler.__new__(
        doh_api._ThreadedDoHRequestHandler
    )
    handler.path = "/not-dns"  # type: ignore[assignment]
    called: list[int] = []

    def fake_send_empty(status: int) -> None:
        called.append(status)

    handler._send_empty = fake_send_empty  # type: ignore[assignment]

    handler.do_GET()
    assert called == [404]


def test_threaded_get_missing_dns_param_400() -> None:
    """Brief: do_GET sends 400 when dns query param is missing.

    Inputs:
      - None

    Outputs:
      - _send_empty called with 400.
    """

    handler = doh_api._ThreadedDoHRequestHandler.__new__(
        doh_api._ThreadedDoHRequestHandler
    )
    handler.path = "/dns-query?foo=bar"  # type: ignore[assignment]
    called: list[int] = []

    def fake_send_empty(status: int) -> None:
        called.append(status)

    handler._send_empty = fake_send_empty  # type: ignore[assignment]

    handler.do_GET()
    assert called == [400]


def test_threaded_get_bad_base64_400(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: do_GET sends 400 when base64 decoding fails.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - _send_empty called with 400.
    """

    handler = doh_api._ThreadedDoHRequestHandler.__new__(
        doh_api._ThreadedDoHRequestHandler
    )
    handler.path = "/dns-query?dns=ignored"  # type: ignore[assignment]

    def boom_decode(s: str) -> bytes:  # pragma: no cover - exercised via handler
        raise ValueError("bad b64")

    monkeypatch.setattr(doh_api, "_b64url_decode_nopad", boom_decode)

    called: list[int] = []

    def fake_send_empty(status: int) -> None:
        called.append(status)

    handler._send_empty = fake_send_empty  # type: ignore[assignment]

    handler.do_GET()
    assert called == [400]


def test_threaded_get_resolver_exception_400() -> None:
    """Brief: do_GET sends 400 when resolver raises.

    Inputs:
      - None

    Outputs:
      - _send_empty called with 400.
    """

    handler = doh_api._ThreadedDoHRequestHandler.__new__(
        doh_api._ThreadedDoHRequestHandler
    )

    query = b"\x12\x34abcd"
    s = base64.urlsafe_b64encode(query).decode("ascii").rstrip("=")
    handler.path = f"/dns-query?dns={s}"  # type: ignore[assignment]

    def fake_client_ip() -> str:
        return "127.0.0.1"

    def bad_resolver(
        q: bytes, client_ip: str
    ) -> bytes:  # pragma: no cover - exercised via handler
        raise RuntimeError("resolver boom")

    called: list[int] = []

    def fake_send_empty(status: int) -> None:
        called.append(status)

    handler._client_ip = fake_client_ip  # type: ignore[assignment]
    handler._send_empty = fake_send_empty  # type: ignore[assignment]
    handler.resolver = bad_resolver  # type: ignore[assignment]

    handler.do_GET()
    assert called == [400]


def test_threaded_post_non_doh_path_404() -> None:
    """Brief: do_POST sends 404 when path is not /dns-query.

    Inputs:
      - None

    Outputs:
      - _send_empty called with 404.
    """

    handler = doh_api._ThreadedDoHRequestHandler.__new__(
        doh_api._ThreadedDoHRequestHandler
    )
    handler.path = "/other"  # type: ignore[assignment]
    called: list[int] = []

    def fake_send_empty(status: int) -> None:
        called.append(status)

    handler._send_empty = fake_send_empty  # type: ignore[assignment]

    handler.do_POST()
    assert called == [404]


def test_threaded_post_wrong_content_type_415() -> None:
    """Brief: do_POST sends 415 when Content-Type is not application/dns-message.

    Inputs:
      - None

    Outputs:
      - _send_empty called with 415.
    """

    handler = doh_api._ThreadedDoHRequestHandler.__new__(
        doh_api._ThreadedDoHRequestHandler
    )
    handler.path = "/dns-query"  # type: ignore[assignment]
    handler.headers = {"Content-Type": "text/plain"}  # type: ignore[assignment]
    called: list[int] = []

    def fake_send_empty(status: int) -> None:
        called.append(status)

    handler._send_empty = fake_send_empty  # type: ignore[assignment]

    handler.do_POST()
    assert called == [415]


def test_threaded_post_content_length_valueerror_uses_zero_and_succeeds() -> None:
    """Brief: do_POST treats invalid Content-Length as 0 and still resolves.

    Inputs:
      - None

    Outputs:
      - Resolver called with empty body and 200 response sent.
    """

    handler = doh_api._ThreadedDoHRequestHandler.__new__(
        doh_api._ThreadedDoHRequestHandler
    )
    handler.path = "/dns-query"  # type: ignore[assignment]
    handler.headers = {
        "Content-Type": "application/dns-message",
        "Content-Length": "not-an-int",
    }  # type: ignore[assignment]
    handler.rfile = BytesIO(b"ignored-body")  # type: ignore[assignment]

    def fake_client_ip() -> str:
        return "127.0.0.1"

    called_send: dict[str, Any] = {}
    seen_resolver: dict[str, Any] = {}

    def fake_send_bytes(status: int, body: bytes, ctype: str) -> None:
        called_send["args"] = (status, body, ctype)

    def good_resolver(
        body: bytes, client_ip: str
    ) -> bytes:  # pragma: no cover - exercised via handler
        seen_resolver["args"] = (body, client_ip)
        return b"ok"

    handler._client_ip = fake_client_ip  # type: ignore[assignment]
    handler._send_bytes = fake_send_bytes  # type: ignore[assignment]
    handler.resolver = good_resolver  # type: ignore[assignment]

    handler.do_POST()

    assert seen_resolver["args"] == (b"", "127.0.0.1")
    assert called_send["args"] == (200, b"ok", "application/dns-message")


def test_threaded_post_resolver_exception_400() -> None:
    """Brief: do_POST sends 400 when resolver raises.

    Inputs:
      - None

    Outputs:
      - _send_empty called with 400.
    """

    handler = doh_api._ThreadedDoHRequestHandler.__new__(
        doh_api._ThreadedDoHRequestHandler
    )
    handler.path = "/dns-query"  # type: ignore[assignment]
    handler.headers = {
        "Content-Type": "application/dns-message",
        "Content-Length": "0",
    }  # type: ignore[assignment]
    handler.rfile = BytesIO(b"")  # type: ignore[assignment]

    def fake_client_ip() -> str:
        return "127.0.0.1"

    def bad_resolver(
        body: bytes, client_ip: str
    ) -> bytes:  # pragma: no cover - exercised via handler
        raise RuntimeError("resolver boom")

    called: list[int] = []

    def fake_send_empty(status: int) -> None:
        called.append(status)

    handler._client_ip = fake_client_ip  # type: ignore[assignment]
    handler._send_empty = fake_send_empty  # type: ignore[assignment]
    handler.resolver = bad_resolver  # type: ignore[assignment]

    handler.do_POST()
    assert called == [400]


def test_threaded_log_message_handles_bad_format() -> None:
    """Brief: log_message falls back to raw format string if formatting fails.

    Inputs:
      - None

    Outputs:
      - Logger.info called with original format string when % formatting fails.
    """

    original_logger = doh_api.logger

    class DummyLogger:
        def __init__(self) -> None:
            self.records: list[tuple[str, tuple[Any, ...]]] = []

        def info(self, fmt: str, *args: Any) -> None:
            self.records.append((fmt, args))

    dummy = DummyLogger()
    doh_api.logger = dummy
    try:
        handler = doh_api._ThreadedDoHRequestHandler.__new__(
            doh_api._ThreadedDoHRequestHandler
        )
        handler.log_message("%s %s", "only-one-arg")
    finally:
        doh_api.logger = original_logger

    assert dummy.records
    fmt, args = dummy.records[0]
    assert fmt == "DoH HTTP: %s"
    assert args[0] == "%s %s"


@pytest.fixture(scope="module")
def selfsigned(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, str]:
    """Brief: Create a short-lived self-signed certificate/key pair for TLS tests.

    Inputs:
      - tmp_path_factory: pytest fixture to create temporary paths.

    Outputs:
      - Tuple of (cert_path, key_path) as strings.
    """

    tmp = tmp_path_factory.mktemp("doh_api_tls")
    cert = tmp / "cert.pem"
    key = tmp / "key.pem"
    try:
        subprocess.check_call(
            [
                "openssl",
                "req",
                "-x509",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-subj",
                "/CN=localhost",
                "-days",
                "1",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pytest.skip("openssl not available for doh_api TLS tests")

    return str(cert), str(key)


def test_start_doh_server_threaded_with_tls(selfsigned: tuple[str, str]) -> None:
    """Brief: _start_doh_server_threaded configures TLS and returns running handle.

    Inputs:
      - selfsigned: (cert_path, key_path) fixture for TLS.

    Outputs:
      - DoHServerHandle with a live thread that can be stopped.
    """

    cert_path, key_path = selfsigned

    def echo_resolver(
        q: bytes, client_ip: str
    ) -> bytes:  # pragma: no cover - exercised via server
        return q

    handle = doh_api._start_doh_server_threaded(
        host="127.0.0.1",
        port=0,
        resolver=echo_resolver,
        cert_file=cert_path,
        key_file=key_path,
    )
    assert handle is not None
    assert isinstance(handle, doh_api.DoHServerHandle)
    assert handle.is_running()
    handle.stop(timeout=0.5)


def test_doh_server_handle_stop_logs_on_server_shutdown_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: DoHServerHandle.stop logs when underlying server shutdown raises.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - logger.exception called for server shutdown error, and join still occurs.
    """

    class DummyThread:
        def is_alive(self) -> bool:
            return True

        def join(self, timeout: float | None = None) -> None:
            return

    class BadServer:
        def shutdown(self) -> None:
            raise RuntimeError("shutdown boom")

        def server_close(self) -> None:
            return

    original_logger = doh_api.logger

    class DummyLogger:
        def __init__(self) -> None:
            self.exceptions: list[str] = []

        def exception(self, msg: str, *args: Any) -> None:
            self.exceptions.append(msg)

        def info(
            self, msg: str, *args: Any
        ) -> None:  # pragma: no cover - not used here
            return

    dummy_logger = DummyLogger()
    doh_api.logger = dummy_logger
    try:
        handle = doh_api.DoHServerHandle(DummyThread(), server=BadServer())
        handle.stop(timeout=0.1)
    finally:
        doh_api.logger = original_logger

    assert any(
        "Error while shutting down DoH server instance" in m
        for m in dummy_logger.exceptions
    )


def test_doh_server_handle_stop_logs_on_thread_join_error() -> None:
    """Brief: DoHServerHandle.stop logs when thread.join raises.

    Inputs:
      - None

    Outputs:
      - logger.exception called for thread stopping error.
    """

    class BadThread:
        def is_alive(self) -> bool:
            return True

        def join(self, timeout: float | None = None) -> None:
            raise RuntimeError("join boom")

    original_logger = doh_api.logger

    class DummyLogger:
        def __init__(self) -> None:
            self.exceptions: list[str] = []

        def exception(self, msg: str, *args: Any) -> None:
            self.exceptions.append(msg)

        def info(
            self, msg: str, *args: Any
        ) -> None:  # pragma: no cover - not used here
            return

    dummy_logger = DummyLogger()
    doh_api.logger = dummy_logger
    try:
        handle = doh_api.DoHServerHandle(BadThread(), server=None)
        handle.stop(timeout=0.1)
    finally:
        doh_api.logger = original_logger

    assert any("Error while stopping DoH thread" in m for m in dummy_logger.exceptions)


def test_start_doh_server_handles_generic_asyncio_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: start_doh_server handles generic asyncio exceptions and still attempts startup.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - start_doh_server returns a handle or None without raising.
    """

    import asyncio

    def boom_new_event_loop() -> asyncio.AbstractEventLoop:  # type: ignore[override]
        raise RuntimeError("boom")

    monkeypatch.setattr(asyncio, "new_event_loop", boom_new_event_loop)

    def echo_resolver(
        q: bytes, client_ip: str
    ) -> bytes:  # pragma: no cover - exercised via server
        return q

    handle = doh_api.start_doh_server("127.0.0.1", 0, echo_resolver)

    # Depending on environment this may choose uvicorn or fall back to threaded HTTP.
    if isinstance(handle, doh_api.DoHServerHandle):
        handle.stop(timeout=0.5)
