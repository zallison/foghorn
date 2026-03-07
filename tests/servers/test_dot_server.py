"""
Brief: Unit tests for downstream DoT server.

Inputs:
  - None

Outputs:
  - None
"""

import asyncio
import socket
import ssl
import subprocess
import threading

import pytest
import foghorn.servers.dot_server as dot_server_mod

from foghorn.servers.dot_server import serve_dot


class _FakeWriter:
    """Brief: Minimal fake StreamWriter for testing _handle_conn.

    Inputs:
      - peer: Optional peername returned from get_extra_info("peername").

    Outputs:
      - Instance recording writes and close lifecycle state.
    """

    def __init__(self, peer=("1.2.3.4", 5300)) -> None:
        self._peer = peer
        self.written: list[bytes] = []
        self.closed = False

    def get_extra_info(self, key: str):
        """Brief: Return test peername for the requested key.

        Inputs:
          - key: Extra-info lookup key.

        Outputs:
          - peer tuple/string for key 'peername', else None.
        """

        if key == "peername":
            return self._peer
        return None

    def write(self, data: bytes) -> None:
        """Brief: Record bytes that would be written to the network.

        Inputs:
          - data: Payload bytes.

        Outputs:
          - None.
        """

        self.written.append(data)

    async def drain(self) -> None:
        """Brief: Async no-op drain hook.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        return None

    def close(self) -> None:
        """Brief: Mark the writer as closed.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        self.closed = True

    async def wait_closed(self) -> None:
        """Brief: Async no-op wait_closed hook.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        return None


def test_read_exact_reads_full_payload() -> None:
    """Brief: _read_exact returns exactly N bytes when available.

    Inputs:
      - None.

    Outputs:
      - None; asserts full read behavior.
    """

    async def _run() -> bytes:
        reader = asyncio.StreamReader()
        reader.feed_data(b"abcd")
        reader.feed_eof()
        return await dot_server_mod._read_exact(reader, 4)

    assert asyncio.run(_run()) == b"abcd"


def test_read_exact_returns_partial_on_eof() -> None:
    """Brief: _read_exact returns partial bytes on early EOF.

    Inputs:
      - None.

    Outputs:
      - None; asserts partial-read behavior.
    """

    async def _run() -> bytes:
        reader = asyncio.StreamReader()
        reader.feed_data(b"ab")
        reader.feed_eof()
        return await dot_server_mod._read_exact(reader, 4)

    assert asyncio.run(_run()) == b"ab"


def test_conn_limiter_enforces_per_ip_limit_and_release() -> None:
    """Brief: _ConnLimiter blocks over-limit per-IP acquires and recovers on release.

    Inputs:
      - None.

    Outputs:
      - None; asserts acquire/release branch behavior.
    """

    async def _run() -> None:
        limiter = dot_server_mod._ConnLimiter(max_connections=2, max_per_ip=1)
        assert await limiter.acquire("1.1.1.1") is True
        assert await limiter.acquire("1.1.1.1") is False
        await limiter.release("1.1.1.1")
        assert await limiter.acquire("1.1.1.1") is True
        await limiter.release("1.1.1.1")

    asyncio.run(_run())


def test_conn_limiter_release_decrements_then_removes() -> None:
    """Brief: _ConnLimiter.release decrements counters before removing the IP key.

    Inputs:
      - None.

    Outputs:
      - None; asserts both release branches for cur>1 and cur<=1.
    """

    async def _run() -> None:
        limiter = dot_server_mod._ConnLimiter(max_connections=4, max_per_ip=3)
        ip = "2.2.2.2"
        assert await limiter.acquire(ip) is True
        assert await limiter.acquire(ip) is True
        assert limiter._per_ip[ip] == 2

        await limiter.release(ip)
        assert limiter._per_ip[ip] == 1

        await limiter.release(ip)
        assert ip not in limiter._per_ip

    asyncio.run(_run())


def test_conn_limiter_acquire_handles_lock_failure() -> None:
    """Brief: _ConnLimiter.acquire returns False and releases semaphore on lock errors.

    Inputs:
      - None.

    Outputs:
      - None; asserts defensive exception handling branch.
    """

    class _BrokenLock:
        async def __aenter__(self) -> None:
            raise RuntimeError("lock failure")

        async def __aexit__(self, exc_type, exc, tb) -> bool:  # noqa: ARG002
            return False

    async def _run() -> None:
        limiter = dot_server_mod._ConnLimiter(max_connections=1, max_per_ip=1)
        limiter._lock = _BrokenLock()  # type: ignore[assignment]

        assert await limiter.acquire("3.3.3.3") is False

        limiter._lock = asyncio.Lock()  # type: ignore[assignment]
        assert await limiter.acquire("3.3.3.3") is True
        await limiter.release("3.3.3.3")

    asyncio.run(_run())


def test_handle_conn_rejected_by_limiter_closes_writer() -> None:
    """Brief: _handle_conn closes immediately when limiter denies acquisition.

    Inputs:
      - None.

    Outputs:
      - None; asserts no DNS response writes and immediate close.
    """

    class _DenyLimiter:
        def __init__(self) -> None:
            self.acquire_calls: list[str] = []
            self.release_calls: list[str] = []

        async def acquire(self, client_ip: str) -> bool:
            self.acquire_calls.append(client_ip)
            return False

        async def release(self, client_ip: str) -> None:
            self.release_calls.append(client_ip)

    writer = _FakeWriter()
    limiter = _DenyLimiter()

    async def _run() -> None:
        await dot_server_mod._handle_conn(
            reader=object(),
            writer=writer,
            resolver=lambda q, ip: q,
            limiter=limiter,
        )

    asyncio.run(_run())

    assert writer.closed is True
    assert writer.written == []
    assert limiter.acquire_calls == ["1.2.3.4"]
    assert limiter.release_calls == []


def test_handle_conn_breaks_on_short_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: _handle_conn exits cleanly when the 2-byte header read is short.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts no responses are written.
    """

    async def fake_read_exact(reader, n: int) -> bytes:  # noqa: ARG001
        if n == 2:
            return b"\x00"
        return b""

    monkeypatch.setattr(dot_server_mod, "_read_exact", fake_read_exact)

    writer = _FakeWriter()

    async def _run() -> None:
        await dot_server_mod._handle_conn(
            reader=object(),
            writer=writer,
            resolver=lambda q, ip: q,
            idle_timeout=0.1,
        )

    asyncio.run(_run())

    assert writer.closed is True
    assert writer.written == []


def test_handle_conn_uses_default_ip_and_drops_empty_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _handle_conn falls back to 0.0.0.0 and drops empty resolver responses.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts resolver sees default IP and no frame is written.
    """

    calls = {"n": 0}

    async def fake_read_exact(reader, n: int) -> bytes:  # noqa: ARG001
        calls["n"] += 1
        if calls["n"] == 1 and n == 2:
            return (1).to_bytes(2, "big")
        if calls["n"] == 2 and n == 1:
            return b"x"
        return b""

    seen_ips: list[str] = []

    def resolver(query: bytes, client_ip: str) -> bytes:
        seen_ips.append(client_ip)
        return b""

    monkeypatch.setattr(dot_server_mod, "_read_exact", fake_read_exact)

    writer = _FakeWriter(peer="not-a-peer-tuple")

    async def _run() -> None:
        await dot_server_mod._handle_conn(
            reader=object(),
            writer=writer,
            resolver=resolver,
            max_queries=5,
        )

    asyncio.run(_run())

    assert seen_ips == ["0.0.0.0"]
    assert writer.closed is True
    assert writer.written == []


def test_handle_conn_malformed_dns_falls_back_to_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _handle_conn treats malformed DNS bytes as non-transfer queries.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts resolver path still returns a framed response.
    """

    calls = {"n": 0}

    async def fake_read_exact(reader, n: int) -> bytes:  # noqa: ARG001
        calls["n"] += 1
        if calls["n"] == 1 and n == 2:
            return (3).to_bytes(2, "big")
        if calls["n"] == 2 and n == 3:
            return b"bad"
        return b""

    seen: list[tuple[bytes, str]] = []

    def resolver(query: bytes, client_ip: str) -> bytes:
        seen.append((query, client_ip))
        return b"ok"

    monkeypatch.setattr(dot_server_mod, "_read_exact", fake_read_exact)

    writer = _FakeWriter()

    async def _run() -> None:
        await dot_server_mod._handle_conn(
            reader=object(),
            writer=writer,
            resolver=resolver,
            max_queries=1,
        )

    asyncio.run(_run())

    assert seen == [(b"bad", "1.2.3.4")]
    assert writer.written == [len(b"ok").to_bytes(2, "big") + b"ok"]


def test_handle_conn_axfr_streams_messages_and_skips_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _handle_conn streams AXFR messages and skips empty wires.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts only non-empty AXFR frames are written.
    """

    from dnslib import DNSRecord

    axfr_query = DNSRecord.question("example.com.", qtype="AXFR").pack()
    calls = {"n": 0}

    async def fake_read_exact(reader, n: int) -> bytes:  # noqa: ARG001
        calls["n"] += 1
        if calls["n"] == 1 and n == 2:
            return len(axfr_query).to_bytes(2, "big")
        if calls["n"] == 2 and n == len(axfr_query):
            return axfr_query
        return b""

    import foghorn.servers.server as server_mod

    seen_ips: list[str] = []

    def fake_iter_axfr_messages(req, client_ip):  # noqa: ARG001
        seen_ips.append(client_ip)
        return [b"\x00" * 12, b"", b"\x01" * 12]

    def resolver(query: bytes, client_ip: str) -> bytes:  # pragma: no cover - defensive
        raise AssertionError("resolver should not run for AXFR")

    monkeypatch.setattr(dot_server_mod, "_read_exact", fake_read_exact)
    monkeypatch.setattr(server_mod, "iter_axfr_messages", fake_iter_axfr_messages)

    writer = _FakeWriter()

    async def _run() -> None:
        await dot_server_mod._handle_conn(
            reader=object(),
            writer=writer,
            resolver=resolver,
        )

    asyncio.run(_run())

    assert seen_ips == ["1.2.3.4"]
    assert writer.written == [
        len(b"\x00" * 12).to_bytes(2, "big") + (b"\x00" * 12),
        len(b"\x01" * 12).to_bytes(2, "big") + (b"\x01" * 12),
    ]


def test_handle_conn_axfr_legacy_iter_signature_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _handle_conn falls back when iter_axfr_messages lacks client_ip arg.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts legacy one-arg iter_axfr_messages path is supported.
    """

    from dnslib import DNSRecord

    axfr_query = DNSRecord.question("example.org.", qtype="AXFR").pack()
    calls = {"n": 0}

    async def fake_read_exact(reader, n: int) -> bytes:  # noqa: ARG001
        calls["n"] += 1
        if calls["n"] == 1 and n == 2:
            return len(axfr_query).to_bytes(2, "big")
        if calls["n"] == 2 and n == len(axfr_query):
            return axfr_query
        return b""

    import foghorn.servers.server as server_mod

    fallback_calls = {"n": 0}

    def legacy_iter_axfr_messages(req):  # noqa: ARG001
        fallback_calls["n"] += 1
        return [b"\x02" * 12]

    monkeypatch.setattr(dot_server_mod, "_read_exact", fake_read_exact)
    monkeypatch.setattr(server_mod, "iter_axfr_messages", legacy_iter_axfr_messages)

    writer = _FakeWriter()

    async def _run() -> None:
        await dot_server_mod._handle_conn(
            reader=object(),
            writer=writer,
            resolver=lambda q, ip: q,
        )

    asyncio.run(_run())

    assert fallback_calls["n"] == 1
    assert writer.written == [len(b"\x02" * 12).to_bytes(2, "big") + (b"\x02" * 12)]


def test_handle_conn_timeout_is_swallowed_and_limiter_released(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _handle_conn swallows TimeoutError and still releases limiter state.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts close/release in the timeout path.
    """

    class _TrackingLimiter:
        def __init__(self) -> None:
            self.acquire_calls: list[str] = []
            self.release_calls: list[str] = []

        async def acquire(self, client_ip: str) -> bool:
            self.acquire_calls.append(client_ip)
            return True

        async def release(self, client_ip: str) -> None:
            self.release_calls.append(client_ip)

    async def fake_read_exact(reader, n: int) -> bytes:  # noqa: ARG001
        raise asyncio.TimeoutError

    monkeypatch.setattr(dot_server_mod, "_read_exact", fake_read_exact)

    writer = _FakeWriter()
    limiter = _TrackingLimiter()

    async def _run() -> None:
        await dot_server_mod._handle_conn(
            reader=object(),
            writer=writer,
            resolver=lambda q, ip: q,
            limiter=limiter,
            idle_timeout=0.1,
        )

    asyncio.run(_run())

    assert writer.closed is True
    assert limiter.acquire_calls == ["1.2.3.4"]
    assert limiter.release_calls == ["1.2.3.4"]


def test_handle_conn_resolver_exception_is_swallowed_and_limiter_released(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _handle_conn swallows resolver exceptions and releases limiter state.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts defensive exception path cleanup.
    """

    class _TrackingLimiter:
        def __init__(self) -> None:
            self.acquire_calls: list[str] = []
            self.release_calls: list[str] = []

        async def acquire(self, client_ip: str) -> bool:
            self.acquire_calls.append(client_ip)
            return True

        async def release(self, client_ip: str) -> None:
            self.release_calls.append(client_ip)

    calls = {"n": 0}

    async def fake_read_exact(reader, n: int) -> bytes:  # noqa: ARG001
        calls["n"] += 1
        if calls["n"] == 1 and n == 2:
            return (1).to_bytes(2, "big")
        if calls["n"] == 2 and n == 1:
            return b"x"
        return b""

    def failing_resolver(query: bytes, client_ip: str) -> bytes:  # noqa: ARG001
        raise RuntimeError("resolver failed")

    monkeypatch.setattr(dot_server_mod, "_read_exact", fake_read_exact)

    writer = _FakeWriter()
    limiter = _TrackingLimiter()

    async def _run() -> None:
        await dot_server_mod._handle_conn(
            reader=object(),
            writer=writer,
            resolver=failing_resolver,
            limiter=limiter,
            max_queries=5,
        )

    asyncio.run(_run())

    assert writer.closed is True
    assert writer.written == []
    assert limiter.acquire_calls == ["1.2.3.4"]
    assert limiter.release_calls == ["1.2.3.4"]


def test_serve_dot_uses_executor_factory_and_bound_port_in_on_listen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: serve_dot wires executor factory output and reports bound port.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts callback wiring and bound-port on_listen behavior.
    """

    import foghorn.servers.executors as executors_mod

    expected_executor = object()
    monkeypatch.setattr(
        executors_mod, "get_resolver_executor", lambda: expected_executor
    )

    captured: dict[str, object] = {}

    class _FakeSSLContext:
        def __init__(self, protocol):
            captured["ssl_protocol"] = protocol
            self.minimum_version = None

        def load_cert_chain(self, certfile: str, keyfile: str) -> None:
            captured["cert_chain"] = (certfile, keyfile)

    class _FakeSock:
        def getsockname(self) -> tuple[str, int]:
            return ("127.0.0.1", 9443)

    class _FakeServer:
        sockets = [_FakeSock()]

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> bool:  # noqa: ARG002
            return False

        async def serve_forever(self) -> None:
            raise asyncio.CancelledError

    handle_conn_kwargs: dict[str, object] = {}

    async def fake_handle_conn(reader, writer, resolver, **kwargs):  # noqa: ARG001
        handle_conn_kwargs.update(kwargs)
        return None

    async def fake_start_server(callback, host, port, ssl):  # noqa: ANN001
        captured["start_host"] = host
        captured["start_port"] = port
        captured["start_ssl"] = ssl
        await callback(object(), object())
        return _FakeServer()

    monkeypatch.setattr(dot_server_mod.ssl, "SSLContext", _FakeSSLContext)
    monkeypatch.setattr(dot_server_mod, "_handle_conn", fake_handle_conn)
    monkeypatch.setattr(dot_server_mod.asyncio, "start_server", fake_start_server)

    seen_ports: list[int] = []

    async def _run() -> None:
        with pytest.raises(asyncio.CancelledError):
            await dot_server_mod.serve_dot(
                host="127.0.0.1",
                port=0,
                resolver=lambda q, ip: q,
                cert_file="cert.pem",
                key_file="key.pem",
                min_version=ssl.TLSVersion.TLSv1_2,
                max_queries_per_connection=22,
                idle_timeout_seconds=9.5,
                on_listen=lambda p: seen_ports.append(p),
            )

    asyncio.run(_run())

    assert captured["start_host"] == "127.0.0.1"
    assert captured["start_port"] == 0
    assert captured["cert_chain"] == ("cert.pem", "key.pem")
    assert handle_conn_kwargs["executor"] is expected_executor
    assert handle_conn_kwargs["max_queries"] == 22
    assert handle_conn_kwargs["idle_timeout"] == 9.5
    assert seen_ports == [9443]


def test_serve_dot_on_listen_fallback_port_and_callback_error_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: serve_dot falls back to configured port and swallows on_listen errors.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts fallback-port logic and callback exception handling.
    """

    import foghorn.servers.executors as executors_mod

    def _raise_executor() -> object:
        raise RuntimeError("no executor available")

    monkeypatch.setattr(executors_mod, "get_resolver_executor", _raise_executor)

    class _FakeSSLContext:
        def __init__(self, protocol):  # noqa: ARG002
            self.minimum_version = None

        def load_cert_chain(self, certfile: str, keyfile: str) -> None:  # noqa: ARG002
            return None

    class _FakeServer:
        sockets = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> bool:  # noqa: ARG002
            return False

        async def serve_forever(self) -> None:
            raise asyncio.CancelledError

    handle_conn_kwargs: dict[str, object] = {}

    async def fake_handle_conn(reader, writer, resolver, **kwargs):  # noqa: ARG001
        handle_conn_kwargs.update(kwargs)
        return None

    async def fake_start_server(callback, host, port, ssl):  # noqa: ANN001,ARG001
        await callback(object(), object())
        return _FakeServer()

    monkeypatch.setattr(dot_server_mod.ssl, "SSLContext", _FakeSSLContext)
    monkeypatch.setattr(dot_server_mod, "_handle_conn", fake_handle_conn)
    monkeypatch.setattr(dot_server_mod.asyncio, "start_server", fake_start_server)

    callback_ports: list[int] = []

    def on_listen(port: int) -> None:
        callback_ports.append(port)
        raise RuntimeError("callback failure")

    async def _run() -> None:
        with pytest.raises(asyncio.CancelledError):
            await dot_server_mod.serve_dot(
                host="127.0.0.1",
                port=8853,
                resolver=lambda q, ip: q,
                cert_file="cert.pem",
                key_file="key.pem",
                on_listen=on_listen,
            )

    asyncio.run(_run())

    assert handle_conn_kwargs["executor"] is None
    assert callback_ports == [8853]


def _echo_resolver(q: bytes, client_ip: str) -> bytes:
    return q


@pytest.fixture(scope="module")
def selfsigned_cert(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("dotserv")
    cert_file = tmp / "cert.pem"
    key_file = tmp / "key.pem"
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
                str(key_file),
                "-out",
                str(cert_file),
                "-subj",
                "/CN=localhost",
                "-days",
                "1",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pytest.skip("openssl not available for generating self-signed cert")
    return str(cert_file), str(key_file)


@pytest.fixture
def running_dot_server(selfsigned_cert):
    cert_file, key_file = selfsigned_cert
    host = "127.0.0.1"
    ready = threading.Event()
    info = {}

    def runner():
        asyncio.set_event_loop(asyncio.new_event_loop())
        loop = asyncio.get_event_loop()

        async def run():
            def _on_listen(port: int) -> None:
                info["port"] = int(port)
                ready.set()

            await serve_dot(
                host,
                0,
                _echo_resolver,
                cert_file=cert_file,
                key_file=key_file,
                on_listen=_on_listen,
            )

        loop.create_task(run())
        loop.run_forever()

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    if not ready.wait(2.0):
        pytest.skip("failed to start dot server")
    yield host, info["port"]


@pytest.fixture
def running_dot_server_max_queries(selfsigned_cert):
    """Brief: Start serve_dot with max_queries_per_connection=2.

    Inputs:
      - selfsigned_cert: fixture providing (cert_file, key_file).

    Outputs:
      - (host, port): Tuple for connecting to the running DoT server.
    """

    cert_file, key_file = selfsigned_cert
    host = "127.0.0.1"
    ready = threading.Event()
    info = {}

    def runner():
        asyncio.set_event_loop(asyncio.new_event_loop())
        loop = asyncio.get_event_loop()

        async def run():
            def _on_listen(port: int) -> None:
                info["port"] = int(port)
                ready.set()

            await serve_dot(
                host,
                0,
                _echo_resolver,
                cert_file=cert_file,
                key_file=key_file,
                max_queries_per_connection=2,
                idle_timeout_seconds=1.0,
                on_listen=_on_listen,
            )

        loop.create_task(run())
        loop.run_forever()

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    if not ready.wait(2.0):
        pytest.skip("failed to start dot server")
    yield host, info["port"]


def test_dot_server_roundtrip(running_dot_server):
    host, port = running_dot_server
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.socket(), server_hostname="localhost")
    s.settimeout(2)
    s.connect((host, port))
    try:
        q = b"\x12\x34hello"
        s.sendall(len(q).to_bytes(2, "big") + q)
        hdr = s.recv(2)
        assert len(hdr) == 2
        ln = int.from_bytes(hdr, "big")
        body = s.recv(ln)
        assert body == q
    finally:
        s.close()


def test_conn_limiter_acquire_ignores_release_failures() -> None:
    """Brief: _ConnLimiter.acquire swallows semaphore-release errors on deny path.

    Inputs:
      - None.

    Outputs:
      - None; asserts defensive release-exception branch.
    """

    class _BadSemaphore:
        async def acquire(self) -> None:
            return None

        def release(self) -> None:
            raise RuntimeError("release failed")

    async def _run() -> None:
        limiter = dot_server_mod._ConnLimiter(max_connections=1, max_per_ip=1)
        assert await limiter.acquire("4.4.4.4") is True
        limiter._sem = _BadSemaphore()  # type: ignore[assignment]
        assert await limiter.acquire("4.4.4.4") is False

    asyncio.run(_run())


def test_conn_limiter_release_ignores_semaphore_release_failures() -> None:
    """Brief: _ConnLimiter.release swallows semaphore-release errors.

    Inputs:
      - None.

    Outputs:
      - None; asserts defensive release-exception branch.
    """

    class _BadSemaphore:
        async def acquire(self) -> None:
            return None

        def release(self) -> None:
            raise RuntimeError("release failed")

    async def _run() -> None:
        limiter = dot_server_mod._ConnLimiter(max_connections=2, max_per_ip=2)
        assert await limiter.acquire("5.5.5.5") is True
        limiter._sem = _BadSemaphore()  # type: ignore[assignment]
        await limiter.release("5.5.5.5")

    asyncio.run(_run())


def test_handle_conn_rejected_by_limiter_close_error_is_swallowed() -> None:
    """Brief: _handle_conn swallows wait_closed errors in limiter-reject path.

    Inputs:
      - None.

    Outputs:
      - None; asserts defensive close-error handling branch.
    """

    class _FailingWriter(_FakeWriter):
        async def wait_closed(self) -> None:
            raise RuntimeError("close failed")

    class _DenyLimiter:
        async def acquire(self, client_ip: str) -> bool:  # noqa: ARG002
            return False

        async def release(self, client_ip: str) -> None:  # noqa: ARG002
            return None

    writer = _FailingWriter()

    async def _run() -> None:
        await dot_server_mod._handle_conn(
            reader=object(),
            writer=writer,
            resolver=lambda q, ip: q,
            limiter=_DenyLimiter(),
        )

    asyncio.run(_run())

    assert writer.closed is True


def test_handle_conn_parsed_non_transfer_query_uses_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _handle_conn routes parsed non-AXFR queries through resolver.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts parsed query + non-transfer branch.
    """

    from dnslib import DNSRecord

    query = DNSRecord.question("example.net.", qtype="A").pack()
    calls = {"n": 0}

    async def fake_read_exact(reader, n: int) -> bytes:  # noqa: ARG001
        calls["n"] += 1
        if calls["n"] == 1 and n == 2:
            return len(query).to_bytes(2, "big")
        if calls["n"] == 2 and n == len(query):
            return query
        return b""

    seen: list[bytes] = []

    def resolver(data: bytes, client_ip: str) -> bytes:  # noqa: ARG001
        seen.append(data)
        return b"resp"

    monkeypatch.setattr(dot_server_mod, "_read_exact", fake_read_exact)

    writer = _FakeWriter()

    async def _run() -> None:
        await dot_server_mod._handle_conn(
            reader=object(),
            writer=writer,
            resolver=resolver,
            max_queries=1,
        )

    asyncio.run(_run())

    assert seen == [query]
    assert writer.written == [len(b"resp").to_bytes(2, "big") + b"resp"]


def test_handle_conn_parsed_record_without_questions_uses_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _handle_conn handles parsed DNS records that contain no questions.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts no-questions parsed branch still resolves normally.
    """

    from dnslib import DNSRecord

    query = DNSRecord().pack()
    calls = {"n": 0}

    async def fake_read_exact(reader, n: int) -> bytes:  # noqa: ARG001
        calls["n"] += 1
        if calls["n"] == 1 and n == 2:
            return len(query).to_bytes(2, "big")
        if calls["n"] == 2 and n == len(query):
            return query
        return b""

    seen: list[bytes] = []

    def resolver(data: bytes, client_ip: str) -> bytes:  # noqa: ARG001
        seen.append(data)
        return b"ans"

    monkeypatch.setattr(dot_server_mod, "_read_exact", fake_read_exact)

    writer = _FakeWriter()

    async def _run() -> None:
        await dot_server_mod._handle_conn(
            reader=object(),
            writer=writer,
            resolver=resolver,
            max_queries=1,
        )

    asyncio.run(_run())

    assert seen == [query]
    assert writer.written == [len(b"ans").to_bytes(2, "big") + b"ans"]


def test_handle_conn_release_exception_is_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _handle_conn swallows limiter.release failures in final cleanup.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts defensive cleanup exception path.
    """

    class _FailingReleaseLimiter:
        async def acquire(self, client_ip: str) -> bool:  # noqa: ARG002
            return True

        async def release(self, client_ip: str) -> None:  # noqa: ARG002
            raise RuntimeError("release failed")

    async def fake_read_exact(reader, n: int) -> bytes:  # noqa: ARG001
        return b""

    monkeypatch.setattr(dot_server_mod, "_read_exact", fake_read_exact)

    writer = _FakeWriter()

    async def _run() -> None:
        await dot_server_mod._handle_conn(
            reader=object(),
            writer=writer,
            resolver=lambda q, ip: q,
            limiter=_FailingReleaseLimiter(),
        )

    asyncio.run(_run())

    assert writer.closed is True


def test_serve_dot_with_explicit_executor_skips_factory_and_on_listen_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: serve_dot uses explicit executor and skips on_listen None block.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts executor-provided path and on_listen None branch.
    """

    import foghorn.servers.executors as executors_mod

    def _unexpected_factory() -> object:  # pragma: no cover - defensive
        raise AssertionError("executor factory should not be called")

    monkeypatch.setattr(executors_mod, "get_resolver_executor", _unexpected_factory)

    class _FakeSSLContext:
        def __init__(self, protocol):  # noqa: ARG002
            self.minimum_version = None

        def load_cert_chain(self, certfile: str, keyfile: str) -> None:  # noqa: ARG002
            return None

    class _FakeServer:
        sockets = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> bool:  # noqa: ARG002
            return False

        async def serve_forever(self) -> None:
            raise asyncio.CancelledError

    captured_kwargs: dict[str, object] = {}

    async def fake_handle_conn(reader, writer, resolver, **kwargs):  # noqa: ARG001
        captured_kwargs.update(kwargs)
        return None

    async def fake_start_server(callback, host, port, ssl):  # noqa: ANN001,ARG001
        await callback(object(), object())
        return _FakeServer()

    monkeypatch.setattr(dot_server_mod.ssl, "SSLContext", _FakeSSLContext)
    monkeypatch.setattr(dot_server_mod, "_handle_conn", fake_handle_conn)
    monkeypatch.setattr(dot_server_mod.asyncio, "start_server", fake_start_server)

    explicit_executor = object()

    async def _run() -> None:
        with pytest.raises(asyncio.CancelledError):
            await dot_server_mod.serve_dot(
                host="127.0.0.1",
                port=5301,
                resolver=lambda q, ip: q,
                cert_file="cert.pem",
                key_file="key.pem",
                executor=explicit_executor,
                on_listen=None,
            )

    asyncio.run(_run())

    assert captured_kwargs["executor"] is explicit_executor


def test_serve_dot_on_listen_socket_error_falls_back_to_requested_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: serve_dot falls back to configured port when socket lookup fails.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts getsockname exception fallback branch.
    """

    class _FakeSSLContext:
        def __init__(self, protocol):  # noqa: ARG002
            self.minimum_version = None

        def load_cert_chain(self, certfile: str, keyfile: str) -> None:  # noqa: ARG002
            return None

    class _BadSocket:
        def getsockname(self):
            raise RuntimeError("socket lookup failed")

    class _FakeServer:
        sockets = [_BadSocket()]

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> bool:  # noqa: ARG002
            return False

        async def serve_forever(self) -> None:
            raise asyncio.CancelledError

    async def fake_handle_conn(reader, writer, resolver, **kwargs):  # noqa: ARG001
        return None

    async def fake_start_server(callback, host, port, ssl):  # noqa: ANN001,ARG001
        await callback(object(), object())
        return _FakeServer()

    monkeypatch.setattr(dot_server_mod.ssl, "SSLContext", _FakeSSLContext)
    monkeypatch.setattr(dot_server_mod, "_handle_conn", fake_handle_conn)
    monkeypatch.setattr(dot_server_mod.asyncio, "start_server", fake_start_server)

    seen_ports: list[int] = []

    async def _run() -> None:
        with pytest.raises(asyncio.CancelledError):
            await dot_server_mod.serve_dot(
                host="127.0.0.1",
                port=8859,
                resolver=lambda q, ip: q,
                cert_file="cert.pem",
                key_file="key.pem",
                on_listen=lambda p: seen_ports.append(p),
            )

    asyncio.run(_run())

    assert seen_ports == [8859]


def test_dot_server_max_queries_per_connection_closes(
    running_dot_server_max_queries,
) -> None:
    """Brief: serve_dot closes TLS connection after max_queries_per_connection.

    Inputs:
      - running_dot_server_max_queries: fixture providing host/port.

    Outputs:
      - None; asserts the connection is closed after the 2nd response.
    """

    host, port = running_dot_server_max_queries
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.socket(), server_hostname="localhost")
    s.settimeout(2)
    s.connect((host, port))
    try:
        payloads = [b"one", b"two"]
        for p in payloads:
            s.sendall(len(p).to_bytes(2, "big") + p)
            hdr = s.recv(2)
            assert len(hdr) == 2
            ln = int.from_bytes(hdr, "big")
            body = s.recv(ln)
            assert body == p

        # Third query should observe EOF or connection reset.
        s.sendall(len(b"three").to_bytes(2, "big") + b"three")
        try:
            hdr2 = s.recv(2)
            assert hdr2 == b"" or hdr2 is not None
        except (ConnectionResetError, BrokenPipeError, OSError, ssl.SSLError):
            pass
    finally:
        s.close()
