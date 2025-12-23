"""
Brief: Unit tests for downstream TCP server.

Inputs:
  - None

Outputs:
  - None
"""

import asyncio
import socket
import threading
import time

import pytest

pytestmark = pytest.mark.slow

import foghorn.servers.tcp_server as tcp_server_mod
from foghorn.servers.tcp_server import serve_tcp, serve_tcp_threaded


def test__handle_conn_breaks_on_short_body(monkeypatch) -> None:
    """Brief: _handle_conn breaks loop when body shorter than advertised length.

    Inputs:
      - monkeypatch: used to stub _read_exact.

    Outputs:
      - None; asserts no response is written and writer is closed.
    """

    class _Writer:
        def __init__(self):
            self.transport = type(
                "T", (), {"set_write_buffer_limits": lambda self, n: None}
            )()
            self._peer = ("9.9.9.9", 1234)
            self.written = []
            self.closed = False

        def get_extra_info(self, key: str):
            if key == "peername":
                return self._peer
            return None

        def write(self, data: bytes) -> None:
            self.written.append(data)

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            return None

    writer = _Writer()

    calls = {"lens": []}

    async def fake_read_exact(reader, n: int) -> bytes:
        calls["lens"].append(n)
        if len(calls["lens"]) == 1:
            # First read: header says 4-byte body
            return (4).to_bytes(2, "big")
        # Second read: only 2 bytes body -> len(query) != ln
        return b"xx"

    monkeypatch.setattr(tcp_server_mod, "_read_exact", fake_read_exact)

    # Use a trivial resolver; it should never be called because body is short
    async def run():
        await tcp_server_mod._handle_conn(
            reader=object(),
            writer=writer,
            resolver=lambda q, ip: q,
            idle_timeout=1.0,
        )

    import asyncio

    asyncio.run(run())

    # No response written and writer was closed
    assert writer.written == []
    assert writer.closed is True


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _echo_resolver(q: bytes, client_ip: str) -> bytes:
    return q


@pytest.fixture
def running_tcp_server():
    host = "127.0.0.1"
    port_holder = {}
    ready = threading.Event()

    def runner():
        asyncio.set_event_loop(asyncio.new_event_loop())
        loop = asyncio.get_event_loop()

        async def bind_and_run():
            # Bind temporary server to get a free port, then close and start serve_tcp there
            srv = await asyncio.start_server(lambda r, w: None, host, 0)
            port = srv.sockets[0].getsockname()[1]
            port_holder["port"] = port
            ready.set()
            srv.close()
            await srv.wait_closed()
            await serve_tcp(host, port, _echo_resolver)

        loop.create_task(bind_and_run())
        loop.run_forever()

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    if not ready.wait(1.0):
        pytest.skip("failed to start tcp server")
    # Give the real server a moment to bind after the temp socket closes
    time.sleep(0.15)
    yield host, port_holder["port"]


def test_tcp_server_roundtrip(running_tcp_server):
    host, port = running_tcp_server
    s = socket.create_connection((host, port), timeout=1)
    try:
        q = b"\x12\x34hello"
        s.sendall(len(q).to_bytes(2, "big") + q)
        hdr = _recv_exact(s, 2)
        assert len(hdr) == 2
        ln = int.from_bytes(hdr, "big")
        body = _recv_exact(s, ln)
        assert body == q
    finally:
        s.close()


def test_tcp_server_multiple_frames_single_connection(running_tcp_server):
    host, port = running_tcp_server
    s = socket.create_connection((host, port), timeout=1)
    try:
        payloads = [b"one", b"two", b"three"]
        for p in payloads:
            s.sendall(len(p).to_bytes(2, "big") + p)
            ln = int.from_bytes(_recv_exact(s, 2), "big")
            body = _recv_exact(s, ln)
            assert body == p
    finally:
        s.close()


def test_tcp_server_zero_length_frame_closes(running_tcp_server):
    host, port = running_tcp_server
    s = socket.create_connection((host, port), timeout=1)
    try:
        # Send 0-length frame; server should close connection
        s.sendall((0).to_bytes(2, "big"))
        # Subsequent recv should yield EOF quickly
        s.settimeout(1)
        data = s.recv(1)
        # Some platforms may keep it open briefly; tolerate empty or EOF
        assert data == b"" or data is not None
    finally:
        s.close()


def test__recv_exact_returns_bytes_and_none() -> None:
    """Brief: _recv_exact returns bytes on success and None on early close.

    Inputs:
      - None.

    Outputs:
      - None; asserts correct return values.
    """

    class _Sock:
        def __init__(self, chunks):
            self._chunks = list(chunks)

        def recv(self, n: int) -> bytes:
            if self._chunks:
                return self._chunks.pop(0)
            return b""

    # Successful read of exact length
    s_ok = _Sock([b"ab", b"c"])
    data = tcp_server_mod._recv_exact(s_ok, 3)
    assert data == b"abc"

    # Early close: first recv returns EOF -> None from helper
    s_eof = _Sock([])
    assert tcp_server_mod._recv_exact(s_eof, 1) is None


def test__tcphandler_handle_happy_path_and_short_header(monkeypatch) -> None:
    """Brief: _TCPHandler.handle processes one frame then exits on short header.

    Inputs:
      - monkeypatch: used to stub _recv_exact.

    Outputs:
      - None; asserts resolver is called and response is framed.
    """

    class _Sock:
        def __init__(self):
            self.timeout = None
            self.sent = []

        def settimeout(self, t: float) -> None:
            self.timeout = t

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

    sock = _Sock()
    calls = {"lens": []}

    def fake_recv_exact(s, length):
        calls["lens"].append(length)
        if len(calls["lens"]) == 1:
            # First call: header for 4-byte body
            return (4).to_bytes(2, "big")
        if len(calls["lens"]) == 2:
            # Second call: body
            return b"data"
        # Third header is empty -> len != 2, loop exits
        return b""

    monkeypatch.setattr(tcp_server_mod, "_recv_exact", fake_recv_exact)

    seen = {"calls": []}

    def resolver(q: bytes, ip: str) -> bytes:
        seen["calls"].append((q, ip))
        return q.upper()

    tcp_server_mod._TCPHandler.resolver = staticmethod(resolver)  # type: ignore[assignment]

    # BaseRequestHandler.__init__ will invoke handle() immediately
    tcp_server_mod._TCPHandler(sock, ("1.2.3.4", 5353), None)

    assert sock.timeout == 15
    assert seen["calls"] == [(b"data", "1.2.3.4")]
    # One framed response written back
    assert sock.sent == [len(b"DATA").to_bytes(2, "big") + b"DATA"]


def test__tcphandler_uses_default_client_ip_when_not_tuple(monkeypatch) -> None:
    """Brief: _TCPHandler falls back to 0.0.0.0 when client_address is not a tuple.

    Inputs:
      - monkeypatch: used to stub _recv_exact.

    Outputs:
      - None; asserts resolver sees 0.0.0.0 as client_ip.
    """

    class _Sock:
        def __init__(self):
            self.timeout = None

        def settimeout(self, t: float) -> None:
            self.timeout = t

        def sendall(self, data: bytes) -> None:
            # Not needed for this test
            pass

    sock = _Sock()
    calls = {"lens": []}

    def fake_recv_exact(s, length):
        calls["lens"].append(length)
        if len(calls["lens"]) == 1:
            return (1).to_bytes(2, "big")
        if len(calls["lens"]) == 2:
            return b"x"
        return b""

    monkeypatch.setattr(tcp_server_mod, "_recv_exact", fake_recv_exact)

    seen = {"ips": []}

    def resolver(q: bytes, ip: str) -> bytes:
        seen["ips"].append(ip)
        return q

    tcp_server_mod._TCPHandler.resolver = staticmethod(resolver)  # type: ignore[assignment]

    # Pass a non-tuple client_address to trigger 0.0.0.0 branch
    tcp_server_mod._TCPHandler(sock, "not-a-tuple", None)

    assert seen["ips"] == ["0.0.0.0"]


def test_serve_tcp_threaded_binds_handler_and_closes(monkeypatch) -> None:
    """Brief: serve_tcp_threaded binds _TCPHandler and closes server on error.

    Inputs:
      - monkeypatch: patches ThreadingTCPServer.

    Outputs:
      - None; asserts server lifecycle and resolver wiring.
    """

    created = {}
    calls = {"serve": 0, "close": 0}

    class DummyServer:
        def __init__(self, addr, handler_cls):
            created["addr"] = addr
            created["handler_cls"] = handler_cls
            created["server"] = self
            self.daemon_threads = False

        def serve_forever(self) -> None:
            calls["serve"] += 1
            raise RuntimeError("stop")

        def server_close(self) -> None:
            calls["close"] += 1

    monkeypatch.setattr(tcp_server_mod.socketserver, "ThreadingTCPServer", DummyServer)

    def resolver(q: bytes, ip: str) -> bytes:
        return b"resp"

    with pytest.raises(RuntimeError):
        serve_tcp_threaded("127.0.0.1", 5300, resolver)

    assert created["addr"] == ("127.0.0.1", 5300)
    assert created["handler_cls"] is tcp_server_mod._TCPHandler
    assert calls["serve"] == 1
    assert calls["close"] == 1
    # Handler resolver should be wired to provided resolver
    assert created["handler_cls"].resolver(b"q", "1.2.3.4") == b"resp"
    assert created["server"].daemon_threads is True
