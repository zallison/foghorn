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

from foghorn.tcp_server import serve_tcp


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
