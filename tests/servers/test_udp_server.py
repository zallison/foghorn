"""
Brief: Unit tests for downstream UDP server wrapper.

Inputs:
  - None

Outputs:
  - None
"""

import socket
import threading
import time

import pytest

from foghorn.udp_server import serve_udp


def _echo_resolver(q: bytes, client_ip: str) -> bytes:
    return q


@pytest.fixture
def running_udp_server():
    host = "127.0.0.1"
    port = 0
    ready = threading.Event()
    actual = {}

    def runner():
        # Bind ephemeral socket to discover a free port, then run server on it
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host, 0))
        actual_port = s.getsockname()[1]
        s.close()
        actual["port"] = actual_port
        ready.set()
        serve_udp(host, actual_port, _echo_resolver)

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    if not ready.wait(1.0):
        pytest.skip("failed to start udp server")
    yield host, actual["port"]
    # daemon thread exits on process end


def test_udp_server_roundtrip(running_udp_server):
    host, port = running_udp_server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        q = b"\x12\x34hello"
        sock.settimeout(1)
        sock.sendto(q, (host, port))
        data, _ = sock.recvfrom(4096)
        assert data == q
    finally:
        sock.close()
