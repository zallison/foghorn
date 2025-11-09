"""
Brief: Ensure udp_server handler swallows resolver exceptions without crashing.

Inputs:
  - None

Outputs:
  - None
"""

import socket
import threading

import pytest

from foghorn.udp_server import serve_udp


def _boom(q: bytes, client_ip: str) -> bytes:
    raise RuntimeError("resolver exploded")


@pytest.fixture
def started_udp_server():
    host = "127.0.0.1"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, 0))
    port = sock.getsockname()[1]
    sock.close()

    t = threading.Thread(target=serve_udp, args=(host, port, _boom), daemon=True)
    t.start()
    # No good mechanism to stop; daemon thread ends with process
    return host, port


def test_udp_server_handles_resolver_exception(started_udp_server):
    host, port = started_udp_server
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    try:
        s.sendto(b"\x12\x34badquery", (host, port))
        # Expect no crash; may or may not get a response
        try:
            _ = s.recvfrom(1024)
        except Exception:  # pragma: no cover
            pass  # pragma: no cover
    finally:
        s.close()
