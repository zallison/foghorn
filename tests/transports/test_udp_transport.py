"""
Brief: Unit tests for UDP upstream transport using a local UDP stub server.

Inputs:
  - None

Outputs:
  - None
"""

import socket
import threading
import time

import pytest

from foghorn.transports.udp import udp_query


class _UDPStub:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.addr = self.sock.getsockname()
        self._stop = False
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self.thread.start()
        time.sleep(0.02)

    def _loop(self):
        while not self._stop:
            try:
                self.sock.settimeout(0.2)
                data, peer = self.sock.recvfrom(4096)
            except Exception:
                continue
            # Echo back
            try:
                self.sock.sendto(data, peer)
            except Exception:
                pass

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass


@pytest.fixture(scope="module")
def udp_stub():
    s = _UDPStub()
    s.start()
    try:
        yield s
    finally:
        s.close()


def test_udp_query_roundtrip(udp_stub):
    q = b"\x12\x34hello"
    resp = udp_query(udp_stub.addr[0], udp_stub.addr[1], q, timeout_ms=500)
    assert resp == q
