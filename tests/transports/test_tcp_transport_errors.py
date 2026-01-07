"""
Brief: Negative-path tests for TCP transport.

Inputs:
  - None

Outputs:
  - None
"""

import socket
import threading
import time

import pytest

from foghorn.servers.transports.tcp import TCPError, tcp_query


class _ShortReadServer:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.addr = self.sock.getsockname()
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self.thread.start()
        time.sleep(0.02)

    def _loop(self):
        try:
            self.sock.settimeout(1)
            conn, _ = self.sock.accept()
            with conn:
                # Read only 1 byte of the len header and close to force short read
                _ = conn.recv(1)
                # Close without sending anything
        except Exception:  # pragma: no cover
            pass  # pragma: no cover

    def close(self):
        try:
            self.sock.close()
        except Exception:  # pragma: no cover
            pass  # pragma: no cover


@pytest.fixture(scope="module")
def short_read_server():
    s = _ShortReadServer()
    s.start()
    try:
        yield s
    finally:
        s.close()


def test_tcp_short_read_raises(short_read_server):
    with pytest.raises(TCPError):
        tcp_query(
            short_read_server.addr[0],
            short_read_server.addr[1],
            b"\x00\x01x",
            connect_timeout_ms=500,
            read_timeout_ms=500,
        )
