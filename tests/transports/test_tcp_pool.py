"""
Brief: Tests for TCPConnectionPool and get_tcp_pool.

Inputs:
  - None

Outputs:
  - None
"""

import socket
import threading
import time

import pytest

from foghorn.transports.tcp import get_tcp_pool


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


class _TCPEcho:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
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
                conn, _ = self.sock.accept()
            except Exception:
                continue
            t = threading.Thread(target=self._conn, args=(conn,), daemon=True)
            t.start()

    def _conn(self, conn: socket.socket):
        with conn:
            while True:
                hdr = _recv_exact(conn, 2)
                if len(hdr) != 2:
                    return
                ln = int.from_bytes(hdr, "big")
                body = _recv_exact(conn, ln)
                if len(body) != ln:
                    return
                conn.sendall(hdr + body)

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:  # pragma: no cover
            pass  # pragma: no cover


@pytest.fixture(scope="module")
def tcp_echo():
    s = _TCPEcho()
    s.start()
    try:
        yield s
    finally:
        s.close()


def test_tcp_pool_reuse_and_getter(tcp_echo):
    host, port = tcp_echo.addr
    pool = get_tcp_pool(host, port)
    pool.set_limits(max_connections=2, idle_timeout_s=5)

    q = b"\x12\x34hello"
    r1 = pool.send(q, 500, 500)
    r2 = pool.send(q, 500, 500)
    assert r1 == q and r2 == q

    # Same instance returned by get_tcp_pool
    assert get_tcp_pool(host, port) is pool
