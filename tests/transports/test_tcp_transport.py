"""
Brief: Unit tests for TCP upstream transport using a local threaded TCP stub.

Inputs:
  - None

Outputs:
  - None
"""

import socket
import threading
import time

import pytest

from foghorn.transports.tcp import tcp_query


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


class _TCPStub:
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
            try:
                hdr = _recv_exact(conn, 2)
                if len(hdr) != 2:
                    return
                ln = int.from_bytes(hdr, "big")
                body = _recv_exact(conn, ln)
                if len(body) != ln:
                    return
                conn.sendall(ln.to_bytes(2, "big") + body)
            except Exception:
                return

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass


@pytest.fixture(scope="module")
def tcp_stub():
    s = _TCPStub()
    s.start()
    try:
        yield s
    finally:
        s.close()


def test_tcp_query_roundtrip(tcp_stub):
    q = b"\x12\x34hello"
    resp = tcp_query(
        tcp_stub.addr[0],
        tcp_stub.addr[1],
        q,
        connect_timeout_ms=500,
        read_timeout_ms=500,
    )
    assert resp == q
