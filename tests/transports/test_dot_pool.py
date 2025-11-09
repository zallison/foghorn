"""
Brief: Tests for DoT connection pool get_dot_pool and send path.

Inputs:
  - None

Outputs:
  - None
"""

import socket
import ssl
import subprocess
import threading
import time

import pytest

from foghorn.transports.dot import get_dot_pool


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


class _TLSEcho:
    def __init__(self, cert_file: str, key_file: str):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.addr = self.sock.getsockname()
        self._stop = False
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self.thread.start()
        time.sleep(0.05)

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
        try:
            with self.ctx.wrap_socket(conn, server_side=True) as s:
                hdr = _recv_exact(s, 2)
                if len(hdr) != 2:
                    return
                ln = int.from_bytes(hdr, "big")
                body = _recv_exact(s, ln)
                if len(body) != ln:
                    return
                s.sendall(hdr + body)
        except Exception:  # pragma: no cover
            pass  # pragma: no cover

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:  # pragma: no cover
            pass  # pragma: no cover


@pytest.fixture(scope="module")
def selfsigned(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("dotpool")
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
        pytest.skip("openssl not available")
    return str(cert), str(key)


@pytest.fixture(scope="module")
def dot_echo(selfsigned):
    cert, key = selfsigned
    s = _TLSEcho(cert, key)
    s.start()
    try:
        yield s
    finally:
        s.close()


def test_dot_pool_send(dot_echo):
    host, port = dot_echo.addr
    pool = get_dot_pool(host, port, server_name=None, verify=False, ca_file=None)
    pool.set_limits(max_connections=2, idle_timeout_s=5)

    q = b"\x12\x34hello"
    r = pool.send(q, 500, 500)
    assert r == q
