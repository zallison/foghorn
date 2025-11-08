"""
Brief: Unit tests for DoT (DNS-over-TLS) upstream transport using a local TLS TCP stub.

Inputs:
  - None

Outputs:
  - None
"""

import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time

import pytest

from foghorn.transports.dot import dot_query


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
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
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
            with self._ctx.wrap_socket(conn, server_side=True) as s:
                hdr = _recv_exact(s, 2)
                if len(hdr) != 2:
                    return
                ln = int.from_bytes(hdr, "big")
                body = _recv_exact(s, ln)
                if len(body) != ln:
                    return
                s.sendall(ln.to_bytes(2, "big") + body)
        except Exception:
            pass

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass


@pytest.fixture(scope="module")
def selfsigned_cert(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("dotcert")
    cert_file = tmp / "cert.pem"
    key_file = tmp / "key.pem"
    # Generate a short-lived self-signed cert via openssl if available
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


@pytest.fixture(scope="module")
def dot_stub(selfsigned_cert):
    cert_file, key_file = selfsigned_cert
    srv = _TLSEcho(cert_file, key_file)
    srv.start()
    try:
        yield srv
    finally:
        srv.close()


def test_dot_query_roundtrip(dot_stub):
    q = b"\x12\x34hello"
    resp = dot_query(
        dot_stub.addr[0],
        dot_stub.addr[1],
        q,
        server_name=None,
        verify=False,
        connect_timeout_ms=800,
        read_timeout_ms=800,
    )
    assert resp == q
