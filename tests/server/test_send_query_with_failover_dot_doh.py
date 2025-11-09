"""
Brief: Tests for send_query_with_failover DoT and DoH branches success paths.

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
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from dnslib import DNSRecord

import foghorn.server as srv


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


class _DoHHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        ln = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(ln)
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


@pytest.fixture(scope="module")
def selfsigned(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sendfailover")
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


@pytest.fixture(scope="module")
def doh_server():
    srv = HTTPServer(("127.0.0.1", 0), _DoHHandler)
    host, port = srv.server_address
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)
    try:
        yield f"http://{host}:{port}/dns-query"
    finally:
        srv.shutdown()
        srv.server_close()


def test_failover_dot_branch(dot_echo):
    q = DNSRecord.question("example.com", "A")
    upstreams = [
        {
            "host": dot_echo.addr[0],
            "port": dot_echo.addr[1],
            "transport": "dot",
            "tls": {"verify": False},
        }
    ]
    resp, used, reason = srv.send_query_with_failover(
        q, upstreams, 800, "example.com", 1
    )
    assert resp is not None and reason == "ok"


def test_failover_doh_branch(doh_server):
    q = DNSRecord.question("example.com", "A")
    upstreams = [
        {
            "transport": "doh",
            "url": doh_server,
            "method": "POST",
        }
    ]
    resp, used, reason = srv.send_query_with_failover(
        q, upstreams, 800, "example.com", 1
    )
    assert resp is not None and reason == "ok"
