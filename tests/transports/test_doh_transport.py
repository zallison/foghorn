"""
Brief: Unit tests for DoH upstream transport using a local HTTP server stub.

Inputs:
  - None

Outputs:
  - None
"""

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

from foghorn.transports.doh import doh_query, DoHError


class _StubHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        ln = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(ln)
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        qs = parse_qs(urlparse(self.path).query)
        if "dns" not in qs:
            self.send_response(400)
            self.end_headers()
            return
        import base64

        s = qs["dns"][0]
        pad = "=" * ((4 - len(s) % 4) % 4)
        data = base64.urlsafe_b64decode(s + pad)
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):  # quiet
        return


@pytest.fixture(scope="module")
def stub_server():
    srv = HTTPServer(("127.0.0.1", 0), _StubHandler)
    host, port = srv.server_address

    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    # Give it a moment to bind
    time.sleep(0.05)
    try:
        yield f"http://{host}:{port}/dns-query"
    finally:
        srv.shutdown()
        srv.server_close()


def test_doh_post_roundtrip(stub_server):
    # 12-byte fake DNS header + payload
    query = b"\x12\x34" + b"x" * 10
    body, headers = doh_query(stub_server, query, method="POST", timeout_ms=500)
    assert body == query
    assert headers.get("content-type", "").startswith("application/dns-message")


def test_doh_get_roundtrip(stub_server):
    query = b"\xab\xcd" + b"y" * 8
    body, headers = doh_query(stub_server, query, method="GET", timeout_ms=500)
    assert body == query
