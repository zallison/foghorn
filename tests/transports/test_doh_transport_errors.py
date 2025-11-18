"""
Brief: Negative-path tests for DoH transport.

Inputs:
  - None

Outputs:
  - None
"""

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from foghorn.transports.doh import DoHError, doh_query


class _ErrHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        self.send_response(500)
        self.end_headers()

    def log_message(self, fmt, *args):
        return


@pytest.fixture(scope="module")
def err_server():
    srv = HTTPServer(("127.0.0.1", 0), _ErrHandler)
    h, p = srv.server_address
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)
    try:
        yield f"http://{h}:{p}/dns-query"
    finally:
        srv.shutdown()
        srv.server_close()


def test_doh_http_500_raises(err_server):
    with pytest.raises(DoHError):
        doh_query(err_server, b"\x00\x01x", method="POST", timeout_ms=500)


def test_doh_unsupported_scheme():
    with pytest.raises(DoHError):
        doh_query("ftp://example.com/dns-query", b"\x00\x01")
