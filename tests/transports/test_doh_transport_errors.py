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

from foghorn.servers.transports.doh import DoHError, _build_ssl_ctx, doh_query


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


def test_build_ssl_ctx_no_verify(monkeypatch):
    calls = {}

    def fake_unverified_context():
        calls["called"] = True
        return "CTX"

    monkeypatch.setattr(
        "foghorn.servers.transports.doh.ssl._create_unverified_context",
        fake_unverified_context,
    )

    ctx = _build_ssl_ctx(verify=False, ca_file=None)
    assert ctx == "CTX"
    assert calls.get("called") is True


def test_build_ssl_ctx_with_cafile(monkeypatch):
    captured = {}

    def fake_create_default_context(*, cafile=None):
        captured["cafile"] = cafile
        return "CTX2"

    monkeypatch.setattr(
        "foghorn.servers.transports.doh.ssl.create_default_context",
        fake_create_default_context,
    )

    ctx = _build_ssl_ctx(verify=True, ca_file="/tmp/ca.pem")
    assert ctx == "CTX2"
    assert captured["cafile"] == "/tmp/ca.pem"


def test_doh_https_tls_error(monkeypatch):
    import ssl as _ssl

    class FailingHTTPSConnection:
        def __init__(self, *_, **__):  # pragma: no cover - init itself not under test
            raise _ssl.SSLError("bad tls")

    monkeypatch.setattr(
        "foghorn.servers.transports.doh.http.client.HTTPSConnection",
        FailingHTTPSConnection,
    )

    with pytest.raises(DoHError) as excinfo:
        doh_query("https://example.com/dns-query", b"\x00\x01")

    assert "TLS error" in str(excinfo.value)


def test_doh_https_os_error(monkeypatch):
    class FailingHTTPSConnection:
        def __init__(self, *_, **__):  # pragma: no cover - init itself not under test
            raise OSError("boom")

    monkeypatch.setattr(
        "foghorn.servers.transports.doh.http.client.HTTPSConnection",
        FailingHTTPSConnection,
    )

    with pytest.raises(DoHError) as excinfo:
        doh_query("https://example.com/dns-query", b"\x00\x01")

    assert "Network error" in str(excinfo.value)
