"""
Brief: Negative-path tests for downstream DoH server.

Inputs:
  - None

Outputs:
  - None
"""

import asyncio
import base64
import http.client
import threading

import pytest

from foghorn.doh_server import serve_doh


def _echo(q: bytes, ip: str) -> bytes:
    return q


@pytest.fixture
def running_doh(tmp_path):
    host = "127.0.0.1"
    ready = threading.Event()
    info = {}

    def runner():
        asyncio.set_event_loop(asyncio.new_event_loop())
        loop = asyncio.get_event_loop()

        async def bind_and_run():
            srv = await asyncio.start_server(lambda r, w: None, host, 0)
            port = srv.sockets[0].getsockname()[1]
            info["port"] = port
            ready.set()
            srv.close()
            await srv.wait_closed()
            await serve_doh(host, port, _echo)

        loop.create_task(bind_and_run())
        loop.run_forever()

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    if not ready.wait(2.0):
        pytest.skip("doh server startup failed")
    # Allow the DoH server to finish binding
    import time as _t

    _t.sleep(0.15)
    yield host, info["port"]


def test_doh_bad_path_404(running_doh):
    h, p = running_doh
    c = http.client.HTTPConnection(h, p, timeout=1)
    try:
        c.request("GET", "/not-found")
        r = c.getresponse()
        assert r.status == 404
    finally:
        c.close()


def test_doh_post_wrong_content_type_415(running_doh):
    h, p = running_doh
    c = http.client.HTTPConnection(h, p, timeout=1)
    try:
        c.request(
            "POST", "/dns-query", body=b"x", headers={"Content-Type": "text/plain"}
        )
        r = c.getresponse()
        assert r.status == 415
    finally:
        c.close()


def test_doh_get_missing_param_400(running_doh):
    h, p = running_doh
    c = http.client.HTTPConnection(h, p, timeout=1)
    try:
        c.request("GET", "/dns-query")
        r = c.getresponse()
        assert r.status == 400
    finally:
        c.close()
