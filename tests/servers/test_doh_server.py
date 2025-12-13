"""
Brief: Unit tests for downstream DoH server using the minimal HTTP implementation.

Inputs:
  - None

Outputs:
  - None
"""

import asyncio
import base64
import http.client
import threading
import time

import pytest

from foghorn.servers.doh_api import start_doh_server
from foghorn.servers.server import resolve_query_bytes


def _echo_resolver(q: bytes, client_ip: str) -> bytes:
    # Echo back with same ID
    return q


pytestmark = pytest.mark.slow


@pytest.fixture
def running_doh_server():
    host = "127.0.0.1"
    ready = threading.Event()
    actual = {}

    def runner():
        asyncio.set_event_loop(asyncio.new_event_loop())
        loop = asyncio.get_event_loop()

        async def _start():
            await asyncio.start_server(lambda r, w: None, host, 0)

        # Start our DoH server
        async def main():
            await asyncio.start_server(lambda r, w: None, host, 0)

        async def start_and_mark():
            await asyncio.start_server(lambda r, w: None, host, 0)

        async def real_start():
            await asyncio.start_server(lambda r, w: None, host, 0)

        # Use serve_doh directly to bind ephemeral port, but need to know address first.
        async def bind_and_run():
            srv = await asyncio.start_server(lambda r, w: None, host, 0)
            addr = srv.sockets[0].getsockname()
            actual["port"] = addr[1]
            ready.set()
            # Close temp and start real DoH on same port using FastAPI/uvicorn
            srv.close()
            await srv.wait_closed()
            # Start DoH server in background thread using resolve_query_bytes
            start_doh_server(host, actual["port"], resolve_query_bytes)

        loop.create_task(bind_and_run())
        loop.run_forever()

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    if not ready.wait(1.0):
        pytest.skip("failed to start loop")
    # Allow bind-to-ready handoff
    time.sleep(0.15)
    try:
        yield host, actual["port"]
    finally:
        # Best-effort: allow thread to continue as daemon
        pass


def test_doh_post_roundtrip(running_doh_server):
    host, port = running_doh_server
    conn = http.client.HTTPConnection(host, port, timeout=1)
    try:
        body = b"\x00\x01hello"
        conn.request(
            "POST",
            "/dns-query",
            body=body,
            headers={"Content-Type": "application/dns-message"},
        )
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert data == body
    finally:
        conn.close()


def test_doh_get_roundtrip(running_doh_server):
    host, port = running_doh_server
    conn = http.client.HTTPConnection(host, port, timeout=1)
    try:
        q = b"\x12\x34zzzz"
        s = base64.urlsafe_b64encode(q).decode("ascii").rstrip("=")
        conn.request("GET", f"/dns-query?dns={s}")
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert data == q
    finally:
        conn.close()
