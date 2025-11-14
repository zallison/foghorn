"""Tests for threaded fallback DoH and admin webserver implementations.

Inputs:
  - monkeypatch/pytest fixtures, real TCP sockets via http.client.

Outputs:
  - Coverage of fallback paths in start_doh_server() and start_webserver().
"""

from __future__ import annotations

import asyncio
import base64
import http.client
import json
import sys
import time
import types
from typing import Any

import pytest

from foghorn import doh_api as doh_mod
from foghorn import webserver as web_mod
from foghorn.doh_api import DoHServerHandle, start_doh_server
from foghorn.webserver import RingBuffer, WebServerHandle, start_webserver


pytestmark = pytest.mark.slow


def _encode_dns(q: bytes) -> str:
    """Brief: Return base64url-without-padding encoding of q.

    Inputs:
      - q: bytes payload to encode.

    Outputs:
      - str: URL-safe base64 encoding without trailing '='.

    Example:
      >>> _encode_dns(b"\x01\x02")
      'AQI'
    """

    return base64.urlsafe_b64encode(q).decode("ascii").rstrip("=")


def test_doh_fallback_threaded_server_roundtrip(monkeypatch: Any) -> None:
    """Brief: When asyncio loop creation fails, start_doh_server uses threaded HTTP.

    Inputs:
      - monkeypatch: used to force asyncio.new_event_loop() to raise PermissionError.

    Outputs:
      - Asserts that DoH threaded fallback serves GET/POST /dns-query correctly.
    """

    # Force asyncio.new_event_loop() to raise PermissionError so the DoH starter
    # chooses the threaded HTTP fallback instead of uvicorn.
    def boom_new_loop(*_a: Any, **_kw: Any) -> asyncio.AbstractEventLoop:
        raise PermissionError("no self-pipe")

    monkeypatch.setattr(asyncio, "new_event_loop", boom_new_loop, raising=True)

    def echo_resolver(q: bytes, client_ip: str) -> bytes:
        # Simple echo resolver used for roundtrip tests.
        return q

    handle = start_doh_server("127.0.0.1", 0, echo_resolver)
    assert isinstance(handle, DoHServerHandle)

    # Discover actual bound port from the underlying HTTP server.
    server = handle._server  # type: ignore[attr-defined]
    assert server is not None
    host, port = server.server_address

    # Give the server a brief moment to start accepting connections.
    time.sleep(0.05)

    # Test POST /dns-query
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

    # Test GET /dns-query?dns=...
    conn2 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        q = b"\x12\x34zzzz"
        s = _encode_dns(q)
        conn2.request("GET", f"/dns-query?dns={s}")
        resp2 = conn2.getresponse()
        data2 = resp2.read()
        assert resp2.status == 200
        assert data2 == q
    finally:
        conn2.close()

    handle.stop()


def test_admin_prefers_uvicorn_when_asyncio_ok(monkeypatch: Any) -> None:
    """Brief: When asyncio loop creation succeeds, admin webserver uses uvicorn.

    Inputs:
      - monkeypatch: used to track asyncio.new_event_loop and block threaded fallback.

    Outputs:
      - Asserts that start_webserver() prefers uvicorn backend and does not
        call the threaded admin fallback when asyncio is available.
    """

    orig_new_loop = asyncio.new_event_loop
    calls = {"count": 0}

    def tracking_new_loop(*a: Any, **kw: Any) -> asyncio.AbstractEventLoop:
        calls["count"] += 1
        loop = orig_new_loop(*a, **kw)
        return loop

    monkeypatch.setattr(asyncio, "new_event_loop", tracking_new_loop, raising=True)

    used_fallback = {"used": False}

    def fail_admin_threaded(*_a: Any, **_kw: Any) -> None:
        used_fallback["used"] = True
        raise AssertionError(
            "threaded admin fallback should not be used when asyncio works"
        )

    monkeypatch.setattr(
        web_mod, "_start_admin_server_threaded", fail_admin_threaded, raising=True
    )

    class DummyConfig:
        def __init__(self, *a: Any, **kw: Any) -> None:
            self.args = a
            self.kwargs = kw

    class DummyServer:
        def __init__(self, config: Any) -> None:
            self.config = config

        def run(self) -> None:
            return None

    dummy_uvicorn = types.SimpleNamespace(Config=DummyConfig, Server=DummyServer)
    monkeypatch.setitem(sys.modules, "uvicorn", dummy_uvicorn)

    cfg = {
        "webserver": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 8053,
        }
    }

    handle = start_webserver(stats=None, config=cfg, log_buffer=RingBuffer())
    assert isinstance(handle, WebServerHandle)
    # uvicorn path attaches no underlying HTTP server instance.
    assert getattr(handle, "_server", None) is None
    assert calls["count"] >= 1
    assert used_fallback["used"] is False

    handle.stop()


def test_doh_prefers_uvicorn_when_asyncio_ok(monkeypatch: Any) -> None:
    """Brief: When asyncio loop creation succeeds, DoH uses uvicorn backend.

    Inputs:
      - monkeypatch: used to track asyncio.new_event_loop and block threaded fallback.

    Outputs:
      - Asserts that start_doh_server() does not call the threaded fallback and
        returns a DoHServerHandle with no attached HTTP server (uvicorn path).
    """

    # Track that asyncio.new_event_loop() is exercised without failing.
    orig_new_loop = asyncio.new_event_loop
    calls = {"count": 0}

    def tracking_new_loop(*a: Any, **kw: Any) -> asyncio.AbstractEventLoop:
        calls["count"] += 1
        loop = orig_new_loop(*a, **kw)
        return loop

    monkeypatch.setattr(asyncio, "new_event_loop", tracking_new_loop, raising=True)

    # Ensure the threaded fallback is NOT used.
    used_fallback = {"used": False}

    def fail_threaded_start(*_a: Any, **_kw: Any) -> None:
        used_fallback["used"] = True
        raise AssertionError(
            "threaded DoH fallback should not be used when asyncio works"
        )

    monkeypatch.setattr(
        doh_mod, "_start_doh_server_threaded", fail_threaded_start, raising=True
    )

    # Provide a dummy uvicorn implementation that does not touch real sockets.
    class DummyConfig:
        def __init__(self, *a: Any, **kw: Any) -> None:
            self.args = a
            self.kwargs = kw

    class DummyServer:
        def __init__(self, config: Any) -> None:
            self.config = config

        def run(self) -> None:
            # No-op run; real network I/O is not required for this test.
            return None

    dummy_uvicorn = types.SimpleNamespace(Config=DummyConfig, Server=DummyServer)
    monkeypatch.setitem(sys.modules, "uvicorn", dummy_uvicorn)

    # Call the public entrypoint; it should use uvicorn path.
    def echo_resolver(q: bytes, client_ip: str) -> bytes:
        return q

    handle = start_doh_server("127.0.0.1", 8053, echo_resolver)
    assert isinstance(handle, DoHServerHandle)
    # uvicorn path does not attach an HTTP server instance.
    assert getattr(handle, "_server", None) is None
    assert calls["count"] >= 1
    assert used_fallback["used"] is False

    handle.stop()


def test_admin_webserver_fallback_health_and_auth(monkeypatch: Any) -> None:
    """Brief: When asyncio loop creation fails, start_webserver uses threaded admin HTTP.

    Inputs:
      - monkeypatch: forces asyncio.new_event_loop() to raise PermissionError.

    Outputs:
      - Asserts that /health is reachable without auth and /stats enforces token auth.
    """

    def boom_new_loop(*_a: Any, **_kw: Any) -> asyncio.AbstractEventLoop:
        raise PermissionError("no self-pipe")

    monkeypatch.setattr(asyncio, "new_event_loop", boom_new_loop, raising=True)

    cfg = {
        "webserver": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 0,
            "auth": {"mode": "token", "token": "secret-token"},
        }
    }

    handle = start_webserver(stats=None, config=cfg, log_buffer=RingBuffer())
    assert isinstance(handle, WebServerHandle)

    server = handle._server  # type: ignore[attr-defined]
    assert server is not None
    host, port = server.server_address

    time.sleep(0.05)

    # /health should be reachable without authentication.
    conn = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn.request("GET", "/health")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 200
        data = json.loads(body.decode("utf-8"))
        assert data["status"] == "ok"
    finally:
        conn.close()

    # /stats without token should be forbidden.
    conn2 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn2.request("GET", "/stats")
        resp2 = conn2.getresponse()
        resp2.read()
        assert resp2.status == 403
    finally:
        conn2.close()

    # /stats with valid bearer token should return JSON with status disabled (no collector).
    conn3 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn3.request(
            "GET",
            "/stats",
            headers={"Authorization": "Bearer secret-token"},
        )
        resp3 = conn3.getresponse()
        body3 = resp3.read()
        assert resp3.status == 200
        data3 = json.loads(body3.decode("utf-8"))
        assert data3["status"] == "disabled"
    finally:
        conn3.close()

    handle.stop()
