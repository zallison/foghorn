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

# DNS-over-HTTP(s) - Provide cert and key to enable HTTPS, otherwise use an ssl terminator
from foghorn.servers import doh_api as doh_mod
from foghorn.servers.doh_api import DoHServerHandle, start_doh_server

# API / index.html / stats
from foghorn.servers import webserver as web_mod
from foghorn.servers.webserver import RingBuffer, WebServerHandle, start_webserver
from foghorn.stats import StatsCollector, StatsSQLiteStore

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


def test_admin_fallback_logs_with_limit_and_static_files(
    monkeypatch: Any, tmp_path
) -> None:
    """Brief: Threaded admin HTTP /logs handles limit and serves static files with path protection.

    Inputs:
      - monkeypatch: forces asyncio.new_event_loop() to raise PermissionError.
      - tmp_path: pytest temp directory for creating html assets.

    Outputs:
      - Asserts that /logs respects the limit query parameter.
      - Asserts that GET /style.css serves a static file from html/.
      - Asserts that path traversal attempts (/../secret.txt) return 404.
    """

    def boom_new_loop(*_a: Any, **_kw: Any) -> asyncio.AbstractEventLoop:
        raise PermissionError("no self-pipe")

    monkeypatch.setattr(asyncio, "new_event_loop", boom_new_loop, raising=True)

    # Create a temporary html directory with a static asset.
    www_root = tmp_path / "html"
    www_root.mkdir()
    asset = www_root / "style.css"
    asset.write_text("body { color: red; }", encoding="utf-8")

    # Create an index.html file for testing / and /index.html.
    index_file = www_root / "index.html"
    index_file.write_text("<html><body>Admin UI</body></html>", encoding="utf-8")

    # Pre-populate a RingBuffer with some log-like entries.
    buf = RingBuffer(capacity=5)
    buf.push({"msg": "entry1"})
    buf.push({"msg": "entry2"})
    buf.push({"msg": "entry3"})

    cfg = {
        "server": {
            "http": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 0,
                "www_root": str(www_root),
            }
        }
    }

    handle = start_webserver(stats=None, config=cfg, log_buffer=buf)
    assert isinstance(handle, WebServerHandle)

    server = handle._server  # type: ignore[attr-defined]
    assert server is not None
    host, port = server.server_address

    time.sleep(0.05)

    # Test /logs with a limit query parameter.
    conn = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn.request("GET", "/logs?limit=2")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 200
        data = json.loads(body.decode("utf-8"))
        # Buffer has 3 items; limit=2 should return the newest 2.
        entries = data["entries"]
        assert len(entries) == 2
        assert entries[0]["msg"] == "entry2"
        assert entries[1]["msg"] == "entry3"
    finally:
        conn.close()

    # Test /logs with an invalid limit query parameter (should fall back to 100).
    conn2 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn2.request("GET", "/logs?limit=not-a-number")
        resp2 = conn2.getresponse()
        body2 = resp2.read()
        assert resp2.status == 200
        data2 = json.loads(body2.decode("utf-8"))
        # Should return all 3 entries (fallback to limit=100).
        assert len(data2["entries"]) == 3
    finally:
        conn2.close()

    # Test static file serving: GET /style.css.
    conn3 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn3.request("GET", "/style.css")
        resp3 = conn3.getresponse()
        body3 = resp3.read()
        assert resp3.status == 200
        assert b"body { color: red; }" == body3
    finally:
        conn3.close()

    # Test path traversal protection: GET /../secret.txt should return 404.
    conn4 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn4.request("GET", "/../secret.txt")
        resp4 = conn4.getresponse()
        resp4.read()
        assert resp4.status == 404
    finally:
        conn4.close()

    # Test GET / and /index.html serve the index file.
    for path in ["/", "/index.html"]:
        conn5 = http.client.HTTPConnection(host, port, timeout=1)
        try:
            conn5.request("GET", path)
            resp5 = conn5.getresponse()
            body5 = resp5.read()
            assert resp5.status == 200
            assert b"<html><body>Admin UI</body></html>" == body5
        finally:
            conn5.close()

    handle.stop()


def test_admin_fallback_query_log_and_aggregate(monkeypatch: Any, tmp_path) -> None:
    """Brief: Threaded admin HTTP exposes /api/v1/query_log and /api/v1/query_log/aggregate.

    Inputs:
      - monkeypatch forcing asyncio.new_event_loop() to raise PermissionError (threaded fallback).
      - tmp_path used for a temporary stats SQLite database.

    Outputs:
      - /api/v1/query_log returns paginated query_log rows.
      - /api/v1/query_log/aggregate returns dense bucket counts.
    """

    def boom_new_loop(*_a: Any, **_kw: Any) -> asyncio.AbstractEventLoop:
        raise PermissionError("no self-pipe")

    monkeypatch.setattr(asyncio, "new_event_loop", boom_new_loop, raising=True)

    store = StatsSQLiteStore(str(tmp_path / "stats.db"))
    collector = StatsCollector(stats_store=store)

    # Insert two rows in a known window.
    from datetime import datetime, timezone

    start_dt = datetime(2025, 12, 10, 1, 0, 0, tzinfo=timezone.utc)
    collector.record_query_result(
        client_ip="192.0.2.1",
        qname="example.com",
        qtype="A",
        rcode="REFUSED",
        upstream_id=None,
        status="error",
        error=None,
        first=None,
        result={"source": "server"},
        ts=start_dt.timestamp() + 60,
    )
    collector.record_query_result(
        client_ip="192.0.2.1",
        qname="example.com",
        qtype="A",
        rcode="REFUSED",
        upstream_id=None,
        status="error",
        error=None,
        first=None,
        result={"source": "server"},
        ts=start_dt.timestamp() + 16 * 60,
    )

    cfg = {
        "server": {
            "http": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 0,
            }
        }
    }

    handle = start_webserver(stats=collector, config=cfg, log_buffer=RingBuffer())
    assert isinstance(handle, WebServerHandle)

    server = handle._server  # type: ignore[attr-defined]
    assert server is not None
    host, port = server.server_address

    time.sleep(0.05)

    # Query log list
    conn = http.client.HTTPConnection(host, port, timeout=2)
    try:
        conn.request("GET", "/api/v1/query_log?page=1&page_size=1")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 200
        data = json.loads(body.decode("utf-8"))
        assert data["total"] == 2
        assert len(data["items"]) == 1
    finally:
        conn.close()

    # Aggregate: 15-minute buckets over 1 hour
    conn2 = http.client.HTTPConnection(host, port, timeout=2)
    try:
        qs = (
            "/api/v1/query_log/aggregate"
            "?rcode=REFUSED"
            "&interval=15"
            "&interval_units=minutes"
            "&start=2025-12-10%2001:00:00"
            "&end=2025-12-10%2002:00:00"
        )
        conn2.request("GET", qs)
        resp2 = conn2.getresponse()
        body2 = resp2.read()
        assert resp2.status == 200
        data2 = json.loads(body2.decode("utf-8"))
        items = data2["items"]
        assert len(items) == 4
        counts = [it["count"] for it in items]
        assert counts == [1, 1, 0, 0]
    finally:
        conn2.close()

    handle.stop()


def test_admin_fallback_config_raw_and_save(monkeypatch: Any, tmp_path) -> None:
    """Brief: Threaded admin HTTP /config/raw and /config/save read/write YAML config.

    Inputs:
      - monkeypatch: forces asyncio.new_event_loop() to raise PermissionError.
      - tmp_path: pytest temp directory for creating a config file.

    Outputs:
      - Asserts that /config/raw returns the raw YAML text and parsed config.
      - Asserts that POST /config/save overwrites the config file and returns success.
    """

    def boom_new_loop(*_a: Any, **_kw: Any) -> asyncio.AbstractEventLoop:
        raise PermissionError("no self-pipe")

    monkeypatch.setattr(asyncio, "new_event_loop", boom_new_loop, raising=True)

    # Prevent config-save from sending a real SIGUSR1 to the pytest process.
    kill_calls: dict[str, tuple[int, int] | None] = {"args": None}

    def fake_kill(pid: int, sig: int) -> None:
        kill_calls["args"] = (pid, sig)

    monkeypatch.setattr(web_mod.os, "kill", fake_kill)

    # Create a temporary config file.
    cfg_path = tmp_path / "config.yaml"
    initial_yaml = "initial: 1\nwebserver:\n  enabled: true\n"
    cfg_path.write_text(initial_yaml, encoding="utf-8")

    cfg = {
        "server": {
            "http": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 0,
            }
        }
    }

    handle = start_webserver(
        stats=None, config=cfg, log_buffer=RingBuffer(), config_path=str(cfg_path)
    )
    assert isinstance(handle, WebServerHandle)

    server = handle._server  # type: ignore[attr-defined]
    assert server is not None
    host, port = server.server_address

    time.sleep(0.05)

    # Test GET /config/raw.json returns the on-disk YAML and parsed config.
    conn = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn.request("GET", "/config/raw.json")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 200
        data = json.loads(body.decode("utf-8"))
        assert data["raw_yaml"] == initial_yaml
        assert data["config"]["initial"] == 1
    finally:
        conn.close()

    # Test POST /config/save overwrites the config file.
    new_cfg = {"answer": 42, "webserver": {"enabled": True}}
    import yaml

    new_yaml = yaml.safe_dump(new_cfg)
    conn2 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        body_data = json.dumps({"raw_yaml": new_yaml}).encode("utf-8")
        conn2.request(
            "POST",
            "/config/save",
            body=body_data,
            headers={"Content-Type": "application/json"},
        )
        resp2 = conn2.getresponse()
        body2 = resp2.read()
        assert resp2.status == 200
        data2 = json.loads(body2.decode("utf-8"))
        assert data2["status"] == "ok"
        assert "backed_up_to" in data2
    finally:
        conn2.close()

    # Verify the config file on disk was updated.
    on_disk = cfg_path.read_text(encoding="utf-8")
    # The threaded handler uses yaml.safe_dump, so the output will be valid YAML.
    import yaml

    reloaded = yaml.safe_load(on_disk)
    assert reloaded["answer"] == 42
    assert reloaded["webserver"]["enabled"] is True

    handle.stop()


def test_admin_webserver_fallback_runtime_state_is_updated(monkeypatch: Any) -> None:
    """Brief: start_webserver(threaded) should update runtime_state with webserver handle.

    Inputs:
      - monkeypatch: forces asyncio.new_event_loop() to raise PermissionError.

    Outputs:
      - runtime_state snapshot includes a webserver listener entry.
    """

    def boom_new_loop(*_a: Any, **_kw: Any) -> asyncio.AbstractEventLoop:
        raise PermissionError("no self-pipe")

    monkeypatch.setattr(asyncio, "new_event_loop", boom_new_loop, raising=True)

    state = web_mod.RuntimeState(startup_complete=True)

    cfg = {
        "server": {
            "http": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 0,
            }
        }
    }

    handle = start_webserver(
        stats=None,
        config=cfg,
        log_buffer=RingBuffer(),
        runtime_state=state,
    )
    assert isinstance(handle, WebServerHandle)

    snap = state.snapshot()
    assert "webserver" in snap["listeners"]

    handle.stop()


def test_admin_fallback_query_log_validation_errors(monkeypatch: Any) -> None:
    """Brief: Threaded query_log endpoints should handle invalid query params.

    Inputs:
      - Threaded admin server forced via asyncio.new_event_loop PermissionError.
      - Requests with malformed paging and datetime query params.

    Outputs:
      - Returns 400 for invalid start/end and missing required fields.
      - Coerces page/page_size defaults when non-integer values are provided.
    """

    def boom_new_loop(*_a: Any, **_kw: Any) -> asyncio.AbstractEventLoop:
        raise PermissionError("no self-pipe")

    monkeypatch.setattr(asyncio, "new_event_loop", boom_new_loop, raising=True)

    class DummyStore:
        def select_query_log(self, **_kw):  # noqa: ANN003
            # Include a non-dict item to exercise the "else" append path in the handler.
            return {"items": ["x"], "total": 0, "total_pages": 0}

        def aggregate_query_log_counts(self, **_kw):  # noqa: ANN003
            return {"items": []}

    class DummyStats:
        def __init__(self) -> None:
            self._store = DummyStore()

    cfg = {
        "server": {
            "http": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 0,
            }
        },
        # Auth configuration for the threaded admin handlers still lives under
        # the legacy webserver block; start_webserver now only reads server.http.
        "webserver": {
            "auth": {"mode": "token", "token": "secret-token"},
        },
    }

    handle = start_webserver(stats=DummyStats(), config=cfg, log_buffer=RingBuffer())
    assert isinstance(handle, WebServerHandle)

    server = handle._server  # type: ignore[attr-defined]
    assert server is not None
    host, port = server.server_address
    time.sleep(0.05)

    # No auth header should be unauthorized (covers early return).
    conn0 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn0.request("GET", "/api/v1/query_log?page=1&page_size=1")
        resp0 = conn0.getresponse()
        resp0.read()
        assert resp0.status == 401
    finally:
        conn0.close()

    # Non-integer page/page_size should be coerced, still 200.
    conn1 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn1.request(
            "GET",
            "/api/v1/query_log?page=bad&page_size=bad",
            headers={"Authorization": "Bearer secret-token"},
        )
        resp1 = conn1.getresponse()
        body1 = resp1.read()
        assert resp1.status == 200
        data1 = json.loads(body1.decode("utf-8"))
        assert data1["page"] == 1
        assert data1["page_size"] == 100
    finally:
        conn1.close()

    # page < 1 and page_size clamps.
    conn1b = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn1b.request(
            "GET",
            "/api/v1/query_log?page=0&page_size=0",
            headers={"Authorization": "Bearer secret-token"},
        )
        resp1b = conn1b.getresponse()
        resp1b.read()
        assert resp1b.status == 200
    finally:
        conn1b.close()

    conn1c = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn1c.request(
            "GET",
            "/api/v1/query_log?page=1&page_size=2001",
            headers={"Authorization": "Bearer secret-token"},
        )
        resp1c = conn1c.getresponse()
        resp1c.read()
        assert resp1c.status == 200
    finally:
        conn1c.close()

    # Invalid start datetime yields 400.
    conn2 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn2.request(
            "GET",
            "/api/v1/query_log?start=bad",
            headers={"Authorization": "Bearer secret-token"},
        )
        resp2 = conn2.getresponse()
        body2 = resp2.read()
        assert resp2.status == 400
        data2 = json.loads(body2.decode("utf-8"))
        assert "invalid start datetime" in data2.get("detail", "")
    finally:
        conn2.close()

    # Invalid end datetime yields 400.
    conn2b = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn2b.request(
            "GET",
            "/api/v1/query_log?end=bad",
            headers={"Authorization": "Bearer secret-token"},
        )
        resp2b = conn2b.getresponse()
        body2b = resp2b.read()
        assert resp2b.status == 400
        data2b = json.loads(body2b.decode("utf-8"))
        assert "invalid end datetime" in data2b.get("detail", "")
    finally:
        conn2b.close()

    # Disabled response when server has no stats/store.
    orig_stats = server.stats
    server.stats = None
    conn2c = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn2c.request(
            "GET",
            "/api/v1/query_log?page=1&page_size=1",
            headers={"Authorization": "Bearer secret-token"},
        )
        resp2c = conn2c.getresponse()
        body2c = resp2c.read()
        assert resp2c.status == 200
        data2c = json.loads(body2c.decode("utf-8"))
        assert data2c["status"] == "disabled"
    finally:
        conn2c.close()

    # Restore stats/store for aggregate validation cases.
    server.stats = orig_stats

    # Aggregate without auth should be unauthorized.
    conn2d = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn2d.request(
            "GET",
            "/api/v1/query_log/aggregate?interval=15&interval_units=minutes&start=2025-12-10%2001:00:00&end=2025-12-10%2002:00:00",
        )
        resp2d = conn2d.getresponse()
        resp2d.read()
        assert resp2d.status == 401
    finally:
        conn2d.close()

    # Aggregate: missing start/end yields 400.
    conn3 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn3.request(
            "GET",
            "/api/v1/query_log/aggregate?interval=15&interval_units=minutes",
            headers={"Authorization": "Bearer secret-token"},
        )
        resp3 = conn3.getresponse()
        body3 = resp3.read()
        assert resp3.status == 400
        data3 = json.loads(body3.decode("utf-8"))
        assert "start and end are required" in data3.get("detail", "")
    finally:
        conn3.close()

    # Aggregate: invalid start/end datetime yields 400.
    conn3b = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn3b.request(
            "GET",
            "/api/v1/query_log/aggregate?interval=15&interval_units=minutes&start=bad&end=2025-12-10%2002:00:00",
            headers={"Authorization": "Bearer secret-token"},
        )
        resp3b = conn3b.getresponse()
        resp3b.read()
        assert resp3b.status == 400
    finally:
        conn3b.close()

    # Aggregate: invalid interval yields 400.
    conn3c = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn3c.request(
            "GET",
            "/api/v1/query_log/aggregate?interval=bad&interval_units=minutes&start=2025-12-10%2001:00:00&end=2025-12-10%2002:00:00",
            headers={"Authorization": "Bearer secret-token"},
        )
        resp3c = conn3c.getresponse()
        resp3c.read()
        assert resp3c.status == 400
    finally:
        conn3c.close()

    # Aggregate: interval <= 0 yields 400.
    conn3d = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn3d.request(
            "GET",
            "/api/v1/query_log/aggregate?interval=0&interval_units=minutes&start=2025-12-10%2001:00:00&end=2025-12-10%2002:00:00",
            headers={"Authorization": "Bearer secret-token"},
        )
        resp3d = conn3d.getresponse()
        resp3d.read()
        assert resp3d.status == 400
    finally:
        conn3d.close()

    # Disabled response when server has no stats/store.
    orig_stats2 = server.stats
    server.stats = None
    conn3e = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn3e.request(
            "GET",
            "/api/v1/query_log/aggregate?interval=15&interval_units=minutes&start=2025-12-10%2001:00:00&end=2025-12-10%2002:00:00",
            headers={"Authorization": "Bearer secret-token"},
        )
        resp3e = conn3e.getresponse()
        body3e = resp3e.read()
        assert resp3e.status == 200
        data3e = json.loads(body3e.decode("utf-8"))
        assert data3e["status"] == "disabled"
    finally:
        conn3e.close()
        server.stats = orig_stats2

    # Aggregate: invalid units yields 400.
    conn4 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn4.request(
            "GET",
            "/api/v1/query_log/aggregate?interval=15&interval_units=weeks&start=2025-12-10%2001:00:00&end=2025-12-10%2002:00:00",
            headers={"Authorization": "Bearer secret-token"},
        )
        resp4 = conn4.getresponse()
        body4 = resp4.read()
        assert resp4.status == 400
        data4 = json.loads(body4.decode("utf-8"))
        assert "interval_units must be" in data4.get("detail", "")
    finally:
        conn4.close()

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
        "server": {
            "http": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 8053,
            }
        }
    }

    handle = start_webserver(stats=None, config=cfg, log_buffer=RingBuffer())
    assert isinstance(handle, WebServerHandle)
    # uvicorn path attaches no underlying HTTP server instance.
    assert getattr(handle, "_server", None) is None
    assert calls["count"] >= 1
    assert used_fallback["used"] is False
    handle.stop()


def test_admin_uvicorn_sets_runtime_state_listener(monkeypatch: Any) -> None:
    """Brief: uvicorn path should update runtime_state with the webserver thread.

    Inputs:
      - Dummy uvicorn module.
      - runtime_state passed to start_webserver().

    Outputs:
      - runtime_state snapshot contains a webserver listener entry.
    """

    calls: dict[str, object] = {}

    class DummyConfig:
        def __init__(self, *a: Any, **kw: Any) -> None:
            self.args = a
            self.kwargs = kw

    class DummyServer:
        def __init__(self, config: Any) -> None:
            self.config = config

        def run(self) -> None:
            # Keep the thread alive briefly.
            time.sleep(0.05)
            calls["ran"] = True

    dummy_uvicorn = types.SimpleNamespace(Config=DummyConfig, Server=DummyServer)
    monkeypatch.setitem(sys.modules, "uvicorn", dummy_uvicorn)

    state = web_mod.RuntimeState(startup_complete=True)

    cfg = {
        "server": {
            "http": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 8053,
            }
        }
    }

    handle = start_webserver(
        stats=None,
        config=cfg,
        log_buffer=RingBuffer(),
        runtime_state=state,
    )
    assert isinstance(handle, WebServerHandle)

    time.sleep(0.01)
    snap = state.snapshot()
    assert "webserver" in snap["listeners"]

    handle.stop()
    assert calls.get("ran") is True


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
        "server": {
            "http": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 0,
            }
        },
        # Auth configuration for threaded handlers continues to live under the
        # legacy webserver block; start_webserver now only reads server.http.
        "webserver": {
            "auth": {"mode": "token", "token": "secret-token"},
        },
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

    # /stats without token should be unauthorized.
    conn2 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn2.request("GET", "/stats")
        resp2 = conn2.getresponse()
        resp2.read()
        assert resp2.status == 401
        assert "bearer" in (resp2.getheader("WWW-Authenticate") or "").lower()
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

    # /stats with X-API-Key should also authorize.
    conn4 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn4.request(
            "GET",
            "/stats",
            headers={"X-API-Key": "secret-token"},
        )
        resp4 = conn4.getresponse()
        body4 = resp4.read()
        assert resp4.status == 200
        data4 = json.loads(body4.decode("utf-8"))
        assert data4["status"] == "disabled"
    finally:
        conn4.close()

    # /about should be reachable without auth.
    conn5 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn5.request("GET", "/about")
        resp5 = conn5.getresponse()
        body5 = resp5.read()
        assert resp5.status == 200
        data5 = json.loads(body5.decode("utf-8"))
        assert "version" in data5
        assert "server_time" in data5
    finally:
        conn5.close()

    # /ready should reflect not-ready state (threaded fallback has no runtime_state wiring here).
    conn6 = http.client.HTTPConnection(host, port, timeout=1)
    try:
        conn6.request("GET", "/ready")
        resp6 = conn6.getresponse()
        body6 = resp6.read()
        assert resp6.status in (200, 503)
        data6 = json.loads(body6.decode("utf-8"))
        assert "ready" in data6
        assert "not_ready" in data6
    finally:
        conn6.close()

    handle.stop()
