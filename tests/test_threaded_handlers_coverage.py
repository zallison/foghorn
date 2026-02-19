"""Additional coverage-focused tests for threaded stdlib admin webserver handlers.

These tests target branches in `src/foghorn/servers/webserver/threaded_handlers.py`
that are either:
- not reachable via the FastAPI implementation, or
- exercised more easily via direct `_AdminHTTPServer` requests.

Inputs:
  - pytest fixtures (tmp_path, monkeypatch)

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

import http.client
import json
import threading
from pathlib import Path
from typing import Any, Dict, Mapping

import pytest

import foghorn.servers.webserver as web_mod
from foghorn.servers.webserver import AdminPageSpec
from foghorn.stats import StatsCollector
from foghorn.utils.config_mermaid import diagram_png_path_for_config


def _one_shot_http_request(
    *,
    method: str,
    path: str,
    config: Dict[str, Any],
    stats: StatsCollector | None = None,
    config_path: str | None = None,
    plugins: list[object] | None = None,
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Brief: Send a single HTTP request through `_AdminHTTPServer` and return response.

    Inputs:
      - method/path: HTTP method and path.
      - config/stats/config_path/plugins: Passed through to `_AdminHTTPServer`.
      - headers/body: Request headers and optional body.

    Outputs:
      - (status_code, headers_lower, body_bytes)
    """

    httpd = web_mod._AdminHTTPServer(
        ("127.0.0.1", 0),
        web_mod._ThreadedAdminRequestHandler,
        stats=stats,
        config=config,
        log_buffer=None,
        config_path=config_path,
        runtime_state=None,
        plugins=plugins,
    )
    host, port = httpd.server_address

    def _serve_once() -> None:
        try:
            httpd.handle_request()
        finally:
            httpd.server_close()

    t = threading.Thread(target=_serve_once, daemon=True)
    t.start()

    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=dict(headers or {}))
        resp = conn.getresponse()
        status = int(resp.status)
        resp_headers = {str(k).lower(): str(v) for k, v in resp.getheaders()}
        data = resp.read()
    finally:
        conn.close()
        t.join(timeout=1.0)

    return status, resp_headers, data


def test_threaded_query_param_helpers_defensive_branches() -> None:
    """Brief: Exercise defensive parsing branches for query-param helper methods.

    Inputs:
      - Synthetic parse_qs-like dicts.

    Outputs:
      - None; asserts helper behaviour for invalid structures.
    """

    h = web_mod._ThreadedAdminRequestHandler.__new__(
        web_mod._ThreadedAdminRequestHandler
    )

    assert h._get_query_param({}, "x", default="d") == "d"
    assert h._get_query_param({"x": []}, "x", default="d") == "d"
    assert h._get_query_param({"x": [None]}, "x", default="d") == "d"
    # Defensive: non-list values (parse_qs won't produce this but code guards it).
    assert h._get_query_param({"x": "not-a-list"}, "x", default="d") == "d"  # type: ignore[arg-type]
    assert h._get_query_param({"x": ["v", "other"]}, "x") == "v"

    assert h._get_int_param({}, "n", default=10) == 10
    assert h._get_int_param({"n": ["bad"]}, "n", default=10) == 10
    assert h._get_int_param({"n": ["12"]}, "n", default=10) == 12

    assert h._get_bool_param({}, "b", default=True) is True
    assert h._get_bool_param({"b": ["true"]}, "b", default=False) is True
    assert h._get_bool_param({"b": ["0"]}, "b", default=True) is False
    assert h._get_bool_param({"b": ["maybe"]}, "b", default=True) is True


def test_threaded_require_auth_token_missing_returns_500() -> None:
    """Brief: auth.mode=token without token configured returns HTTP 500.

    Inputs:
      - Threaded /stats request with webserver.auth.mode=token and missing token.

    Outputs:
      - HTTP 500 with a detail message.
    """

    cfg = {"webserver": {"auth": {"mode": "token"}}}
    status, _hdrs, body = _one_shot_http_request(
        method="GET", path="/stats", config=cfg, stats=None
    )
    assert status == 500
    data = json.loads(body.decode("utf-8"))
    assert "token not configured" in str(data.get("detail", ""))


def test_threaded_stats_table_pairs_to_rows_filters_invalid_pairs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: /api/v1/stats/table filters invalid pairs and count conversions.

    Inputs:
      - Monkeypatched snapshot providing malformed pairs and grouped mappings.

    Outputs:
      - Invalid pairs are skipped and counts are coerced to int.
      - Grouped table with non-dict mapping returns empty items.
      - Empty table id returns 404.
    """

    import sys
    import types

    th = sys.modules.get("foghorn.servers.webserver.threaded_handlers")
    assert th is not None

    dummy_snap = types.SimpleNamespace(
        created_at="now",
        cache_miss_domains=[
            ("ok", "3"),
            ("bad-count", "nope"),
            ("too-short",),
            "not-a-pair",
            ("extra", 1, 2),
        ],
        qtype_qnames=["not-a-dict"],
    )

    monkeypatch.setattr(th, "_get_stats_snapshot_cached", lambda *_a, **_kw: dummy_snap)

    cfg = {"webserver": {"auth": {"mode": "none"}}}
    collector = StatsCollector(track_uniques=False)

    status, _hdrs, body = _one_shot_http_request(
        method="GET",
        path="/api/v1/stats/table/cache_miss_domains",
        config=cfg,
        stats=collector,
    )
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    items = data.get("items")
    assert isinstance(items, list)
    assert len(items) == 2
    # build_table_page_payload defaults to sort by count desc.
    assert items[0]["name"] == "ok"
    assert items[0]["count"] == 3
    assert items[1]["name"] == "extra"
    assert items[1]["count"] == 1

    status2, _hdrs2, body2 = _one_shot_http_request(
        method="GET",
        path="/api/v1/stats/table/qtype_qnames?group_key=A",
        config=cfg,
        stats=collector,
    )
    assert status2 == 200
    data2 = json.loads(body2.decode("utf-8"))
    assert data2.get("items") == []

    status3, _hdrs3, body3 = _one_shot_http_request(
        method="GET",
        path="/api/v1/stats/table/",
        config=cfg,
        stats=collector,
    )
    assert status3 == 404
    data3 = json.loads(body3.decode("utf-8"))
    assert "unknown stats table" in str(data3.get("detail", ""))


def test_threaded_config_diagram_png_endpoints(tmp_path: Path) -> None:
    """Brief: Threaded /api/v1/config/diagram.png handles missing and present PNGs.

    Inputs:
      - tmp_path config file and optional PNG.

    Outputs:
      - 500 when config_path missing.
      - 404 when PNG missing.
      - 200 image/png when PNG exists.
    """

    cfg = {"webserver": {"auth": {"mode": "none"}}}

    status, _hdrs, body = _one_shot_http_request(
        method="GET",
        path="/api/v1/config/diagram.png",
        config=cfg,
        config_path=None,
    )
    assert status == 500
    assert "config_path" in body.decode("utf-8")

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("webserver:\n  enabled: true\n", encoding="utf-8")

    status2, hdrs2, body2 = _one_shot_http_request(
        method="GET",
        path="/api/v1/config/diagram.png",
        config=cfg,
        config_path=str(cfg_path),
    )
    assert status2 == 404
    assert hdrs2.get("content-type", "").startswith("text/plain")
    assert body2 == b"config diagram not found"

    png_path = Path(diagram_png_path_for_config(str(cfg_path)))
    png_path.parent.mkdir(parents=True, exist_ok=True)
    png_bytes = b"\x89PNG\r\n\x1a\nFAKE"
    png_path.write_bytes(png_bytes)

    status3, hdrs3, body3 = _one_shot_http_request(
        method="GET",
        path="/api/v1/config/diagram.png",
        config=cfg,
        config_path=str(cfg_path),
    )
    assert status3 == 200
    assert hdrs3.get("content-type", "").startswith("image/png")
    assert body3 == png_bytes


def test_threaded_plugin_admin_endpoints() -> None:
    """Brief: Threaded plugin pages/UI/snapshot endpoints return expected shapes.

    Inputs:
      - Dummy plugins passed to `_AdminHTTPServer`.

    Outputs:
      - /api/v1/plugin_pages returns pages.
      - /api/v1/plugin_pages/{plugin}/{slug} returns detail.
      - /api/v1/plugins/ui returns descriptors.
      - /api/v1/plugins/{name}/{kind} returns snapshot or 404.
    """

    class _PluginWithPages:
        def __init__(self, name: str) -> None:
            self.name = name

        def get_admin_pages(self) -> list[AdminPageSpec]:
            return [
                AdminPageSpec(slug="summary", title="Summary", description="d1"),
            ]

        def get_admin_ui_descriptor(self) -> Dict[str, Any]:
            return {
                "name": self.name,
                "title": "Docker",
                "order": 10,
                "kind": "docker_hosts",
            }

    class _SnapshotPlugin:
        def __init__(self, name: str) -> None:
            self.name = name

        def get_http_snapshot(self) -> Dict[str, Any]:
            return {"ok": True, "name": self.name}

    plugins = [
        _PluginWithPages("docker"),
        _SnapshotPlugin("docker_hosts"),
        _SnapshotPlugin("mdns"),
        _SnapshotPlugin("etc_hosts"),
    ]

    cfg = {"webserver": {"auth": {"mode": "none"}}}

    # List pages
    status, _hdrs, body = _one_shot_http_request(
        method="GET", path="/api/v1/plugin_pages", config=cfg, plugins=plugins
    )
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    pages = data.get("pages")
    assert isinstance(pages, list)
    assert any(
        p.get("plugin") == "docker" and p.get("slug") == "summary" for p in pages
    )

    # Detail OK
    status2, _hdrs2, body2 = _one_shot_http_request(
        method="GET",
        path="/api/v1/plugin_pages/docker/summary",
        config=cfg,
        plugins=plugins,
    )
    assert status2 == 200
    data2 = json.loads(body2.decode("utf-8"))
    assert data2["page"]["slug"] == "summary"

    # Detail route with invalid segments
    status3, _hdrs3, body3 = _one_shot_http_request(
        method="GET",
        path="/api/v1/plugin_pages/docker",
        config=cfg,
        plugins=plugins,
    )
    assert status3 == 404
    assert "plugin page not found" in body3.decode("utf-8")

    # UI descriptors
    status4, _hdrs4, body4 = _one_shot_http_request(
        method="GET", path="/api/v1/plugins/ui", config=cfg, plugins=plugins
    )
    assert status4 == 200
    data4 = json.loads(body4.decode("utf-8"))
    items = data4.get("items")
    assert isinstance(items, list)
    assert any(it.get("name") == "docker" for it in items)

    # Snapshot endpoints
    for p in [
        "/api/v1/plugins/docker_hosts/docker_hosts",
        "/api/v1/plugins/mdns/mdns",
        "/api/v1/plugins/etc_hosts/etc_hosts",
    ]:
        st, _h, b = _one_shot_http_request(
            method="GET", path=p, config=cfg, plugins=plugins
        )
        assert st == 200
        payload = json.loads(b.decode("utf-8"))
        assert payload.get("plugin") in {"docker_hosts", "mdns", "etc_hosts"}
        assert isinstance(payload.get("data"), dict)

    st5, _h5, b5 = _one_shot_http_request(
        method="GET",
        path="/api/v1/plugins/unknown/docker_hosts",
        config=cfg,
        plugins=plugins,
    )
    assert st5 == 404
    payload5 = json.loads(b5.decode("utf-8"))
    assert "detail" in payload5


def test_threaded_ratelimit_and_upstream_status_endpoints() -> None:
    """Brief: Threaded /api/v1/ratelimit and /api/v1/upstream_status respond.

    Inputs:
      - Minimal config for both endpoints.

    Outputs:
      - Both return HTTP 200 with a JSON payload containing server_time.
    """

    cfg = {"plugins": [], "webserver": {"auth": {"mode": "none"}}}

    st1, _h1, b1 = _one_shot_http_request(
        method="GET", path="/api/v1/ratelimit", config=cfg
    )
    assert st1 == 200
    data1 = json.loads(b1.decode("utf-8"))
    assert "server_time" in data1
    assert isinstance(data1.get("databases"), list)

    st2, _h2, b2 = _one_shot_http_request(
        method="GET", path="/api/v1/upstream_status", config=cfg
    )
    assert st2 == 200
    data2 = json.loads(b2.decode("utf-8"))
    assert "server_time" in data2
    assert "items" in data2
