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
from foghorn.utils.config_diagram import (
    diagram_dark_png_path_for_config,
    diagram_png_path_for_config,
)


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

    effective_config = dict(config or {})
    legacy_web_cfg = effective_config.get("webserver")
    server_cfg = effective_config.get("server")
    if isinstance(legacy_web_cfg, dict):
        if not isinstance(server_cfg, dict):
            server_cfg = {}
            effective_config["server"] = server_cfg
        if not isinstance(server_cfg.get("http"), dict):
            server_cfg["http"] = dict(legacy_web_cfg)

    httpd = web_mod._AdminHTTPServer(
        ("127.0.0.1", 0),
        web_mod._ThreadedAdminRequestHandler,
        stats=stats,
        config=effective_config,
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


def _multipart_file_body(
    *,
    boundary: str,
    field_name: str = "file",
    filename: str = "diagram.png",
    payload: bytes,
) -> bytes:
    """Brief: Build a minimal multipart/form-data body with one file part.

    Inputs:
      - boundary: Multipart boundary token.
      - field_name: Form field key used in Content-Disposition.
      - filename: Filename in Content-Disposition.
      - payload: Raw file bytes to include.

    Outputs:
      - bytes multipart request body.
    """

    boundary_b = boundary.encode("utf-8")
    head = (
        b"--"
        + boundary_b
        + b"\r\n"
        + f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode(
            "utf-8"
        )
        + b"Content-Type: application/octet-stream\r\n"
        + b"\r\n"
    )
    tail = b"\r\n" + b"--" + boundary_b + b"--\r\n"
    return head + payload + tail


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


def test_threaded_stats_table_disabled_and_group_key_required() -> None:
    """Brief: /api/v1/stats/table handles disabled collector and grouped-key errors.

    Inputs:
      - Requests against threaded server with and without a StatsCollector.

    Outputs:
      - 404 when stats collector is disabled.
      - 400 when grouped tables omit required group_key.
    """

    cfg = {"webserver": {"auth": {"mode": "none"}}}

    st1, _h1, b1 = _one_shot_http_request(
        method="GET",
        path="/api/v1/stats/table/top_clients",
        config=cfg,
        stats=None,
    )
    assert st1 == 404
    assert "stats collector disabled" in b1.decode("utf-8")

    collector = StatsCollector(track_uniques=False)
    collector.record_query("192.0.2.1", "example.com", "A")
    st2, _h2, b2 = _one_shot_http_request(
        method="GET",
        path="/api/v1/stats/table/qtype_qnames",
        config=cfg,
        stats=collector,
    )
    assert st2 == 400
    assert "group_key is required" in b2.decode("utf-8")


def test_threaded_config_diagram_dot_endpoint(tmp_path: Path) -> None:
    """Brief: Threaded /api/v1/config/diagram.dot returns dot source text.

    Inputs:
      - No config_path configured.
      - Minimal config file on disk.

    Outputs:
      - 500 when config_path missing.
      - 200 text/plain containing dot digraph when config_path present.
    """

    cfg = {"webserver": {"auth": {"mode": "none"}}}

    status, _hdrs, body = _one_shot_http_request(
        method="GET",
        path="/api/v1/config/diagram.dot",
        config=cfg,
        config_path=None,
    )
    assert status == 500
    assert "config_path" in body.decode("utf-8")

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        (
            "server:\n"
            "  resolver:\n"
            "    mode: forward\n"
            "  http:\n"
            "    enabled: false\n"
            "listen:\n"
            "  udp:\n"
            "    enabled: false\n"
            "upstreams:\n"
            "  endpoints:\n"
            "    - transport: udp\n"
            "      host: 1.1.1.1\n"
            "      port: 53\n"
            "plugins: []\n"
        ),
        encoding="utf-8",
    )

    status2, hdrs2, body2 = _one_shot_http_request(
        method="GET",
        path="/api/v1/config/diagram.dot",
        config=cfg,
        config_path=str(cfg_path),
    )
    assert status2 == 200
    assert hdrs2.get("content-type", "").startswith("text/plain")
    text = body2.decode("utf-8")
    assert "digraph" in text


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
        _SnapshotPlugin("access_control"),
        _SnapshotPlugin("rate_limit"),
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
        "/api/v1/plugins/access_control/access_control",
        "/api/v1/plugins/rate_limit/rate_limit",
    ]:
        st, _h, b = _one_shot_http_request(
            method="GET", path=p, config=cfg, plugins=plugins
        )
        assert st == 200
        payload = json.loads(b.decode("utf-8"))
        assert payload.get("plugin") in {
            "docker_hosts",
            "mdns",
            "etc_hosts",
            "access_control",
            "rate_limit",
        }
        assert isinstance(payload.get("data"), dict)
    for p in [
        "/api/v1/plugins/unknown/docker_hosts",
        "/api/v1/plugins/unknown/mdns",
        "/api/v1/plugins/unknown/etc_hosts",
        "/api/v1/plugins/unknown/access_control",
        "/api/v1/plugins/unknown/rate_limit",
    ]:
        st5, _h5, b5 = _one_shot_http_request(
            method="GET",
            path=p,
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


def test_threaded_openapi_and_docs_oauth_edge_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: /openapi.json and /docs/oauth2-redirect return expected 404 variants.

    Inputs:
      - monkeypatch fixture for forcing schema cache helper to return None.

    Outputs:
      - /openapi.json returns text 404 when schema is disabled.
      - /docs/oauth2-redirect returns text 404 when docs/schema are disabled.
      - /openapi.json returns JSON 404 when schema generation is unavailable.
    """

    cfg_disabled = {
        "webserver": {
            "auth": {"mode": "none"},
            "enable_schema": False,
            "enable_docs": False,
        }
    }

    st1, _h1, b1 = _one_shot_http_request(
        method="GET", path="/openapi.json", config=cfg_disabled
    )
    assert st1 == 404
    assert b1 == b"openapi schema not available"

    st2, _h2, b2 = _one_shot_http_request(
        method="GET", path="/docs/oauth2-redirect", config=cfg_disabled
    )
    assert st2 == 404
    assert b2 == b"not found"

    monkeypatch.setattr(
        web_mod._ThreadedAdminRequestHandler,
        "_get_openapi_schema_cached",
        lambda _self: None,
    )
    cfg_enabled = {"webserver": {"auth": {"mode": "none"}, "enable_schema": True}}
    st3, h3, b3 = _one_shot_http_request(
        method="GET", path="/openapi.json", config=cfg_enabled
    )
    assert st3 == 404
    assert h3.get("content-type", "").startswith("application/json")
    assert json.loads(b3.decode("utf-8"))["detail"] == "openapi schema not available"


def test_threaded_get_openapi_schema_cached_fast_path() -> None:
    """Brief: _get_openapi_schema_cached returns an already-cached schema dict.

    Inputs:
      - Handler with server._openapi_schema_cache set.

    Outputs:
      - Cached schema dict is returned directly.
    """

    import types

    h = web_mod._ThreadedAdminRequestHandler.__new__(
        web_mod._ThreadedAdminRequestHandler
    )
    h.server = types.SimpleNamespace(_openapi_schema_cache={"openapi": "3.1.0"})
    assert h._get_openapi_schema_cached() == {"openapi": "3.1.0"}


def test_threaded_parse_multipart_form_file_corner_cases() -> None:
    """Brief: Multipart parser handles malformed and valid uploads defensively.

    Inputs:
      - Synthetic multipart Content-Type/header/body values.

    Outputs:
      - None for malformed inputs.
      - (filename, payload) tuple for valid file part.
    """

    h = web_mod._ThreadedAdminRequestHandler.__new__(
        web_mod._ThreadedAdminRequestHandler
    )

    assert (
        h._parse_multipart_form_file(
            body=b"abc", content_type="application/octet-stream", field_name="file"
        )
        is None
    )
    assert (
        h._parse_multipart_form_file(
            body=b"abc", content_type="multipart/form-data", field_name="file"
        )
        is None
    )

    malformed = (
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="x.png"\r\n'
        b"--BOUNDARY--\r\n"
    )
    assert (
        h._parse_multipart_form_file(
            body=malformed,
            content_type="multipart/form-data; boundary=BOUNDARY",
            field_name="file",
        )
        is None
    )

    wrong_field = _multipart_file_body(
        boundary="BOUNDARY",
        field_name="other",
        filename="x.png",
        payload=b"payload",
    )
    assert (
        h._parse_multipart_form_file(
            body=wrong_field,
            content_type="multipart/form-data; boundary=BOUNDARY",
            field_name="file",
        )
        is None
    )

    good = _multipart_file_body(
        boundary="BOUNDARY",
        field_name="file",
        filename="diagram.png",
        payload=b"\x89PNG\r\n\x1a\nDATA",
    )
    parsed = h._parse_multipart_form_file(
        body=good,
        content_type="multipart/form-data; boundary=BOUNDARY",
        field_name="file",
    )
    assert parsed == ("diagram.png", b"\x89PNG\r\n\x1a\nDATA")


def test_threaded_config_diagram_dark_png_meta_and_present(tmp_path: Path) -> None:
    """Brief: /api/v1/config/diagram-dark.png handles missing/meta/present cases.

    Inputs:
      - tmp_path containing a temporary config file and optional dark PNG.

    Outputs:
      - 500 when config_path is missing.
      - meta=1 returns X-Foghorn-Exists header.
      - Existing dark PNG returns image bytes.
    """

    cfg = {"webserver": {"auth": {"mode": "none"}}}

    st0, _h0, b0 = _one_shot_http_request(
        method="GET",
        path="/api/v1/config/diagram-dark.png",
        config=cfg,
        config_path=None,
    )
    assert st0 == 500
    assert "config_path" in b0.decode("utf-8")

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("webserver:\n  enabled: true\n", encoding="utf-8")

    st1, h1, b1 = _one_shot_http_request(
        method="GET",
        path="/api/v1/config/diagram-dark.png?meta=1",
        config=cfg,
        config_path=str(cfg_path),
    )
    assert st1 == 200
    assert b1 == b""
    assert h1.get("x-foghorn-exists") == "0"

    dark_png = Path(diagram_dark_png_path_for_config(str(cfg_path)))
    dark_png.parent.mkdir(parents=True, exist_ok=True)
    payload = b"\x89PNG\r\n\x1a\nDARK"
    dark_png.write_bytes(payload)

    st2, h2, b2 = _one_shot_http_request(
        method="GET",
        path="/api/v1/config/diagram-dark.png",
        config=cfg,
        config_path=str(cfg_path),
    )
    assert st2 == 200
    assert h2.get("content-type", "").startswith("image/png")
    assert h2.get("x-foghorn-exists") == "1"
    assert b2 == payload


def test_threaded_config_diagram_png_upload_validation_and_success(
    tmp_path: Path,
) -> None:
    """Brief: /api/v1/config/diagram.png upload validates and persists PNG data.

    Inputs:
      - tmp_path config file and multipart upload variants.

    Outputs:
      - Expected error statuses for invalid upload bodies.
      - 200 and persisted diagram.png for valid upload.
    """

    cfg = {"webserver": {"auth": {"mode": "none"}}}
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("webserver:\n  enabled: true\n", encoding="utf-8")

    st0, _h0, b0 = _one_shot_http_request(
        method="POST",
        path="/api/v1/config/diagram.png",
        config=cfg,
        config_path=None,
        headers={"Content-Type": "multipart/form-data; boundary=x"},
        body=b"",
    )
    assert st0 == 500
    assert "config_path" in b0.decode("utf-8")

    too_large_body = b"x" * (1_000_000 + 1_025)
    st1, _h1, b1 = _one_shot_http_request(
        method="POST",
        path="/api/v1/config/diagram.png",
        config=cfg,
        config_path=str(cfg_path),
        headers={"Content-Type": "multipart/form-data; boundary=x"},
        body=too_large_body,
    )
    assert st1 == 413
    assert "file too large" in b1.decode("utf-8")

    st2, _h2, b2 = _one_shot_http_request(
        method="POST",
        path="/api/v1/config/diagram.png",
        config=cfg,
        config_path=str(cfg_path),
        headers={"Content-Type": "multipart/form-data; boundary=x"},
        body=b"not-a-multipart-payload",
    )
    assert st2 == 400
    assert "invalid multipart upload" in b2.decode("utf-8")

    png_sig = b"\x89PNG\r\n\x1a\n"
    bad_ext = _multipart_file_body(
        boundary="b-ext",
        filename="diagram.txt",
        payload=png_sig + b"ABC",
    )
    st3, _h3, b3 = _one_shot_http_request(
        method="POST",
        path="/api/v1/config/diagram.png",
        config=cfg,
        config_path=str(cfg_path),
        headers={"Content-Type": "multipart/form-data; boundary=b-ext"},
        body=bad_ext,
    )
    assert st3 == 400
    assert "file must have .png extension" in b3.decode("utf-8")

    not_png = _multipart_file_body(
        boundary="b-not-png",
        filename="diagram.png",
        payload=b"plain-text",
    )
    st4, _h4, b4 = _one_shot_http_request(
        method="POST",
        path="/api/v1/config/diagram.png",
        config=cfg,
        config_path=str(cfg_path),
        headers={"Content-Type": "multipart/form-data; boundary=b-not-png"},
        body=not_png,
    )
    assert st4 == 400
    assert "does not look like a PNG" in b4.decode("utf-8")

    oversized_payload = png_sig + (b"A" * (1_000_001 - len(png_sig)))
    overs_payload_body = _multipart_file_body(
        boundary="b-oversize-payload",
        filename="diagram.png",
        payload=oversized_payload,
    )
    st5, _h5, b5 = _one_shot_http_request(
        method="POST",
        path="/api/v1/config/diagram.png",
        config=cfg,
        config_path=str(cfg_path),
        headers={"Content-Type": "multipart/form-data; boundary=b-oversize-payload"},
        body=overs_payload_body,
    )
    assert st5 == 413
    assert "file too large" in b5.decode("utf-8")

    payload = png_sig + b"VALID"
    good = _multipart_file_body(
        boundary="b-good",
        filename="diagram.png",
        payload=payload,
    )
    st6, _h6, b6 = _one_shot_http_request(
        method="POST",
        path="/api/v1/config/diagram.png",
        config=cfg,
        config_path=str(cfg_path),
        headers={"Content-Type": "multipart/form-data; boundary=b-good"},
        body=good,
    )
    assert st6 == 200
    out = json.loads(b6.decode("utf-8"))
    assert out["status"] == "ok"
    assert out["size_bytes"] == len(payload)
    assert (cfg_path.parent / "diagram.png").read_bytes() == payload


def test_threaded_descriptor_and_hash_helpers_defensive_branches() -> None:
    """Brief: Helper branches for descriptor parsing and hash-like detection.

    Inputs:
      - Synthetic descriptor objects and host labels.

    Outputs:
      - Descriptor helper resolves/falls back as expected.
      - Hash-like helper only accepts 12-64 character hex labels.
    """

    h = web_mod._ThreadedAdminRequestHandler.__new__(
        web_mod._ThreadedAdminRequestHandler
    )

    assert h._table_path_from_descriptor(None, "x") == ("x", None, "asc")
    assert h._table_path_from_descriptor({"layout": []}, "x") == ("x", None, "asc")
    assert h._table_path_from_descriptor({"layout": {"sections": "bad"}}, "x") == (
        "x",
        None,
        "asc",
    )
    assert h._table_path_from_descriptor(
        {"layout": {"sections": [{"id": "x", "type": "chart", "path": "a.b"}]}}, "x"
    ) == ("", None, "asc")
    assert h._table_path_from_descriptor(
        {"layout": {"sections": ["bad", {"id": "y", "type": "table", "path": "x"}]}},
        "x",
    ) == ("", None, "asc")
    assert h._table_path_from_descriptor(
        {
            "layout": {
                "sections": [
                    {"id": "x", "type": "table", "path": "tables.x", "sort": "by_calls"}
                ]
            }
        },
        "x",
    ) == ("tables.x", "calls_total", "desc")

    assert h._is_hex_hash_like("0123456789ab.example") is True
    assert h._is_hex_hash_like("0123456789ag.example") is False
    assert h._is_hex_hash_like("abcd") is False
    assert h._is_hex_hash_like("a" * 65) is False


def test_threaded_schedule_restart_calls_signal_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _schedule_restart delegates to _schedule_process_signal with SIGHUP.

    Inputs:
      - monkeypatch fixture replacing _schedule_process_signal.

    Outputs:
      - Captured signal and delay arguments reflect SIGHUP and requested delay.
    """

    import importlib
    import signal

    th = importlib.import_module("foghorn.servers.webserver.threaded_handlers")

    h = web_mod._ThreadedAdminRequestHandler.__new__(
        web_mod._ThreadedAdminRequestHandler
    )
    captured: list[tuple[int, float]] = []

    monkeypatch.setattr(
        th,
        "_schedule_process_signal",
        lambda sig, delay_seconds: captured.append((int(sig), float(delay_seconds))),
    )
    h._schedule_restart(delay_seconds=2.5)
    assert captured == [(int(signal.SIGHUP), 2.5)]


def test_threaded_cache_snapshot_and_table_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Threaded cache endpoints cover missing, error, and table filter branches.

    Inputs:
      - monkeypatch fixture replacing global DNS cache object.

    Outputs:
      - /api/v1/cache returns 404/500/200 across cache states.
      - /api/v1/cache/table filters and error branches behave as expected.
    """

    from foghorn.plugins.resolve import base as plugin_base

    cfg = {"webserver": {"auth": {"mode": "none"}}}

    monkeypatch.setattr(plugin_base, "DNS_CACHE", None, raising=False)
    st0, _h0, b0 = _one_shot_http_request(
        method="GET", path="/api/v1/cache", config=cfg
    )
    assert st0 == 404
    assert "cache plugin not found" in b0.decode("utf-8")

    class _ExplodingCache:
        name = "explode"

        def get_http_snapshot(self) -> Dict[str, Any]:
            raise RuntimeError("boom")

    monkeypatch.setattr(plugin_base, "DNS_CACHE", _ExplodingCache(), raising=False)
    st1, _h1, b1 = _one_shot_http_request(
        method="GET", path="/api/v1/cache", config=cfg
    )
    assert st1 == 500
    assert "failed to build cache snapshot" in b1.decode("utf-8")
    st1b, _h1b, b1b = _one_shot_http_request(
        method="GET", path="/api/v1/cache/table/clients", config=cfg
    )
    assert st1b == 500
    assert "failed to build cache snapshot" in b1b.decode("utf-8")

    class _DummyCache:
        name = "dummy-cache"

        def get_http_snapshot(self) -> Dict[str, Any]:
            return {
                "tables": {
                    "clients": [
                        {"name": "zero.example", "calls_total": 0, "cache_hits": 0},
                        {"name": "good.example", "calls_total": 3, "cache_hits": 2},
                    ]
                }
            }

        def get_admin_ui_descriptor(self) -> Dict[str, Any]:
            return {
                "layout": {
                    "sections": [
                        {
                            "id": "clients",
                            "type": "table",
                            "path": "tables.clients",
                            "sort": "by_calls",
                        }
                    ]
                }
            }

    monkeypatch.setattr(plugin_base, "DNS_CACHE", _DummyCache(), raising=False)
    st2, _h2, b2 = _one_shot_http_request(
        method="GET", path="/api/v1/cache", config=cfg
    )
    assert st2 == 200
    assert json.loads(b2.decode("utf-8"))["cache"] == "dummy-cache"

    st3, _h3, b3 = _one_shot_http_request(
        method="GET",
        path="/api/v1/cache/table/clients?hide_zero_calls=1&hide_zero_hits=1",
        config=cfg,
    )
    assert st3 == 200
    payload3 = json.loads(b3.decode("utf-8"))
    items = payload3.get("items") or []
    assert len(items) == 1
    assert items[0]["name"] == "good.example"
    assert payload3.get("sort_key") == "calls_total"
    assert payload3.get("sort_dir") == "desc"

    st4, _h4, b4 = _one_shot_http_request(
        method="GET", path="/api/v1/cache/table/nope", config=cfg
    )
    assert st4 == 404
    assert "cache table not found" in b4.decode("utf-8")

    st5, _h5, b5 = _one_shot_http_request(
        method="GET", path="/api/v1/cache/table/", config=cfg
    )
    assert st5 == 404
    assert "cache table not found" in b5.decode("utf-8")


def test_threaded_plugins_ui_descriptors_includes_global_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: /api/v1/plugins/ui includes global DNS cache descriptor when exposed.

    Inputs:
      - monkeypatch fixture setting plugins.resolve.base.DNS_CACHE.

    Outputs:
      - Response includes descriptor contributed by global DNS cache object.
    """

    from foghorn.plugins.resolve import base as plugin_base

    class _DummyCache:
        name = "global-cache"

        def get_admin_ui_descriptor(self) -> Dict[str, Any]:
            return {
                "name": self.name,
                "title": "Global Cache",
                "kind": "cache",
                "order": 5,
            }

    monkeypatch.setattr(plugin_base, "DNS_CACHE", _DummyCache(), raising=False)
    cfg = {"webserver": {"auth": {"mode": "none"}}}
    st, _h, b = _one_shot_http_request(
        method="GET", path="/api/v1/plugins/ui", config=cfg, plugins=[]
    )
    assert st == 200
    items = json.loads(b.decode("utf-8")).get("items") or []
    assert any(item.get("name") == "global-cache" for item in items)


def test_threaded_plugin_table_additional_branches() -> None:
    """Brief: Threaded plugin table endpoint covers success and key error paths.

    Inputs:
      - Dummy plugins that expose admin descriptor/snapshot table data.

    Outputs:
      - hide_hash_like removes hash-like rows.
      - Missing table/plugin and snapshot failures return 404/500.
    """

    class _TablePlugin:
        def __init__(self, name: str) -> None:
            self.name = name

        def get_admin_ui_descriptor(self) -> Dict[str, Any]:
            return {
                "layout": {
                    "sections": [
                        {
                            "id": "entries",
                            "type": "table",
                            "path": "tables.entries",
                            "sort": "by_calls",
                        }
                    ]
                }
            }

        def get_http_snapshot(self) -> Dict[str, Any]:
            return {
                "tables": {
                    "entries": [
                        {"name": "0123456789ab.example", "calls_total": 1},
                        {"name": "good.example", "calls_total": 8},
                    ]
                }
            }

    class _ExplodingPlugin(_TablePlugin):
        def get_http_snapshot(self) -> Dict[str, Any]:
            raise RuntimeError("snapshot-fail")

    cfg = {"webserver": {"auth": {"mode": "none"}}}
    plugins = [_TablePlugin("demo"), _ExplodingPlugin("boom")]

    st1, _h1, b1 = _one_shot_http_request(
        method="GET",
        path="/api/v1/plugins/demo/table/entries?hide_hash_like=1",
        config=cfg,
        plugins=plugins,
    )
    assert st1 == 200
    payload1 = json.loads(b1.decode("utf-8"))
    assert payload1["plugin"] == "demo"
    assert [row["name"] for row in payload1.get("items") or []] == ["good.example"]

    st2, _h2, b2 = _one_shot_http_request(
        method="GET",
        path="/api/v1/plugins/demo/table/nope",
        config=cfg,
        plugins=plugins,
    )
    assert st2 == 404
    assert "plugin table not found" in b2.decode("utf-8")

    st3, _h3, b3 = _one_shot_http_request(
        method="GET",
        path="/api/v1/plugins/missing/table/entries",
        config=cfg,
        plugins=plugins,
    )
    assert st3 == 404
    assert "plugin not found" in b3.decode("utf-8")

    st4, _h4, b4 = _one_shot_http_request(
        method="GET",
        path="/api/v1/plugins/boom/table/entries",
        config=cfg,
        plugins=plugins,
    )
    assert st4 == 500
    assert "failed to build plugin snapshot" in b4.decode("utf-8")


def test_threaded_reload_and_save_handlers_direct_branching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Direct tests for save/reload handlers cover major non-trivial branches.

    Inputs:
      - monkeypatch fixture replacing runtime_config and scheduling side effects.

    Outputs:
      - Exercises 400/409/500/200 branches for save-and-reload/reload endpoints.
      - Verifies successful reload updates server config/plugins.
    """

    import types

    from foghorn import runtime_config

    h = web_mod._ThreadedAdminRequestHandler.__new__(
        web_mod._ThreadedAdminRequestHandler
    )
    h.server = types.SimpleNamespace(
        config={"old": True},
        plugins=["old"],
        config_path="/tmp/test-config.yaml",
    )
    h.headers = {}
    monkeypatch.setattr(h, "_require_auth", lambda: True)

    calls: list[tuple[int, dict[str, Any], dict[str, str] | None]] = []

    def _capture_send_json(
        status_code: int,
        payload: Dict[str, Any],
        headers: Dict[str, str] | None = None,
    ) -> None:
        calls.append((status_code, payload, headers))

    monkeypatch.setattr(h, "_send_json", _capture_send_json)
    monkeypatch.setattr(
        h,
        "_save_config_to_disk",
        lambda *, body: (_ for _ in ()).throw(ValueError("bad payload")),
    )
    h._handle_config_save_and_reload({"raw_yaml": "x"})
    assert calls[-1][0] == 400

    monkeypatch.setattr(
        h,
        "_save_config_to_disk",
        lambda *, body: (_ for _ in ()).throw(RuntimeError("write failed")),
    )
    h._handle_config_save_and_reload({"raw_yaml": "x"})
    assert calls[-1][0] == 500

    monkeypatch.setattr(
        h,
        "_save_config_to_disk",
        lambda *, body: {
            "cfg_path_abs": "/tmp/test-config.yaml",
            "backup_path": "/tmp/test-config.yaml.bak",
            "analysis": {"restart_required": True},
        },
    )
    h._handle_config_save_and_reload({"raw_yaml": "x"})
    assert calls[-1][0] == 409

    monkeypatch.setattr(
        h,
        "_save_config_to_disk",
        lambda *, body: {
            "cfg_path_abs": "/tmp/test-config.yaml",
            "backup_path": "/tmp/test-config.yaml.bak",
            "analysis": {"restart_required": False},
        },
    )
    monkeypatch.setattr(
        runtime_config,
        "reload_from_disk",
        lambda **_kw: types.SimpleNamespace(
            ok=True,
            generation=3,
            restart_required=True,
            restart_reasons=["x"],
            error=None,
        ),
    )
    monkeypatch.setattr(
        runtime_config,
        "get_runtime_snapshot",
        lambda: types.SimpleNamespace(cfg={"updated": True}, plugins=["p1"]),
    )
    h._handle_config_save_and_reload({"raw_yaml": "x"})
    assert calls[-1][0] == 409
    assert calls[-1][1]["reload"]["restart_required"] is True

    monkeypatch.setattr(
        runtime_config,
        "reload_from_disk",
        lambda **_kw: types.SimpleNamespace(
            ok=False,
            generation=4,
            restart_required=False,
            restart_reasons=[],
            error="reload failed",
        ),
    )
    h._handle_config_save_and_reload({"raw_yaml": "x"})
    assert calls[-1][0] == 500
    assert calls[-1][1]["status"] == "error"

    monkeypatch.setattr(
        runtime_config,
        "reload_from_disk",
        lambda **_kw: types.SimpleNamespace(
            ok=True,
            generation=5,
            restart_required=False,
            restart_reasons=[],
            error=None,
        ),
    )
    h._handle_config_save_and_reload({"raw_yaml": "x"})
    assert calls[-1][0] == 200
    assert h.server.config == {"updated": True}
    assert h.server.plugins == ["p1"]

    scheduled: list[float] = []
    monkeypatch.setattr(
        h,
        "_schedule_restart",
        lambda *, delay_seconds=1.0: scheduled.append(float(delay_seconds)),
    )
    monkeypatch.setattr(
        h,
        "_save_config_to_disk",
        lambda *, body: (_ for _ in ()).throw(ValueError("bad payload")),
    )
    h._handle_config_save_and_restart({"raw_yaml": "x"})
    assert calls[-1][0] == 400
    monkeypatch.setattr(
        h,
        "_save_config_to_disk",
        lambda *, body: (_ for _ in ()).throw(RuntimeError("write failed")),
    )
    h._handle_config_save_and_restart({"raw_yaml": "x"})
    assert calls[-1][0] == 500
    monkeypatch.setattr(
        h,
        "_save_config_to_disk",
        lambda *, body: {
            "cfg_path_abs": "/tmp/test-config.yaml",
            "backup_path": "/tmp/test-config.yaml.bak",
            "analysis": {"restart_required": False},
        },
    )
    h._handle_config_save_and_restart({"raw_yaml": "x"})
    assert calls[-1][0] == 200
    assert scheduled == [1.0]

    h.server.config_path = None
    h._handle_config_reload_reloadable()
    assert calls[-1][0] == 500

    monkeypatch.setattr(
        runtime_config,
        "load_config_from_disk",
        lambda **_kw: (_ for _ in ()).throw(ValueError("bad config")),
    )
    h.server.config_path = "/tmp/test-config.yaml"
    h._handle_config_reload_reloadable()
    assert calls[-1][0] == 400

    monkeypatch.setattr(
        runtime_config, "load_config_from_disk", lambda **_kw: {"cfg": 1}
    )
    monkeypatch.setattr(
        runtime_config,
        "analyze_config_change",
        lambda desired_cfg, current_cfg: {"restart_required": True},
    )
    monkeypatch.setattr(
        runtime_config,
        "reload_from_config",
        lambda *_a, **_kw: types.SimpleNamespace(
            ok=True,
            generation=6,
            restart_required=True,
            restart_reasons=["x"],
            error=None,
        ),
    )
    h._handle_config_reload_reloadable()
    assert calls[-1][0] == 200
    assert "restart required" in calls[-1][1]["message"]

    monkeypatch.setattr(
        runtime_config,
        "analyze_config_change",
        lambda desired_cfg, current_cfg: {"restart_required": True},
    )
    h._handle_config_reload()
    assert calls[-1][0] == 409

    monkeypatch.setattr(
        runtime_config,
        "analyze_config_change",
        lambda desired_cfg, current_cfg: {"restart_required": False},
    )
    monkeypatch.setattr(
        runtime_config,
        "reload_from_config",
        lambda *_a, **_kw: types.SimpleNamespace(
            ok=False,
            generation=7,
            restart_required=False,
            restart_reasons=[],
            error="x",
        ),
    )
    h._handle_config_reload()
    assert calls[-1][0] == 500

    monkeypatch.setattr(
        runtime_config,
        "reload_from_config",
        lambda *_a, **_kw: types.SimpleNamespace(
            ok=True,
            generation=8,
            restart_required=False,
            restart_reasons=[],
            error=None,
        ),
    )
    monkeypatch.setattr(
        runtime_config,
        "get_runtime_snapshot",
        lambda: types.SimpleNamespace(cfg={"fresh": 1}, plugins=["p2"]),
    )
    h._handle_config_reload()
    assert calls[-1][0] == 200
    assert h.server.config == {"fresh": 1}
    assert h.server.plugins == ["p2"]
