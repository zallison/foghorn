"""Brief: Tests for foghorn.servers.webserver admin UI helpers and endpoints.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

try:  # FastAPI is an optional dependency
    from fastapi.testclient import TestClient
except ModuleNotFoundError:  # pragma: no cover - environment dependent
    TestClient = None
    pytest.skip(
        "fastapi not installed; skipping webserver admin UI tests",
        allow_module_level=True,
    )

from foghorn.servers.webserver import AdminPageSpec, create_app, start_webserver


class _PluginWithPages:
    """Brief: Dummy plugin exposing get_admin_pages and get_admin_ui_descriptor.

    Inputs:
      - name: plugin instance name.

    Outputs:
      - Instances used for admin page/descriptor collection tests.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def get_admin_pages(self) -> List[AdminPageSpec]:
        return [
            AdminPageSpec(slug="summary", title="Summary", description="d1"),
            # Invalid (no slug/title) should be ignored.
            AdminPageSpec(slug="", title=""),
        ]

    def get_admin_ui_descriptor(self) -> Dict[str, Any]:
        # Include instance name in title so normalisation strips it.
        return {
            "name": self.name,
            "title": f"Docker ({self.name})",
            "order": 10,
            "kind": "docker_hosts",
        }


class _EtcHostsPlugin:
    def __init__(self, name: str) -> None:
        self.name = name

    def get_http_snapshot(self) -> Dict[str, Any]:  # pragma: no cover - via handler
        return {"plugin": self.name, "data": "ok"}


@pytest.fixture
def web_config(tmp_path: Path) -> Dict[str, Any]:
    www_root = tmp_path / "html"
    www_root.mkdir()
    (www_root / "index.html").write_text("<html>ok</html>", encoding="utf-8")

    return {
        "webserver": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 0,
            "index": True,
        },
        "foghorn": {"use_asyncio": False},
        "www_root": str(www_root),
    }


@pytest.fixture
def web_app(web_config: Dict[str, Any]) -> TestClient:
    plugins: List[object] = [
        _PluginWithPages("docker"),
        _EtcHostsPlugin("docker_hosts"),
        _EtcHostsPlugin("etc_hosts"),
        _EtcHostsPlugin("mdns"),
    ]
    app = create_app(
        stats=None,
        config=web_config,
        log_buffer=None,
        config_path=None,
        runtime_state=None,
        plugins=plugins,
    )
    # Attach www_root to app.state so static/index handlers can find it.
    app.state.www_root = web_config["www_root"]
    return TestClient(app)


def test_list_plugin_pages_and_detail(web_app: TestClient) -> None:
    resp = web_app.get("/api/v1/plugin_pages")
    assert resp.status_code == 200
    data = resp.json()
    pages = data["pages"]
    # Only valid pages should be present.
    assert any(p["slug"] == "summary" and p["title"] == "Summary" for p in pages)

    # Detail endpoint for existing page.
    resp2 = web_app.get("/api/v1/plugin_pages/docker/summary")
    assert resp2.status_code == 200
    page = resp2.json()["page"]
    assert page["slug"] == "summary"
    assert page["title"] == "Summary"

    # Unknown plugin/page -> 404.
    resp3 = web_app.get("/api/v1/plugin_pages/unknown/summary")
    assert resp3.status_code == 404


def test_list_plugin_ui_descriptors_and_title_normalisation(
    web_app: TestClient,
) -> None:
    resp = web_app.get("/api/v1/plugins/ui")
    assert resp.status_code == 200
    items = resp.json()["items"]
    # Descriptor from _PluginWithPages should be present with normalised title.
    names = {it["name"] for it in items}
    assert "docker" in names
    titles = {it["title"] for it in items}
    # Base title "Docker" without suffix should appear at least once.
    assert any(t.startswith("Docker") for t in titles)


def test_cache_snapshot_404_and_success(
    monkeypatch: pytest.MonkeyPatch, web_config: Dict[str, Any]
) -> None:
    from foghorn.plugins import base as plugin_base

    # First, ensure 404 when DNS_CACHE is missing or lacks helper.
    monkeypatch.setattr(plugin_base, "DNS_CACHE", None, raising=False)
    app_404 = create_app(None, web_config, None, None, None, plugins=[])
    client_404 = TestClient(app_404)
    r404 = client_404.get("/api/v1/cache")
    assert r404.status_code == 404

    # Then provide a cache with get_http_snapshot.
    class DummyCache:
        def __init__(self) -> None:
            self.name = "dummy_cache"

        def get_http_snapshot(self) -> Dict[str, Any]:  # pragma: no cover - via handler
            return {"ok": True}

    monkeypatch.setattr(plugin_base, "DNS_CACHE", DummyCache(), raising=False)
    app_ok = create_app(None, web_config, None, None, None, plugins=[])
    client_ok = TestClient(app_ok)
    r_ok = client_ok.get("/api/v1/cache")
    assert r_ok.status_code == 200
    payload = r_ok.json()
    assert payload["cache"] == "dummy_cache"
    assert payload["data"]["ok"] is True


def test_plugin_specific_snapshot_endpoints(web_app: TestClient) -> None:
    # DockerHosts snapshot
    r_docker = web_app.get("/api/v1/plugins/docker_hosts/docker_hosts")
    assert r_docker.status_code == 200
    assert r_docker.json()["plugin"] == "docker_hosts"

    # EtcHosts snapshot
    r_etc = web_app.get("/api/v1/plugins/etc_hosts/etc_hosts")
    assert r_etc.status_code == 200
    assert r_etc.json()["plugin"] == "etc_hosts"

    # Mdns snapshot
    r_mdns = web_app.get("/api/v1/plugins/mdns/mdns")
    assert r_mdns.status_code == 200
    assert r_mdns.json()["plugin"] == "mdns"

    # Unknown plugin -> 404
    r_unknown = web_app.get("/api/v1/plugins/unknown/docker_hosts")
    assert r_unknown.status_code == 404


def test_index_and_static_www_serving(
    tmp_path: Path, web_config: Dict[str, Any]
) -> None:
    # Ensure index.html exists in www_root from fixture.
    app = create_app(None, web_config, None, None, None, plugins=[])
    app.state.www_root = web_config["www_root"]
    client = TestClient(app)

    r_index = client.get("/")
    assert r_index.status_code == 200
    assert "ok" in r_index.text

    # Static file path under html/.
    www_root = Path(web_config["www_root"])
    sub = www_root / "css"
    sub.mkdir()
    (sub / "file.txt").write_text("hello", encoding="utf-8")

    r_static = client.get("/css/file.txt")
    assert r_static.status_code == 200
    assert r_static.text == "hello"

    # Path traversal outside root must return 404.
    r_traverse = client.get("/../secret.txt")
    assert r_traverse.status_code == 404


def test_start_webserver_threaded_fallback(
    monkeypatch: pytest.MonkeyPatch, web_config: Dict[str, Any]
) -> None:
    """Brief: start_webserver falls back to minimal _start_admin_server_threaded call.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts fallback path is taken when initial call raises.
    """

    from foghorn.servers import webserver as ws

    # Ensure webserver is enabled and use_asyncio is False so threaded path is used.
    cfg = dict(web_config)

    calls: dict[str, int] = {"n": 0}

    class DummyHandle:
        pass

    def fake_start_threaded(stats_obj, cfg_obj, buf_obj, **kwargs):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return DummyHandle()

    monkeypatch.setattr(ws, "_start_admin_server_threaded", fake_start_threaded)

    handle = start_webserver(
        stats=None,
        config=cfg,
        log_buffer=None,
        config_path=None,
        runtime_state=None,
        plugins=[],
    )

    assert isinstance(handle, DummyHandle)
    assert calls["n"] == 2
