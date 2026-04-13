"""Brief: Additional branch-coverage tests for FastAPI routes_core endpoints.

Inputs:
  - pytest fixtures (`tmp_path`, `monkeypatch`).
  - FastAPI TestClient requests and direct endpoint calls.

Outputs:
  - Assertions that non-trivial defensive/error branches in routes_core are
    exercised and return stable response shapes/status codes.
"""

from __future__ import annotations

import asyncio
import builtins
import importlib
import os
import signal
import types
from pathlib import Path
from typing import Any

import pytest

try:  # FastAPI is an optional dependency
    from fastapi import HTTPException
    from fastapi.testclient import TestClient
except ModuleNotFoundError:  # pragma: no cover - environment dependent
    TestClient = None
    pytest.skip(
        "fastapi not installed; skipping routes_core branch tests",
        allow_module_level=True,
    )

from foghorn.servers.webserver import RingBuffer, create_app
from foghorn.utils.config_diagram import (
    diagram_dark_png_path_for_config,
    diagram_dot_path_for_config,
    diagram_png_path_for_config,
)

admin_logic_mod = importlib.import_module("foghorn.servers.webserver.admin_logic")
routes_core_mod = importlib.import_module("foghorn.servers.webserver.routes_core")


def _create_test_app(
    *, config_path: str | None = None, plugins: list[object] | None = None
):
    """Brief: Build a minimal FastAPI admin app for endpoint branch testing.

    Inputs:
      - config_path: Optional path for config-backed endpoints.
      - plugins: Optional plugin instances attached to app.state.plugins.

    Outputs:
      - FastAPI application instance from `create_app`.
    """

    return create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=RingBuffer(),
        config_path=config_path,
        runtime_state=None,
        plugins=plugins or [],
    )


def _get_route_endpoint(app: Any, *, path: str, method: str):
    """Brief: Return a registered route endpoint callable by path/method.

    Inputs:
      - app: FastAPI application instance.
      - path: Route path template as registered on app.router.
      - method: HTTP method name (GET/POST/...) to match.

    Outputs:
      - The endpoint callable associated with the matching route.
    """

    method_u = str(method or "").upper()
    for route in app.router.routes:
        if getattr(route, "path", None) != path:
            continue
        methods = set(getattr(route, "methods", set()) or set())
        if method_u in methods:
            return route.endpoint
    raise AssertionError(f"route not found: {method_u} {path}")


def _reload_result(
    *,
    ok: bool,
    generation: int = 1,
    restart_required: bool = False,
    restart_reasons: list[str] | None = None,
    error: str | None = None,
) -> Any:
    """Brief: Build a runtime_config reload result object for tests.

    Inputs:
      - ok/generation/restart_required/restart_reasons/error: Reload result fields.

    Outputs:
      - SimpleNamespace carrying the expected reload attributes.
    """

    return types.SimpleNamespace(
        ok=bool(ok),
        generation=int(generation),
        restart_required=bool(restart_required),
        restart_reasons=list(restart_reasons or []),
        error=error,
    )


def _patch_save_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    *,
    analysis: dict[str, Any],
) -> Any:
    """Brief: Stub save-to-disk internals to control save/reload branches.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - analysis: Dict returned by runtime_config.analyze_config_change.

    Outputs:
      - Imported `foghorn.runtime_config` module after monkeypatching.
    """

    from foghorn import runtime_config

    monkeypatch.setattr(
        routes_core_mod._config_persistence,
        "safe_write_raw_yaml",
        lambda **_kw: None,
    )
    monkeypatch.setattr(
        runtime_config, "load_config_from_disk", lambda **_kw: {"server": {}}
    )
    monkeypatch.setattr(
        runtime_config,
        "analyze_config_change",
        lambda _desired, current_cfg=None: dict(analysis),
    )
    return runtime_config


def test_config_diagram_png_missing_config_path_returns_500() -> None:
    """Brief: /api/v1/config/diagram.png returns 500 when config_path is unset.

    Inputs:
      - App created without config_path.

    Outputs:
      - HTTP 500 with a config_path-not-configured detail.
    """

    app = _create_test_app(config_path=None)
    client = TestClient(app)
    resp = client.get("/api/v1/config/diagram.png")
    assert resp.status_code == 500
    assert "config_path not configured" in resp.text


def test_config_diagram_png_meta_warning_and_stat_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: /api/v1/config/diagram.png meta path sets warning headers robustly.

    Inputs:
      - Existing diagram PNG file.
      - os.stat patched to raise, forcing cfg_sig fallback path.
      - stale_diagram_warning patched to return a warning string.

    Outputs:
      - HTTP 200 empty response with X-Foghorn-Exists=1 and warning header.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("webserver:\n  enabled: true\n", encoding="utf-8")
    png_path = Path(diagram_png_path_for_config(str(cfg_path)))
    png_path.write_bytes(b"\x89PNG\r\n\x1a\nMETA")

    real_stat = routes_core_mod.os.stat

    def _fake_stat(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *args: Any,
        **kwargs: Any,
    ):
        if str(path) == str(cfg_path):
            raise OSError("no-stat")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(routes_core_mod.os, "stat", _fake_stat)
    monkeypatch.setattr(
        routes_core_mod,
        "stale_diagram_warning",
        lambda **_kw: "stale-diagram",
    )

    app = _create_test_app(config_path=str(cfg_path))
    client = TestClient(app)
    resp = client.get("/api/v1/config/diagram.png?meta=1")
    assert resp.status_code == 200
    assert resp.text == ""
    assert resp.headers.get("x-foghorn-exists") == "1"
    assert resp.headers.get("x-foghorn-warning") == "stale-diagram"


def test_config_diagram_dark_png_on_demand_build_and_meta_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: /api/v1/config/diagram-dark.png covers on-demand build and meta warn.

    Inputs:
      - Config path with no dark PNG initially.
      - config_diagram `_find_dot_cmd` and `ensure_config_diagram_png` stubs.
      - stale_diagram_warning returning a deterministic warning.

    Outputs:
      - On-demand request returns image/png with generated bytes.
      - meta=1 response includes X-Foghorn-Warning.
    """

    import foghorn.utils.config_diagram as diagram_mod

    missing_cfg_app = _create_test_app(config_path=None)
    missing_cfg_client = TestClient(missing_cfg_app)
    assert missing_cfg_client.get("/api/v1/config/diagram-dark.png").status_code == 500

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("webserver:\n  enabled: true\n", encoding="utf-8")
    dark_path = Path(diagram_dark_png_path_for_config(str(cfg_path)))

    def _ensure_png(*, config_path: str) -> tuple[bool, str, str]:
        _ = config_path
        dark_path.parent.mkdir(parents=True, exist_ok=True)
        dark_path.write_bytes(b"\x89PNG\r\n\x1a\nDARK")
        return True, "rendered", str(dark_path)

    monkeypatch.setattr(diagram_mod, "_find_dot_cmd", lambda: "/usr/bin/dot")
    monkeypatch.setattr(diagram_mod, "ensure_config_diagram_png", _ensure_png)
    monkeypatch.setattr(
        routes_core_mod,
        "stale_diagram_warning",
        lambda **_kw: "dark-stale",
    )
    real_stat = routes_core_mod.os.stat

    def _fake_stat(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *args: Any,
        **kwargs: Any,
    ):
        if str(path) == str(cfg_path):
            raise OSError("no-stat")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(routes_core_mod.os, "stat", _fake_stat)

    app = _create_test_app(config_path=str(cfg_path))
    client = TestClient(app)

    resp = client.get("/api/v1/config/diagram-dark.png")
    assert resp.status_code == 200
    assert resp.headers.get("content-type", "").startswith("image/png")
    assert resp.content.endswith(b"DARK")

    resp_meta = client.get("/api/v1/config/diagram-dark.png?meta=1")
    assert resp_meta.status_code == 200
    assert resp_meta.headers.get("x-foghorn-warning") == "dark-stale"


def test_config_diagram_dark_png_missing_without_dot_returns_404(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: Dark diagram endpoint returns 404 when no file exists and dot is absent.

    Inputs:
      - Config path with no dark diagram artifacts.
      - dot discovery patched to None.

    Outputs:
      - HTTP 404 with a not-found message.
    """

    import foghorn.utils.config_diagram as diagram_mod

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("webserver:\n  enabled: true\n", encoding="utf-8")
    monkeypatch.setattr(diagram_mod, "_find_dot_cmd", lambda: None)
    app = _create_test_app(config_path=str(cfg_path))
    client = TestClient(app)
    missing = client.get("/api/v1/config/diagram-dark.png")
    assert missing.status_code == 404
    assert "config diagram not found" in missing.text


def test_upload_config_diagram_png_defensive_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: Upload endpoint handles missing config_path, bad payloads, and bad PNGs.

    Inputs:
      - App instances with and without config_path.
      - Direct endpoint call with a custom upload object returning non-bytes.

    Outputs:
      - 500 for missing config_path.
      - HTTPException(400) for non-bytes payload while close() raises.
      - 400 for non-PNG signature over multipart upload.
    """

    app_no_cfg = _create_test_app(config_path=None)
    client_no_cfg = TestClient(app_no_cfg)
    missing = client_no_cfg.post(
        "/api/v1/config/diagram.png",
        files={"file": ("diagram.png", b"\x89PNG\r\n\x1a\nX", "image/png")},
    )
    assert missing.status_code == 500

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("webserver:\n  enabled: true\n", encoding="utf-8")
    app = _create_test_app(config_path=str(cfg_path))
    endpoint = _get_route_endpoint(
        app, path="/api/v1/config/diagram.png", method="POST"
    )

    class _WeirdUpload:
        filename = "diagram.png"

        async def read(self, _limit: int) -> str:
            return "not-bytes"

        async def close(self) -> None:
            raise RuntimeError("close-failure")

    async def _run_direct_call() -> None:
        with pytest.raises(HTTPException) as excinfo:
            await endpoint(file=_WeirdUpload())
        assert excinfo.value.status_code == 400
        assert "invalid upload payload" in str(excinfo.value.detail)

    asyncio.run(_run_direct_call())

    client = TestClient(app)
    bad_sig = client.post(
        "/api/v1/config/diagram.png",
        files={"file": ("diagram.png", b"not-a-png", "image/png")},
    )
    assert bad_sig.status_code == 400
    assert "does not look like a PNG" in bad_sig.text


def test_config_diagram_dot_meta_file_and_generate_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: /api/v1/config/diagram.dot covers meta, read-file, and generation.

    Inputs:
      - Config path with diagram.png and diagram.dot files.
      - stale_diagram_warning and generate_dot_text_from_config_path stubs.

    Outputs:
      - 500 when config_path missing.
      - meta includes warning headers.
      - Existing dot file is returned as text/plain.
      - Missing dot file falls back to generated dot text.
    """

    no_cfg_app = _create_test_app(config_path=None)
    no_cfg_client = TestClient(no_cfg_app)
    assert no_cfg_client.get("/api/v1/config/diagram.dot").status_code == 500

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("webserver:\n  enabled: true\n", encoding="utf-8")

    png_path = Path(diagram_png_path_for_config(str(cfg_path)))
    png_path.write_bytes(b"\x89PNG\r\n\x1a\nDOT")
    dot_path = Path(diagram_dot_path_for_config(str(cfg_path)))
    dot_path.write_text("digraph from_file {}\n", encoding="utf-8")

    def _warn(*, config_path: str, diagram_path: str) -> str | None:
        _ = config_path
        if str(diagram_path).endswith(".dot"):
            return "dot-warn"
        return None

    monkeypatch.setattr(routes_core_mod, "stale_diagram_warning", _warn)
    monkeypatch.setattr(
        routes_core_mod,
        "generate_dot_text_from_config_path",
        lambda _path: "digraph generated {}\n",
    )

    app = _create_test_app(config_path=str(cfg_path))
    client = TestClient(app)

    meta_resp = client.get("/api/v1/config/diagram.dot?meta=1")
    assert meta_resp.status_code == 200
    assert meta_resp.headers.get("x-foghorn-warning") == "dot-warn"

    monkeypatch.setattr(
        routes_core_mod,
        "stale_diagram_warning",
        lambda **kw: (
            "png-warn" if str(kw.get("diagram_path", "")).endswith(".png") else None
        ),
    )
    png_meta_resp = client.get("/api/v1/config/diagram.dot?meta=1")
    assert png_meta_resp.status_code == 200
    assert png_meta_resp.headers.get("x-foghorn-warning") == "png-warn"

    read_resp = client.get("/api/v1/config/diagram.dot")
    assert read_resp.status_code == 200
    assert "from_file" in read_resp.text

    dot_path.unlink()
    gen_resp = client.get("/api/v1/config/diagram.dot")
    assert gen_resp.status_code == 200
    assert "generated" in gen_resp.text


def test_save_config_restores_backup_when_validation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: Save endpoint restores backup when post-write validation fails.

    Inputs:
      - Fake persistence writer creating a backup file.
      - runtime_config.load_config_from_disk patched to raise.

    Outputs:
      - HTTP 400 with restored_backup=True in error details.
    """

    from foghorn import runtime_config

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("server: {}\n", encoding="utf-8")

    def _fake_safe_write_raw_yaml(**kwargs: Any) -> None:
        Path(kwargs["dst_path"]).write_text(str(kwargs["raw_yaml"]), encoding="utf-8")
        Path(kwargs["backup_path"]).write_text("backup-data", encoding="utf-8")

    monkeypatch.setattr(
        routes_core_mod._config_persistence,
        "safe_write_raw_yaml",
        _fake_safe_write_raw_yaml,
    )
    monkeypatch.setattr(
        runtime_config,
        "load_config_from_disk",
        lambda **_kw: (_ for _ in ()).throw(ValueError("bad-config")),
    )

    app = _create_test_app(config_path=str(cfg_path))
    client = TestClient(app)
    resp = client.post("/api/v1/config/save", json={"raw_yaml": "invalid: ["})
    assert resp.status_code == 400
    assert "restored_backup=True" in resp.text


def test_save_config_sets_restored_false_when_backup_copy_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: Save endpoint reports restored_backup=False when backup restore fails.

    Inputs:
      - Fake persistence writer creating a backup file.
      - runtime_config.load_config_from_disk and shutil.copy patched to raise.

    Outputs:
      - HTTP 400 with restored_backup=False in error details.
    """

    from foghorn import runtime_config

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("server: {}\n", encoding="utf-8")

    def _fake_safe_write_raw_yaml(**kwargs: Any) -> None:
        Path(kwargs["dst_path"]).write_text(str(kwargs["raw_yaml"]), encoding="utf-8")
        Path(kwargs["backup_path"]).write_text("backup-data", encoding="utf-8")

    monkeypatch.setattr(
        routes_core_mod._config_persistence,
        "safe_write_raw_yaml",
        _fake_safe_write_raw_yaml,
    )
    monkeypatch.setattr(
        runtime_config,
        "load_config_from_disk",
        lambda **_kw: (_ for _ in ()).throw(ValueError("bad-config")),
    )
    monkeypatch.setattr(
        routes_core_mod.shutil,
        "copy",
        lambda *_a, **_kw: (_ for _ in ()).throw(OSError("copy-failed")),
    )

    app = _create_test_app(config_path=str(cfg_path))
    client = TestClient(app)
    resp = client.post("/api/v1/config/save", json={"raw_yaml": "invalid: ["})
    assert resp.status_code == 400
    assert "restored_backup=False" in resp.text


def test_save_config_restart_message_and_diagram_sync_failure_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: Save endpoint keeps success path when diagram-sync best effort fails.

    Inputs:
      - Save pipeline patched with analysis.changed=True and restart_required=True.
      - ensure_config_diagram_png patched to raise.

    Outputs:
      - HTTP 200 with restart-required save message.
    """

    import foghorn.utils.config_diagram as diagram_mod

    runtime_config = _patch_save_pipeline(
        monkeypatch,
        analysis={"changed": True, "restart_required": True},
    )
    monkeypatch.setattr(
        diagram_mod,
        "ensure_config_diagram_png",
        lambda **_kw: (_ for _ in ()).throw(RuntimeError("diagram-fail")),
    )
    monkeypatch.setattr(
        runtime_config,
        "load_config_from_disk",
        lambda **_kw: {"server": {"http": {"enabled": True}}},
    )

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("server: {}\n", encoding="utf-8")
    app = _create_test_app(config_path=str(cfg_path))
    client = TestClient(app)
    resp = client.post("/api/v1/config/save", json={"raw_yaml": "server: {}"})
    assert resp.status_code == 200
    data = resp.json()
    assert "restart required" in data["message"]


def test_save_and_reload_config_branch_matrix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: save_and_reload covers 409/500/200 plus snapshot-update fallback.

    Inputs:
      - Save/reload pipeline monkeypatches for analysis and reload outcomes.

    Outputs:
      - 409 when analysis says restart_required.
      - 409 when reload returns restart_required.
      - 500 when reload fails.
      - 200 when reload succeeds without restart requirement.
    """

    from foghorn import runtime_config

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("server: {}\n", encoding="utf-8")

    monkeypatch.setattr(
        routes_core_mod._config_persistence,
        "safe_write_raw_yaml",
        lambda **_kw: None,
    )
    monkeypatch.setattr(
        runtime_config, "load_config_from_disk", lambda **_kw: {"server": {}}
    )

    app = _create_test_app(config_path=str(cfg_path))
    client = TestClient(app)

    monkeypatch.setattr(
        runtime_config,
        "analyze_config_change",
        lambda *_a, **_kw: {"restart_required": True},
    )
    resp1 = client.post(
        "/api/v1/config/save_and_reload",
        json={"raw_yaml": "server: {}"},
    )
    assert resp1.status_code == 409

    monkeypatch.setattr(
        runtime_config,
        "analyze_config_change",
        lambda *_a, **_kw: {"restart_required": False},
    )
    monkeypatch.setattr(
        runtime_config,
        "reload_from_disk",
        lambda **_kw: _reload_result(
            ok=True,
            generation=2,
            restart_required=True,
            restart_reasons=["listener"],
        ),
    )
    monkeypatch.setattr(
        runtime_config,
        "get_runtime_snapshot",
        lambda: (_ for _ in ()).throw(RuntimeError("snap-fail")),
    )
    resp2 = client.post(
        "/api/v1/config/save_and_reload",
        json={"raw_yaml": "server: {}"},
    )
    assert resp2.status_code == 409

    monkeypatch.setattr(
        runtime_config,
        "reload_from_disk",
        lambda **_kw: _reload_result(ok=False, generation=3, error="reload-failed"),
    )
    resp3 = client.post(
        "/api/v1/config/save_and_reload",
        json={"raw_yaml": "server: {}"},
    )
    assert resp3.status_code == 500
    assert resp3.json()["status"] == "error"

    monkeypatch.setattr(
        runtime_config,
        "reload_from_disk",
        lambda **_kw: _reload_result(ok=True, generation=4, restart_required=False),
    )
    monkeypatch.setattr(
        runtime_config,
        "get_runtime_snapshot",
        lambda: types.SimpleNamespace(cfg={"new": True}, plugins=["p1"]),
    )
    resp4 = client.post(
        "/api/v1/config/save_and_reload",
        json={"raw_yaml": "server: {}"},
    )
    assert resp4.status_code == 200
    assert resp4.json()["status"] == "ok"


def test_save_and_restart_and_restart_delay_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: Save-and-restart and restart endpoints schedule SIGHUP safely.

    Inputs:
      - Save pipeline monkeypatches.
      - _schedule_process_signal capture list.

    Outputs:
      - save_and_restart schedules SIGHUP at 1.0s delay.
      - restart with invalid delay_seconds falls back to 1.0.
    """

    from foghorn import runtime_config

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("server: {}\n", encoding="utf-8")

    _patch_save_pipeline(monkeypatch, analysis={"changed": False})
    monkeypatch.setattr(
        runtime_config,
        "analyze_config_change",
        lambda *_a, **_kw: {"changed": False},
    )

    captured: list[tuple[int, float]] = []
    monkeypatch.setattr(
        routes_core_mod,
        "_schedule_process_signal",
        lambda sig, delay_seconds: captured.append((int(sig), float(delay_seconds))),
    )

    app = _create_test_app(config_path=str(cfg_path))
    client = TestClient(app)

    resp1 = client.post("/api/v1/config/save_and_restart", json={"raw_yaml": "x"})
    assert resp1.status_code == 200
    assert captured[-1] == (int(signal.SIGHUP), 1.0)

    resp2 = client.post("/api/v1/restart", json={"delay_seconds": "bad"})
    assert resp2.status_code == 200
    assert captured[-1] == (int(signal.SIGHUP), 1.0)


def test_reload_config_branch_matrix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: /api/v1/reload covers missing path, parse error, 409, 200, and 500.

    Inputs:
      - App variants with/without config_path.
      - runtime_config monkeypatches for load/analyze/reload/snapshot behavior.

    Outputs:
      - Distinct status codes for each branch path.
    """

    from foghorn import runtime_config

    no_cfg_app = _create_test_app(config_path=None)
    no_cfg_client = TestClient(no_cfg_app)
    assert no_cfg_client.post("/api/v1/reload").status_code == 500

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("server: {}\n", encoding="utf-8")
    app = _create_test_app(config_path=str(cfg_path))
    client = TestClient(app)

    monkeypatch.setattr(
        runtime_config,
        "load_config_from_disk",
        lambda **_kw: (_ for _ in ()).throw(ValueError("bad-load")),
    )
    bad_load = client.post("/api/v1/reload")
    assert bad_load.status_code == 400

    monkeypatch.setattr(
        runtime_config, "load_config_from_disk", lambda **_kw: {"server": {}}
    )
    monkeypatch.setattr(
        runtime_config,
        "analyze_config_change",
        lambda *_a, **_kw: {"restart_required": True},
    )
    refused = client.post("/api/v1/reload")
    assert refused.status_code == 409

    monkeypatch.setattr(
        runtime_config,
        "analyze_config_change",
        lambda *_a, **_kw: {"restart_required": False},
    )
    monkeypatch.setattr(
        runtime_config,
        "reload_from_config",
        lambda *_a, **_kw: _reload_result(ok=True, generation=7),
    )
    monkeypatch.setattr(
        runtime_config,
        "get_runtime_snapshot",
        lambda: (_ for _ in ()).throw(RuntimeError("snap-fail")),
    )
    ok_resp = client.post("/api/v1/reload")
    assert ok_resp.status_code == 200

    monkeypatch.setattr(
        runtime_config,
        "reload_from_config",
        lambda *_a, **_kw: _reload_result(ok=True, generation=8),
    )
    monkeypatch.setattr(
        runtime_config,
        "get_runtime_snapshot",
        lambda: types.SimpleNamespace(cfg={"updated": True}, plugins=["new-plugin"]),
    )
    ok_with_snapshot = client.post("/api/v1/reload")
    assert ok_with_snapshot.status_code == 200
    assert app.state.config == {"updated": True}
    assert app.state.plugins == ["new-plugin"]

    monkeypatch.setattr(
        runtime_config,
        "reload_from_config",
        lambda *_a, **_kw: _reload_result(ok=False, generation=8, error="reload"),
    )
    fail_resp = client.post("/api/v1/reload")
    assert fail_resp.status_code == 500
    assert fail_resp.json()["status"] == "error"


def test_reload_reloadable_branch_matrix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: /api/v1/reload_reloadable covers missing path, parse error, and ok.

    Inputs:
      - App variants with and without config_path.
      - runtime_config monkeypatches for load/analyze/reload behavior.

    Outputs:
      - 500, 400, and 200 paths are exercised with expected messages.
    """

    from foghorn import runtime_config

    no_cfg_app = _create_test_app(config_path=None)
    no_cfg_client = TestClient(no_cfg_app)
    assert no_cfg_client.post("/api/v1/reload_reloadable").status_code == 500

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("server: {}\n", encoding="utf-8")
    app = _create_test_app(config_path=str(cfg_path))
    client = TestClient(app)

    monkeypatch.setattr(
        runtime_config,
        "load_config_from_disk",
        lambda **_kw: (_ for _ in ()).throw(ValueError("bad-load")),
    )
    bad_load = client.post("/api/v1/reload_reloadable")
    assert bad_load.status_code == 400

    monkeypatch.setattr(
        runtime_config, "load_config_from_disk", lambda **_kw: {"server": {}}
    )
    monkeypatch.setattr(
        runtime_config,
        "analyze_config_change",
        lambda *_a, **_kw: {"restart_required": True},
    )
    monkeypatch.setattr(
        runtime_config,
        "reload_from_config",
        lambda *_a, **_kw: _reload_result(
            ok=True,
            generation=11,
            restart_required=True,
            restart_reasons=["listener"],
        ),
    )
    monkeypatch.setattr(
        runtime_config,
        "get_runtime_snapshot",
        lambda: (_ for _ in ()).throw(RuntimeError("snap-fail")),
    )
    ok_resp = client.post("/api/v1/reload_reloadable")
    assert ok_resp.status_code == 200
    assert "restart required" in ok_resp.json()["message"]


def test_plugins_ui_import_and_cache_descriptor_defensive_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: plugins/ui handles import failures and descriptor getattr failures.

    Inputs:
      - builtins.__import__ patched to fail for foghorn.plugins.resolve import.
      - DNS_CACHE object whose get_admin_ui_descriptor attribute lookup fails.

    Outputs:
      - Endpoint still returns HTTP 200 payloads.
    """

    from foghorn.plugins.resolve import base as plugin_base

    app = _create_test_app()
    client = TestClient(app)

    real_import = builtins.__import__

    def _fake_import(
        name: str,
        globals: dict[str, Any] | None = None,
        locals: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] | tuple[Any, ...] = (),
        level: int = 0,
    ) -> Any:
        if name.startswith("foghorn.plugins.resolve"):
            raise RuntimeError("import-failed")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    resp1 = client.get("/api/v1/plugins/ui")
    assert resp1.status_code == 200

    class _BadCache:
        def __getattribute__(self, name: str) -> Any:
            if name == "get_admin_ui_descriptor":
                raise RuntimeError("attr-failed")
            return object.__getattribute__(self, name)

    monkeypatch.setattr(builtins, "__import__", real_import)
    monkeypatch.setattr(plugin_base, "DNS_CACHE", _BadCache(), raising=False)
    resp2 = client.get("/api/v1/plugins/ui")
    assert resp2.status_code == 200


def test_cache_snapshot_and_table_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: cache and cache/table endpoints cover error and descriptor paths.

    Inputs:
      - DNS_CACHE monkeypatched with multiple implementations.
      - Direct endpoint call for invalid hide_zero_* values.

    Outputs:
      - 404/500/success table responses across branch cases.
      - direct endpoint call tolerates non-int hide flags (defensive _flag_int).
    """

    from foghorn.plugins.resolve import base as plugin_base

    app = _create_test_app()
    client = TestClient(app)

    monkeypatch.setattr(plugin_base, "DNS_CACHE", None, raising=False)
    assert client.get("/api/v1/cache/table/clients").status_code == 404

    class _ExplodingCache:
        def get_http_snapshot(self) -> dict[str, Any]:
            raise RuntimeError("boom")

    monkeypatch.setattr(plugin_base, "DNS_CACHE", _ExplodingCache(), raising=False)
    assert client.get("/api/v1/cache").status_code == 500
    assert client.get("/api/v1/cache/table/clients").status_code == 500

    class _DescRaisesCache:
        def get_http_snapshot(self) -> dict[str, Any]:
            return {
                "clients": [
                    {"name": "ok.example", "calls_total": 1, "cache_hits": 1},
                ]
            }

        def get_admin_ui_descriptor(self) -> dict[str, Any]:
            raise RuntimeError("desc-failed")

    monkeypatch.setattr(plugin_base, "DNS_CACHE", _DescRaisesCache(), raising=False)
    endpoint = _get_route_endpoint(
        app, path="/api/v1/cache/table/{table_id}", method="GET"
    )

    async def _run_bad_flag_call() -> None:
        payload = await endpoint(
            table_id="clients",
            hide_zero_calls="bad",
            hide_zero_hits="bad",
        )
        assert payload["table_id"] == "clients"
        assert payload["total"] == 1

    asyncio.run(_run_bad_flag_call())

    class _LayoutNotDictCache:
        def get_http_snapshot(self) -> dict[str, Any]:
            return {"clients": [{"name": "layout.example", "calls_total": 1}]}

        def get_admin_ui_descriptor(self) -> dict[str, Any]:
            return {"layout": None}

    monkeypatch.setattr(plugin_base, "DNS_CACHE", _LayoutNotDictCache(), raising=False)
    assert client.get("/api/v1/cache/table/clients").status_code == 200

    class _SectionsNotListCache:
        def get_http_snapshot(self) -> dict[str, Any]:
            return {"clients": [{"name": "sections.example", "calls_total": 1}]}

        def get_admin_ui_descriptor(self) -> dict[str, Any]:
            return {"layout": {"sections": {"bad": True}}}

    monkeypatch.setattr(
        plugin_base, "DNS_CACHE", _SectionsNotListCache(), raising=False
    )
    assert client.get("/api/v1/cache/table/clients").status_code == 200

    class _SectionContinueCache:
        def get_http_snapshot(self) -> dict[str, Any]:
            return {"clients": [{"name": "continue.example", "calls_total": 1}]}

        def get_admin_ui_descriptor(self) -> dict[str, Any]:
            return {
                "layout": {
                    "sections": [
                        123,
                        {"id": "clients", "type": "text", "path": "clients"},
                        {"id": "clients", "type": "table", "path": "clients"},
                    ]
                }
            }

    monkeypatch.setattr(
        plugin_base, "DNS_CACHE", _SectionContinueCache(), raising=False
    )
    assert client.get("/api/v1/cache/table/clients").status_code == 200

    class _NoTableCache:
        def get_http_snapshot(self) -> dict[str, Any]:
            return {"tables": {"clients": []}}

        def get_admin_ui_descriptor(self) -> dict[str, Any]:
            return {
                "layout": {
                    "sections": [
                        {"id": "other", "type": "table", "path": "tables.clients"}
                    ]
                }
            }

    monkeypatch.setattr(plugin_base, "DNS_CACHE", _NoTableCache(), raising=False)
    assert client.get("/api/v1/cache/table/clients").status_code == 404

    class _ValidCache:
        name = "valid-cache"

        def get_http_snapshot(self) -> dict[str, Any]:
            return {
                "tables": {
                    "clients": [
                        {"name": "zero.example", "calls_total": 0, "cache_hits": 0},
                        {"name": "keep.example", "calls_total": 5, "cache_hits": 2},
                    ]
                }
            }

        def get_admin_ui_descriptor(self) -> dict[str, Any]:
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

    monkeypatch.setattr(plugin_base, "DNS_CACHE", _ValidCache(), raising=False)
    ok = client.get("/api/v1/cache/table/clients?hide_zero_calls=1&hide_zero_hits=1")
    assert ok.status_code == 200
    data = ok.json()
    assert data["sort_key"] == "calls_total"
    assert data["sort_dir"] == "desc"
    assert [row["name"] for row in data["items"]] == ["keep.example"]


def test_plugin_table_branches_and_hash_filtering() -> None:
    """Brief: plugin table endpoint covers missing/path/snapshot/filter branches.

    Inputs:
      - Plugins exposing descriptor/snapshot success and failure variants.

    Outputs:
      - 200 with hash-like rows filtered out.
      - 404 for missing plugin and missing table.
      - 500 for snapshot failure.
      - Descriptor-get failure still works via fallback table_id path.
    """

    class _TablePlugin:
        def __init__(self, name: str) -> None:
            self.name = name

        def get_admin_ui_descriptor(self) -> dict[str, Any]:
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

        def get_http_snapshot(self) -> dict[str, Any]:
            return {
                "tables": {
                    "entries": [
                        {"name": "0123456789ab.example", "calls_total": 1},
                        {"name": "ok.example", "calls_total": 8},
                    ]
                }
            }

    class _ExplodingPlugin:
        def __init__(self, name: str) -> None:
            self.name = name

        def get_admin_ui_descriptor(self) -> dict[str, Any]:
            return {
                "layout": {
                    "sections": [{"id": "entries", "type": "table", "path": "entries"}]
                }
            }

        def get_http_snapshot(self) -> dict[str, Any]:
            raise RuntimeError("snapshot-failed")

    class _DescErrorPlugin:
        def __init__(self, name: str) -> None:
            self.name = name

        def get_admin_ui_descriptor(self) -> dict[str, Any]:
            raise RuntimeError("desc-failed")

        def get_http_snapshot(self) -> dict[str, Any]:
            return {"entries": [{"name": "ok.example", "calls_total": 3}]}

    app = _create_test_app(
        plugins=[
            _TablePlugin("demo"),
            _ExplodingPlugin("boom"),
            _DescErrorPlugin("desc_err"),
        ]
    )
    client = TestClient(app)

    filtered = client.get("/api/v1/plugins/demo/table/entries?hide_hash_like=1")
    assert filtered.status_code == 200
    assert [r["name"] for r in filtered.json()["items"]] == ["ok.example"]

    assert client.get("/api/v1/plugins/missing/table/entries").status_code == 404
    assert client.get("/api/v1/plugins/demo/table/nope").status_code == 404
    assert client.get("/api/v1/plugins/boom/table/entries").status_code == 500

    fallback = client.get("/api/v1/plugins/desc_err/table/entries")
    assert fallback.status_code == 200
    assert fallback.json()["total"] == 1


def test_named_plugin_snapshot_endpoints_raise_mapped_http_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Named plugin snapshot endpoints map AdminLogicHttpError to HTTP.

    Inputs:
      - build_named_plugin_snapshot monkeypatched to raise AdminLogicHttpError.

    Outputs:
      - Access-control/rate-limit/etc-hosts/mdns routes return mapped status/detail.
    """

    def _raise_named_snapshot(
        plugins_list: list[object], plugin_name: str, label: str
    ) -> dict[str, Any]:
        _ = (plugins_list, plugin_name)
        raise admin_logic_mod.AdminLogicHttpError(
            status_code=418, detail=f"bad-{label}"
        )

    monkeypatch.setattr(
        routes_core_mod._admin_logic,
        "build_named_plugin_snapshot",
        _raise_named_snapshot,
    )

    app = _create_test_app()
    client = TestClient(app)

    for path in [
        "/api/v1/plugins/demo/access_control",
        "/api/v1/plugins/demo/rate_limit",
        "/api/v1/plugins/demo/etc_hosts",
        "/api/v1/plugins/demo/mdns",
    ]:
        resp = client.get(path)
        assert resp.status_code == 418
        assert "bad-" in resp.text

    monkeypatch.setattr(
        routes_core_mod._admin_logic,
        "build_named_plugin_snapshot",
        lambda _plugins, plugin_name, label: {
            "plugin": plugin_name,
            "data": {"label": label},
        },
    )
    ok_access = client.get("/api/v1/plugins/demo/access_control")
    assert ok_access.status_code == 200
    assert ok_access.json()["plugin"] == "demo"

    ok_rate = client.get("/api/v1/plugins/demo/rate_limit")
    assert ok_rate.status_code == 200
    assert ok_rate.json()["plugin"] == "demo"
