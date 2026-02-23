"""Brief: Tests for config diagram generation and serving.

Inputs:
  - tmp_path: pytest tmp_path fixture.
  - monkeypatch: pytest monkeypatch fixture.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

from pathlib import Path
import types

import pytest

from foghorn.utils.config_diagram import (
    diagram_png_path_for_config,
    ensure_config_diagram_png,
)

try:  # FastAPI is an optional dependency
    from fastapi.testclient import TestClient
except ModuleNotFoundError:  # pragma: no cover - environment dependent
    TestClient = None
    pytest.skip(
        "fastapi not installed; skipping config diagram endpoint tests",
        allow_module_level=True,
    )

from foghorn.servers.webserver import create_app


_MINIMAL_CONFIG_YAML = """
server:
  resolver:
    mode: forward
  http:
    enabled: false
listen:
  udp:
    enabled: false
upstreams:
  endpoints:
    - transport: udp
      host: 1.1.1.1
      port: 53
plugins: []
""".lstrip()


def test_ensure_config_diagram_png_returns_false_when_dot_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png should fail soft when no renderer exists.

    Inputs:
      - config file on disk.
      - dot not present (shutil.which returns None).

    Outputs:
      - ok is False, png_path is None.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    import foghorn.utils.config_diagram as cm

    monkeypatch.setattr(cm.shutil, "which", lambda _n: None)

    ok, detail, png_path = ensure_config_diagram_png(config_path=str(cfg_path))
    assert ok is False
    assert png_path is None
    assert "dot" in detail


def test_ensure_config_diagram_png_renders_when_dot_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png should create PNG when dot is available.

    Inputs:
      - config file on disk.
      - dot present (shutil.which returns a path).
      - subprocess.run stubbed to write the output PNG.

    Outputs:
      - ok is True and the PNG exists at the expected path.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    import foghorn.utils.config_diagram as cm

    monkeypatch.setattr(cm.shutil, "which", lambda _n: "/usr/bin/dot")

    def fake_run(cmd, check=False, stdout=None, stderr=None, text=None):  # type: ignore[no-untyped-def]
        assert "-Tpng" in cmd
        assert "-o" in cmd
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_bytes(b"\x89PNG\r\n\x1a\nFAKE")
        return types.SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(cm.subprocess, "run", fake_run)

    ok, detail, png_path = ensure_config_diagram_png(config_path=str(cfg_path))
    assert ok is True
    assert png_path == str(cfg_path.parent / "diagram.png")
    assert Path(png_path).is_file()

    dark_png = cfg_path.parent / "diagram-dark.png"
    assert dark_png.is_file()

    assert "rendered" in detail


def test_ensure_config_diagram_png_skips_when_up_to_date(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png should not re-render when PNG newer than config.

    Inputs:
      - config file and diagram.png where PNG mtime >= config mtime.

    Outputs:
      - ok True with detail up-to-date.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    png_path = tmp_path / "diagram.png"
    png_path.write_bytes(b"\x89PNG\r\n\x1a\nEXISTING")

    dark_png_path = tmp_path / "diagram-dark.png"
    dark_png_path.write_bytes(b"\x89PNG\r\n\x1a\nEXISTING-DARK")

    # Force PNGs to be newer than config.
    png_path.touch()
    dark_png_path.touch()

    import foghorn.utils.config_diagram as cm

    # If the function attempted to call dot, fail the test.
    monkeypatch.setattr(
        cm.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("called")),
    )  # type: ignore[arg-type]

    ok, detail, out = ensure_config_diagram_png(config_path=str(cfg_path))
    assert ok is True
    assert out == str(png_path)
    assert detail == "up-to-date"


def test_config_diagram_endpoint_regenerates_when_stale_and_dot_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: GET /api/v1/config/diagram.png refreshes stale diagram when dot exists.

    Inputs:
      - config newer than an existing diagram.png.
      - dot available (shutil.which returns a path).
      - subprocess.run stubbed to write a new PNG.

    Outputs:
      - Endpoint returns the refreshed PNG and clears the staleness warning.
    """

    png_path = tmp_path / "diagram.png"
    png_path.write_bytes(b"\x89PNG\r\n\x1a\nOLD")

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    import foghorn.utils.config_diagram as cm

    # Ensure the generator doesn't depend on full config parsing in this test.
    monkeypatch.setattr(
        cm,
        "generate_dot_text_from_config_path",
        lambda _p, **_k: "digraph config_diagram {\n}\n",
    )

    monkeypatch.setattr(
        cm.shutil,
        "which",
        lambda n: "/usr/bin/dot" if n == "dot" else None,
    )

    def fake_run(cmd, check=False, stdout=None, stderr=None, text=None):  # type: ignore[no-untyped-def]
        assert "-o" in cmd
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_bytes(b"\x89PNG\r\n\x1a\nNEW")
        return types.SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(cm.subprocess, "run", fake_run)

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=None,
        config_path=str(cfg_path),
        runtime_state=None,
        plugins=[],
    )

    client = TestClient(app)
    resp = client.get("/api/v1/config/diagram.png")
    assert resp.status_code == 200
    assert resp.content.endswith(b"NEW")
    assert "X-Foghorn-Warning" not in resp.headers

    # And the file on disk should have been replaced.
    assert png_path.read_bytes().endswith(b"NEW")


def test_config_diagram_endpoint_builds_on_demand_when_missing_and_dot_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: GET /api/v1/config/diagram.png builds diagram.png on-demand when missing.

    Inputs:
      - diagram.png missing.
      - dot available.

    Outputs:
      - Endpoint returns 200 and creates diagram.png.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    import foghorn.utils.config_diagram as cm

    monkeypatch.setattr(
        cm,
        "generate_dot_text_from_config_path",
        lambda _p, **_k: "digraph config_diagram {\n}\n",
    )
    monkeypatch.setattr(
        cm.shutil, "which", lambda n: "/usr/bin/dot" if n == "dot" else None
    )

    def fake_run(cmd, check=False, stdout=None, stderr=None, text=None):  # type: ignore[no-untyped-def]
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_bytes(b"\x89PNG\r\n\x1a\nOND")
        return types.SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(cm.subprocess, "run", fake_run)

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=None,
        config_path=str(cfg_path),
        runtime_state=None,
        plugins=[],
    )

    client = TestClient(app)
    resp = client.get("/api/v1/config/diagram.png")
    assert resp.status_code == 200
    assert resp.content.endswith(b"OND")
    assert (tmp_path / "diagram.png").is_file()


def test_config_diagram_endpoint_builds_on_demand_only_once_when_generation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: On-demand build is attempted only once per config signature.

    Inputs:
      - diagram.png missing.
      - dot available.
      - subprocess.run returns non-zero.

    Outputs:
      - Both requests return 404.
      - dot subprocess is invoked only once.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    import foghorn.utils.config_diagram as cm

    monkeypatch.setattr(
        cm,
        "generate_dot_text_from_config_path",
        lambda _p, **_k: "digraph config_diagram {\n}\n",
    )
    monkeypatch.setattr(
        cm.shutil, "which", lambda n: "/usr/bin/dot" if n == "dot" else None
    )

    calls = {"n": 0}

    def fake_run(cmd, check=False, stdout=None, stderr=None, text=None):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        return types.SimpleNamespace(returncode=1, stderr="nope", stdout="")

    monkeypatch.setattr(cm.subprocess, "run", fake_run)

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=None,
        config_path=str(cfg_path),
        runtime_state=None,
        plugins=[],
    )

    client = TestClient(app)
    resp1 = client.get("/api/v1/config/diagram.png")
    assert resp1.status_code == 404
    resp2 = client.get("/api/v1/config/diagram.png")
    assert resp2.status_code == 404
    assert calls["n"] == 1


def test_config_diagram_endpoint_serves_png_when_present(tmp_path: Path) -> None:
    """Brief: /api/v1/config/diagram.png returns image/png when file exists.

    Inputs:
      - create_app with config_path set.
      - pre-created diagram PNG file.

    Outputs:
      - HTTP 200 and Content-Type image/png.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    png_path = Path(diagram_png_path_for_config(str(cfg_path)))
    png_path.write_bytes(b"\x89PNG\r\n\x1a\nOK")

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=None,
        config_path=str(cfg_path),
        runtime_state=None,
        plugins=[],
    )

    client = TestClient(app)
    resp = client.get("/api/v1/config/diagram.png")
    assert resp.status_code == 200
    assert resp.headers.get("content-type", "").startswith("image/png")


def test_config_diagram_endpoint_returns_404_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: /api/v1/config/diagram.png returns 404 when file is absent.

    Notes:
      - This test forces dot to be unavailable so the endpoint doesn't try an
        on-demand build.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    import foghorn.utils.config_diagram as cm

    monkeypatch.setattr(cm.shutil, "which", lambda _n: None)

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=None,
        config_path=str(cfg_path),
        runtime_state=None,
        plugins=[],
    )

    client = TestClient(app)
    resp = client.get("/api/v1/config/diagram.png")
    assert resp.status_code == 404


def test_config_diagram_png_upload_saves_diagram_png_in_config_dir(
    tmp_path: Path,
) -> None:
    """Brief: POST /api/v1/config/diagram.png writes config/diagram.png.

    Inputs:
      - tmp_path: pytest tmp_path fixture.

    Outputs:
      - Upload returns 200 and GET serves the uploaded PNG.
    """

    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    cfg_path = cfg_dir / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=None,
        config_path=str(cfg_path),
        runtime_state=None,
        plugins=[],
    )

    client = TestClient(app)

    payload = b"\x89PNG\r\n\x1a\nFAKEPAYLOAD"
    resp = client.post(
        "/api/v1/config/diagram.png",
        files={"file": ("diagram.png", payload, "image/png")},
    )
    assert resp.status_code == 200

    saved = cfg_dir / "diagram.png"
    assert saved.is_file()
    assert saved.read_bytes() == payload

    resp2 = client.get("/api/v1/config/diagram.png")
    assert resp2.status_code == 200
    assert resp2.content == payload


def test_config_diagram_png_upload_rejects_non_png_extension(tmp_path: Path) -> None:
    """Brief: POST /api/v1/config/diagram.png rejects non-.png filenames."""

    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    cfg_path = cfg_dir / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=None,
        config_path=str(cfg_path),
        runtime_state=None,
        plugins=[],
    )

    client = TestClient(app)
    payload = b"\x89PNG\r\n\x1a\nFAKEPAYLOAD"
    resp = client.post(
        "/api/v1/config/diagram.png",
        files={"file": ("diagram.jpg", payload, "image/png")},
    )
    assert resp.status_code == 400


def test_config_diagram_png_upload_rejects_too_large(tmp_path: Path) -> None:
    """Brief: POST /api/v1/config/diagram.png enforces a 1,000,000 byte limit."""

    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    cfg_path = cfg_dir / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    app = create_app(
        stats=None,
        config={"webserver": {"enabled": True}},
        log_buffer=None,
        config_path=str(cfg_path),
        runtime_state=None,
        plugins=[],
    )

    client = TestClient(app)

    max_bytes = 1_000_000
    payload = b"\x89PNG\r\n\x1a\n" + (b"A" * (max_bytes + 1 - 8))
    assert len(payload) == max_bytes + 1

    resp = client.post(
        "/api/v1/config/diagram.png",
        files={"file": ("diagram.png", payload, "image/png")},
    )
    assert resp.status_code == 413
