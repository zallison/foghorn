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

from foghorn.utils.config_mermaid import (
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


def test_ensure_config_diagram_png_returns_false_when_mmdc_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png should fail soft when no renderer exists.

    Inputs:
      - config file on disk.
      - mmdc not present (shutil.which returns None).

    Outputs:
      - ok is False, png_path is None.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    import foghorn.utils.config_mermaid as cm

    monkeypatch.setattr(cm.shutil, "which", lambda _n: None)

    ok, detail, png_path = ensure_config_diagram_png(config_path=str(cfg_path))
    assert ok is False
    assert png_path is None
    assert "mmdc" in detail


def test_ensure_config_diagram_png_renders_when_mmdc_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png should create PNG when mmdc is available.

    Inputs:
      - config file on disk.
      - mmdc present (shutil.which returns a path).
      - subprocess.run stubbed to write the output PNG.

    Outputs:
      - ok is True and the PNG exists at the expected path.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    import foghorn.utils.config_mermaid as cm

    monkeypatch.setattr(cm.shutil, "which", lambda _n: "/usr/bin/mmdc")

    def fake_run(cmd, check=False, stdout=None, stderr=None, text=None):  # type: ignore[no-untyped-def]
        assert "-o" in cmd
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_bytes(b"\x89PNG\r\n\x1a\nFAKE")
        return types.SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(cm.subprocess, "run", fake_run)

    ok, detail, png_path = ensure_config_diagram_png(config_path=str(cfg_path))
    assert ok is True
    assert png_path == diagram_png_path_for_config(str(cfg_path))
    assert Path(png_path).is_file()
    assert "rendered" in detail


def test_ensure_config_diagram_png_skips_when_up_to_date(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: ensure_config_diagram_png should not re-render when PNG newer than config.

    Inputs:
      - config file and PNG file where PNG mtime >= config mtime.

    Outputs:
      - ok True with detail up-to-date.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_MINIMAL_CONFIG_YAML, encoding="utf-8")

    png_path = Path(diagram_png_path_for_config(str(cfg_path)))
    png_path.write_bytes(b"\x89PNG\r\n\x1a\nEXISTING")

    # Force PNG to be newer than config.
    png_path.touch()
    png_path.touch()

    import foghorn.utils.config_mermaid as cm

    # If the function attempted to call mmdc, fail the test.
    monkeypatch.setattr(cm.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("called")))  # type: ignore[arg-type]

    ok, detail, out = ensure_config_diagram_png(config_path=str(cfg_path))
    assert ok is True
    assert out == str(png_path)
    assert detail == "up-to-date"


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


def test_config_diagram_endpoint_returns_404_when_missing(tmp_path: Path) -> None:
    """Brief: /api/v1/config/diagram.png returns 404 when file is absent."""

    cfg_path = tmp_path / "config.yaml"
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
    resp = client.get("/api/v1/config/diagram.png")
    assert resp.status_code == 404
