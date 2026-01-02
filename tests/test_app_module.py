"""
Brief: Tests for foghorn.app FastAPI compatibility module.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

try:  # FastAPI is an optional dependency
    from fastapi import FastAPI
except ModuleNotFoundError:  # pragma: no cover - environment dependent
    FastAPI = None  # type: ignore[assignment]
    pytest.skip(
        "fastapi not installed; skipping foghorn.app tests",
        allow_module_level=True,
    )

from foghorn import app as fog_app
from foghorn.servers.webserver import RingBuffer


def test_empty_config_structure() -> None:
    """Brief: _empty_config returns minimal enabled webserver configuration.

    Inputs:
      - None.

    Outputs:
      - None; asserts keys and default values of the returned config.
    """
    cfg: Dict[str, Any] = fog_app._empty_config()
    assert "webserver" in cfg
    web_cfg = cfg["webserver"]
    assert web_cfg["enabled"] is True
    assert web_cfg["host"] == "127.0.0.1"
    assert web_cfg["port"] == 8053
    assert web_cfg["index"] is True


def test_app_module_exposes_fastapi_app_instance() -> None:
    """Brief: foghorn.app exposes a FastAPI app and expected globals.

    Inputs:
      - None.

    Outputs:
      - None; asserts that app, _config, and _log_buffer are wired correctly.
    """
    # app attribute should be a FastAPI instance constructed via create_app.
    assert isinstance(fog_app.app, FastAPI)

    # _config should be the result of _empty_config.
    cfg = fog_app._empty_config()
    assert fog_app._config == cfg

    # _log_buffer should be a RingBuffer with the default capacity.
    assert isinstance(fog_app._log_buffer, RingBuffer)
    # RingBuffer stores capacity on a private attribute.
    assert getattr(fog_app._log_buffer, "_capacity") == 500
