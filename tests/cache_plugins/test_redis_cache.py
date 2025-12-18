"""Brief: Unit tests for the Redis/Valkey cache plugin.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import sys

import pytest

from foghorn.cache_plugins.registry import get_cache_plugin_class, load_cache_plugin


def test_registry_resolves_redis_alias_to_plugin_class() -> None:
    """Brief: Cache plugin registry exposes the redis/valkey cache plugin aliases.

    Inputs:
      - None

    Outputs:
      - None; asserts alias resolution returns the expected class.
    """

    cls = get_cache_plugin_class("redis")
    assert cls.__name__ == "RedisCachePlugin"

    cls2 = get_cache_plugin_class("valkey")
    assert cls2 is cls


def test_load_cache_plugin_redis_raises_helpful_error_when_dependency_missing(
    monkeypatch,
) -> None:
    """Brief: Instantiating the redis cache plugin errors clearly when redis is missing.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts ImportError message contains install hint.
    """

    # Simulate that `redis` is not installed.
    monkeypatch.delitem(sys.modules, "redis", raising=False)

    # Force importlib.import_module('redis') to fail.
    import importlib

    real_import = importlib.import_module

    def _fake_import(name: str, package=None):  # type: ignore[no-untyped-def]
        if name == "redis":
            raise ModuleNotFoundError("No module named redis")
        return real_import(name, package=package)

    monkeypatch.setattr(importlib, "import_module", _fake_import)

    with pytest.raises(ImportError) as excinfo:
        _ = load_cache_plugin(
            {"module": "redis", "config": {"url": "redis://localhost:6379/0"}}
        )

    msg = str(excinfo.value).lower()
    assert "pip install redis" in msg
