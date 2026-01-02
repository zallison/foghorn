"""Brief: Unit tests for foghorn.config.config_parser helpers.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from foghorn.config import config_parser as cp
from foghorn.plugins.resolve.base import BasePlugin


def test_is_var_key_empty_and_uppercase() -> None:
    """Brief: _is_var_key rejects empty and accepts ALL_UPPERCASE names.

    Inputs:
      - None.

    Outputs:
      - None; asserts behaviour for empty and valid keys.
    """

    assert cp._is_var_key("") is False
    assert cp._is_var_key("TTL") is True
    assert cp._is_var_key("ttl") is False


def test_parse_config_variables_non_mapping_raises() -> None:
    """Brief: parse_config_variables rejects non-mapping variables root.

    Inputs:
      - None.

    Outputs:
      - None; asserts ValueError when cfg['variables'] is not a dict.
    """

    cfg: Dict[str, Any] = {"variables": [1, 2, 3]}
    with pytest.raises(ValueError, match="config.variables must be a mapping"):
        cp.parse_config_variables(cfg)


def test_parse_config_variables_env_and_cli_validation() -> None:
    """Brief: parse_config_variables filters env keys and validates CLI vars.

    Inputs:
      - None.

    Outputs:
      - None; asserts env lowercase keys are ignored and CLI validation errors.
    """

    cfg: Dict[str, Any] = {"variables": {"EXISTING": 1}}
    env = {"lower": "1", "UPPER": "2"}
    merged = cp.parse_config_variables(cfg, environ=env, cli_vars=["NEW=3"])
    # lower should be ignored; UPPER and NEW merged as YAML scalars.
    assert "lower" not in merged
    assert merged["UPPER"] == 2
    assert merged["NEW"] == 3

    # Invalid CLI assignment missing '='.
    with pytest.raises(ValueError):
        cp.parse_config_variables({"variables": {}}, cli_vars=["BAD"])

    # Invalid variable name (not ALL_UPPERCASE).
    with pytest.raises(ValueError):
        cp.parse_config_variables({"variables": {}}, cli_vars=["bad=1"])


def test_parse_config_file_non_mapping_root_raises(tmp_path, monkeypatch) -> None:
    """Brief: parse_config_file enforces mapping root type.

    Inputs:
      - tmp_path: temporary directory fixture.

    Outputs:
      - None; asserts ValueError when YAML root is not a mapping.
    """

    p = tmp_path / "cfg.yaml"
    p.write_text("- 1\n- 2\n", encoding="utf-8")

    # Force yaml.safe_load to return a list for this file.
    import yaml as _yaml

    real_safe_load = _yaml.safe_load

    def fake_safe_load(text: str) -> Any:  # noqa: D401
        """Return a list to trigger non-mapping error for this test file."""

        data = real_safe_load(text)
        if isinstance(data, list):
            return data
        return data

    monkeypatch.setattr(cp.yaml, "safe_load", fake_safe_load)

    with pytest.raises(ValueError, match="Configuration root must be a mapping"):
        cp.parse_config_file(str(p))


def test_normalize_upstream_config_invalid_foghorn_and_timeout_fallback() -> None:
    """Brief: normalize_upstream_config validates foghorn section and timeout.

    Inputs:
      - None.

    Outputs:
      - None; asserts foghorn must be mapping and timeout_ms fallback on error.
    """

    # foghorn present but not a mapping.
    cfg_bad_foghorn = {"upstreams": [{"host": "1.1.1.1"}], "foghorn": [1, 2]}
    with pytest.raises(ValueError, match="config.foghorn must be a mapping"):
        cp.normalize_upstream_config(cfg_bad_foghorn)

    # Invalid timeout_ms that cannot be converted to int falls back to default.
    class Bad:
        def __int__(self) -> int:  # noqa: D401
            """Raise TypeError when converted to int."""

            raise TypeError("no int")

    cfg_timeout = {
        "upstreams": [{"host": "1.1.1.1"}],
        "foghorn": {"timeout_ms": Bad()},
    }
    upstreams, timeout_ms = cp.normalize_upstream_config(cfg_timeout)
    assert upstreams and timeout_ms == 2000


class DummyPlugin(BasePlugin):
    """Brief: Minimal BasePlugin subclass for config_parser tests.

    Inputs:
      - name: plugin instance name.

    Outputs:
      - DummyPlugin instance; records last init kwargs for assertions.
    """

    last_init: Dict[str, Any] | None = None

    def __init__(self, name: str, **config: Any) -> None:  # type: ignore[override]
        super().__init__(name=name, **config)
        DummyPlugin.last_init = {"name": name, **config}


def test_validate_plugin_config_attaches_logging_for_plain_plugins() -> None:
    """Brief: _validate_plugin_config preserves logging for plain plugins.

    Inputs:
      - None.

    Outputs:
      - None; asserts logging sub-config is re-attached when no model/schema.
    """

    cfg = {"logging": {"level": "debug"}, "foo": 1}
    validated = cp._validate_plugin_config(DummyPlugin, cfg)
    assert validated["foo"] == 1
    assert validated["logging"] == {"level": "debug"}


def test_derive_plugin_instance_name_explicit_and_duplicates() -> None:
    """Brief: _derive_plugin_instance_name validates explicit names and collisions.

    Inputs:
      - None.

    Outputs:
      - None; asserts empty and duplicate explicit names raise.
    """

    used: set[str] = set()

    with pytest.raises(ValueError):
        cp._derive_plugin_instance_name(
            plugin_cls=DummyPlugin,
            module_path="mod.DummyPlugin",
            explicit_name="  ",
            used_names=used,
        )

    used.add("dup")
    with pytest.raises(ValueError):
        cp._derive_plugin_instance_name(
            plugin_cls=DummyPlugin,
            module_path="mod.DummyPlugin",
            explicit_name="dup",
            used_names=used,
        )

    name = cp._derive_plugin_instance_name(
        plugin_cls=DummyPlugin,
        module_path="mod.DummyPlugin",
        explicit_name="ok",
        used_names=used,
    )
    assert name == "ok" and "ok" in used


class AliasPlugin(BasePlugin):
    @staticmethod
    def get_aliases() -> List[str]:  # type: ignore[override]
        return ["docker-hosts", "docker"]


class BrokenAliasPlugin(BasePlugin):
    @staticmethod
    def get_aliases() -> List[str]:  # type: ignore[override]
        raise RuntimeError("boom")


def test_derive_plugin_instance_name_aliases_suffix_and_fallbacks() -> None:
    """Brief: _derive_plugin_instance_name handles aliases, suffixes, and fallbacks.

    Inputs:
      - None.

    Outputs:
      - None; asserts alias preference, suffixing, and class-name fallback.
    """

    used: set[str] = set()

    # Prefer simple alias without hyphens/underscores and auto-suffix duplicates.
    name1 = cp._derive_plugin_instance_name(
        plugin_cls=AliasPlugin,
        module_path="foghorn.plugins.docker_hosts.DockerHosts",
        explicit_name=None,
        used_names=used,
    )
    name2 = cp._derive_plugin_instance_name(
        plugin_cls=AliasPlugin,
        module_path="foghorn.plugins.docker_hosts.DockerHosts",
        explicit_name=None,
        used_names=used,
    )
    assert name1 == "docker"
    assert name2 == "docker2"

    # When get_aliases raises, fall back to module tail or class name.
    used.clear()
    name3 = cp._derive_plugin_instance_name(
        plugin_cls=BrokenAliasPlugin,
        module_path="pkg.mod",
        explicit_name=None,
        used_names=used,
    )
    assert name3 in {"mod", "BrokenAliasPlugin"}

    # When everything else is empty, fall back to plugin class name.
    used.clear()
    name4 = cp._derive_plugin_instance_name(
        plugin_cls=BrokenAliasPlugin,
        module_path="  ",
        explicit_name=None,
        used_names=used,
    )
    assert name4 == "BrokenAliasPlugin"


def test_load_plugins_rejects_uppercase_comment_keys(monkeypatch) -> None:
    """Brief: load_plugins rejects 'Comment' keys in specs and config.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts ValueError for bad keys in spec and config.
    """

    # Monkeypatch discover_plugins/get_plugin_class to avoid importing real plugins.
    monkeypatch.setattr(cp, "discover_plugins", lambda: {})
    monkeypatch.setattr(cp, "get_plugin_class", lambda ident, reg=None: DummyPlugin)

    # Spec-level "Comment".
    with pytest.raises(ValueError, match="use 'comment' \(lowercase\)"):
        cp.load_plugins(
            [
                {"module": "dummy", "Comment": "oops"},
            ]
        )

    # Config-level "Comment".
    with pytest.raises(ValueError, match="plugins\[\]\.config: use 'comment'"):
        cp.load_plugins(
            [
                {"module": "dummy", "config": {"Comment": "oops"}},
            ]
        )


def test_load_plugins_enabled_and_priority_propagation_and_cache_error(
    monkeypatch,
) -> None:
    """Brief: load_plugins respects enabled flags, priorities, and cache errors.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts disabled plugins skipped, priorities propagated, and
        cache config errors wrapped in ValueError.
    """

    monkeypatch.setattr(cp, "discover_plugins", lambda: {})
    monkeypatch.setattr(cp, "get_plugin_class", lambda ident, reg=None: DummyPlugin)

    # Monkeypatch load_cache_plugin to raise so we hit the error path.
    def boom_cache(cfg: Any) -> Any:  # noqa: D401, ARG001
        """Always raise to simulate bad cache configuration."""

        raise RuntimeError("bad cache")

    monkeypatch.setattr(cp, "load_cache_plugin", boom_cache)

    # First spec: disabled via config.enabled -> skipped.
    disabled_spec = {
        "module": "dummy",
        "config": {"enabled": False},
    }

    # Second spec: enabled with generic priority and cache config that errors.
    bad_cache_spec = {
        "module": "dummy",
        "priority": 5,
        "config": {
            "priority": 7,
            "cache": {"module": "sqlite3", "config": {}},
        },
    }

    # Disabled plugin is skipped silently; bad cache spec raises ValueError.
    with pytest.raises(ValueError, match="Invalid cache configuration"):
        cp.load_plugins([disabled_spec, bad_cache_spec])

    # Now test successful priority propagation without cache errors.
    def ok_cache(cfg: Any) -> Any:  # noqa: D401, ARG001
        """Return a sentinel cache object for plugin config injection."""

        return {"cache": "ok"}

    monkeypatch.setattr(cp, "load_cache_plugin", ok_cache)

    specs = [
        {
            "module": "dummy",
            "priority": 9,
            "config": {
                "cache": {"module": "none"},
            },
        }
    ]

    DummyPlugin.last_init = None
    plugins = cp.load_plugins(specs)
    assert len(plugins) == 1
    init_cfg = DummyPlugin.last_init or {}
    # Generic priority should be propagated into per-plugin priorities.
    assert init_cfg.get("pre_priority") == 9
    assert init_cfg.get("post_priority") == 9
    assert init_cfg.get("setup_priority") == 9
    # Cache instance should be injected into plugin config.
    assert "cache" in init_cfg
