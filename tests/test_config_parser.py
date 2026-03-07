"""Brief: Unit tests for foghorn.config.config_parser helpers.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations
import ssl

from typing import Any, Dict, List

import pytest

from foghorn.config import config_parser as cp
from foghorn.plugins.resolve.base import BasePlugin


def test_is_var_key_empty_and_case_flexible_identifier() -> None:
    """Brief: _is_var_key accepts identifier-style names with any letter case.

    Inputs:
      - None.

    Outputs:
      - None; asserts behaviour for empty, valid, and invalid keys.
    """

    assert cp._is_var_key("") is False
    assert cp._is_var_key("TTL") is True
    assert cp._is_var_key("ttl") is True
    assert cp._is_var_key("MiXeD_123") is True
    assert cp._is_var_key("bad-name") is False


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
    """Brief: parse_config_variables parses env/CLI vars and validates bad names.

    Inputs:
      - None.

    Outputs:
      - None; asserts env keys are parsed and CLI validation errors on bad keys.
    """

    cfg: Dict[str, Any] = {"variables": {"EXISTING": 1}}
    env = {"lower": "1", "UPPER": "2"}
    merged = cp.parse_config_variables(cfg, environ=env, cli_vars=["NEW=3"])
    # lowercase, uppercase, and CLI keys are merged as YAML scalars.
    assert merged["lower"] == 1
    assert merged["UPPER"] == 2
    assert merged["NEW"] == 3

    # Invalid CLI assignment missing '='.
    with pytest.raises(ValueError):
        cp.parse_config_variables({"variables": {}}, cli_vars=["BAD"])

    # Invalid variable name (must match identifier pattern).
    with pytest.raises(ValueError):
        cp.parse_config_variables({"variables": {}}, cli_vars=["bad-name=1"])


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


def test_parse_config_file_tls_ca_missing_is_fatal(tmp_path) -> None:
    """Brief: parse_config_file raises when upstream TLS ca_file does not exist.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - None; asserts missing TLS CA bundle is treated as fatal by default.
    """

    missing_ca = tmp_path / "missing-ca.pem"
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text(
        "\n".join(
            [
                "server:",
                "  resolver:",
                "    mode: forward",
                "upstreams:",
                "  endpoints:",
                "    - host: 1.1.1.1",
                "      port: 853",
                "      transport: dot",
                "      tls:",
                f"        ca_file: {missing_ca}",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="does not exist"):
        cp.parse_config_file(str(cfg_path))


def test_parse_config_file_tls_ca_missing_nonfatal_when_abort_disabled(
    tmp_path,
    caplog,
) -> None:
    """Brief: parse_config_file warns (not raises) when abort_on_fail is disabled.

    Inputs:
      - tmp_path: pytest temporary directory fixture.
      - caplog: pytest log-capture fixture.

    Outputs:
      - None; asserts missing CA file is logged and config still parses.
    """

    missing_ca = tmp_path / "missing-ca.pem"
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text(
        "\n".join(
            [
                "server:",
                "  resolver:",
                "    mode: forward",
                "upstreams:",
                "  endpoints:",
                "    - host: 1.1.1.1",
                "      port: 853",
                "      transport: dot",
                "      abort_on_fail: false",
                "      tls:",
                f"        ca_file: {missing_ca}",
            ]
        ),
        encoding="utf-8",
    )

    with caplog.at_level("WARNING", logger="foghorn.config.config_parser"):
        cfg = cp.parse_config_file(str(cfg_path))

    assert isinstance(cfg, dict)
    assert any(
        "continuing because abort_on_fail/abort_on_failure is false" in r.message
        for r in caplog.records
    )


def test_validate_tls_ca_file_reports_unreadable_path(tmp_path, monkeypatch) -> None:
    """Brief: _validate_tls_ca_file raises clear errors for unreadable files.

    Inputs:
      - tmp_path: pytest temporary directory fixture.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts unreadable CA files are rejected.
    """

    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("dummy", encoding="utf-8")

    def _raise_permission_error(*_args, **_kwargs) -> object:
        raise PermissionError("permission denied")

    monkeypatch.setattr(cp, "open", _raise_permission_error, raising=False)

    with pytest.raises(ValueError, match="not readable"):
        cp._validate_tls_ca_file(
            str(ca_file), location="upstreams.endpoints[0].tls.ca_file"
        )


def test_validate_tls_ca_file_reports_invalid_format(tmp_path, monkeypatch) -> None:
    """Brief: _validate_tls_ca_file raises clear errors for invalid CA formats.

    Inputs:
      - tmp_path: pytest temporary directory fixture.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts invalid PEM/CA content is rejected.
    """

    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("not a cert", encoding="utf-8")

    def _raise_ssl_error(*_args, **_kwargs) -> object:
        raise ssl.SSLError("bad cert")

    monkeypatch.setattr(cp.ssl, "create_default_context", _raise_ssl_error)

    with pytest.raises(ValueError, match="not a valid TLS CA bundle"):
        cp._validate_tls_ca_file(
            str(ca_file), location="upstreams.endpoints[0].tls.ca_file"
        )


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


def test_normalize_upstream_backup_config_returns_empty_when_missing() -> None:
    """Brief: normalize_upstream_backup_config returns [] when backup is absent.

    Inputs:
      - cfg without upstreams.backup.

    Outputs:
      - Empty list.
    """

    cfg = {"upstreams": {"endpoints": [{"host": "1.1.1.1", "port": 53}]}}
    assert cp.normalize_upstream_backup_config(cfg) == []


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


def test_load_plugins_hooks_priority_shorthands_and_precedence(monkeypatch) -> None:
    """Brief: load_plugins supports hooks-based priority shorthands.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts hooks.pre_resolve/hooks.post_resolve accept int or
        {priority: int}, hooks.priority sets all three, and hooks take
        precedence over deprecated *_priority/priority fields.
    """

    monkeypatch.setattr(cp, "discover_plugins", lambda: {})
    monkeypatch.setattr(cp, "get_plugin_class", lambda ident, reg=None: DummyPlugin)

    # hooks.pre_resolve as int; hooks.post_resolve as {priority: ...}
    DummyPlugin.last_init = None
    plugins = cp.load_plugins(
        [
            {
                "module": "dummy",
                "hooks": {"pre_resolve": 11, "post_resolve": {"priority": 22}},
            }
        ]
    )
    assert len(plugins) == 1
    init_cfg = DummyPlugin.last_init or {}
    assert init_cfg.get("pre_priority") == 11
    assert init_cfg.get("post_priority") == 22
    # setup should be untouched (defaults to BasePlugin class default).
    assert "setup_priority" not in init_cfg

    # hooks.priority sets all three.
    DummyPlugin.last_init = None
    plugins2 = cp.load_plugins(
        [
            {
                "module": "dummy",
                "hooks": {"priority": 7},
            }
        ]
    )
    assert len(plugins2) == 1
    init_cfg2 = DummyPlugin.last_init or {}
    assert init_cfg2.get("pre_priority") == 7
    assert init_cfg2.get("post_priority") == 7
    assert init_cfg2.get("setup_priority") == 7

    # hooks.setup overrides setup priority.
    DummyPlugin.last_init = None
    plugins2b = cp.load_plugins(
        [
            {
                "module": "dummy",
                "hooks": {"priority": 7, "setup": 9},
            }
        ]
    )
    assert len(plugins2b) == 1
    init_cfg2b = DummyPlugin.last_init or {}
    assert init_cfg2b.get("pre_priority") == 7
    assert init_cfg2b.get("post_priority") == 7
    assert init_cfg2b.get("setup_priority") == 9

    # hooks.setup can also be {priority: ...}.
    DummyPlugin.last_init = None
    plugins2c = cp.load_plugins(
        [
            {
                "module": "dummy",
                "hooks": {"setup": {"priority": 12}},
            }
        ]
    )
    assert len(plugins2c) == 1
    init_cfg2c = DummyPlugin.last_init or {}
    assert init_cfg2c.get("setup_priority") == 12

    # Hook-specific values override hooks.priority.
    DummyPlugin.last_init = None
    plugins3 = cp.load_plugins(
        [
            {
                "module": "dummy",
                "hooks": {"priority": 3, "pre_resolve": 9},
            }
        ]
    )
    assert len(plugins3) == 1
    init_cfg3 = DummyPlugin.last_init or {}
    assert init_cfg3.get("pre_priority") == 9
    assert init_cfg3.get("post_priority") == 3
    assert init_cfg3.get("setup_priority") == 3

    # Hooks take precedence over deprecated *_priority and priority.
    DummyPlugin.last_init = None
    plugins4 = cp.load_plugins(
        [
            {
                "module": "dummy",
                "hooks": {"priority": 1},
                "pre_priority": 99,
                "post_priority": 98,
                "setup_priority": 97,
                "priority": 96,
                "config": {"pre_priority": 95, "priority": 94},
            }
        ]
    )
    assert len(plugins4) == 1
    init_cfg4 = DummyPlugin.last_init or {}
    assert init_cfg4.get("pre_priority") == 1
    assert init_cfg4.get("post_priority") == 1
    assert init_cfg4.get("setup_priority") == 1
