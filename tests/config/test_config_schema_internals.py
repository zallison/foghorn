"""Brief: Unit tests for the JSON Schema-based config validation helpers.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List
import json

import pytest

from foghorn.config import config_schema as config_schema_mod


def test_normalize_cache_config_treats_null_module_as_none_alias_and_strips_null_config() -> None:
    """Brief: _normalize_cache_config_for_validation handles null module/config.

    Inputs:
      - None.

    Outputs:
      - None; asserts cache.module None becomes "none" and config None is removed.
    """

    cfg: Dict[str, Any] = {"cache": {"module": None, "config": None}}
    config_schema_mod._normalize_cache_config_for_validation(cfg)
    cache_cfg = cfg["cache"]
    assert cache_cfg["module"] == "none"
    assert "config" not in cache_cfg


def test_normalize_variables_legacy_alias_and_basic_substitution() -> None:
    """Brief: _normalize_variables_for_validation expands legacy variables and substitutes.

    Inputs:
      - None.

    Outputs:
      - None; asserts legacy "variables" is aliased to "vars" and used for substitution.
    """

    cfg: Dict[str, Any] = {
        "variables": {"HOST": "127.0.0.1", "PORT": 5353},
        "listen": {"host": "${HOST}", "port": "$PORT"},
    }

    config_schema_mod._normalize_variables_for_validation(cfg)

    assert "variables" not in cfg
    assert "vars" not in cfg
    listen = cfg["listen"]
    assert listen["host"] == "127.0.0.1"
    assert listen["port"] == 5353


def test_normalize_variables_rejects_non_mapping_legacy_variables() -> None:
    """Brief: _normalize_variables_for_validation errors when legacy variables is not a mapping.

    Inputs:
      - None.

    Outputs:
      - None; asserts ValueError for non-mapping legacy config.variables.
    """

    cfg: Dict[str, Any] = {"variables": "not-a-mapping"}
    with pytest.raises(ValueError):
        config_schema_mod._normalize_variables_for_validation(cfg)


def test_normalize_variables_enforces_uppercase_and_pattern() -> None:
    """Brief: _normalize_variables_for_validation enforces ALL_UPPERCASE keys.

    Inputs:
      - None.

    Outputs:
      - None; asserts lowercase variable keys are rejected.
    """

    cfg: Dict[str, Any] = {"vars": {"lower": 1}}
    with pytest.raises(ValueError):
        config_schema_mod._normalize_variables_for_validation(cfg)


def test_normalize_variables_detects_cycles() -> None:
    """Brief: _normalize_variables_for_validation detects cyclic variable references.

    Inputs:
      - None.

    Outputs:
      - None; asserts ValueError when variables form a cycle.
    """

    cfg: Dict[str, Any] = {"vars": {"FOO": "$BAR", "BAR": "$FOO"}}
    with pytest.raises(ValueError):
        config_schema_mod._normalize_variables_for_validation(cfg)


def test_normalize_variables_list_injection_and_splicing(tmp_path: Path) -> None:
    """Brief: _normalize_variables_for_validation splices list variables into lists.

    Inputs:
      - tmp_path: pytest temporary path fixture (unused; kept for parity with other tests).

    Outputs:
      - None; asserts $LIST entries expand and splice into surrounding list.
    """

    cfg: Dict[str, Any] = {
        "vars": {
            "BLOCKED": [
                {"ip": "1.1.1.1"},
                {"ip": "2.2.2.2"},
            ]
        },
        "blocked_ips": ["$BLOCKED", {"ip": "3.3.3.3"}],
    }

    config_schema_mod._normalize_variables_for_validation(cfg)

    blocked = cfg["blocked_ips"]
    assert isinstance(blocked, list)
    assert blocked[0]["ip"] == "1.1.1.1"
    assert blocked[1]["ip"] == "2.2.2.2"
    assert blocked[2]["ip"] == "3.3.3.3"


def test_normalize_variables_embeds_non_scalar_as_json_in_string() -> None:
    """Brief: _normalize_variables_for_validation JSON-embeds non-scalar values in strings.

    Inputs:
      - None.

    Outputs:
      - None; asserts a dict variable used inside a string is JSON-encoded.
    """

    cfg: Dict[str, Any] = {
        "vars": {"OPTS": {"a": 1}},
        "text": "prefix ${OPTS} suffix",
    }

    config_schema_mod._normalize_variables_for_validation(cfg)

    text = cfg["text"]
    assert "\"a\": 1" in text


def test_normalize_dnssec_config_lowercases_validation_fields() -> None:
    """Brief: _normalize_dnssec_config_for_validation lowercases validation.

    Inputs:
      - None.

    Outputs:
      - None; asserts both root and nested foghorn.dnssec.validation are lowercased.
    """

    cfg: Dict[str, Any] = {
        "dnssec": {"validation": "LOCAL_EXTENDED"},
        "foghorn": {"dnssec": {"validation": "LOCAL"}},
    }

    config_schema_mod._normalize_dnssec_config_for_validation(cfg)

    assert cfg["dnssec"]["validation"] == "local_extended"
    assert cfg["foghorn"]["dnssec"]["validation"] == "local"


def test_normalize_plugin_entries_strips_disabled_and_applies_priority_and_comment() -> None:
    """Brief: _normalize_plugin_entries_for_validation normalizes plugin meta fields.

    Inputs:
      - None.

    Outputs:
      - None; asserts disabled entries are removed and priority/comment handled.
    """

    cfg: Dict[str, Any] = {
        "plugins": [
            {"module": "a", "enabled": False},
            {"module": "b", "config": {"enabled": False}},
            {"module": "c", "priority": 5, "comment": "human"},
            {"module": "d", "config": {"foo": 1}},
            "not-a-dict",
        ]
    }

    config_schema_mod._normalize_plugin_entries_for_validation(cfg)

    plugins = cfg["plugins"]
    assert len(plugins) == 3
    assert "a" not in {getattr(p, "get", lambda *_: None)("module") for p in plugins if isinstance(p, dict)}
    # Entry "c" should have its priority expanded and comment stripped.
    entry_c = next(p for p in plugins if isinstance(p, dict) and p.get("module") == "c")
    assert "priority" not in entry_c
    assert "comment" not in entry_c
    assert entry_c["pre_priority"] == 5
    assert entry_c["post_priority"] == 5
    assert entry_c["setup_priority"] == 5


def test_normalize_plugin_entries_rejects_capitalized_comment_keys() -> None:
    """Brief: _normalize_plugin_entries_for_validation rejects Comment keys.

    Inputs:
      - None.

    Outputs:
      - None; asserts ValueError for Comment/Comment in entry or config.
    """

    cfg_entry: Dict[str, Any] = {"plugins": [{"Comment": "bad"}]}
    with pytest.raises(ValueError):
        config_schema_mod._normalize_plugin_entries_for_validation(cfg_entry)

    cfg_config: Dict[str, Any] = {"plugins": [{"config": {"Comment": "bad"}}]}
    with pytest.raises(ValueError):
        config_schema_mod._normalize_plugin_entries_for_validation(cfg_config)


def test_get_default_schema_path_uses_assets_in_source_tree() -> None:
    """Brief: get_default_schema_path locates assets/config-schema.json in ancestors.

    Inputs:
      - None.

    Outputs:
      - None; asserts the returned path is a file under an assets directory.
    """

    path = config_schema_mod.get_default_schema_path()
    assert path.name == "config-schema.json"
    assert "assets" in str(path.parent)


def test_get_default_schema_path_project_root_fallback(monkeypatch) -> None:
    """Brief: get_default_schema_path falls back to project_root/assets when files are missing.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts the computed fallback path matches the documented behavior.
    """

    original_is_file = Path.is_file

    def _always_false(self: Path) -> bool:  # type: ignore[override]
        return False

    monkeypatch.setattr("pathlib.Path.is_file", _always_false)

    path = config_schema_mod.get_default_schema_path()
    here = Path(config_schema_mod.__file__).resolve()
    project_root = here.parents[2]
    expected = project_root / "assets" / "config-schema.json"
    assert path == expected

    # Ensure we did not change the original method for other tests.
    monkeypatch.setattr("pathlib.Path.is_file", original_is_file)


def test_format_errors_includes_paths_and_schema_paths() -> None:
    """Brief: _format_errors renders instance and schema paths.

    Inputs:
      - None.

    Outputs:
      - None; asserts formatted string contains paths and messages.
    """

    errors: List[Any] = [
        SimpleNamespace(path=["foo"], schema_path=["properties", "foo"], message="is bad"),
        SimpleNamespace(path=[], schema_path=["root"], message="root error"),
    ]

    msg = config_schema_mod._format_errors(errors, config_path="./cfg.yml")
    assert "Invalid configuration in ./cfg.yml" in msg
    assert "foo" in msg
    assert "schema: properties/foo" in msg
    assert "<root>" in msg


def test_split_extra_property_errors_partitions_by_validator() -> None:
    """Brief: _split_extra_property_errors splits extra vs non-extra errors.

    Inputs:
      - None.

    Outputs:
      - None; asserts additionalProperties/unevaluatedProperties are separated.
    """

    e1 = SimpleNamespace(validator="additionalProperties")
    e2 = SimpleNamespace(validator="unevaluatedProperties")
    e3 = SimpleNamespace(validator="type")

    extra, other = config_schema_mod._split_extra_property_errors([e1, e2, e3])

    assert e1 in extra and e2 in extra
    assert e3 in other and e3 not in extra


def test_validate_config_rejects_invalid_unknown_keys_policy() -> None:
    """Brief: validate_config rejects unsupported unknown_keys values.

    Inputs:
      - None.

    Outputs:
      - None; asserts ValueError is raised for bad unknown_keys.
    """

    with pytest.raises(ValueError):
        config_schema_mod.validate_config({}, unknown_keys="bogus")


def test_validate_config_skips_when_schema_file_missing(tmp_path: Path) -> None:
    """Brief: validate_config returns without error when schema file is missing.

    Inputs:
      - tmp_path: pytest temporary path fixture.

    Outputs:
      - None; asserts no exception when schema_path does not exist.
    """

    missing = tmp_path / "does-not-exist.json"
    cfg: Dict[str, Any] = {"listen": {"host": "127.0.0.1", "port": 5353}}
    config_schema_mod.validate_config(cfg, schema_path=missing)


def test_validate_config_skips_when_schema_load_fails(tmp_path: Path, monkeypatch) -> None:
    """Brief: validate_config logs and returns when _load_schema raises.

    Inputs:
      - tmp_path: pytest temporary path fixture.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts no exception when _load_schema raises OSError/SchemaError.
    """

    path = tmp_path / "schema.json"
    path.write_text("{}", encoding="utf-8")

    def _boom(_path: Path) -> Dict[str, Any]:
        raise config_schema_mod.SchemaError("bad schema")

    monkeypatch.setattr(config_schema_mod, "_load_schema", _boom)

    cfg: Dict[str, Any] = {"listen": {"host": "127.0.0.1", "port": 5353}}
    config_schema_mod.validate_config(cfg, schema_path=path)


def test_validate_config_skips_when_jsonschema_not_installed(tmp_path: Path, monkeypatch) -> None:
    """Brief: validate_config returns when Draft202012Validator is None.

    Inputs:
      - tmp_path: pytest temporary path fixture.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts no exception and no validation when Draft202012Validator is None.
    """

    path = tmp_path / "schema.json"
    path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(config_schema_mod, "Draft202012Validator", None)

    cfg: Dict[str, Any] = {"listen": {"host": "127.0.0.1", "port": 5353}}
    config_schema_mod.validate_config(cfg, schema_path=path)


def test_validate_config_handles_non_extra_and_extra_errors(monkeypatch, tmp_path: Path) -> None:
    """Brief: validate_config treats non-extra errors as fatal regardless of unknown_keys.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - tmp_path: pytest temporary path fixture.

    Outputs:
      - None; asserts ValueError message includes both non-extra and extra errors.
    """

    path = tmp_path / "schema.json"
    path.write_text("{}", encoding="utf-8")

    class DummyValidator:
        def __init__(self, schema: Dict[str, Any]) -> None:
            self.schema = schema

        def iter_errors(self, cfg: Dict[str, Any]):  # type: ignore[no-untyped-def]
            yield SimpleNamespace(
                path=["foo"],
                schema_path=["properties", "foo"],
                message="is bad",
                validator="type",
            )
            yield SimpleNamespace(
                path=["bar"],
                schema_path=["properties", "bar"],
                message="extra property",
                validator="additionalProperties",
            )

    monkeypatch.setattr(config_schema_mod, "Draft202012Validator", DummyValidator)

    cfg: Dict[str, Any] = {"foo": 1, "bar": 2}

    with pytest.raises(ValueError) as excinfo:
        config_schema_mod.validate_config(cfg, schema_path=path, unknown_keys="warn")

    msg = str(excinfo.value)
    assert "foo" in msg and "bar" in msg


def test_validate_config_extra_property_policy_variants(monkeypatch, tmp_path: Path) -> None:
    """Brief: validate_config honors ignore/warn/error for extra-property errors.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - tmp_path: pytest temporary path fixture.

    Outputs:
      - None; asserts ignore/warn succeed and error raises ValueError.
    """

    path = tmp_path / "schema.json"
    path.write_text("{}", encoding="utf-8")

    class ExtraOnlyValidator:
        def __init__(self, schema: Dict[str, Any]) -> None:
            self.schema = schema

        def iter_errors(self, cfg: Dict[str, Any]):  # type: ignore[no-untyped-def]
            yield SimpleNamespace(
                path=["foo"],
                schema_path=["properties", "foo"],
                message="extra property",
                validator="additionalProperties",
            )

    monkeypatch.setattr(config_schema_mod, "Draft202012Validator", ExtraOnlyValidator)

    cfg: Dict[str, Any] = {"foo": 1}

    # unknown_keys = "ignore": no exception.
    config_schema_mod.validate_config(cfg, schema_path=path, unknown_keys="ignore")

    # unknown_keys = "warn": still no exception.
    config_schema_mod.validate_config(cfg, schema_path=path, unknown_keys="warn")

    # unknown_keys = "error": should raise ValueError.
    with pytest.raises(ValueError):
        config_schema_mod.validate_config(cfg, schema_path=path, unknown_keys="error")
