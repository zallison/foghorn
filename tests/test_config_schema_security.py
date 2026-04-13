"""Brief: Regression tests for config schema validation hardening.

Inputs:
  - None.

Outputs:
  - None.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from foghorn.config import config_parser as cp
from foghorn.config import config_schema as cs


def test_validate_config_schema_missing_is_fatal(tmp_path: Path) -> None:
    """Brief: validate_config hard-fails when schema file is missing.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - None; asserts ValueError is raised.
    """

    missing = tmp_path / "missing-schema.json"
    cfg: Dict[str, Any] = {}

    with pytest.raises(ValueError, match="schema file .* not found|not found"):
        cs.validate_config(cfg, schema_path=missing, config_path="cfg.yaml")


def test_validate_config_schema_corrupt_is_fatal(tmp_path: Path) -> None:
    """Brief: validate_config hard-fails when schema file cannot be parsed.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - None; asserts ValueError is raised.
    """

    corrupt = tmp_path / "corrupt-schema.json"
    corrupt.write_text("{not json", encoding="utf-8")

    cfg: Dict[str, Any] = {}

    with pytest.raises(
        ValueError, match="Failed to load or parse configuration schema"
    ):
        cs.validate_config(cfg, schema_path=corrupt, config_path="cfg.yaml")


def test_validate_config_missing_jsonschema_is_fatal(
    tmp_path: Path, monkeypatch
) -> None:
    """Brief: validate_config hard-fails when jsonschema is unavailable.

    Inputs:
      - tmp_path: pytest temporary directory fixture.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts ValueError is raised.
    """

    schema_path = tmp_path / "schema.json"
    schema_path.write_text('{"type": "object"}', encoding="utf-8")

    cfg: Dict[str, Any] = {}

    monkeypatch.setattr(cs, "Draft202012Validator", None)

    with pytest.raises(ValueError, match="jsonschema is not installed"):
        cs.validate_config(cfg, schema_path=schema_path, config_path="cfg.yaml")


def test_skip_schema_validation_bypasses_schema_loading(tmp_path: Path) -> None:
    """Brief: skip_schema_validation allows startup even when schema is missing.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - None; asserts no exception is raised.
    """

    missing = tmp_path / "missing-schema.json"
    cfg: Dict[str, Any] = {
        # Include a simple variable usage to ensure normalization still runs.
        "vars": {"X": "abc"},
        "server": {"example": "${X}"},
        "__schema_validation_config_var_keys": ["X"],
    }

    cs.validate_config(
        cfg,
        schema_path=missing,
        config_path="cfg.yaml",
        skip_schema_validation=True,
    )

    assert cfg.get("server", {}).get("example") == "abc"


def test_env_vars_cannot_whole_node_inject_types(tmp_path: Path) -> None:
    """Brief: Env-sourced variables must not whole-node inject non-string types.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - None; asserts env vars do not inject lists/dicts via $KEY/${KEY}.
    """

    cfg: Dict[str, Any] = {
        "variables": {
            # config-authored var
            "FROM_CFG": [1, 2],
        },
        "server": {
            "a": "$FROM_CFG",
            "b": "$FROM_ENV",
            "c": "${FROM_ENV}",
        },
    }

    # Merge env vars (these are interpolation vars but should not be allowed for
    # whole-node injection in config_schema).
    cp.parse_config_variables(cfg, environ={"FROM_ENV": "[3, 4]"}, cli_vars=[])

    # Ensure validate_config uses the allowlist generated from config vars.
    cs.validate_config(cfg, skip_schema_validation=True)

    # Config-authored variables can still whole-node inject.
    assert cfg["server"]["a"] == [1, 2]

    # Env vars must not whole-node inject.
    assert cfg["server"]["b"] == "$FROM_ENV"
    # For ${FROM_ENV} whole-node injection is blocked, but ${KEY} interpolation
    # occurs and returns JSON embedded as text.
    assert cfg["server"]["c"] == "[3, 4]"


def test_variable_cycle_message_is_deterministic() -> None:
    """Brief: Variable cycle errors show a deterministic, ordered path.

    Inputs:
      - None.

    Outputs:
      - None; asserts ordered cycle path in error message.
    """

    cfg: Dict[str, Any] = {
        "vars": {
            "A": "$B",
            "B": "$A",
        },
        "__schema_validation_config_var_keys": ["A", "B"],
    }

    with pytest.raises(ValueError, match=r"cycle: A -> B -> A"):
        cs.validate_config(cfg, skip_schema_validation=True)


def test_plugins_nested_enabled_is_stripped() -> None:
    """Brief: plugins[].config.enabled is removed before plugin construction.

    Inputs:
      - None.

    Outputs:
      - None; asserts enabled key is stripped from nested plugin config.
    """

    cfg: Dict[str, Any] = {
        "plugins": [
            {
                "module": "zone_records",
                "config": {"enabled": True, "example": 1},
            }
        ]
    }

    cs.validate_config(cfg, skip_schema_validation=True)

    assert isinstance(cfg["plugins"], list)
    assert cfg["plugins"][0]["config"] == {"example": 1}
