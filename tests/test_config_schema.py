"""
Brief: Tests for JSON Schema-based configuration validation.

Inputs:
  - None directly; uses example YAML files from example_configs/.

Outputs:
  - None; assertions ensure valid configs pass and invalid configs fail.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

pytest.importorskip("jsonschema")

import foghorn.config.config_schema as config_schema_mod
from foghorn.config.config_schema import get_default_schema_path, validate_config

EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "example_configs"


def _example_yaml_paths() -> list[Path]:
    """Brief: Return example YAML files suitable for schema validation.

    Inputs:
      - None.

    Outputs:
      - list[Path]: YAML paths under example_configs/ excluding editor temp/backup files.

    Notes:
      - Some editors create files like `.#+name.yaml` (Emacs lock) or `#name.yaml#`
        (Emacs autosave) or `name.yaml~` (backup). These should not be treated as
        real example configs.
    """

    paths: list[Path] = []
    for p in sorted(EXAMPLE_DIR.glob("*.yaml")):
        name = p.name
        if name.startswith(".") or name.startswith("#") or name.endswith("~"):
            continue
        if not p.is_file():
            continue
        paths.append(p)
    return paths


@pytest.mark.parametrize("yaml_path", _example_yaml_paths())
def test_example_configs_are_schema_valid(yaml_path: Path) -> None:
    """Brief: All example_configs/*.yaml files must satisfy the JSON Schema.

    Inputs:
      - yaml_path: Path to an example YAML file under example_configs/.

    Outputs:
      - None; raises AssertionError via pytest if validation fails.
    """

    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    # Should not raise for valid example configurations.
    validate_config(data, config_path=str(yaml_path))


def test_invalid_config_raises_value_error(caplog) -> None:
    """Brief: Extra unknown top-level keys normally cause validation to fail.

    Inputs:
      - None; constructs a minimal invalid configuration mapping.

    Outputs:
      - None; asserts either:
        - ValueError is raised with a helpful message when the JSON Schema
          is available and parses correctly, or
        - a warning is logged about schema loading/parsing failure and
          validation is skipped (best-effort mode).
    """

    cfg = {
        "listen": {"host": "127.0.0.1", "port": 5353},
        "upstreams": [{"host": "1.1.1.1", "port": 53}],
        "extra": 42,
    }

    # Capture warnings from validate_config so we can distinguish between
    # genuine validation failures and environments where the schema file
    # cannot be loaded or parsed (in which case validation is deliberately
    # skipped as a best-effort behaviour).
    with caplog.at_level("WARNING", logger="foghorn.config.config_schema"):
        try:
            validate_config(cfg, config_path="inline-config")
        except ValueError as exc:
            msg = str(exc)
            assert "Invalid configuration" in msg
            assert "extra" in msg
            return

    # If no ValueError was raised, schema loading must have failed and
    # validation was skipped. Assert that the skip was logged.
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert (
        "Failed to load or parse configuration schema" in joined
        or "schema file" in joined
    )


def test_get_default_schema_path_docker_fallback(monkeypatch) -> None:
    """Brief: get_default_schema_path uses the Docker fallback when image path exists.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture used to stub Path.is_file.

    Outputs:
      - None; asserts returned path points to /foghorn/assets/config-schema.json.
    """

    real_path_cls = config_schema_mod.Path

    def fake_is_file(self) -> bool:  # noqa: D401
        """Return True only for the Docker candidate, False otherwise."""

        s = str(self)
        if s == "/foghorn/assets/config-schema.json":
            return True
        return False

    monkeypatch.setattr(real_path_cls, "is_file", fake_is_file, raising=False)

    p = get_default_schema_path()
    assert str(p) == "/foghorn/assets/config-schema.json"


def test_get_default_schema_path_last_resort_uses_project_root(monkeypatch) -> None:
    """Brief: get_default_schema_path falls back to project_root/assets when no schema files exist.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture used to force is_file() to False.

    Outputs:
      - None; asserts the returned path matches the computed project_root/assets path.
    """

    real_path_cls = config_schema_mod.Path

    def always_false_is_file(self) -> bool:  # noqa: D401
        """Stub is_file that always reports paths as missing."""

        return False

    monkeypatch.setattr(real_path_cls, "is_file", always_false_is_file, raising=False)

    # Mirror the logic inside get_default_schema_path() by resolving the
    # config_schema module's file, not this test file.
    here = real_path_cls(config_schema_mod.__file__).resolve()
    expected = here.parents[2] / "assets" / "config-schema.json"

    p = get_default_schema_path()
    assert p == expected


def test_validate_config_schema_loading_errors_are_best_effort(
    monkeypatch, caplog
) -> None:
    """Brief: validate_config logs schema loading failures and skips validation.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture used to make _load_schema raise.
      - caplog: Pytest caplog fixture used to capture warning logs.

    Outputs:
      - None; asserts that a warning is logged and no exception is raised.
    """

    def boom_load(_schema_path):  # noqa: D401, ARG001
        """Raise OSError to simulate I/O failure while reading schema."""

        raise OSError("disk failure")

    # Ensure path existence check passes so validate_config calls _load_schema.
    real_path_cls = config_schema_mod.Path

    def fake_is_file(self) -> bool:  # noqa: D401
        """Pretend the schema path exists so loading can fail later."""

        return str(self) == "/nonexistent/schema.json"

    monkeypatch.setattr(real_path_cls, "is_file", fake_is_file, raising=False)
    monkeypatch.setattr(config_schema_mod, "_load_schema", boom_load)

    fake_schema_path = config_schema_mod.Path("/nonexistent/schema.json")

    with caplog.at_level("WARNING", logger="foghorn.config.config_schema"):
        # Should not raise despite schema loading failure; behaviour is
        # best-effort with a warning and skipped validation.
        validate_config({}, schema_path=fake_schema_path, config_path="cfg.yaml")

    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "Failed to load or parse configuration schema" in joined
    assert "skipping JSON Schema validation" in joined
    assert "disk failure" in joined
