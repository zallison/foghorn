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

from foghorn.config_schema import validate_config


EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "example_configs"


@pytest.mark.parametrize("yaml_path", sorted(EXAMPLE_DIR.glob("*.yaml")))
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


def test_invalid_config_raises_value_error() -> None:
    """Brief: Extra unknown top-level keys cause validation to fail.

    Inputs:
      - None; constructs a minimal invalid configuration mapping.

    Outputs:
      - None; asserts ValueError is raised with a helpful message.
    """

    cfg = {
      "listen": {"host": "127.0.0.1", "port": 5353},
      "upstream": [{"host": "1.1.1.1", "port": 53}],
      "extra": 42,
    }

    with pytest.raises(ValueError) as excinfo:
        validate_config(cfg, config_path="inline-config")

    msg = str(excinfo.value)
    assert "Invalid configuration" in msg
    assert "extra" in msg
