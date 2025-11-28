"""JSON Schema-based validation for Foghorn YAML configuration.

This module centralizes loading and validating the main ``config.yaml`` using
an external JSON Schema document stored under ``assets/config-yaml.schema``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from jsonschema import Draft202012Validator, ValidationError


def get_default_schema_path() -> Path:
    """Brief: Resolve the default JSON Schema path for configuration.

    Inputs:
      - None.

    Outputs:
      - Path to ``assets/config-yaml.schema`` located at the project root.
    """

    # ``config_schema.py`` lives at ``src/foghorn/config_schema.py``.
    # The repository root is two levels up from this file.
    here = Path(__file__).resolve()
    project_root = here.parents[2]
    return project_root / "assets" / "config-yaml.schema"


def _load_schema(schema_path: Optional[Path] = None) -> Dict[str, Any]:
    """Brief: Load JSON Schema from disk.

    Inputs:
      - schema_path: Optional explicit path to the schema file.

    Outputs:
      - Dict representing the JSON Schema.
    """

    path = schema_path or get_default_schema_path()
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _format_errors(errors: List[ValidationError], *, config_path: Optional[str]) -> str:
    """Brief: Format jsonschema validation errors into a human-readable string.

    Inputs:
      - errors: List of jsonschema.ValidationError instances.
      - config_path: Optional path to the YAML config being validated.

    Outputs:
      - String suitable for display in logs or CLI output.
    """

    header = f"Invalid configuration in {config_path or '<config dict>'}:" if errors else "Invalid configuration:"
    lines: List[str] = [header]
    for err in errors:
        instance_path = "/".join(str(p) for p in err.path) or "<root>"
        schema_path = "/".join(str(p) for p in err.schema_path)
        lines.append(f"- {instance_path}: {err.message} (schema: {schema_path})")
    return "\n".join(lines)


def validate_config(cfg: Dict[str, Any], *, schema_path: Optional[Path] = None, config_path: Optional[str] = "./config/config.yaml") -> None:
    """Brief: Validate a parsed YAML configuration mapping against JSON Schema.

    Inputs:
      - cfg: Dict loaded from YAML (top-level configuration mapping).
      - schema_path: Optional explicit path to JSON Schema file. When omitted,
        the default ``assets/config-yaml.schema`` is used.
      - config_path: Optional string path to the YAML file, used only for
        error messages.

    Outputs:
      - None on success.

    Raises:
      - ValueError: when validation fails; the message includes all validation
        errors and the offending instance paths.

    Example:
      >>> from pathlib import Path
      >>> import yaml
      >>> data = yaml.safe_load("listen: {host: 127.0.0.1, port: 5353}\nupstream: [{host: 1.1.1.1, port: 53}]")
      >>> validate_config(data)  # does not raise for valid config
    """

    schema = _load_schema(schema_path)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(cfg), key=lambda e: list(e.path))
    if errors:
        message = _format_errors(errors, config_path=config_path)
        raise ValueError(message)
