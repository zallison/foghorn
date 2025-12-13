"""JSON Schema-based validation for Foghorn YAML configuration.

This module centralizes loading and validating the main ``config.yaml`` using
an external JSON Schema document stored under ``assets/config-schema.json``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from jsonschema import Draft202012Validator, ValidationError
    from jsonschema.exceptions import SchemaError
except Exception:  # pragma: no cover
    Draft202012Validator = None  # type: ignore[assignment]
    ValidationError = Exception  # type: ignore[assignment]
    SchemaError = Exception  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def _normalize_cache_config_for_validation(cfg: Dict[str, Any]) -> None:
    """Brief: Normalize cache config for backward-compatible schema validation.

    Inputs:
      - cfg: Parsed YAML configuration mapping (mutated in-place).

    Outputs:
      - None.

    Notes:
      - Some configuration templating patterns produce YAML like:

          cache:
            module:

        which is parsed as {"module": None}. The runtime cache loader treats this
        as "use the default cache", but the JSON Schema expects either:
        - cache omitted entirely, or
        - cache: null, or
        - cache: <string>, or
        - cache: {module: <string>, config: <object>}

        To keep validation aligned with runtime behavior, treat:
        - cache: {module: null, config: {}} as "cache omitted"
        - cache: {module: null, config: {...}} as "module=in_memory_ttl".
    """

    cache_cfg = cfg.get("cache")
    if not isinstance(cache_cfg, dict):
        return

    module = cache_cfg.get("module")
    if isinstance(module, str) and not module.strip():
        module = None

    # If cache.module is explicitly null, interpret it as the "none" cache
    # plugin alias (i.e., disable caching). This keeps behavior aligned with the
    # NullCache documentation which uses `module: null`.
    if "module" in cache_cfg and cache_cfg.get("module") is None:
        cache_cfg["module"] = "none"
        module = "none"

    # Support legacy/alternate keys used elsewhere in the config.
    if module is None:
        module = cache_cfg.get("class") or cache_cfg.get("type")

    subcfg = cache_cfg.get("config")
    if subcfg is None:
        # Schema expects an object when present; keep validation permissive.
        cache_cfg.pop("config", None)


def get_default_schema_path() -> Path:
    """Brief: Resolve the default JSON Schema path for configuration.

    Inputs:
      - None.

    Outputs:
      - Path to a readable ``assets/config-schema.json`` file.
    """

    here = Path(__file__).resolve()

    # 1) Look for assets/config-schema.json in ancestors (source checkout).
    for ancestor in here.parents:
        candidate = ancestor / "assets" / "config-schema.json"
        if candidate.is_file():
            return candidate

    # 2) Docker image fallback: COPY . /foghorn puts assets here.
    docker_candidate = Path("/foghorn/assets/config-schema.json")
    if docker_candidate.is_file():
        return docker_candidate

    # 3) Last resort: previous behavior (keeps error message shape consistent).
    project_root = here.parents[2]
    return project_root / "assets" / "config-schema.json"


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

    header = (
        f"Invalid configuration in {config_path or '<config dict>'}:"
        if errors
        else "Invalid configuration:"
    )
    lines: List[str] = [header]
    for err in errors:
        instance_path = "/".join(str(p) for p in err.path) or "<root>"
        schema_path = "/".join(str(p) for p in err.schema_path)
        lines.append(f"- {instance_path}: {err.message} (schema: {schema_path})")
    return "\n".join(lines)


def validate_config(
    cfg: Dict[str, Any],
    *,
    schema_path: Optional[Path] = None,
    config_path: Optional[str] = "./config/config.yaml",
) -> None:
    """Brief: Validate a parsed YAML configuration mapping against JSON Schema.

    Inputs:
      - cfg: Dict loaded from YAML (top-level configuration mapping).
      - schema_path: Optional explicit path to JSON Schema file. When omitted,
        the default ``assets/config-schema.json`` is used.
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
      >>> data = yaml.safe_load("listen: {host: 127.0.0.1, port: 5353}\\nupstreams: [{host: 1.1.1.1, port: 53}]")
      >>> validate_config(data)  # does not raise for valid config
    """
    # Resolve the effective schema path so that error messages clearly state
    # which file failed to load when something goes wrong.
    effective_schema_path = schema_path or get_default_schema_path()

    # If the base schema file cannot be found, log a warning and skip
    # validation rather than aborting startup. This keeps behaviour resilient
    # in environments where assets are missing or relocated while still
    # surfacing the problem clearly in logs.
    if not effective_schema_path.is_file():
        logger.warning(
            "Configuration schema file %s not found; skipping JSON Schema validation",
            effective_schema_path,
        )
        return None

    try:
        schema = _load_schema(effective_schema_path)
    except (OSError, json.JSONDecodeError, SchemaError) as exc:
        logger.warning(
            "Failed to load or parse configuration schema at %s: %s; "
            "skipping JSON Schema validation",
            effective_schema_path,
            exc,
        )
        return None

    if Draft202012Validator is None:
        logger.warning("jsonschema is not installed; skipping JSON Schema validation")
        return None

    # Normalize select config fields to keep schema validation aligned with
    # runtime defaulting and backwards-compatible parsing.
    _normalize_cache_config_for_validation(cfg)

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(cfg), key=lambda e: list(e.path))
    if errors:
        message = _format_errors(errors, config_path=config_path)
        raise ValueError(message)

    # No validation errors; configuration is considered valid.
    return None
