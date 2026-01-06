"""JSON Schema-based validation for Foghorn YAML configuration.

This module centralizes loading and validating the main ``config.yaml`` using
an external JSON Schema document stored under ``assets/config-schema.json``.
"""

from __future__ import annotations

import copy
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from jsonschema import Draft202012Validator, ValidationError
    from jsonschema.exceptions import SchemaError
except (
    Exception
):  # pragma: nocover defensive: allow import in environments without jsonschema installed
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

        which is parsed as {"module": None}. The runtime cache loader treats an
        explicit null module as "disable caching" (i.e., the `none` cache plugin),
        but the JSON Schema expects either:
        - cache omitted entirely, or
        - cache: null, or
        - cache: <string>, or
        - cache: {module: <string>, config: <object>}

        To keep validation aligned with runtime behavior, treat an explicit
        null cache module value as if the user had configured `module=none`.
    """

    cache_cfg = cfg.get("cache")
    if not isinstance(cache_cfg, dict):
        return

    module = cache_cfg.get("module")
    if isinstance(module, str) and not module.strip():
        module = None

    # If cache.module is explicitly null, interpret it as the "none" cache
    # plugin alias (i.e., disable caching). This keeps schema validation aligned
    # with runtime behavior even when YAML templating emits an explicit null.
    if "module" in cache_cfg and cache_cfg.get("module") is None:
        cache_cfg["module"] = "none"
        module = "none"

    subcfg = cache_cfg.get("config")
    if subcfg is None:
        # Schema expects an object when present; keep validation permissive.
        cache_cfg.pop("config", None)


_VAR_PATTERN = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")


def _normalize_variables_for_validation(cfg: Dict[str, Any]) -> None:
    """Brief: Expand top-level `vars` into the config and remove the group.

    Inputs:
      - cfg: Parsed YAML configuration mapping (mutated in-place).

    Outputs:
      - None.

    Behavior:
      - Reads cfg['variables'] (a mapping of key -> YAML value).
      - Replaces `${KEY}` occurrences inside strings.
      - If a string value is exactly `$KEY` or `${KEY}`, the value is replaced
        with the variable's underlying YAML value (list/dict/int/etc.).
      - The `variables` group itself is removed after expansion so JSON Schema
        validation does not reject it.

    Notes:
      - Variable substitution is applied across the entire config (excluding the
        `variables` group). Keys are not substituted, only values.
      - Cycles in variables are detected and will raise ValueError.
    """

    variables = cfg.get("vars")
    # Backward compatibility: accept legacy top-level 'variables' as an alias
    # for 'vars' and normalize it before schema validation.
    if variables is None and "variables" in cfg:
        legacy = cfg.get("variables")
        if not isinstance(legacy, dict):
            raise ValueError("config.variables must be a mapping when present")
        cfg["vars"] = legacy
        cfg.pop("variables", None)
        variables = legacy
    if variables is None:
        return
    if not isinstance(variables, dict):
        raise ValueError("config.vars must be a mapping when present")

    # Enforce uppercase variable keys to make substitutions visually distinct
    # and avoid accidentally treating normal config fields as variables.
    for k in variables.keys():
        if not isinstance(k, str):
            raise ValueError("config.vars keys must be strings")
        if k != k.upper():
            raise ValueError(f"config.vars key {k!r} must be ALL_UPPERCASE")
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", k):
            raise ValueError(f"config.vars key {k!r} must match [A-Z_][A-Z0-9_]*")

    resolved: Dict[str, Any] = {}

    def _resolve_var(key: str, stack: set[str]) -> Any:
        if key in resolved:
            return resolved[key]
        if key in stack:
            cycle = " -> ".join(list(stack) + [key])
            raise ValueError(f"config.variables contains a cycle: {cycle}")
        if key not in variables:
            raise KeyError(key)

        stack.add(key)
        resolved_value = _expand_obj(variables[key], stack)
        stack.remove(key)

        resolved[key] = resolved_value
        return resolved_value

    def _expand_string(text: str, stack: set[str]) -> Any:
        # Whole-node injection: "$KEY" or "${KEY}" becomes the variable value.
        if text.startswith("${") and text.endswith("}") and len(text) > 3:
            candidate = text[2:-1]
            if candidate in variables:
                return copy.deepcopy(_resolve_var(candidate, stack))
        if text.startswith("$") and len(text) > 1:
            candidate2 = text[1:]
            if candidate2 in variables:
                return copy.deepcopy(_resolve_var(candidate2, stack))

        # In-string substitution: replace `${KEY}` occurrences.
        def _repl(match: re.Match[str]) -> str:
            k = match.group(1)
            try:
                v = _resolve_var(k, stack)
            except KeyError:
                return match.group(0)

            if isinstance(v, bool):
                return "true" if v else "false"
            if v is None:
                return "null"
            if isinstance(v, (int, float, str)):
                return str(v)
            # Non-scalar values should be injected as whole nodes; fall back to
            # JSON text when embedded in a string.
            try:
                return json.dumps(v)
            except Exception:
                return str(v)

        return _VAR_PATTERN.sub(_repl, text)

    def _injection_var_name(text: str) -> str | None:
        if text.startswith("${") and text.endswith("}") and len(text) > 3:
            candidate = text[2:-1]
            if candidate in variables:
                return candidate
        if text.startswith("$") and len(text) > 1:
            candidate2 = text[1:]
            if candidate2 in variables:
                return candidate2
        return None

    def _expand_obj(obj: Any, stack: set[str]) -> Any:
        if isinstance(obj, str):
            return _expand_string(obj, stack)
        if isinstance(obj, list):
            out: list[Any] = []
            for item in obj:
                # Support splicing a variable list into a list, enabling config like:
                #   blocked_ips:
                #     - $BLOCKED_IPS
                #     - {ip: 4.3.2.1, action: remove}
                if isinstance(item, str):
                    var_name = _injection_var_name(item)
                    expanded = _expand_string(item, stack)
                    if var_name is not None and isinstance(expanded, list):
                        out.extend(expanded)
                        continue
                    out.append(expanded)
                    continue
                out.append(_expand_obj(item, stack))
            return out
        if isinstance(obj, dict):
            return {k: _expand_obj(v, stack) for k, v in obj.items()}
        return obj

    # Resolve all variables first (so missing references are caught early).
    for k in list(variables.keys()):
        _resolve_var(str(k), set())

    # Expand the rest of the config. Do not expand inside the vars mapping.
    for top_key in list(cfg.keys()):
        if top_key == "vars":
            continue
        cfg[top_key] = _expand_obj(cfg[top_key], set())

    # Remove variable groups after expansion so JSON Schema validation accepts
    # configs that used either 'vars' (new) or 'variables' (legacy/public).
    cfg.pop("vars", None)
    cfg.pop("variables", None)


def _normalize_dnssec_config_for_validation(cfg: Dict[str, Any]) -> None:
    """Brief: Normalize DNSSEC config fields for schema/runtime compatibility.

    Inputs:
      - cfg: Parsed YAML configuration mapping (mutated in-place).

    Outputs:
      - None.

    Behavior:
      - Accept a legacy key 'validate' as an alias for 'validation' when
        'validation' is not already set.
      - Canonicalize the 'validation' string to lowercase (e.g. LOCAL_EXTENDED ->
        local_extended) so JSON Schema enums remain case-insensitive.

    Notes:
      - DNSSEC config can appear at the root 'dnssec' block or nested under
        'foghorn.dnssec' (preferred).
      - Unlike previous versions, 'local' and 'local_extended' are preserved as
        distinct values.
    """

    def _normalize_dnssec_block(block: Any) -> None:
        if not isinstance(block, dict):
            return

        validation = block.get("validation")
        if isinstance(validation, str):
            block["validation"] = validation.strip().lower()

    _normalize_dnssec_block(cfg.get("dnssec"))

    foghorn_cfg = cfg.get("foghorn")
    if isinstance(foghorn_cfg, dict):
        _normalize_dnssec_block(foghorn_cfg.get("dnssec"))


def _normalize_plugin_entries_for_validation(cfg: Dict[str, Any]) -> None:
    """Brief: Normalize plugin entry aliases/meta fields for JSON Schema validation.

    Inputs:
      - cfg: Parsed YAML configuration mapping (mutated in-place).

    Outputs:
      - None.

    Behavior:
      - Supports plugin entry meta keys that are not part of the JSON Schema by
        translating or stripping them.
      - Removes disabled plugin entries (enabled: false) so they are not loaded.

    Supported meta fields:
      - priority: Shorthand that sets pre_priority/post_priority/setup_priority.
      - enabled: When false (either at entry level or in entry.config), the
        plugin entry is removed.
      - comment: Optional human-only string; removed.

    Notes:
      - Explicit pre_priority/post_priority/setup_priority values win over the
        shorthand when both are provided.
      - JSON Schema disallows unknown keys on plugin entries
        (additionalProperties: false).
    """

    plugins = cfg.get("plugins")
    if not isinstance(plugins, list):
        return

    normalized: list[Any] = []
    for entry in plugins:
        if not isinstance(entry, dict):
            normalized.append(entry)
            continue

        # Determine enabled state (entry-level or inside config).
        enabled_obj: Any = entry.get("enabled")
        config_obj = entry.get("config")

        # Enforce lowercase-only comment.
        if "Comment" in entry:
            raise ValueError(
                "plugins[]: use 'comment' (lowercase) rather than 'Comment'"
            )
        if isinstance(config_obj, dict) and "Comment" in config_obj:
            raise ValueError(
                "plugins[].config: use 'comment' (lowercase) rather than 'Comment'"
            )

        if isinstance(config_obj, dict) and "enabled" in config_obj:
            enabled_obj = config_obj.get("enabled")

        enabled = True
        if enabled_obj is not None:
            enabled = bool(enabled_obj)

        if not enabled:
            continue

        # Strip non-schema fields.
        entry.pop("enabled", None)
        entry.pop("comment", None)

        if "priority" in entry:
            prio = entry.pop("priority")
            entry.setdefault("pre_priority", prio)
            entry.setdefault("post_priority", prio)
            entry.setdefault("setup_priority", prio)

        normalized.append(entry)

    cfg["plugins"] = normalized


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


def _split_extra_property_errors(
    errors: List[ValidationError],
) -> tuple[List[ValidationError], List[ValidationError]]:
    """Brief: Partition validation errors into extra-property vs other errors.

    Inputs:
      - errors: List of jsonschema.ValidationError instances.

    Outputs:
      - (extra_errors, other_errors):
        - extra_errors: Errors whose validator indicates an unexpected property
          (e.g. ``additionalProperties`` or ``unevaluatedProperties``).
        - other_errors: All remaining errors.
    """

    extra: List[ValidationError] = []
    other: List[ValidationError] = []
    for err in errors:
        if getattr(err, "validator", None) in {
            "additionalProperties",
            "unevaluatedProperties",
        }:
            extra.append(err)
        else:
            other.append(err)
    return extra, other


def validate_config(
    cfg: Dict[str, Any],
    *,
    schema_path: Optional[Path] = None,
    config_path: Optional[str] = "./config/config.yaml",
    unknown_keys: str = "warn",
) -> None:
    """Brief: Validate a parsed YAML configuration mapping against JSON Schema.

    Inputs:
      - cfg: Dict loaded from YAML (top-level configuration mapping).
      - schema_path: Optional explicit path to JSON Schema file. When omitted,
        the default ``assets/config-schema.json`` is used.
      - config_path: Optional string path to the YAML file, used only for
        error messages.
      - unknown_keys: Policy for keys not described by the JSON Schema at any
        depth. Supported values:

        - "ignore": ignore extra-property validation errors entirely.
        - "warn": (default) log a warning listing the offending paths but do
          not treat them as fatal.
        - "error": treat extra-property errors as fatal, alongside all other
          validation errors.

    Outputs:
      - None on success.

    Raises:
      - ValueError: when non-extra validation fails, or when ``unknown_keys`` is
        "error" and there are any extra-property errors. The message includes
        all relevant validation errors and offending instance paths.

    Example:
      >>> from pathlib import Path
      >>> import yaml
      >>> data = yaml.safe_load("listen: {host: 127.0.0.1, port: 5353}\\nupstreams: [{host: 1.1.1.1, port: 53}]")
      >>> validate_config(data)  # does not raise for valid config
    """
    # Resolve the effective schema path so that error messages clearly state
    # which file failed to load when something goes wrong.
    effective_schema_path = schema_path or get_default_schema_path()

    if unknown_keys not in {"ignore", "warn", "error"}:
        raise ValueError(
            f"unknown_keys policy must be 'ignore', 'warn', or 'error', got {unknown_keys!r}"
        )

    # Normalize config regardless of whether JSON Schema validation is
    # available. This keeps runtime behavior consistent even when assets are
    # missing or jsonschema is not installed.
    _normalize_variables_for_validation(cfg)
    _normalize_cache_config_for_validation(cfg)
    _normalize_dnssec_config_for_validation(cfg)
    _normalize_plugin_entries_for_validation(cfg)

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

    validator = Draft202012Validator(schema)
    all_errors = sorted(validator.iter_errors(cfg), key=lambda e: list(e.path))
    if not all_errors:
        # No validation errors; configuration is considered valid.
        return None

    extra_errors, other_errors = _split_extra_property_errors(all_errors)

    # Any non-extra validation failure is always fatal. Include both non-extra
    # and extra-property errors in the message so operators see the full
    # picture when fixing the config.
    if other_errors:
        message = _format_errors(other_errors + extra_errors, config_path=config_path)
        raise ValueError(message)

    # Only extra-property errors remain.
    if not extra_errors:
        return None

    message = _format_errors(extra_errors, config_path=config_path)

    if unknown_keys == "ignore":
        return None
    if unknown_keys == "warn":
        logger.warning(message)
        return None

    # unknown_keys == "error": treat these as fatal.
    raise ValueError(message)

    # No validation errors; configuration is considered valid.
    return None
