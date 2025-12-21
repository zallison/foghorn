"""Configuration parsing and normalization helpers for Foghorn.

Brief:
  This module contains the configuration-parsing utilities that are used by the
  CLI entrypoint. It centralizes:
    - reading YAML config files
    - merging variables from config/env/CLI
    - JSON Schema validation (including variable expansion performed by
      validate_config)
    - normalization helpers for upstreams
    - loading plugins from config plugin specs

Inputs:
  - YAML config dicts and paths

Outputs:
  - Normalized config dicts and constructed plugin instances
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

from .config_schema import validate_config
from ..cache_plugins.registry import load_cache_plugin
from ..plugins.base import BasePlugin
from ..plugins.registry import discover_plugins, get_plugin_class


def _is_var_key(key: str) -> bool:
    """Brief: Validate whether a string is a supported variable key name.

    Inputs:
      - key: Candidate variable name.

    Outputs:
      - bool: True when the name is ALL_UPPERCASE and matches [A-Z_][A-Z0-9_]*.
    """

    if not key:
        return False
    if key != key.upper():
        return False

    # Keep in sync with config_schema variable name rules.
    import re as _re

    return bool(_re.fullmatch(r"[A-Z_][A-Z0-9_]*", key))


def _parse_yaml_value(text: str) -> Any:
    """Brief: Parse a CLI/environment variable value as YAML.

    Inputs:
      - text: String containing YAML scalar/list/dict.

    Outputs:
      - Any: Parsed value (falls back to original string on parse errors).
    """

    try:
        return yaml.safe_load(text)
    except Exception:
        return text


def parse_config_variables(
    cfg: Dict[str, Any],
    *,
    cli_vars: Optional[List[str]] = None,
    environ: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Brief: Merge config/environment/CLI variables into cfg['variables'].

    Inputs:
      - cfg: Parsed YAML configuration mapping (mutated in-place).
      - cli_vars: Optional list of CLI `KEY=YAML` assignments.
      - environ: Optional environment mapping (defaults to os.environ).

    Outputs:
      - dict: The merged variables mapping stored back onto cfg['variables'].

    Precedence:
      - CLI (-v/--var) overrides environment overrides config-file variables.

    Notes:
      - Only ALL_UPPERCASE keys matching [A-Z_][A-Z0-9_]* are considered.
      - Values are parsed as YAML so list/dict/int/bool values can be provided.

    Example:
      >>> cfg = {'variables': {'TTL': 100}}
      >>> parse_config_variables(cfg, cli_vars=['TTL=300'])['TTL']
      300
    """

    base = cfg.get("variables")
    if base is None:
        merged: Dict[str, Any] = {}
    elif isinstance(base, dict):
        merged = dict(base)
    else:
        raise ValueError("config.variables must be a mapping when present")

    env = environ or dict(os.environ)
    for k, v in env.items():
        if not isinstance(k, str):
            continue
        if not _is_var_key(k):
            continue
        merged[k] = _parse_yaml_value(str(v))

    for assignment in cli_vars or []:
        if "=" not in assignment:
            raise ValueError(
                "Invalid -v/--var value (expected KEY=YAML), got: %r" % assignment
            )
        k, raw = assignment.split("=", 1)
        k = str(k).strip()
        if not _is_var_key(k):
            raise ValueError(
                "Invalid variable name %r (must be ALL_UPPERCASE and match [A-Z_][A-Z0-9_]*)"
                % k
            )
        merged[k] = _parse_yaml_value(raw)

    cfg["variables"] = merged
    return merged


def parse_config_file(
    config_path: str,
    *,
    cli_vars: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Brief: Read, variable-merge, and schema-validate a YAML config file.

    Inputs:
      - config_path: Path to the YAML configuration file.
      - cli_vars: Optional list of CLI `KEY=YAML` assignments (from -v/--var).

    Outputs:
      - dict: Parsed configuration mapping (mutated by validate_config).

    Raises:
      - ValueError: When schema validation fails or variables are invalid.

    Notes:
      - validate_config() performs normalization steps, including variable
        expansion, and may remove cfg['variables'] after expansion.
    """

    with open(config_path, "r") as f:
        cfg = yaml.safe_load(f) or {}

    if not isinstance(cfg, dict):
        raise ValueError("Configuration root must be a mapping")

    parse_config_variables(cfg, cli_vars=list(cli_vars or []))
    validate_config(cfg, config_path=config_path)
    return cfg


def normalize_upstream_config(
    cfg: Dict[str, Any],
) -> Tuple[List[Dict[str, Union[str, int, dict]]], int]:
    """Brief: Normalize upstream configuration to endpoints + timeout.

    Inputs:
      - cfg: dict containing parsed YAML. Supports:
        - cfg['upstreams'] as a list of upstream entries (dicts)
        - cfg['foghorn']['timeout_ms'] for the global upstream timeout.

    Outputs:
      - (upstreams, timeout_ms):
        - upstreams: list[dict] with keys like {'host': str, 'port': int} or DoH metadata.
        - timeout_ms: int timeout in milliseconds applied per upstream attempt.

    Raises:
      - ValueError: For invalid types or missing required fields.
    """

    upstream_raw = cfg.get("upstreams")
    if not isinstance(upstream_raw, list):
        raise ValueError("config.upstreams must be a list of upstream definitions")

    upstreams: List[Dict[str, Union[str, int, dict]]] = []
    for u in upstream_raw:
        if not isinstance(u, dict):
            raise ValueError("each upstream entry must be a mapping")

        transport = str(u.get("transport", "udp")).lower()

        if transport == "doh":
            rec: Dict[str, Union[str, int, dict]] = {
                "transport": "doh",
                "url": str(u["url"]),
            }
            if "method" in u:
                rec["method"] = str(u.get("method"))
            if "headers" in u and isinstance(u["headers"], dict):
                rec["headers"] = u["headers"]
            if "tls" in u and isinstance(u["tls"], dict):
                rec["tls"] = u["tls"]
            upstreams.append(rec)
            continue

        if "host" not in u:
            raise ValueError("each upstream entry must include 'host'")

        default_port = 853 if transport == "dot" else 53
        rec2: Dict[str, Union[str, int, dict]] = {
            "host": str(u["host"]),
            "port": int(u.get("port", default_port)),
        }
        if "transport" in u:
            rec2["transport"] = transport
        if "tls" in u and isinstance(u["tls"], dict):
            rec2["tls"] = u["tls"]
        if "pool" in u and isinstance(u["pool"], dict):
            rec2["pool"] = u["pool"]
        upstreams.append(rec2)

    foghorn_cfg = cfg.get("foghorn") or {}
    if not isinstance(foghorn_cfg, dict):
        raise ValueError("config.foghorn must be a mapping when present")

    try:
        timeout_ms = int(foghorn_cfg.get("timeout_ms", 2000))
    except (TypeError, ValueError):
        timeout_ms = 2000

    return upstreams, timeout_ms


def _validate_plugin_config(plugin_cls: type[BasePlugin], config: dict | None) -> dict:
    """Brief: Validate and normalize plugin configuration via optional schema hooks.

    Inputs:
      - plugin_cls: Plugin class (subclass of BasePlugin).
      - config: Raw config mapping for this plugin (may be None).

    Outputs:
      - dict: Validated/normalized config mapping to be passed into plugin_cls.

    Notes:
      - The optional "logging" sub-config is treated as a BasePlugin-level option
        and preserved verbatim across validation so that per-plugin logging
        continues to work even when plugins use typed config models.
    """

    # Preserve a shallow copy so we can safely pop meta-keys like "logging"
    # without mutating the caller's dictionary.
    base_cfg: dict = dict(config or {})

    # "logging" is consumed by BasePlugin to configure a per-plugin logger.
    # It is intentionally excluded from plugin-specific validation and
    # re-attached to the validated mapping before returning.
    logging_cfg = base_cfg.pop("logging", None)

    cfg = base_cfg

    get_model = getattr(plugin_cls, "get_config_model", None)
    if callable(get_model):  # pragma: no cover
        model_cls = get_model()
        if model_cls is None:
            validated: dict = cfg
        else:
            try:
                model_instance = model_cls(**cfg)
            except Exception as exc:  # pragma: no cover
                raise ValueError(
                    f"Invalid configuration for plugin {plugin_cls.__name__}: {exc}"
                ) from exc

            validated = cfg
            for attr in ("dict", "model_dump"):
                method = getattr(model_instance, attr, None)
                if callable(method):
                    try:
                        validated = dict(method())
                        break
                    except Exception:  # pragma: no cover
                        continue
            else:  # pragma: no cover
                try:
                    validated = dict(model_instance)
                except Exception:
                    validated = cfg

        if logging_cfg is not None and "logging" not in validated:
            validated["logging"] = logging_cfg
        return validated

    get_schema = getattr(plugin_cls, "get_config_schema", None)
    if callable(get_schema):  # pragma: no cover
        schema = get_schema()
        if schema is None:
            validated_schema_cfg = cfg
        else:
            try:
                from jsonschema import validate as _js_validate  # type: ignore

                _js_validate(instance=cfg, schema=schema)
                validated_schema_cfg = cfg
            except Exception as exc:
                raise ValueError(
                    f"Invalid configuration for plugin {plugin_cls.__name__}: {exc}"
                ) from exc

        if logging_cfg is not None and "logging" not in validated_schema_cfg:
            validated_schema_cfg["logging"] = logging_cfg
        return validated_schema_cfg

    if logging_cfg is not None and "logging" not in cfg:
        cfg["logging"] = logging_cfg
    return cfg


def load_plugins(plugin_specs: List[dict]) -> List[BasePlugin]:
    """Brief: Load and initialize plugins from config plugin specifications.

    Inputs:
      - plugin_specs: List of plugin specs. Each item is either:
        - str: a dotted module path or short alias, or
        - dict: plugin entry mapping supporting:
          - module: dotted module path or alias
          - name: optional friendly plugin label
          - config: plugin-specific configuration mapping
          - enabled: bool (default True). When false, the plugin is skipped.
          - comment: optional human-only string (ignored)
          - pre_priority/post_priority/setup_priority: BasePlugin hook priorities
          - priority: shorthand that sets all three priority fields above

    Outputs:
      - list[BasePlugin]: Initialized plugin instances.

    Notes:
      - Priority keys are treated as BasePlugin options and are not passed into
        per-plugin config model/schema validation.
      - When both explicit priority keys and `priority` are present, explicit
        keys win.
      - `Comment` is rejected; use `comment`.
      - Each plugin instance must have a unique name. When a config entry omits
        `name`, the module text is used as the instance name for consistency
        with logging and HTTP routing.
    """

    alias_registry = discover_plugins()
    plugins: List[BasePlugin] = []
    seen_names: set[str] = set()

    for spec in plugin_specs or []:
        module_path: Optional[str]
        plugin_name: Optional[object]
        raw_config: Dict[str, Any]

        spec_priority: object | None = None
        spec_pre: object | None = None
        spec_post: object | None = None
        spec_setup: object | None = None
        spec_enabled: object | None = None

        if isinstance(spec, str):
            module_path = spec
            plugin_name = None
            raw_config = {}
        elif isinstance(spec, dict):
            module_path = spec.get("module")
            plugin_name = spec.get("name")

            spec_priority = spec.get("priority")
            spec_pre = spec.get("pre_priority")
            spec_post = spec.get("post_priority")
            spec_setup = spec.get("setup_priority")
            spec_enabled = spec.get("enabled")

            if "Comment" in spec:
                raise ValueError(
                    "plugins[]: use 'comment' (lowercase) rather than 'Comment'"
                )
            _ = spec.get("comment")

            cfg_obj = spec.get("config", {})
            raw_config = cfg_obj if isinstance(cfg_obj, dict) else {}
        else:
            continue

        if not module_path:
            continue

        # Determine effective instance name used for logging, statistics, and
        # HTTP routing. When name is omitted, fall back to the module text.
        effective_name_obj: object = (
            plugin_name if plugin_name is not None else module_path
        )
        effective_name = str(effective_name_obj or "").strip()
        if not effective_name:
            raise ValueError(
                "plugins[]: each entry must have a non-empty module or name"
            )

        if effective_name in seen_names:
            raise ValueError(
                "Duplicate plugin name '%s'. Each plugin must have a unique name; "
                "set 'name' explicitly in plugins[] to disambiguate." % effective_name
            )
        seen_names.add(effective_name)

        cfg_enabled = raw_config.get("enabled")
        if "Comment" in raw_config:
            raise ValueError(
                "plugins[].config: use 'comment' (lowercase) rather than 'Comment'"
            )
        _ = raw_config.get("comment")

        enabled_obj = cfg_enabled if cfg_enabled is not None else spec_enabled
        if enabled_obj is None:
            enabled_obj = True
        if not bool(enabled_obj):
            continue

        cfg_priority = raw_config.get("priority")
        cfg_pre = raw_config.get("pre_priority")
        cfg_post = raw_config.get("post_priority")
        cfg_setup = raw_config.get("setup_priority")

        generic_priority = spec_priority if spec_priority is not None else cfg_priority

        pre_priority = cfg_pre if cfg_pre is not None else spec_pre
        post_priority = cfg_post if cfg_post is not None else spec_post
        setup_priority = cfg_setup if cfg_setup is not None else spec_setup

        if pre_priority is None and generic_priority is not None:
            pre_priority = generic_priority
        if post_priority is None and generic_priority is not None:
            post_priority = generic_priority
        if setup_priority is None and generic_priority is not None:
            setup_priority = generic_priority

        plugin_specific_config = dict(raw_config)

        # Per-plugin cache selection.
        cache_cfg = plugin_specific_config.pop("cache", None)

        for k in (
            "enabled",
            "comment",
            "priority",
            "pre_priority",
            "post_priority",
            "setup_priority",
        ):
            plugin_specific_config.pop(k, None)

        plugin_cls = get_plugin_class(module_path, alias_registry)
        validated_config = _validate_plugin_config(plugin_cls, plugin_specific_config)

        # Resolve cache instance and inject into plugin configuration.
        try:
            from foghorn.plugins import base as plugin_base

            global_cache = getattr(plugin_base, "DNS_CACHE", None)
        except Exception:
            global_cache = None

        cache_instance = global_cache
        if cache_cfg is not None:
            try:
                cache_instance = load_cache_plugin(cache_cfg)
            except Exception as exc:
                raise ValueError(
                    f"Invalid cache configuration for plugin {module_path}: {exc}"
                ) from exc

        if cache_instance is not None:
            validated_config["cache"] = cache_instance

        if pre_priority is not None:
            validated_config["pre_priority"] = pre_priority
        if post_priority is not None:
            validated_config["post_priority"] = post_priority
        if setup_priority is not None:
            validated_config["setup_priority"] = setup_priority

        # Always pass the effective instance name into the plugin constructor so
        # BasePlugin.name is stable and unique, even when config omits name.
        plugin = plugin_cls(name=effective_name, **validated_config)
        plugins.append(plugin)

    return plugins
