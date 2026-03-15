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

import logging
import os
import ssl
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

from ..plugins.cache.registry import load_cache_plugin
from ..plugins.resolve.base import BasePlugin
from ..plugins.resolve.registry import discover_plugins, get_plugin_class
from .config_schema import validate_config


def _is_var_key(key: str) -> bool:
    """Brief: Validate whether a string is a supported variable key name.

    Inputs:
      - key: Candidate variable name.

    Outputs:
      - bool: True when the name matches [A-Za-z_][A-Za-z0-9_]*.
    """

    if not key:
        return False

    # Keep in sync with config_schema variable name rules.
    import re as _re

    return bool(_re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key))


def _is_interpolation_var_key(key: str) -> bool:
    """Brief: Check whether a variable key should participate in interpolation.

    Inputs:
      - key: Candidate variable name.

    Outputs:
      - bool: True when key is a valid identifier and has no lowercase letters.
    """

    return _is_var_key(key) and key.upper() == key


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
      - dict: The merged variables mapping stored back onto cfg['variables'] and
        cfg['vars'] (for internal normalization helpers).

    Precedence:
      - CLI (-v/--var) overrides environment overrides config-file variables.

    Notes:
      - Accepts both top-level 'variables' (preferred) and legacy 'vars'. When
        both are present, 'variables' wins.
      - Keys must match [A-Za-z_][A-Za-z0-9_]*.
      - Keys from config-file 'variables'/'vars' that are not ALL_CAPS are
        ignored for interpolation (reserved for YAML anchors).
      - Values are parsed as YAML so list/dict/int/bool values can be provided.

    Example:
      >>> cfg = {'variables': {'TTL': 100}}
      >>> parse_config_variables(cfg, cli_vars=['TTL=300'])['TTL']
      300
    """

    # Prefer the public "variables" key but continue to support the legacy
    # internal "vars" key for backward compatibility.
    variables_base = cfg.get("variables")
    vars_base = cfg.get("vars") if "variables" not in cfg else None

    if variables_base is not None:
        if not isinstance(variables_base, dict):
            raise ValueError("config.variables must be a mapping when present")
        merged = {
            k: v
            for k, v in variables_base.items()
            if isinstance(k, str) and _is_interpolation_var_key(k)
        }
    elif vars_base is not None:
        if not isinstance(vars_base, dict):
            raise ValueError("config.vars must be a mapping when present")
        merged = {
            k: v
            for k, v in vars_base.items()
            if isinstance(k, str) and _is_interpolation_var_key(k)
        }
    else:
        merged = {}

    # Track which variable keys were sourced from the config file. This is used
    # by config_schema normalization to restrict whole-node injection to
    # config-authored variables only (environment variables are interpolation-only).
    cfg["__schema_validation_config_var_keys"] = sorted(str(k) for k in merged.keys())

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
                "Invalid variable name %r (must match [A-Za-z_][A-Za-z0-9_]*)" % k
            )
        merged[k] = _parse_yaml_value(raw)

    # Store on both keys so that downstream helpers which look at cfg['vars']
    # continue to work while callers see the public 'variables' mapping.
    cfg["variables"] = merged
    cfg["vars"] = merged
    return merged


def _coerce_bool_flag(value: object, *, default: bool) -> bool:
    """Brief: Coerce a config value to bool with string-aware parsing.

    Inputs:
      - value: Candidate boolean-like value.
      - default: Fallback boolean used when value is None or unrecognized.

    Outputs:
      - bool: Parsed boolean value.
    """

    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
    return bool(default)


def _resolve_abort_on_fail_flag(container: Dict[str, Any], *, default: bool) -> bool:
    """Brief: Resolve abort behavior from a config mapping.

    Inputs:
      - container: Mapping that may include abort_on_fail or abort_on_failure.
      - default: Fallback when no explicit abort flag is present.

    Outputs:
      - bool: Effective abort behavior.

    Notes:
      - Supports both 'abort_on_fail' and 'abort_on_failure'; when both are
        present, 'abort_on_fail' takes precedence.
    """

    if "abort_on_fail" in container:
        return _coerce_bool_flag(container.get("abort_on_fail"), default=default)
    if "abort_on_failure" in container:
        return _coerce_bool_flag(container.get("abort_on_failure"), default=default)
    return bool(default)


def _iter_tls_ca_file_checks(
    cfg: Dict[str, Any],
) -> List[Tuple[str, str, bool]]:
    """Brief: Collect TLS ca_file validation checks from upstream config.

    Inputs:
      - cfg: Parsed configuration mapping.

    Outputs:
      - list[tuple[str, str, bool]] where each item is:
        - ca_file path string
        - human-readable config location
        - effective abort_on_fail behavior
    """
    checks: List[Tuple[str, str, bool]] = []
    upstream_cfg = cfg.get("upstreams")
    if not isinstance(upstream_cfg, dict):
        return checks

    def _collect_from_endpoints(raw: object, path_prefix: str) -> None:
        if not isinstance(raw, list):
            return
        for idx, endpoint in enumerate(raw):
            if not isinstance(endpoint, dict):
                continue
            tls_cfg = endpoint.get("tls")
            if not isinstance(tls_cfg, dict):
                continue
            raw_ca_file = tls_cfg.get("ca_file")
            if raw_ca_file is None:
                continue
            ca_file = str(raw_ca_file).strip()
            if not ca_file:
                continue

            endpoint_abort = _resolve_abort_on_fail_flag(endpoint, default=True)
            tls_abort = _resolve_abort_on_fail_flag(tls_cfg, default=endpoint_abort)
            checks.append(
                (
                    ca_file,
                    f"{path_prefix}[{idx}].tls.ca_file",
                    tls_abort,
                )
            )

    _collect_from_endpoints(upstream_cfg.get("endpoints"), "upstreams.endpoints")

    backup_cfg = upstream_cfg.get("backup")
    if isinstance(backup_cfg, dict):
        _collect_from_endpoints(
            backup_cfg.get("endpoints"),
            "upstreams.backup.endpoints",
        )

    return checks


def _validate_tls_ca_file(ca_file: str, *, location: str) -> None:
    """Brief: Validate a TLS CA bundle path for existence, readability, and format.

    Inputs:
      - ca_file: Filesystem path to CA bundle file.
      - location: Config key path used in error messages.

    Outputs:
      - None.

    Raises:
      - ValueError: When the CA bundle path is missing, unreadable, or invalid.
    """
    if not os.path.exists(ca_file):
        raise ValueError(
            f"{location}: CA file {ca_file!r} does not exist",
        )
    if not os.path.isfile(ca_file):
        raise ValueError(
            f"{location}: CA file {ca_file!r} is not a regular file",
        )
    try:
        with open(ca_file, "rb"):
            pass
    except OSError as exc:
        raise ValueError(
            f"{location}: CA file {ca_file!r} is not readable: {exc}",
        ) from exc

    try:
        ssl.create_default_context(cafile=ca_file)
    except (ssl.SSLError, OSError, ValueError) as exc:
        raise ValueError(
            f"{location}: CA file {ca_file!r} is not a valid TLS CA bundle: {exc}",
        ) from exc


def _validate_tls_ca_files(cfg: Dict[str, Any]) -> None:
    """Brief: Validate all configured TLS CA bundle paths.

    Inputs:
      - cfg: Parsed and schema-validated configuration mapping.

    Outputs:
      - None.

    Notes:
      - For each TLS ca_file, failures are fatal by default.
      - When abort_on_fail/abort_on_failure is explicitly false on the endpoint
        or tls block, failures are logged and startup continues.
    """
    logger = logging.getLogger("foghorn.config.config_parser")

    for ca_file, location, abort_on_fail in _iter_tls_ca_file_checks(cfg):
        try:
            _validate_tls_ca_file(ca_file, location=location)
        except ValueError as exc:
            if abort_on_fail:
                raise
            logger.warning(
                "%s (continuing because abort_on_fail/abort_on_failure is false)",
                exc,
            )


def parse_config_file(
    config_path: str,
    *,
    cli_vars: Optional[List[str]] = None,
    unknown_keys: str = "warn",
    skip_schema_validation: bool = False,
) -> Dict[str, Any]:
    """Brief: Read, variable-merge, and schema-validate a v2 YAML config file.

    Inputs:
      - config_path: Path to the YAML configuration file.
      - cli_vars: Optional list of CLI `KEY=YAML` assignments (from -v/--var).
      - unknown_keys: Policy for unknown config keys not described by the
        JSON Schema ("ignore", "warn", or "error"). See
        ``foghorn.config.config_schema.validate_config`` for semantics.
      - skip_schema_validation: When true, bypass JSON Schema validation.

    Outputs:
      - dict: Parsed configuration mapping (mutated by validate_config).

    Raises:
      - ValueError: When schema validation fails or variables are invalid.

    Notes:
      - validate_config() performs normalization steps, including variable
        expansion, and may remove cfg['vars'] after expansion.
      - The JSON Schema document enforces the v2 root layout
        (vars/server/upstreams/logging/stats/http/plugins); legacy root keys are
        not part of the accepted schema anymore.
    """

    with open(config_path, "r") as f:
        cfg: Dict[str, Any] = yaml.safe_load(f) or {}

    if not isinstance(cfg, dict):
        raise ValueError("Configuration root must be a mapping")

    # Expand and validate variables, then run JSON Schema validation.
    parse_config_variables(cfg, cli_vars=list(cli_vars or []))
    validate_config(
        cfg,
        config_path=config_path,
        unknown_keys=unknown_keys,
        skip_schema_validation=bool(skip_schema_validation),
    )
    _validate_tls_ca_files(cfg)

    return cfg


def _normalize_upstream_endpoints_list(
    upstream_raw: List[Any],
) -> List[Dict[str, Union[str, int, dict]]]:
    """Brief: Normalize a raw upstream endpoints list.

    Inputs:
      - upstream_raw: List of upstream endpoint mappings.

    Outputs:
      - list[dict]: Normalized upstream endpoint mappings compatible with
        foghorn.servers.server.send_query_with_failover.

    Raises:
      - ValueError: When items are not mappings or required fields are missing.

    Notes:
      - This helper is shared by normalize_upstream_config() and
        normalize_upstream_backup_config() so that the 'endpoints' and
        'upstreams.backup.endpoints' blocks share identical parsing rules.
    """

    upstreams: List[Dict[str, Union[str, int, dict]]] = []
    for u in upstream_raw:
        if not isinstance(u, dict):
            raise ValueError("each upstream entry must be a mapping")

        transport = str(u.get("transport", "udp")).strip().lower()

        if transport == "doh":
            rec: Dict[str, Union[str, int, dict]] = {
                "transport": "doh",
                "url": str(u["url"]),
            }
            if "id" in u and str(u.get("id", "")).strip():
                rec["id"] = str(u.get("id")).strip()
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
        raw_port = u.get("port")
        if raw_port is None or (isinstance(raw_port, str) and not raw_port.strip()):
            raw_port = default_port
        rec2: Dict[str, Union[str, int, dict]] = {
            "host": str(u["host"]),
            "port": int(raw_port),
        }
        if "id" in u and str(u.get("id", "")).strip():
            rec2["id"] = str(u.get("id")).strip()
        if "transport" in u:
            rec2["transport"] = transport
        if "tls" in u and isinstance(u["tls"], dict):
            rec2["tls"] = u["tls"]
        if "pool" in u and isinstance(u["pool"], dict):
            rec2["pool"] = u["pool"]
        upstreams.append(rec2)

    return upstreams


def normalize_upstream_config(
    cfg: Dict[str, Any],
) -> Tuple[List[Dict[str, Union[str, int, dict]]], int]:
    """Brief: Normalize upstream configuration to endpoints + timeout.

    Inputs:
      - cfg: dict containing parsed YAML with v2 layout:

            upstreams:
              strategy: failover|round_robin|random
              max_concurrent: int
              endpoints: [...]

            server:
              resolver:
                timeout_ms: int

    Outputs:
      - (upstreams, timeout_ms):
        - upstreams: list[dict] with keys like {'host': str, 'port': int} or DoH
          metadata (transport/url/method/headers/tls).
        - timeout_ms: int timeout in milliseconds applied per upstream attempt.

    Raises:
      - ValueError: For invalid types or missing required fields.
    """

    upstream_block = cfg.get("upstreams")
    if not isinstance(upstream_block, dict):
        raise ValueError("config.upstreams must be a mapping with an 'endpoints' list")

    upstream_raw = upstream_block.get("endpoints")
    if not isinstance(upstream_raw, list):
        raise ValueError("config.upstreams.endpoints must be a list")

    upstreams = _normalize_upstream_endpoints_list(upstream_raw)

    timeout_ms = 2000
    server_cfg = cfg.get("server") or {}
    if not isinstance(server_cfg, dict):
        raise ValueError("config.server must be a mapping when present")

    resolver_cfg = server_cfg.get("resolver") or {}
    if not isinstance(resolver_cfg, dict):
        raise ValueError("config.server.resolver must be a mapping when present")
    try:
        timeout_ms = int(resolver_cfg.get("timeout_ms", timeout_ms))
    except (TypeError, ValueError):
        timeout_ms = 2000

    return upstreams, timeout_ms


def normalize_upstream_backup_config(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Brief: Normalize upstreams.backup.endpoints to a list of upstream dicts.

    Inputs:
      - cfg: Parsed configuration mapping.

    Outputs:
      - list[dict]: Normalized backup upstream endpoints.

    Notes:
      - This is a v2-only helper. When upstreams.backup.endpoints is missing,
        returns an empty list.
      - Backup endpoints are normalized using the same parsing rules as primary
        upstream endpoints.

    Example:
      >>> cfg = {'upstreams': {'endpoints': [{'host': '1.1.1.1'}], 'backup': {'endpoints': [{'host': '8.8.8.8'}]}}}
      >>> normalize_upstream_backup_config(cfg)[0]['host']
      '8.8.8.8'
    """

    upstream_cfg = cfg.get("upstreams")
    if not isinstance(upstream_cfg, dict):
        return []

    backup_cfg = upstream_cfg.get("backup")
    if backup_cfg is None:
        return []
    if not isinstance(backup_cfg, dict):
        raise ValueError("config.upstreams.backup must be a mapping when present")

    raw = backup_cfg.get("endpoints")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(
            "config.upstreams.backup.endpoints must be a list when present"
        )

    return [dict(x) for x in _normalize_upstream_endpoints_list(raw)]


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


def _derive_plugin_instance_name(
    *,
    plugin_cls: type[BasePlugin],
    module_path: str,
    explicit_name: object | None,
    used_names: set[str],
) -> str:
    """Brief: Compute a stable, unique plugin instance name with auto-suffixing.

    Inputs:
      - plugin_cls: Resolved BasePlugin subclass.
      - module_path: Original module/alias text from the configuration.
      - explicit_name: Optional explicit name from the config entry.
      - used_names: Set of names already assigned to earlier plugin instances.

    Outputs:
      - str: Unique instance name. When explicit_name is non-empty and not
        already present in used_names, it is used as-is. When explicit_name is
        omitted or empty, a base name is derived from the plugin's aliases,
        falling back to the final segment of module_path, and a numeric suffix
        ("2", "3", ...) is appended when needed to avoid collisions.
    """

    # Honor explicit names exactly but keep collisions strict for operator
    # supplied values so configuration mistakes are surfaced early.
    if explicit_name is not None:
        base = str(explicit_name).strip()
        if not base:
            raise ValueError(
                "plugins[]: explicit 'name' must not be empty when provided"
            )
        if base in used_names:
            raise ValueError(
                "Duplicate plugin name '%s'. Each plugin must have a unique name; "
                "set a different 'name' value in plugins[] to disambiguate." % base
            )
        used_names.add(base)
        return base

    # Derived name path: prefer first declared alias, then module basename,
    # then the plugin class name. This keeps defaults stable even if call
    # ordering changes.
    try:
        raw_aliases = list(getattr(plugin_cls, "get_aliases", lambda: [])())
    except Exception:
        raw_aliases = []

    aliases = [str(a or "").strip() for a in raw_aliases if str(a or "").strip()]

    # Heuristic: prefer aliases without hyphens/underscores when available so
    # that plugins like DockerHosts default to a short, friendly name such as
    # "docker" instead of "docker-hosts".
    root: str
    if aliases:
        simple_candidates = [a for a in aliases if "-" not in a and "_" not in a]
        if simple_candidates:
            root = simple_candidates[0]
        else:
            root = aliases[0]
    else:
        # Fall back to the last segment of the module path, then the class name.
        module_tail = str(module_path or "").strip().split(".")[-1]
        root = module_tail or getattr(plugin_cls, "__name__", "plugin")

    if not root:
        root = getattr(plugin_cls, "__name__", "plugin")

    # Normalize to a simple, human-friendly identifier.
    base_name = str(root).strip()

    # If unused, take it as-is; otherwise append a numeric suffix starting at 2.
    if base_name not in used_names:
        used_names.add(base_name)
        return base_name

    idx = 2
    while True:
        candidate = f"{base_name}{idx}"
        if candidate not in used_names:
            used_names.add(candidate)
            return candidate
        idx += 1


def load_plugins(plugin_specs: List[dict]) -> List[BasePlugin]:
    """Brief: Load and initialize plugins from config plugin specifications.

    Inputs:
      - plugin_specs: List of plugin specs. Each item is either:
        - str: a dotted module path or short alias, or
        - dict: plugin entry mapping with v2 keys:
            - type: plugin type/alias (maps to discover_plugins/get_plugin_class)
            - id/name: optional identifier for the plugin instance
            - config: plugin-specific configuration mapping
            - enabled: bool (default True). When false, the plugin is skipped.
            - comment: optional human-only string (ignored)
            - hooks.pre_resolve / hooks.post_resolve / hooks.setup:
              per-hook priorities as int or {priority: int}
            - hooks.priority: shorthand setting all three hook priorities

    Outputs:
      - list[BasePlugin]: Initialized plugin instances.

    Notes:
      - `Comment` is rejected; use `comment`.
      - Each plugin instance must have a unique name. When a config entry omits
        `name` and `id`, a name derived from the plugin's primary alias (or
        module basename) is used and a numeric suffix ("2", "3", ...) is
        appended when needed to avoid collisions.
    """

    alias_registry = discover_plugins()
    plugins: List[BasePlugin] = []
    seen_names: set[str] = set()

    for spec in plugin_specs or []:
        module_path: Optional[str]
        plugin_name: Optional[object]
        raw_config: Dict[str, Any]

        spec_enabled: object | None = None

        # Hooks shorthands (preferred):
        # - hooks.pre_resolve: <int> or {priority: <int>}
        # - hooks.post_resolve: <int> or {priority: <int>}
        # - hooks.priority: <int> sets pre/post/setup priorities
        hooks_priority: object | None = None
        hooks_pre: object | None = None
        hooks_post: object | None = None
        hooks_setup: object | None = None

        if isinstance(spec, str):
            module_path = spec
            plugin_name = None
            raw_config = {}
        elif isinstance(spec, dict):
            if "module" in spec:
                raise ValueError(
                    "plugins[]: 'module' is no longer supported; use 'type'"
                )

            module_path = spec.get("type")
            # Prefer explicit "name" when provided; otherwise fall back to the
            # v2 "id" field so operator-assigned instance IDs become the
            # human-visible plugin names.
            plugin_name = spec.get("name") or spec.get("id")

            # Hooks are the preferred way to set per-hook priorities.
            hooks_obj = spec.get("hooks")
            if isinstance(hooks_obj, dict):
                hooks_priority = hooks_obj.get("priority")

                pre_obj = hooks_obj.get("pre_resolve")
                if isinstance(pre_obj, dict):
                    hooks_pre = pre_obj.get("priority")
                elif pre_obj is not None:
                    hooks_pre = pre_obj

                post_obj = hooks_obj.get("post_resolve")
                if isinstance(post_obj, dict):
                    hooks_post = post_obj.get("priority")
                elif post_obj is not None:
                    hooks_post = post_obj

                setup_obj = hooks_obj.get("setup")
                if isinstance(setup_obj, dict):
                    hooks_setup = setup_obj.get("priority")
                elif setup_obj is not None:
                    hooks_setup = setup_obj

            for legacy_key in (
                "priority",
                "pre_priority",
                "post_priority",
                "setup_priority",
            ):
                if legacy_key in spec:
                    raise ValueError(
                        f"plugins[]: '{legacy_key}' is no longer supported; use hooks.* priorities"
                    )
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

        cfg_enabled = raw_config.get("enabled")
        for legacy_key in (
            "priority",
            "pre_priority",
            "post_priority",
            "setup_priority",
        ):
            if legacy_key in raw_config:
                raise ValueError(
                    f"plugins[].config: '{legacy_key}' is no longer supported; use hooks.* priorities"
                )
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

        # Hooks are encouraged as the default priority mechanism.
        pre_priority: object | None = None
        post_priority: object | None = None
        setup_priority: object | None = None

        # 1) Hook-specific priorities (preferred; take precedence).
        if hooks_priority is not None:
            pre_priority = hooks_priority
            post_priority = hooks_priority
            setup_priority = hooks_priority
        if hooks_pre is not None:
            pre_priority = hooks_pre
        if hooks_post is not None:
            post_priority = hooks_post
        if hooks_setup is not None:
            setup_priority = hooks_setup

        plugin_specific_config = dict(raw_config)

        # Resolve plugin class eagerly so we can derive a stable, human-friendly
        # instance name when the config omits "name". The effective instance
        # name is used for logging, statistics, and HTTP routing.
        #
        # In minimal/headless builds, optional plugin dependencies may be absent.
        # When this happens, skip the plugin by default unless the plugin config
        # explicitly sets abort_on_failure=true.
        import_abort_on_failure = bool(raw_config.get("abort_on_failure", False))
        try:
            plugin_cls = get_plugin_class(module_path, alias_registry)
        except Exception as exc:
            log = logging.getLogger("foghorn.config.plugins")
            if import_abort_on_failure:
                raise RuntimeError(
                    f"Failed to load plugin {module_path!r} with abort_on_failure=true: {exc}"
                ) from exc
            log.warning(
                "Skipping plugin %s because it could not be imported (%s). "
                "Set abort_on_failure=true to make this fatal.",
                module_path,
                exc,
            )
            continue

        effective_name = _derive_plugin_instance_name(
            plugin_cls=plugin_cls,
            module_path=module_path,
            explicit_name=plugin_name,
            used_names=seen_names,
        )

        # Per-plugin cache selection.
        cache_cfg = plugin_specific_config.pop("cache", None)

        for k in (
            "enabled",
            "comment",
        ):
            plugin_specific_config.pop(k, None)

        validated_config = _validate_plugin_config(plugin_cls, plugin_specific_config)

        # Resolve cache instance and inject into plugin configuration.
        try:
            from foghorn.plugins.resolve import base as plugin_base

            global_cache = getattr(plugin_base, "DNS_CACHE", None)
        except (
            Exception
        ):  # pragma: nocover defensive: import failure falls back to no global cache
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
