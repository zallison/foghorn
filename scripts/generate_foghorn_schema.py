#!/usr/bin/env python3
"""Brief: Generate an aggregated JSON schema document for Foghorn.

Inputs:
  - Command-line arguments (optional):
    - --output / -o: Output path for JSON schema (default: ./schema.json).
    - --verbose / -v: Enable verbose logging.
    - --base-schema: Optional path to a base schema JSON file. When omitted, the
      generator searches for `assets/config-schema.json` by walking up from this
      script.

Outputs:
  - JSON file written to the specified output path.

Notes:
  - The generator *loads* the existing base schema (usually `assets/config-schema.json`)
    and adds an additional `$defs.plugin_configs` mapping that contains per-plugin
    configuration schemas.
  - This is primarily intended for tooling/editor support; it does not otherwise
    change runtime behavior.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Type

# Add the 'src' directory to sys.path to resolve 'foghorn' module imports
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
src_dir = project_root / "src"
if src_dir.is_dir() and str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from foghorn.plugins.resolve.base import BasePlugin
from foghorn.plugins.resolve import registry as plugin_registry

logger = logging.getLogger(__name__)


def _model_to_json_schema(model_cls: Type[Any]) -> Dict[str, Any]:
    """Brief: Convert a Pydantic model class into a JSON Schema mapping.

    Inputs:
      - model_cls: Pydantic BaseModel subclass providing either
        ``model_json_schema()`` (Pydantic v2) or ``schema()`` (Pydantic v1).

    Outputs:
      - Dict representing the model's JSON Schema, or an empty dict on failure.
    """

    try:
        # Prefer Pydantic v2 API when available
        modern = getattr(model_cls, "model_json_schema", None)
        if callable(modern):
            return modern()  # type: ignore[no-any-return]

        legacy = getattr(model_cls, "schema", None)
        if callable(legacy):
            return legacy()  # type: ignore[no-any-return]
    except Exception:  # pragma: no cover - defensive logging only
        logger.exception("Failed to build JSON schema for %s", model_cls)

    return {}


def _enrich_schema_descriptions(schema: Dict[str, Any]) -> None:
    """Brief: Heuristically populate missing descriptions/default notes.

    Inputs:
      - schema: Mutable JSON Schema mapping to enrich in place.

    Outputs:
      - None; ``schema`` is updated in place where descriptions are missing.

    Notes:
      - This is intentionally conservative: it never overwrites existing
        ``description`` fields and attempts to keep generated text short.
      - When possible it adds a brief mention of valid values (for ``enum``)
        or known subkeys (for ``properties``/``patternProperties``).
    """

    def _describe_node(node: Any) -> None:
        if not isinstance(node, dict):
            return

        has_description = isinstance(node.get("description"), str)
        type_value = node.get("type")
        enum_values = node.get("enum")
        properties = node.get("properties") if isinstance(node.get("properties"), dict) else None
        pattern_props = (
            node.get("patternProperties")
            if isinstance(node.get("patternProperties"), dict)
            else None
        )
        default_value = node.get("default") if "default" in node else None

        pieces: list[str] = []

        if not has_description:
            if isinstance(type_value, str):
                pieces.append(f"Type: {type_value}.")
            elif isinstance(type_value, list) and type_value:
                joined = ", ".join(str(t) for t in type_value)
                pieces.append(f"Types: {joined}.")

            if isinstance(enum_values, list) and enum_values:
                # Avoid regenerating if a previous run already added text.
                pieces.append(
                    "Valid values: "
                    + ", ".join(json.dumps(v, ensure_ascii=False) for v in enum_values)
                    + "."
                )

            if properties:
                keys_preview = ", ".join(sorted(properties.keys())[:8])
                pieces.append(f"Object with subkeys: {keys_preview}.")

            if pattern_props:
                patterns_preview = ", ".join(sorted(pattern_props.keys())[:4])
                pieces.append(f"Object with keys matching patterns: {patterns_preview}.")

        # Append a default note even if the node already had a human description,
        # but avoid duplicating if something similar is present.
        if default_value is not None:
            default_str = json.dumps(default_value, ensure_ascii=False)
            existing = node.get("description", "")
            default_sentence = f" Default: {default_str}."
            if default_sentence.strip() not in str(existing):
                pieces.append(default_sentence.strip())

        if pieces and not has_description:
            node["description"] = " ".join(pieces)
        elif pieces and has_description:
            # Only append default info to existing descriptions.
            default_sentences = [p for p in pieces if p.startswith("Default:")]
            if default_sentences:
                desc = str(node["description"]).rstrip()
                if not desc.endswith("."):
                    desc += "."
                desc += " " + " ".join(default_sentences)
                node["description"] = desc

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            _describe_node(node)

            # Recurse into common schema containers.
            for key in ("properties", "patternProperties", "$defs", "definitions"):
                child = node.get(key)
                if isinstance(child, dict):
                    for sub in child.values():
                        _walk(sub)

            for key in ("items",):
                child = node.get(key)
                if isinstance(child, dict):
                    _walk(child)
                elif isinstance(child, list):
                    for sub in child:
                        _walk(sub)

            for key in ("oneOf", "anyOf", "allOf"):
                child = node.get(key)
                if isinstance(child, list):
                    for sub in child:
                        _walk(sub)

    _walk(schema)


def collect_plugin_schemas() -> Dict[str, Any]:
    """Brief: Discover plugins and build per-plugin configuration schemas.

    Inputs:
      - None (uses ``foghorn.plugins.registry.discover_plugins()``).

    Outputs:
      - Dict mapping canonical plugin alias to a description object:

        .. code-block:: json

           {
             "<alias>": {
               "module": "foghorn.plugins.module.PluginClass",
               "aliases": ["alias", "alt"],
               "config_schema": { ... JSON Schema dict ... } | null
             }
           }
    """

    aliases_to_cls: Mapping[str, Type[BasePlugin]] = plugin_registry.discover_plugins()
    by_cls: Dict[Type[BasePlugin], Dict[str, Any]] = {}

    for alias, cls in aliases_to_cls.items():
        entry = by_cls.setdefault(
            cls,
            {
                "module": f"{cls.__module__}.{cls.__name__}",
                "aliases": set(),
                "config_schema": None,
            },
        )
        entry["aliases"].add(alias)

    results: Dict[str, Any] = {}

    for cls, info in by_cls.items():
        # Canonical alias is derived from the class name (e.g. Filter -> filter)
        canonical = plugin_registry._default_alias_for(cls)  # type: ignore[attr-defined]
        aliases = sorted(info["aliases"])
        module_path = info["module"]

        config_schema: Optional[Dict[str, Any]] = None

        # Prefer typed models when available
        get_model = getattr(cls, "get_config_model", None)
        if callable(get_model):
            try:
                model_cls = get_model()
            except Exception:  # pragma: no cover - defensive logging only
                logger.exception("get_config_model() failed for %s", module_path)
                model_cls = None

            if model_cls is not None:
                config_schema = _model_to_json_schema(model_cls)

        # Fallback: plugin-provided JSON Schema
        if config_schema is None:
            get_schema = getattr(cls, "get_config_schema", None)
            if callable(get_schema):
                try:
                    maybe_schema = get_schema()
                    if isinstance(maybe_schema, dict):
                        config_schema = maybe_schema
                except Exception:  # pragma: no cover - defensive logging only
                    logger.exception("get_config_schema() failed for %s", module_path)

        if isinstance(config_schema, dict):
            # Best-effort enrichment so each plugin config field has at least a
            # minimal description and any enum/default information is surfaced.
            _enrich_schema_descriptions(config_schema)

        results[canonical] = {
            "module": module_path,
            "aliases": aliases,
            "config_schema": config_schema,
        }

    return results


def _load_base_schema(base_schema_path: Optional[str] = None) -> Dict[str, Any]:
    """Brief: Load the main Foghorn config JSON Schema from disk.

    Inputs:
      - base_schema_path: Optional explicit path to a base schema JSON file.

    Outputs:
      - Dict representing the base configuration JSON Schema.
    """

    if base_schema_path:
        p = Path(base_schema_path)
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)

    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "assets" / "config-schema.json"
        if candidate.is_file():
            with candidate.open("r", encoding="utf-8") as f:
                return json.load(f)

    raise FileNotFoundError(
        "assets/config-schema.json not found relative to generate_foghorn_schema.py"
    )


def _augment_variables_schema(base: Dict[str, Any]) -> None:
    """Brief: Ensure top-level `variables` is described for editor tooling.

    Inputs:
      - base: Mutable JSON Schema mapping loaded from the base schema file.

    Outputs:
      - None; ``base`` is modified in place when the expected root structure is
        present.

    Notes:
      - Runtime validation strips the `variables` block before applying the
        JSON Schema, but editors and language servers still need to know that
        `variables` is a legal top-level key. This helper adds a minimal schema
        that matches the semantics enforced by _normalize_variables_for_validation:

        - keys must be ALL_CAPS identifiers matching ``[A-Z_][A-Z0-9_]*``;
        - values are arbitrary YAML/JSON values (left intentionally untyped).
    """

    try:
        root_props = base.get("properties")
        if not isinstance(root_props, dict):
            return

        if "variables" not in root_props:
            root_props["variables"] = {
                "type": "object",
                "description": (
                    "Optional mapping of ALL_CAPS variable names to arbitrary "
                    "values. These are expanded before validation and removed "
                    "from the runtime config."
                ),
                "patternProperties": {
                    r"^[A-Z_][A-Z0-9_]*$": {
                        # Accept any JSON type for variable values; runtime code
                        # performs the actual substitution and type handling.
                    }
                },
                "additionalProperties": False,
            }
    except Exception:  # pragma: no cover - defensive logging only
        logger.exception("Failed to augment variables schema")


def _augment_statistics_persistence_schema(base: Dict[str, Any]) -> None:
    """Brief: Extend statistics/stats schema with persistence and backend configuration.

    Inputs:
      - base: Mutable JSON Schema mapping loaded from the base schema file.

    Outputs:
      - None; ``base`` is modified in place when the expected statistics or
        stats structure is present. Any missing or unexpected shapes are
        treated as no-ops to keep the generator robust against schema drift.
    """

    try:
        root_props = base.get("properties")
        if not isinstance(root_props, dict):
            return

        # Support both legacy root-level "statistics" (older schemas) and the
        # v2 "stats" block used by the current configuration layout.
        stats_obj = root_props.get("statistics")
        if not isinstance(stats_obj, dict):
            stats_obj = root_props.get("stats")
            if not isinstance(stats_obj, dict):
                return

        # Ensure a properties mapping exists so we can safely extend it even
        # when the base schema only declared a bare "type": "object".
        stats_props = stats_obj.get("properties")
        if not isinstance(stats_props, dict):
            stats_props = {}
            stats_obj["properties"] = stats_props

        # Primary backend selector for the new layout where statistics and
        # query-log backends are described under logging.backends and
        # stats.source_backend picks the primary read backend. This is modeled
        # as a simple string so operators can reference either a logical backend
        # id (for example, "local-log") or a backend alias.
        if "source_backend" not in stats_props:
            stats_props["source_backend"] = {
                "type": "string",
                "description": (
                    "Identifier of the primary statistics/query-log backend "
                    "to read from. When logging.backends is configured, this "
                    "typically matches one of the backends[].id values."
                ),
            }

        persistence_obj = stats_props.get("persistence")
        if not isinstance(persistence_obj, dict):
            return

        persistence_props = persistence_obj.get("properties")
        if not isinstance(persistence_props, dict):
            return

        # Optional hint selecting which configured backend should be treated as
        # the primary read backend when multiple backends are present.
        if "primary_backend" not in persistence_props:
            persistence_props["primary_backend"] = {
                "type": "string",
                "description": (
                    "Logical name or backend alias of the primary statistics "
                    "store used for reads when multiple backends are configured."
                ),
            }

        # Optional list of backend entries used by the stats/query-log backend
        # loader. When omitted, the legacy single-backend configuration using
        # db_path/batch_* remains valid.
        if "backends" not in persistence_props:
            persistence_props["backends"] = {
                "type": "array",
                "description": (
                    "Optional list of statistics/query-log backends. When "
                    "omitted, the legacy single-backend SQLite configuration "
                    "(db_path, batch_writes, batch_time_sec, batch_max_size) "
                    "is used."
                ),
                "items": {
                    "type": "object",
                    # Keep the top-level backend entries strict so obvious
                    # misconfigurations (for example, using 'driver' instead of
                    # 'backend') are surfaced by validation, while still
                    # allowing arbitrary fields inside the nested 'config'
                    # mapping.
                    "additionalProperties": False,
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": (
                                "Optional logical instance name used when "
                                "selecting a primary backend in multi-backend "
                                "setups."
                            ),
                        },
                        "backend": {
                            "type": "string",
                            "description": (
                                "Backend identifier (for example 'sqlite', "
                                "'mysql', 'mariadb', or a dotted import path to "
                                "a BaseStatsStore implementation)."
                            ),
                        },
                        "config": {
                            "type": "object",
                            "description": (
                                "Backend-specific configuration mapping passed "
                                "verbatim to the selected backend."
                            ),
                            "additionalProperties": True,
                        },
                    },
                    "required": ["backend"],
                },
            }
    except Exception:  # pragma: no cover - defensive logging only
        logger.exception("Failed to augment statistics.persistence schema")


def _build_v2_root_schema(base: Dict[str, Any], plugins: Dict[str, Any]) -> Dict[str, Any]:
    """Brief: Construct the v2 root JSON Schema from a v1-like base + plugin defs.

    Inputs:
      - base: Existing schema mapping loaded from assets/config-schema.json.
      - plugins: Mapping of plugin alias -> {module, aliases, config_schema}.

    Outputs:
      - Dict: New v2 schema mapping with a v2 root layout and attached defs.

    Notes:
      - This function intentionally ignores the legacy root "properties" layout
        and instead builds a new root with top-level keys: vars, server,
        upstreams, logging, stats, plugins.
      - It reuses the detailed sub-schemas for things like dnssec, logging,
        resolver, statistics, and webserver/http from the base schema to avoid
        duplicating those definitions.
    """

    # Reuse detailed component schemas from the old root where possible.
    base_props: Dict[str, Any] = dict(base.get("properties", {}))

    # Historically, these lived at the root; newer schemas may nest them under
    # server.* instead. Prefer the nested forms when available for forward
    # compatibility while still accepting older base schemas.
    server_obj = base_props.get("server")
    server_props = server_obj.get("properties") if isinstance(server_obj, dict) else None

    dnssec_schema = (
        server_props.get("dnssec")  # type: ignore[union-attr]
        if isinstance(server_props, dict) and "dnssec" in server_props
        else base_props.get("dnssec", {"type": "object"})
    )
    listen_schema = (
        server_props.get("listen")  # type: ignore[union-attr]
        if isinstance(server_props, dict) and "listen" in server_props
        else base_props.get("listen", {"type": "object"})
    )
    resolver_schema = (
        server_props.get("resolver")  # type: ignore[union-attr]
        if isinstance(server_props, dict) and "resolver" in server_props
        else base_props.get("resolver", {"type": "object"})
    )
    cache_schema = (
        server_props.get("cache")  # type: ignore[union-attr]
        if isinstance(server_props, dict) and "cache" in server_props
        else base_props.get("cache", {"type": ["object", "null"]})
    )
    # Logging schema: only the v2 layout is modeled here, with Python logging
    # under logging.python and statistics/query-log backends described under
    # logging.backends. Legacy root-level logging keys (level/stderr/file/syslog)
    # are no longer part of the accepted configuration schema.
    legacy_logging = base_props.get("logging", {"type": "object", "properties": {}})
    legacy_props = (
        legacy_logging.get("properties", {}) if isinstance(legacy_logging, dict) else {}
    )

    python_logging_schema: Dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "file": legacy_props.get("file", {"type": "string"}),
            "level": legacy_props.get(
                "level",
                {
                    "type": "string",
                    "enum": [
                        "debug",
                        "info",
                        "warn",
                        "warning",
                        "error",
                        "crit",
                        "critical",
                    ],
                },
            ),
            "stderr": legacy_props.get("stderr", {"type": "boolean"}),
            "syslog": legacy_props.get(
                "syslog",
                {"oneOf": [{"type": "boolean"}, {"type": "object"}]},
            ),
        },
    }

    logging_schema: Dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "description": (
            "Global logging configuration. Python logging lives under "
            "logging.python and statistics/query-log backends live under "
            "logging.backends."
        ),
        "properties": {
            # V2 Python logging block (file/level/stderr/syslog).
            "python": python_logging_schema,
            # Global async flag applied to statistics/query-log backends when
            # they do not override async_logging explicitly.
            "async": {
                "type": "boolean",
                "description": (
                    "When true, statistics/query-log backends default to using "
                    "an async worker queue for high-volume writes. When false, "
                    "backends perform writes synchronously unless they opt in "
                    "explicitly via their own async_logging setting."
                ),
                "default": True,
            },
            # Global toggle for keeping only the raw query_log in persistence
            # and avoiding mirroring aggregate counters into the backend.
            "query_log_only": {
                "type": "boolean",
                "description": (
                    "When true, only the raw query_log is written to the "
                    "configured backends and aggregate counters are kept "
                    "in-memory only."
                ),
                "default": False,
            },
            # Backends used for statistics and query logging; each entry maps to
            # a BaseStatsStore implementation (for example, sqlite, mysql,
            # mqtt_logging).
            "backends": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": (
                                "Logical backend identifier used by "
                                "stats.source_backend and any future per-server "
                                "logging selectors."
                            ),
                        },
                        "backend": {
                            "type": "string",
                            "description": (
                                "Backend identifier or dotted import path (for "
                                "example 'sqlite', 'mysql', 'mqtt_logging')."
                            ),
                        },
                        "config": {
                            "type": "object",
                            "description": (
                                "Backend-specific configuration mapping passed "
                                "verbatim to the selected BaseStatsStore "
                                "implementation."
                            ),
                            "additionalProperties": True,
                        },
                    },
                    "required": ["backend"],
                },
            },
        },
    }

    statistics_schema = base_props.get("statistics", {"type": "object"})

    # Web/admin HTTP schema: only consider server.http in the base schema. If
    # it is missing, fall back to a minimal object schema rather than any
    # legacy root-level keys.
    if isinstance(server_props, dict) and "http" in server_props:
        webserver_schema = server_props["http"]
    else:
        webserver_schema = {"type": "object"}

    # Variable schema: prefer modern 'vars', then legacy 'variables'.
    variables_schema = base_props.get("vars", base_props.get("variables", {"type": "object"}))

    # Upstreams v2: wrap endpoints + strategy/max_concurrent while reusing
    # upstream_host/upstream_doh defs from $defs.
    defs = base.setdefault("$defs", {})

    # Decorated cache overrides are modelled via a dedicated definition so that
    # both tooling and runtime helpers share the same canonical module+name
    # shape. Always override any existing definition to keep the schema in sync
    # with the public configuration format.
    defs["DecoratedCacheOverride"] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "module": {
                "type": "string",
                "description": "Fully-qualified module name of the decorated function (e.g. 'foghorn.dnssec.dnssec_validate').",
            },
            "name": {
                "type": "string",
                "description": "Function name / qualified name for the decorated callable (e.g. '_find_zone_apex_cached' or 'MdnsBridge._normalize_owner').",
            },
            "backend": {
                "type": "string",
                "enum": [
                    "ttlcache",
                    "lru_cache",
                    "foghorn_ttl",
                    "sqlite_ttl",
                    "lfu_cache",
                    "rr_cache",
                ],
                "description": "Optional backend filter (ttlcache, lru_cache, foghorn_ttl, sqlite_ttl, lfu_cache, or rr_cache).",
            },
            "maxsize": {
                "type": "integer",
                "minimum": 0,
                "description": "Optional maxsize override for the underlying cache (>= 0).",
            },
            "ttl": {
                "type": "integer",
                "minimum": 0,
                "description": "Optional TTL override in seconds for ttlcache backends (>= 0).",
            },
            "reset_on_ttl_change": {
                "type": "boolean",
                "description": "When true, clear the cache after applying a TTL override when the TTL value changes.",
                "default": False,
            },
        },
        "required": ["module", "name"],
    }

    # Extend and normalize the server.cache schema so that both the legacy
    # 'decorated_overrides' and preferred 'modify' arrays share the same
    # DecoratedCacheOverride item shape and description.
    if isinstance(cache_schema, dict):
        cache_props = cache_schema.get("properties")
        if not isinstance(cache_props, dict):
            cache_props = {}
            cache_schema["properties"] = cache_props

        override_array_schema = {
            "type": "array",
            "description": (
                "Optional list of overrides for decorated caches (functions "
                "wrapped by registered_cached/registered_lru_cached). Each "
                "entry may target a specific module+name pair and override "
                "backend-specific settings such as maxsize or TTL."
            ),
            "items": {"$ref": "#/$defs/DecoratedCacheOverride"},
        }

        # Normalize any existing decorated_overrides entry to the canonical
        # description and item reference.
        if "decorated_overrides" in cache_props:
            existing = cache_props.get("decorated_overrides")
            if isinstance(existing, dict):
                existing["type"] = "array"
                existing["description"] = override_array_schema["description"]
                existing["items"] = override_array_schema["items"]
            else:
                cache_props["decorated_overrides"] = override_array_schema

        # Ensure modify exists and matches the canonical override array schema.
        existing_modify = cache_props.get("modify")
        if isinstance(existing_modify, dict):
            existing_modify["type"] = "array"
            existing_modify["description"] = override_array_schema["description"]
            existing_modify["items"] = override_array_schema["items"]
        else:
            cache_props["modify"] = override_array_schema

    upstream_host_ref = {"$ref": "#/$defs/upstream_host"}
    upstream_doh_ref = {"$ref": "#/$defs/upstream_doh"}

    upstreams_v2: Dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "strategy": {
                "type": "string",
                "enum": ["failover", "round_robin", "random"],
                "description": "Strategy for picking upstreams per query.",
                "default": "failover",
            },
            "max_concurrent": {
                "type": "integer",
                "minimum": 1,
                "description": "Maximum concurrent upstream queries.",
                "default": 1,
            },
            "endpoints": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "oneOf": [upstream_host_ref, upstream_doh_ref],
                },
            },
        },
        "required": ["endpoints"],
    }

    # Attach plugin config schemas under $defs.PluginConfigs.
    defs["PluginConfigs"] = {
        alias: {
            "module": meta["module"],
            "aliases": meta["aliases"],
            "config_schema": meta["config_schema"],
        }
        for alias, meta in plugins.items()
    }

    # Lightweight PluginInstance schema: keep it permissive for now but reflect
    # the v2 shape (id/type/enabled/logging/setup/hooks/config).
    defs["PluginInstance"] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "id": {
                "type": "string",
                "description": "Optional stable identifier for this plugin instance.",
            },
            "type": {
                "type": "string",
                "description": "Plugin type/alias.",
            },
            "enabled": {
                "type": "boolean",
                "default": True,
            },
            "logging": {
                "type": "object",
                "description": "Per-plugin logging overrides.",
                "additionalProperties": True,
            },
            "setup": {
                "type": "object",
                "additionalProperties": True,
                "description": "Setup-phase behaviour (enabled/priority/abort_on_failure).",
            },
            "hooks": {
                "type": "object",
                "additionalProperties": True,
                "description": "Per-hook enablement/priorities (pre_resolve/post_resolve).",
            },
            "config": {
                "type": "object",
                "additionalProperties": True,
                "description": "Plugin-specific configuration mapping.",
            },
        },
        "required": ["type"],
    }

    v2_root: Dict[str, Any] = {
        "$id": base.get("$id", "https://example.com/foghorn/config-v2.schema.json"),
        "$schema": base.get("$schema", "https://json-schema.org/draft/2020-12/schema"),
        "title": base.get("title", "Foghorn Config (v2)"),
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "$schema": {
                "type": "string",
                "description": "Optional URI or identifier for the JSON Schema associated with this configuration file.",
            },
            "vars": variables_schema,
            "server": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "listen": listen_schema,
                    "dnssec": dnssec_schema,
                    "resolver": resolver_schema,
                    "cache": cache_schema,
                    # Preferred v2 placement for admin HTTP/web UI config.
                    "http": webserver_schema,
                },
            },
            "upstreams": upstreams_v2,
            "logging": logging_schema,
            "stats": statistics_schema,
            # Legacy root-level http is no longer part of the v2 schema; it is
            # still accepted at runtime as a fallback for older configs.
            "plugins": {
                "type": "array",
                "items": {"$ref": "#/$defs/PluginInstance"},
            },
        },
        "required": ["server", "upstreams"],
        "$defs": defs,
    }

    return v2_root


def build_document(base_schema_path: Optional[str] = None) -> Dict[str, Any]:
    """Brief: Build a combined v2 JSON Schema including core config and plugins.

    Inputs:
      - base_schema_path: Optional explicit path to a base schema JSON file.

    Outputs:
      - Dict describing the v2 configuration JSON Schema with attached plugin
        config definitions.
    """

    base = _load_base_schema(base_schema_path=base_schema_path)

    # Ensure top-level helpers (like `variables`) and statistics persistence
    # backends are visible to tooling that consumes the JSON Schema directly.
    _augment_variables_schema(base)

    # Ensure statistics.persistence documents the backend loader options used
    # by foghorn.plugins.querylog.load_stats_store_backend().
    _augment_statistics_persistence_schema(base)

    # Heuristically fill in missing descriptions/default notes across the base
    # schema so that editor tooling always has something useful to display.
    _enrich_schema_descriptions(base)

    plugins = collect_plugin_schemas()

    return _build_v2_root_schema(base, plugins)


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    """Brief: Parse CLI arguments for the schema generator.

    Inputs:
      - argv: Optional iterable of CLI argument strings; defaults to
        ``sys.argv[1:]`` when omitted.

    Outputs:
      - ``argparse.Namespace`` with at least:

        - ``output``: Path to write the schema JSON file to.
        - ``verbose``: Boolean flag enabling verbose logging.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Generate a JSON document describing configuration schemas for all "
            "discovered Foghorn plugins."
        )
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        default="schema.json",
        help="Output JSON file path (default: ./schema.json)",
    )
    parser.add_argument(
        "--base-schema",
        dest="base_schema",
        default=None,
        help="Optional path to base schema JSON (default: auto-detect assets/config-schema.json)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging to stderr.",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Iterable[str]] = None) -> int:
    """Brief: CLI entrypoint to generate a combined schema JSON.

    Inputs:
      - argv: Optional iterable of CLI argument strings.

    Outputs:
      - int: 0 on success, non-zero on failure.

    Example usage (from project root):
      - ``PYTHONPATH=src python scripts/generate_foghorn_schema.py``
      - ``PYTHONPATH=src python scripts/generate_foghorn_schema.py -o schema.json``
      - ``PYTHONPATH=src python scripts/generate_foghorn_schema.py --base-schema assets/config-schema.json -o schema.json``
    """

    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    output_path = Path(args.output)
    logger.info("Generating plugin schema to %s", output_path)

    try:
        doc = build_document(base_schema_path=getattr(args, "base_schema", None))
        output_path.write_text(
            json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8"
        )
    except Exception:  # pragma: no cover - defensive logging only
        logger.exception("Failed to write plugin schema to %s", output_path)
        return 1

    logger.info("Plugin schema written to %s", output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
