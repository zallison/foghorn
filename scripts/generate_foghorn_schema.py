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

from foghorn.plugins.resolve import registry as plugin_registry
from foghorn.plugins.resolve.base import BasePlugin

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
        properties = (
            node.get("properties") if isinstance(node.get("properties"), dict) else None
        )
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
                pieces.append(
                    f"Object with keys matching patterns: {patterns_preview}."
                )

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

        - keys must be identifier-style names matching
          ``[A-Za-z_][A-Za-z0-9_]*``;
        - values are arbitrary YAML/JSON values (left intentionally untyped).
    """

    try:
        root_props = base.get("properties")
        if not isinstance(root_props, dict):
            return
        key_pattern = r"^[A-Za-z_][A-Za-z0-9_]*$"
        description = (
            "Optional mapping of variable names to arbitrary values. "
            "These are expanded before validation and removed from the "
            "runtime config."
        )

        def _normalize_variables_shape(schema_obj: Dict[str, Any]) -> None:
            schema_obj["type"] = "object"
            schema_obj["description"] = description
            schema_obj["patternProperties"] = {
                key_pattern: {
                    # Accept any JSON type for variable values; runtime code
                    # performs the actual substitution and type handling.
                }
            }
            schema_obj["additionalProperties"] = False

        existing_vars = root_props.get("vars")
        if isinstance(existing_vars, dict):
            _normalize_variables_shape(existing_vars)

        existing_variables = root_props.get("variables")
        if isinstance(existing_variables, dict):
            _normalize_variables_shape(existing_variables)

        if "variables" not in root_props:
            root_props["variables"] = {}
            _normalize_variables_shape(root_props["variables"])
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


def _augment_server_limits_and_listen_schema(base: Dict[str, Any]) -> None:
    """Brief: Extend the base schema with DoS-hardening listener limit knobs.

    Inputs:
      - base: Mutable JSON Schema mapping loaded from assets/config-schema.json.

    Outputs:
      - None; ``base`` is updated in place when the expected server/listen/http
        shapes exist.

    Notes:
      - This is intentionally additive and uses setdefault so repeated schema
        generation is idempotent.
    """

    def _ensure_obj_schema(node: Any) -> Dict[str, Any] | None:
        if not isinstance(node, dict):
            return None
        node.setdefault("type", "object")
        node.setdefault("additionalProperties", True)
        props = node.get("properties")
        if not isinstance(props, dict):
            props = {}
            node["properties"] = props
        return node

    def _ensure_limit_keys(listener_node: Dict[str, Any]) -> None:
        props = listener_node.get("properties")
        if not isinstance(props, dict):
            props = {}
            listener_node["properties"] = props

        props.setdefault(
            "max_connections",
            {
                "type": "integer",
                "minimum": 1,
                "default": 1024,
                "description": "Maximum concurrent connections accepted by this listener.",
            },
        )
        props.setdefault(
            "max_connections_per_ip",
            {
                "type": "integer",
                "minimum": 1,
                "default": 64,
                "description": "Maximum concurrent connections from a single client IP.",
            },
        )
        props.setdefault(
            "max_queries_per_connection",
            {
                "type": "integer",
                "minimum": 1,
                "default": 100,
                "description": "Maximum number of DNS queries processed per connection before closing it.",
            },
        )
        props.setdefault(
            "idle_timeout_seconds",
            {
                "type": "number",
                "minimum": 0,
                "default": 15.0,
                "description": "Idle timeout (seconds) before closing an inactive connection.",
            },
        )

    try:
        root_props = base.get("properties")
        if not isinstance(root_props, dict):
            return

        server_obj = root_props.get("server")
        server_schema = _ensure_obj_schema(server_obj)
        if server_schema is None:
            return

        server_props = server_schema.get("properties")
        if not isinstance(server_props, dict):
            return

        # server.limits: global hardening knobs.
        limits_obj = server_props.setdefault("limits", {"type": "object"})
        limits_schema = _ensure_obj_schema(limits_obj)
        if limits_schema is not None:
            limits_props = limits_schema.get("properties")
            if isinstance(limits_props, dict):
                limits_props.setdefault(
                    "resolver_executor_workers",
                    {
                        "type": ["integer", "null"],
                        "minimum": 1,
                        "description": (
                            "Max workers for the shared resolver ThreadPoolExecutor used by asyncio "
                            "listeners (TCP/DoT). Null uses a conservative default."
                        ),
                        "default": None,
                    },
                )

        # server.listen.{udp,tcp,dot} hardening knobs.
        listen_obj = server_props.get("listen")
        listen_schema = _ensure_obj_schema(listen_obj)
        if listen_schema is not None:
            listen_props = listen_schema.get("properties")
            if isinstance(listen_props, dict):
                for key in ("tcp", "dot"):
                    child = listen_props.get(key)
                    if not isinstance(child, dict):
                        child = {"type": "object"}
                        listen_props[key] = child
                    child_schema = _ensure_obj_schema(child)
                    if child_schema is not None:
                        _ensure_limit_keys(child_schema)

                # UDP hardening knobs (asyncio UDP and response sizing).
                udp_obj = listen_props.get("udp")
                if not isinstance(udp_obj, dict):
                    udp_obj = {"type": "object"}
                    listen_props["udp"] = udp_obj
                udp_schema = _ensure_obj_schema(udp_obj)
                if udp_schema is not None:
                    udp_props = udp_schema.get("properties")
                    if isinstance(udp_props, dict):
                        udp_props.setdefault(
                            "use_asyncio",
                            {
                                "type": "boolean",
                                "default": True,
                                "description": "When true, prefer the asyncio UDP listener when available.",
                            },
                        )
                        udp_props.setdefault(
                            "allow_threaded_fallback",
                            {
                                "type": "boolean",
                                "default": True,
                                "description": (
                                    "When false, refuse to fall back to the threaded ThreadingUDPServer when "
                                    "asyncio UDP cannot start."
                                ),
                            },
                        )
                        udp_props.setdefault(
                            "exit_on_asyncio_failure",
                            {
                                "type": "boolean",
                                "default": False,
                                "description": (
                                    "When true, exit non-zero if the asyncio UDP listener fails to start, instead "
                                    "of falling back to a threaded UDP server."
                                ),
                            },
                        )
                        udp_props.setdefault(
                            "max_inflight",
                            {
                                "type": "integer",
                                "minimum": 1,
                                "default": 1024,
                                "description": "Global cap on in-flight UDP queries for asyncio UDP listener.",
                            },
                        )
                        udp_props.setdefault(
                            "max_inflight_per_ip",
                            {
                                "type": "integer",
                                "minimum": 1,
                                "default": 64,
                                "description": "Per-client-IP cap on in-flight UDP queries for asyncio UDP listener.",
                            },
                        )
                        udp_props.setdefault(
                            "max_inflight_by_cidr",
                            {
                                "type": "array",
                                "description": (
                                    "Optional CIDR bucket limits for UDP in-flight queries. Each entry is {cidr, max_inflight}. "
                                    "When multiple buckets match a client IP, the strictest (smallest max_inflight) wins."
                                ),
                                "items": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "properties": {
                                        "cidr": {
                                            "type": "string",
                                            "description": "CIDR block (e.g. '10.0.0.0/8' or '2001:db8::/32').",
                                        },
                                        "max_inflight": {
                                            "type": "integer",
                                            "minimum": 1,
                                            "description": "Maximum in-flight UDP queries for clients within this CIDR.",
                                        },
                                    },
                                    "required": ["cidr", "max_inflight"],
                                },
                            },
                        )
                        udp_props.setdefault(
                            "max_response_bytes",
                            {
                                "type": ["integer", "null"],
                                "minimum": 0,
                                "default": None,
                                "description": (
                                    "Optional explicit UDP response size ceiling. When null, defaults to server.dnssec.udp_payload_size. "
                                    "Effective ceiling per query is min(client advertised EDNS UDP size (or 512 without EDNS), server ceiling)."
                                ),
                            },
                        )

                for key in ("doh",):
                    child = listen_props.get(key)
                    if not isinstance(child, dict):
                        child = {"type": "object"}
                        listen_props[key] = child

                # listen.doh.allow_threaded_fallback
                doh_obj = listen_props.get("doh")
                doh_schema = _ensure_obj_schema(doh_obj)
                if doh_schema is not None:
                    doh_props = doh_schema.get("properties")
                    if isinstance(doh_props, dict):
                        doh_props.setdefault(
                            "allow_threaded_fallback",
                            {
                                "type": "boolean",
                                "default": True,
                                "description": (
                                    "When false, refuse to start the threaded stdlib DoH fallback when "
                                    "FastAPI/uvicorn or asyncio is unavailable."
                                ),
                            },
                        )

        # server.http.*
        http_obj = server_props.get("http")
        http_schema = _ensure_obj_schema(http_obj)
        if http_schema is not None:
            http_props = http_schema.get("properties")
            if isinstance(http_props, dict):
                http_props.setdefault(
                    "allow_threaded_fallback",
                    {
                        "type": "boolean",
                        "default": True,
                        "description": (
                            "When false, refuse to start the threaded stdlib admin HTTP fallback when "
                            "FastAPI/uvicorn or asyncio is unavailable."
                        ),
                    },
                )
                http_props.setdefault(
                    "enable_api",
                    {
                        "type": "boolean",
                        "default": True,
                        "description": (
                            "When false, do not serve the admin API endpoints (e.g. /api/v1/stats, /config, /logs)."
                        ),
                    },
                )
                http_props.setdefault(
                    "enable_schema",
                    {
                        "type": "boolean",
                        "default": True,
                        "description": "When false, disable OpenAPI schema generation and /openapi.json.",
                    },
                )
                http_props.setdefault(
                    "enable_docs",
                    {
                        "type": "boolean",
                        "default": True,
                        "description": "When false, disable Swagger UI at /docs (requires enable_schema=true).",
                    },
                )
    except Exception:  # pragma: no cover - defensive logging only
        logger.exception("Failed to augment server.listen/server.limits schema")


def _allow_comment_id_fields(schema: Dict[str, Any]) -> None:
    """Brief: Allow optional comment/id keys on every object schema.

    Inputs:
      - schema: Mutable JSON Schema mapping (updated in place).

    Outputs:
      - None; schema is updated to allow `comment` and `id` keys on objects.

    Notes:
      - Applies a lightweight rule: any schema node that represents an object
        (explicit type=object, or has properties/patternProperties) will gain
        optional `comment` and `id` properties constrained to <= 254 chars.
      - This keeps additionalProperties=False schemas strict while still
        allowing comment/id everywhere.
    """

    comment_id_schema = {
        "type": "string",
        "maxLength": 254,
        "description": "Optional human metadata string (max 254 characters).",
    }

    def _is_object_schema(node: Dict[str, Any]) -> bool:
        if "properties" in node or "patternProperties" in node:
            return True
        t = node.get("type")
        if isinstance(t, str) and t == "object":
            return True
        if isinstance(t, list) and "object" in t:
            return True
        return False

    def _ensure_comment_id(node: Dict[str, Any]) -> None:
        props = node.get("properties")
        if not isinstance(props, dict):
            props = {}
            node["properties"] = props
        props.setdefault("comment", dict(comment_id_schema))
        props.setdefault("id", dict(comment_id_schema))

    def _walk(node: Any) -> None:
        if not isinstance(node, dict):
            return

        if _is_object_schema(node):
            _ensure_comment_id(node)

        for key in ("properties", "patternProperties", "$defs", "definitions"):
            child = node.get(key)
            if isinstance(child, dict):
                for sub in child.values():
                    _walk(sub)

        items = node.get("items")
        if isinstance(items, dict):
            _walk(items)
        elif isinstance(items, list):
            for sub in items:
                _walk(sub)

        for key in ("oneOf", "anyOf", "allOf"):
            child = node.get(key)
            if isinstance(child, list):
                for sub in child:
                    _walk(sub)

    _walk(schema)


def _build_v2_root_schema(
    base: Dict[str, Any], plugins: Dict[str, Any]
) -> Dict[str, Any]:
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
    server_props = (
        server_obj.get("properties") if isinstance(server_obj, dict) else None
    )

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

    # Ensure the listener schemas are concrete enough for editor tooling even
    # when the base schema is permissive.
    if isinstance(listen_schema, dict):
        listen_schema.setdefault("type", "object")
        listen_schema["additionalProperties"] = False
        listen_props = listen_schema.setdefault("properties", {})
        if isinstance(listen_props, dict):
            # Obsolete root-level defaults under server.listen are intentionally
            # removed; listeners must now be configured under listen.dns and/or
            # per-listener blocks (udp/tcp/dot/doh).
            listen_props.pop("host", None)
            listen_props.pop("port", None)

            dns_child = listen_props.get("dns")
            if not isinstance(dns_child, dict):
                dns_child = {"type": "object", "additionalProperties": False}
                listen_props["dns"] = dns_child
            dns_child.setdefault("type", "object")
            dns_child["additionalProperties"] = False
            dns_props = dns_child.setdefault("properties", {})
            if isinstance(dns_props, dict):
                dns_props.setdefault(
                    "host",
                    {
                        "type": "string",
                        "description": "Default host for UDP/TCP listeners when per-listener host is not set.",
                    },
                )
                dns_props.setdefault(
                    "port",
                    {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Default port for UDP/TCP listeners when per-listener port is not set.",
                    },
                )

            def _ensure_listener_child(key: str) -> Dict[str, Any]:
                child = listen_props.get(key)
                if not isinstance(child, dict):
                    child = {"type": "object", "additionalProperties": True}
                    listen_props[key] = child
                child.setdefault("type", "object")
                child.setdefault("additionalProperties", True)
                cprops = child.setdefault("properties", {})
                if not isinstance(cprops, dict):
                    cprops = {}
                    child["properties"] = cprops
                return child

            def _ensure_conn_limit_props(child: Dict[str, Any]) -> None:
                cprops = child.get("properties")
                if not isinstance(cprops, dict):
                    return
                cprops.setdefault(
                    "max_connections",
                    {
                        "type": "integer",
                        "minimum": 1,
                        "default": 1024,
                        "description": "Maximum concurrent connections accepted by this listener.",
                    },
                )
                cprops.setdefault(
                    "max_connections_per_ip",
                    {
                        "type": "integer",
                        "minimum": 1,
                        "default": 64,
                        "description": "Maximum concurrent connections from a single client IP.",
                    },
                )
                cprops.setdefault(
                    "max_queries_per_connection",
                    {
                        "type": "integer",
                        "minimum": 1,
                        "default": 100,
                        "description": "Maximum DNS queries processed per connection before closing it.",
                    },
                )
                cprops.setdefault(
                    "idle_timeout_seconds",
                    {
                        "type": "number",
                        "minimum": 0,
                        "default": 15.0,
                        "description": "Idle timeout (seconds) before closing an inactive connection.",
                    },
                )

            tcp_child = _ensure_listener_child("tcp")
            dot_child = _ensure_listener_child("dot")
            udp_child = _ensure_listener_child("udp")
            _ensure_conn_limit_props(tcp_child)
            _ensure_conn_limit_props(dot_child)

            # UDP-specific hardening knobs.
            udp_props = udp_child.get("properties")
            if isinstance(udp_props, dict):
                udp_props.setdefault(
                    "use_asyncio",
                    {
                        "type": "boolean",
                        "default": True,
                        "description": "When true, prefer the asyncio UDP listener when available.",
                    },
                )
                udp_props.setdefault(
                    "allow_threaded_fallback",
                    {
                        "type": "boolean",
                        "default": True,
                        "description": (
                            "When false, refuse to fall back to the threaded ThreadingUDPServer when "
                            "asyncio UDP cannot start."
                        ),
                    },
                )
                udp_props.setdefault(
                    "exit_on_asyncio_failure",
                    {
                        "type": "boolean",
                        "default": False,
                        "description": (
                            "When true, exit non-zero if the asyncio UDP listener fails to start, instead "
                            "of falling back to a threaded UDP server."
                        ),
                    },
                )
                udp_props.setdefault(
                    "max_inflight",
                    {
                        "type": "integer",
                        "minimum": 1,
                        "default": 1024,
                        "description": "Global cap on in-flight UDP queries for asyncio UDP listener.",
                    },
                )
                udp_props.setdefault(
                    "max_inflight_per_ip",
                    {
                        "type": "integer",
                        "minimum": 1,
                        "default": 64,
                        "description": "Per-client-IP cap on in-flight UDP queries for asyncio UDP listener.",
                    },
                )
                udp_props.setdefault(
                    "max_inflight_by_cidr",
                    {
                        "type": "array",
                        "description": (
                            "Optional CIDR bucket limits for UDP in-flight queries. Each entry is {cidr, max_inflight}. "
                            "When multiple buckets match a client IP, the strictest (smallest max_inflight) wins."
                        ),
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "cidr": {
                                    "type": "string",
                                    "description": "CIDR block (e.g. '10.0.0.0/8' or '2001:db8::/32').",
                                },
                                "max_inflight": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "description": "Maximum in-flight UDP queries for clients within this CIDR.",
                                },
                            },
                            "required": ["cidr", "max_inflight"],
                        },
                    },
                )
                udp_props.setdefault(
                    "max_response_bytes",
                    {
                        "type": ["integer", "null"],
                        "minimum": 0,
                        "default": None,
                        "description": (
                            "Optional explicit UDP response size ceiling. When null, defaults to server.dnssec.udp_payload_size. "
                            "Effective ceiling per query is min(client advertised EDNS UDP size (or 512 without EDNS), server ceiling)."
                        ),
                    },
                )

            doh_child = _ensure_listener_child("doh")
            doh_props = doh_child.get("properties")
            if isinstance(doh_props, dict):
                doh_props.setdefault(
                    "allow_threaded_fallback",
                    {
                        "type": "boolean",
                        "default": True,
                        "description": (
                            "When false, refuse to start the threaded stdlib DoH fallback when "
                            "FastAPI/uvicorn or asyncio is unavailable."
                        ),
                    },
                )
    resolver_schema = (
        server_props.get("resolver")  # type: ignore[union-attr]
        if isinstance(server_props, dict) and "resolver" in server_props
        else base_props.get("resolver", {"type": "object"})
    )

    # server.limits: hardening knobs.
    limits_schema: Dict[str, Any] = {
        "type": "object",
        "additionalProperties": True,
        "properties": {
            "resolver_executor_workers": {
                "type": ["integer", "null"],
                "minimum": 1,
                "default": None,
                "description": (
                    "Max workers for the shared resolver ThreadPoolExecutor used by asyncio listeners "
                    "(TCP/DoT). Null uses a conservative default."
                ),
            }
        },
    }

    # Ensure server.resolver exposes the runtime configuration surface. Some
    # older base schemas model this as a generic object; augment it here so
    # editor tooling can validate supported modes.
    resolver_schema = {
        "type": "object",
        "additionalProperties": True,
        "description": (
            "Resolver configuration. mode selects how unanswered queries are "
            "handled: forward (default), recursive (walk from root), or "
            "master (authoritative-only; no forwarding). 'none' is an alias "
            "for 'master'."
        ),
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["forward", "recursive", "master", "none"],
                "default": "forward",
                "description": "Resolver mode: forward | recursive | master (none).",
            },
            "timeout_ms": {
                "type": "integer",
                "minimum": 0,
                "default": 2000,
                "description": "Upstream/recursive timeout budget per query (milliseconds).",
            },
            "max_depth": {
                "type": "integer",
                "minimum": 1,
                "default": 16,
                "description": "Maximum delegation hops for recursive mode.",
            },
            "per_try_timeout_ms": {
                "type": "integer",
                "minimum": 0,
                "default": 2000,
                "description": "Per-authority timeout for recursive mode (milliseconds).",
            },
            "use_asyncio": {
                "type": "boolean",
                "default": True,
                "description": "Enable asyncio-based listeners when available.",
            },
        },
    }
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
            "color": {
                "type": "boolean",
                "default": True,
                "description": (
                    "Enable ANSI colorized stderr logging output for improved "
                    "readability of levels and important tokens."
                ),
            },
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
    variables_schema = base_props.get(
        "vars", base_props.get("variables", {"type": "object"})
    )

    # ZoneRecords plugin schema: ensure axfr_notify options are documented when
    # the plugin is present in the base schema.
    zone_plugin = None
    if isinstance(base_props.get("plugins"), dict):
        plugins_schema = base_props["plugins"]
        if isinstance(plugins_schema.get("items"), dict):
            plugin_items = plugins_schema["items"]
            props = (
                plugin_items.get("properties")
                if isinstance(plugin_items, dict)
                else None
            )
            if isinstance(props, dict) and isinstance(props.get("config"), dict):
                cfg_props = props["config"].get("properties")
                if isinstance(cfg_props, dict):
                    zone_plugin = cfg_props.get("zone")
    if isinstance(zone_plugin, dict):
        zone_cfg_props = zone_plugin.get("properties") or {}
        if isinstance(zone_cfg_props, dict):
            # axfr_notify: list of upstream-like objects for NOTIFY recipients.
            zone_cfg_props.setdefault(
                "axfr_notify",
                {
                    "type": "array",
                    "description": (
                        "Optional list of NOTIFY recipients for AXFR-backed zones. "
                        "Each entry reuses the upstream_host shape (host/port/transport/"
                        "server_name/verify/ca_file) and is limited to TCP and DoT."
                    ),
                    "items": {"$ref": "#/$defs/upstream_host"},
                },
            )
            # axfr_notify_all: learn NOTIFY targets from AXFR/IXFR clients.
            zone_cfg_props.setdefault(
                "axfr_notify_all",
                {
                    "type": "boolean",
                    "description": (
                        "When true, any client that performs AXFR/IXFR from this "
                        "server is remembered as a NOTIFY target for its zone "
                        "using its source IP and TCP port 53."
                    ),
                    "default": False,
                },
            )
            # axfr_notify_scheduled: delay before sending follow-up NOTIFY.
            zone_cfg_props.setdefault(
                "axfr_notify_scheduled",
                {
                    "type": "integer",
                    "minimum": 0,
                    "description": (
                        "Optional delay in seconds after serving AXFR/IXFR to a "
                        "client before sending a follow-up NOTIFY for that zone. "
                        "Ignored when null or zero."
                    ),
                },
            )

    # Upstreams v2: wrap endpoints + strategy/max_concurrent while reusing
    # upstream_host/upstream_doh defs from $defs.
    defs = base.setdefault("$defs", {})

    # Ensure upstream_host definition exposes an optional notify block used for
    # NOTIFY handling. This preserves any existing upstream_host shape and only
    # augments its properties.
    upstream_host_def = defs.get("upstream_host")
    if isinstance(upstream_host_def, dict):
        host_props = upstream_host_def.setdefault("properties", {})
        if isinstance(host_props, dict):
            host_props.setdefault(
                "abort_on_fail",
                {
                    "type": "boolean",
                    "description": (
                        "When true (default behavior), startup fails if this "
                        "upstream's TLS CA file validation fails. When false, "
                        "validation failures are logged and startup continues."
                    ),
                },
            )
            host_props.setdefault(
                "abort_on_failure",
                {
                    "type": "boolean",
                    "description": (
                        "Alias for abort_on_fail. When true, TLS CA validation "
                        "errors for this upstream are fatal."
                    ),
                },
            )
            notify_schema = {
                "type": "object",
                "additionalProperties": False,
                "description": (
                    "Optional NOTIFY policy for this upstream. allow_zones may "
                    "be 'none', 'all', '*' or a list of zone suffixes (for "
                    "example ['.lan', '.mycorp']). allow_hosts/block_hosts are "
                    "optional hostname allow/block lists."
                ),
                "properties": {
                    "allow_zones": {
                        "oneOf": [
                            {
                                "type": "string",
                                "enum": ["none", "all", "*"],
                                "description": (
                                    "String policy for accepted NOTIFY zones: "
                                    "'none' to refuse all, 'all' or '*' to "
                                    "accept all zones."
                                ),
                            },
                            {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "Explicit list of zone names or suffixes "
                                    "from which NOTIFY will be accepted."
                                ),
                            },
                        ],
                        "default": "all",
                    },
                    "allow_hosts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Optional list of hostnames that are allowed to "
                            "send NOTIFY for this upstream."
                        ),
                    },
                    "block_hosts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Optional list of hostnames whose NOTIFY messages "
                            "should always be refused, even if otherwise "
                            "allowed."
                        ),
                    },
                },
            }
            # Only inject notify when not already present so repeated schema
            # generation remains idempotent.
            host_props.setdefault("notify", notify_schema)

    upstream_doh_def = defs.get("upstream_doh")
    if isinstance(upstream_doh_def, dict):
        doh_props = upstream_doh_def.setdefault("properties", {})
        if isinstance(doh_props, dict):
            doh_props.setdefault(
                "abort_on_fail",
                {
                    "type": "boolean",
                    "description": (
                        "When true (default behavior), startup fails if this "
                        "upstream's TLS CA file validation fails. When false, "
                        "validation failures are logged and startup continues."
                    ),
                },
            )
            doh_props.setdefault(
                "abort_on_failure",
                {
                    "type": "boolean",
                    "description": (
                        "Alias for abort_on_fail. When true, TLS CA validation "
                        "errors for this upstream are fatal."
                    ),
                },
            )

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

    upstreams_backup_v2: Dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "endpoints": {
                "type": "array",
                "minItems": 1,
                "items": {"oneOf": [upstream_host_ref, upstream_doh_ref]},
            }
        },
        "required": ["endpoints"],
    }

    upstreams_health_v2: Dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "description": "Upstream health tracking and failover probing knobs.",
        "properties": {
            "profile": {
                "type": "string",
                "description": (
                    "Optional name of a built-in health profile loaded from "
                    "upstreams_health_profiles.yaml. Explicit keys under upstreams.health "
                    "override profile values."
                ),
            },
            "max_serv_fail": {
                "type": "integer",
                "minimum": 0,
                "description": "Mark an upstream unhealthy when its failure counter exceeds this threshold.",
                "default": 3,
            },
            "unknown_after_seconds": {
                "type": "number",
                "minimum": 0,
                "description": "If an upstream has not had a successful response in this many seconds, its status becomes 'unknown' (treated as eligible like healthy).",
                "default": 300,
            },
            "probe_percent": {
                "type": "number",
                "minimum": 0,
                "maximum": 100,
                "description": "Percent of queries that should probe an unhealthy upstream first (before healthy/unknown upstreams).",
                "default": 1.0,
            },
            "probe_min_percent": {
                "type": "number",
                "minimum": 0.5,
                "maximum": 100,
                "description": (
                    "Lower bound for the dynamic probe percent. Must be > 0 so "
                    "unhealthy upstreams are eventually retried."
                ),
                "default": 0.5,
            },
            "probe_max_percent": {
                "type": "number",
                "minimum": 0,
                "maximum": 100,
                "description": "Upper bound for the dynamic probe percent.",
                "default": 50.0,
            },
            "probe_increase": {
                "type": "number",
                "minimum": 0,
                "maximum": 100,
                "description": "Amount to increase probe_percent after a successful unhealthy probe.",
                "default": 1.0,
            },
            "probe_decrease": {
                "type": "number",
                "minimum": 0,
                "maximum": 100,
                "description": "Amount to decrease probe_percent after a failed unhealthy probe.",
                "default": 1.0,
            },
        },
    }

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
            "backup": {
                "description": "Optional backup upstream endpoints used only when no eligible primary upstreams are available.",
                "allOf": [upstreams_backup_v2],
            },
            "health": upstreams_health_v2,
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
                    "limits": limits_schema,
                    # Preferred v2 placement for admin HTTP/web UI config.
                    "http": webserver_schema,
                    # Feature gate for Extended DNS Errors (RFC 8914). When true,
                    # the resolver pipeline is allowed to attach EDE options to
                    # responses for EDNS-capable clients.
                    "enable_ede": {
                        "type": "boolean",
                        "description": "Enable generation and pass-through of Extended DNS Errors (RFC 8914) for EDNS clients.",
                        "default": False,
                    },
                    # RFC 6762 specifies that .local is reserved for mDNS. By
                    # default Foghorn blocks forwarding .local queries to
                    # upstream resolvers; set this to true to allow forwarding.
                    "forward_local": {
                        "type": "boolean",
                        "description": "Allow forwarding .local queries to upstream resolvers. Default false blocks them per RFC 6762.",
                        "default": False,
                    },
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
        "required": ["server"],
        # Conditionally require upstreams only when running in forward mode.
        "allOf": [
            {
                "if": {
                    "required": ["server"],
                    "properties": {
                        "server": {
                            "required": ["resolver"],
                            "properties": {
                                "resolver": {
                                    "required": ["mode"],
                                    "properties": {
                                        "mode": {
                                            "enum": ["recursive", "master", "none"],
                                        }
                                    },
                                }
                            },
                        }
                    },
                },
                "then": {},
                "else": {"required": ["upstreams"]},
            }
        ],
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

    # Ensure schema includes hardening knobs for threaded fallbacks, connection
    # limits, and the shared resolver executor sizing.
    _augment_server_limits_and_listen_schema(base)

    # Heuristically fill in missing descriptions/default notes across the base
    # schema so that editor tooling always has something useful to display.
    _enrich_schema_descriptions(base)

    plugins = collect_plugin_schemas()
    v2_root = _build_v2_root_schema(base, plugins)
    _allow_comment_id_fields(v2_root)
    return v2_root
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
