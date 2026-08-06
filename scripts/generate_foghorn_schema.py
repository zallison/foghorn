#!/usr/bin/env python3
"""Brief: Generate Foghorn's JSON Schema from Pydantic models + plugins.

Inputs:
  - Command-line arguments (optional):
    - --output / -o: Output path (default: ./schema.json).
    - --verbose / -v: Enable verbose logging.
    - --base-schema: Deprecated/ignored (models are the sole source of truth).

Outputs:
  - JSON Schema file written to the output path.

Notes:
  - Core config shape comes from foghorn.config.models.FoghornConfig.
  - Resolve plugins contribute $defs.PluginConfigs via discovery.
  - assets/config-schema.json must not be hand-edited; run this script or
    `make schema` after model changes.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

# Ensure `src/` is importable when invoked as a script from the repo root.
_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
_SRC_DIR = _PROJECT_ROOT / "src"
if _SRC_DIR.is_dir() and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from foghorn.config.models import (
    DecoratedCacheOverride,
    FoghornConfig,
    PluginInstance,
    UpstreamDoh,
    UpstreamHost,
    UpstreamUrl,
)
from foghorn.plugins.resolve import registry as plugin_registry
from foghorn.plugins.resolve.base import BasePlugin

logger = logging.getLogger(__name__)

_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
_SCHEMA_ID = "https://foghorn.local/config-schema.json"
_SCHEMA_TITLE = "Foghorn Config"
_VARS_KEY_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]*$"

# Stable $defs names expected by tests/tooling.
_DEF_ALIASES: dict[str, type[Any]] = {
    "PluginInstance": PluginInstance,
    "DecoratedCacheOverride": DecoratedCacheOverride,
    "upstream_host": UpstreamHost,
    "upstream_doh": UpstreamDoh,
    "upstream_url": UpstreamUrl,
}


def _model_to_json_schema(model_cls: type[Any]) -> dict[str, Any]:
    """Brief: Convert a Pydantic model class into a JSON Schema mapping.

    Inputs:
      - model_cls: Pydantic BaseModel subclass.

    Outputs:
      - Dict JSON Schema, or {} on failure.
    """

    try:
        modern = getattr(model_cls, "model_json_schema", None)
        if callable(modern):
            return modern()  # type: ignore[no-any-return]
        legacy = getattr(model_cls, "schema", None)
        if callable(legacy):
            return legacy()  # type: ignore[no-any-return]
    except Exception:  # pragma: no cover - defensive logging only
        logger.exception("Failed to build JSON schema for %s", model_cls)
    return {}


def collect_plugin_schemas() -> dict[str, Any]:
    """Brief: Discover resolve plugins and build per-plugin config schemas.

    Inputs:
      - None (uses plugin_registry.discover_plugins()).

    Outputs:
      - Dict mapping canonical plugin alias -> {module, aliases, config_schema}.
    """

    aliases_to_cls: Mapping[str, type[BasePlugin]] = plugin_registry.discover_plugins()
    by_cls: dict[type[BasePlugin], dict[str, Any]] = {}

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

    results: dict[str, Any] = {}
    for cls, info in by_cls.items():
        canonical = plugin_registry._default_alias_for(cls)  # type: ignore[attr-defined]
        aliases = sorted(info["aliases"])
        module_path = info["module"]
        config_schema: dict[str, Any] | None = None

        get_model = getattr(cls, "get_config_model", None)
        if callable(get_model):
            try:
                model_cls = get_model()
            except Exception:  # pragma: no cover
                logger.exception("get_config_model() failed for %s", module_path)
                model_cls = None
            if model_cls is not None:
                config_schema = _model_to_json_schema(model_cls)

        if config_schema is None:
            get_schema = getattr(cls, "get_config_schema", None)
            if callable(get_schema):
                try:
                    maybe = get_schema()
                    if isinstance(maybe, dict):
                        config_schema = maybe
                except Exception:  # pragma: no cover
                    logger.exception("get_config_schema() failed for %s", module_path)

        results[canonical] = {
            "module": module_path,
            "aliases": aliases,
            "config_schema": config_schema,
        }
    return results


def _promote_stable_defs(schema: dict[str, Any]) -> None:
    """Brief: Ensure stable $defs names exist for tooling/tests.

    Inputs:
      - schema: Mutable root JSON Schema from model_json_schema().

    Outputs:
      - None; updates schema['$defs'] in place.
    """

    defs = schema.setdefault("$defs", {})
    if not isinstance(defs, dict):
        defs = {}
        schema["$defs"] = defs

    # Always re-emit from the model classes so names stay exact.
    for stable_name, model_cls in _DEF_ALIASES.items():
        model_schema = _model_to_json_schema(model_cls)
        if isinstance(model_schema, dict):
            model_schema = dict(model_schema)
            model_schema.pop("$defs", None)
            model_schema.pop("definitions", None)
            defs[stable_name] = model_schema


def _annotate_vars_pattern_properties(schema: dict[str, Any]) -> None:
    """Brief: Mark top-level vars with identifier patternProperties.

    Inputs:
      - schema: Mutable root JSON Schema.

    Outputs:
      - None; updates properties.vars when present.
    """

    props = schema.get("properties")
    if not isinstance(props, dict):
        return
    vars_schema = props.get("vars")
    if not isinstance(vars_schema, dict):
        return
    vars_schema["type"] = "object"
    vars_schema["additionalProperties"] = False
    vars_schema["patternProperties"] = {_VARS_KEY_PATTERN: {}}
    existing_props = vars_schema.get("properties")
    if not isinstance(existing_props, dict):
        vars_schema["properties"] = {}


def _attach_conditional_upstreams_requirement(schema: dict[str, Any]) -> None:
    """Brief: Require upstreams unless resolver mode is recursive/master/none.

    Inputs:
      - schema: Mutable root JSON Schema.

    Outputs:
      - None; sets schema['allOf'] conditional.
    """

    schema["allOf"] = [
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
    ]


def _attach_plugin_catalog(schema: dict[str, Any], plugins: dict[str, Any]) -> None:
    """Brief: Attach discovered plugin config catalog under $defs.

    Inputs:
      - schema: Mutable root JSON Schema.
      - plugins: collect_plugin_schemas() result.

    Outputs:
      - None; sets PluginConfigs and plugin_configs.
    """

    defs = schema.setdefault("$defs", {})
    catalog = {
        alias: {
            "module": meta["module"],
            "aliases": meta["aliases"],
            "config_schema": meta["config_schema"],
        }
        for alias, meta in plugins.items()
    }
    defs["PluginConfigs"] = catalog
    defs["plugin_configs"] = catalog

    props = schema.get("properties")
    if isinstance(props, dict):
        plugins_schema = props.get("plugins")
        if isinstance(plugins_schema, dict):
            plugins_schema["items"] = {"$ref": "#/$defs/PluginInstance"}


def _iter_object_schema_nodes(node: Any) -> Iterable[dict[str, Any]]:
    """Brief: Yield object-like schema nodes, unwrapping anyOf/oneOf unions.

    Inputs:
      - node: JSON Schema node.

    Outputs:
      - Iterable of dict schema nodes.
    """

    if not isinstance(node, dict):
        return
    yield node
    for key in ("anyOf", "oneOf", "allOf"):
        block = node.get(key)
        if isinstance(block, list):
            for child in block:
                if isinstance(child, dict):
                    yield child


def _resolve_ref(schema: dict[str, Any], ref: str) -> dict[str, Any] | None:
    """Brief: Resolve a local #/$defs/... reference on the root schema.

    Inputs:
      - schema: Root JSON Schema document.
      - ref: JSON Pointer-style ref (e.g. '#/$defs/ServerConfig').

    Outputs:
      - Referenced dict schema, or None when not resolvable.
    """

    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node: Any = schema
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, dict) else None


def _deref_schema_node(
    schema: dict[str, Any], node: Any, *, _seen: set[str] | None = None
) -> Any:
    """Brief: Inline local $ref objects one level deep for navigation-friendly schema.

    Inputs:
      - schema: Root schema (for $defs lookup).
      - node: Schema node to dereference.
      - _seen: Cycle guard for ref URIs.

    Outputs:
      - Node with local $refs merged/inlined where practical.
    """

    if _seen is None:
        _seen = set()
    if not isinstance(node, dict):
        return node

    # Unwrap optional unions like anyOf[{$ref: X}, {type: null}] to a plain object
    # schema plus nullable type when that is the only meaningful branch.
    for union_key in ("anyOf", "oneOf"):
        union = node.get(union_key)
        if not isinstance(union, list) or len(union) != 2:
            continue
        ref_branch = None
        null_branch = False
        for branch in union:
            if not isinstance(branch, dict):
                ref_branch = None
                break
            if branch.get("type") == "null" and len(branch) == 1:
                null_branch = True
            elif "$ref" in branch:
                ref_branch = branch
            else:
                ref_branch = None
                break
        if ref_branch is not None and null_branch:
            merged = {k: v for k, v in node.items() if k != union_key}
            ref = ref_branch.get("$ref")
            target = _resolve_ref(schema, str(ref)) if isinstance(ref, str) else None
            if isinstance(target, dict):
                # Copy target without nested defs; keep description/default from parent.
                body = {
                    k: v
                    for k, v in target.items()
                    if k not in {"$defs", "definitions", "title"}
                }
                out = dict(body)
                for k, v in merged.items():
                    if k not in out or k in {"description", "default", "title"}:
                        out[k] = v
                # Preserve nullability in type when possible.
                t = out.get("type")
                if isinstance(t, str):
                    out["type"] = [t, "null"]
                elif isinstance(t, list) and "null" not in t:
                    out["type"] = list(t) + ["null"]
                return _deref_schema_node(schema, out, _seen=_seen)

    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        if ref in _seen:
            return node
        _seen.add(ref)
        target = _resolve_ref(schema, ref)
        if isinstance(target, dict):
            body = {
                k: v for k, v in target.items() if k not in {"$defs", "definitions"}
            }
            merged = dict(body)
            for k, v in node.items():
                if k == "$ref":
                    continue
                merged[k] = v
            return _deref_schema_node(schema, merged, _seen=_seen)
        return node

    out: dict[str, Any] = {}
    for k, v in node.items():
        if k in {
            "properties",
            "patternProperties",
            "$defs",
            "definitions",
        } and isinstance(v, dict):
            out[k] = {
                pk: _deref_schema_node(schema, pv, _seen=set(_seen))
                for pk, pv in v.items()
            }
        elif k in {"items"} and isinstance(v, dict):
            out[k] = _deref_schema_node(schema, v, _seen=set(_seen))
        elif k in {"items", "anyOf", "oneOf", "allOf"} and isinstance(v, list):
            out[k] = [_deref_schema_node(schema, x, _seen=set(_seen)) for x in v]
        else:
            out[k] = v
    return out


def _inline_root_section_refs(schema: dict[str, Any]) -> None:
    """Brief: Inline $ref/$anyOf-null wrappers on root and major nested sections.

    Inputs:
      - schema: Mutable root JSON Schema.

    Outputs:
      - None; updates schema['properties'] in place for editor/test navigation.
    """

    props = schema.get("properties")
    if not isinstance(props, dict):
        return
    for key in list(props.keys()):
        props[key] = _deref_schema_node(schema, props[key])


def _rewrite_upstream_endpoint_refs(schema: dict[str, Any]) -> None:
    """Brief: Prefer stable upstream_* $ref names on endpoints oneOf.

    Inputs:
      - schema: Mutable root JSON Schema.

    Outputs:
      - None; best-effort rewrite of upstreams.endpoints.items.
    """

    try:
        ups = schema.get("properties", {}).get("upstreams")
        if not isinstance(ups, dict):
            return
        stable_items = {
            "oneOf": [
                {"$ref": "#/$defs/upstream_host"},
                {"$ref": "#/$defs/upstream_doh"},
                {"$ref": "#/$defs/upstream_url"},
            ]
        }
        for node in _iter_object_schema_nodes(ups):
            props = node.get("properties")
            if not isinstance(props, dict):
                continue
            ep = props.get("endpoints")
            if isinstance(ep, dict):
                ep["items"] = dict(stable_items)
            backup = props.get("backup")
            if not isinstance(backup, dict):
                continue
            # Older tooling/tests expect backup.allOf[0].properties.endpoints.
            if "allOf" not in backup and isinstance(backup.get("properties"), dict):
                body = {
                    k: v
                    for k, v in backup.items()
                    if k not in {"default", "description", "title"}
                }
                wrapper = {
                    "allOf": [body],
                }
                if "default" in backup:
                    wrapper["default"] = backup["default"]
                if "description" in backup:
                    wrapper["description"] = backup["description"]
                props["backup"] = wrapper
                backup = wrapper
            for bnode in _iter_object_schema_nodes(backup):
                bprops = bnode.get("properties")
                if isinstance(bprops, dict) and isinstance(
                    bprops.get("endpoints"), dict
                ):
                    bprops["endpoints"]["items"] = dict(stable_items)
    except Exception:  # pragma: no cover
        logger.exception("Failed to rewrite upstream endpoint refs")


def _flatten_optional_enums(node: Any) -> None:
    """Brief: Lift enum out of anyOf[enum, null] unions for tooling/tests.

    Inputs:
      - node: Mutable JSON Schema node (walked recursively).

    Outputs:
      - None; updates nodes in place when an optional enum union is detected.
    """

    if isinstance(node, list):
        for item in node:
            _flatten_optional_enums(item)
        return
    if not isinstance(node, dict):
        return

    for union_key in ("anyOf", "oneOf"):
        union = node.get(union_key)
        if not isinstance(union, list) or len(union) != 2:
            continue
        enum_branch = None
        null_branch = False
        for branch in union:
            if not isinstance(branch, dict):
                enum_branch = None
                break
            if branch.get("type") == "null" and set(branch.keys()) <= {"type"}:
                null_branch = True
            elif "enum" in branch:
                enum_branch = branch
            else:
                enum_branch = None
                break
        if enum_branch is not None and null_branch:
            node.pop(union_key, None)
            node["enum"] = list(enum_branch.get("enum") or [])
            base_type = enum_branch.get("type", "string")
            if isinstance(base_type, list):
                types = list(base_type)
            else:
                types = [base_type]
            if "null" not in types:
                types.append("null")
            node["type"] = types

    for key, child in list(node.items()):
        if key in {
            "properties",
            "patternProperties",
            "$defs",
            "definitions",
        } and isinstance(child, dict):
            for sub in child.values():
                _flatten_optional_enums(sub)
        elif key == "items":
            _flatten_optional_enums(child)
        elif key in {"anyOf", "oneOf", "allOf"} and isinstance(child, list):
            for sub in child:
                _flatten_optional_enums(sub)


def build_document() -> dict[str, Any]:
    """Brief: Build the full Foghorn configuration JSON Schema document.

    Inputs:
      - None (uses FoghornConfig and plugin discovery).

    Outputs:
      - Dict ready to serialize as assets/config-schema.json.
    """

    schema = FoghornConfig.model_json_schema(mode="validation")
    if not isinstance(schema, dict):
        raise TypeError("FoghornConfig.model_json_schema() did not return a dict")

    schema["$schema"] = _SCHEMA_DRAFT
    schema["$id"] = _SCHEMA_ID
    schema["title"] = _SCHEMA_TITLE
    schema["type"] = "object"
    schema["additionalProperties"] = False

    required = schema.get("required")
    if not isinstance(required, list):
        required = []
    if "server" not in required:
        required = ["server", *required]
    schema["required"] = required

    _promote_stable_defs(schema)
    _annotate_vars_pattern_properties(schema)
    _inline_root_section_refs(schema)
    _flatten_optional_enums(schema)
    _attach_conditional_upstreams_requirement(schema)
    _rewrite_upstream_endpoint_refs(schema)

    plugins = collect_plugin_schemas()
    _attach_plugin_catalog(schema, plugins)

    # Second pass: nested $refs inside inlined sections (e.g. axfr.tsig.keys items).
    _inline_root_section_refs(schema)
    _flatten_optional_enums(schema)
    _rewrite_upstream_endpoint_refs(schema)

    props = schema.get("properties")
    if isinstance(props, dict) and "$schema" not in props and "schema_uri" in props:
        props["$schema"] = props.pop("schema_uri")

    return schema


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    """Brief: Parse CLI arguments for the schema generator.

    Inputs:
      - argv: Optional argument list (defaults to sys.argv[1:]).

    Outputs:
      - argparse.Namespace with output/verbose/base_schema fields.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Generate Foghorn configuration JSON Schema from Pydantic models "
            "and discovered plugin config models."
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
        help="Deprecated and ignored; models are the source of truth.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging to stderr.",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    """Brief: CLI entrypoint to generate configuration JSON Schema.

    Inputs:
      - argv: Optional CLI argument strings.

    Outputs:
      - int process status (0 on success).

    Example:
      - ``PYTHONPATH=src python scripts/generate_foghorn_schema.py -o assets/config-schema.json``
      - ``make schema``
    """

    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if getattr(args, "base_schema", None):
        logger.warning("--base-schema is deprecated and ignored")

    output_path = Path(args.output)
    logger.info("Generating configuration schema to %s", output_path)

    try:
        doc = build_document()
        text = json.dumps(doc, indent=2, sort_keys=True)
        if not text.endswith("\n"):
            text += "\n"
        output_path.write_text(text, encoding="utf-8")
    except Exception:  # pragma: no cover
        logger.exception("Failed to write schema to %s", output_path)
        return 1

    logger.info("Schema written to %s", output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
