#!/usr/bin/env python3
"""Generate aggregated JSON schema for all Foghorn plugins.

Inputs:
    - Command-line arguments (optional):
        - --output / -o: Output path for JSON schema (default: ./schema.json).
        - --verbose / -v: Enable verbose logging.

Outputs:
    - JSON file written to the specified output path containing discovered
      plugin configuration schemas keyed by canonical alias.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Type

from foghorn.config_schema import get_default_schema_path
from foghorn.plugins.base import BasePlugin
from foghorn.plugins import registry as plugin_registry

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
        # Canonical alias is derived from the class name (e.g. FilterPlugin -> filter)
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

        results[canonical] = {
            "module": module_path,
            "aliases": aliases,
            "config_schema": config_schema,
        }

    return results


def _load_base_schema() -> Dict[str, Any]:
    """Brief: Load the main Foghorn config JSON Schema from disk.

    Inputs:
      - None (uses get_default_schema_path()).

    Outputs:
      - Dict representing the base configuration JSON Schema.
    """

    schema_path = get_default_schema_path()
    with schema_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_document() -> Dict[str, Any]:
    """Brief: Build a combined JSON Schema including core config and plugins.

    Inputs:
      - None.

    Outputs:
      - Dict based on the existing config-yaml.schema with an extra
        ``$defs.plugin_configs`` mapping that contains all discovered plugin
        configuration schemas keyed by canonical alias.

    Notes:
      - This does not change validation behaviour of the main schema; the
        additional definitions are informational only and can be consumed by
        tooling (e.g. UIs or editors) that want per-plugin config schemas.
    """

    base = _load_base_schema()
    plugins = collect_plugin_schemas()

    # Attach plugin schemas under a dedicated defs key so existing references
    # remain untouched.
    defs = base.setdefault("$defs", {})
    defs["plugin_configs"] = plugins

    return base


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    """Brief: Parse CLI arguments for the plugin schema generator.

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
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging to stderr.",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Iterable[str]] = None) -> int:
    """Brief: CLI entrypoint to generate plugin schema JSON.

    Inputs:
      - argv: Optional iterable of CLI argument strings.

    Outputs:
      - int: 0 on success, non-zero on failure.

    Example usage (from project root):

      - ``PYTHONPATH=src python scripts/generate_plugin_schema.py``
      - ``PYTHONPATH=src python scripts/generate_plugin_schema.py -o assets/plugin-schema.json``
    """

    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    output_path = Path(args.output)
    logger.info("Generating plugin schema to %s", output_path)

    try:
        doc = build_document()
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
