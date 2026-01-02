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

from foghorn.plugins.resolve.base import BasePlugin
from foghorn.plugins.resolve import registry as plugin_registry

# Add the 'src' directory to sys.path to resolve 'foghorn' module imports
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
src_dir = project_root / "src"
if src_dir.is_dir() and str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

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
    """Brief: Extend statistics.persistence schema with backend configuration.

    Inputs:
      - base: Mutable JSON Schema mapping loaded from the base schema file.

    Outputs:
      - None; ``base`` is modified in place when the expected statistics
        structure is present. Any missing or unexpected shapes are treated as
        no-ops to keep the generator robust against schema drift.
    """

    try:
        root_props = base.get("properties")
        if not isinstance(root_props, dict):
            return

        stats_obj = root_props.get("statistics")
        if not isinstance(stats_obj, dict):
            return

        stats_props = stats_obj.get("properties")
        if not isinstance(stats_props, dict):
            return

        # Optional toggle to restrict runtime statistics behaviour to a
        # "logging-only" mode where background warm-load/rebuild passes are
        # skipped and only insert-style operations (query_log appends and
        # counter increments) are performed. This is written directly into the
        # base statistics schema so that validation tools always see it as a
        # first-class optional property, just like other booleans under
        # statistics.
        stats_props["logging_only"] = {
            "type": "boolean",
            "description": (
                "When true, restrict statistics to logging-only mode where "
                "only insert-style operations (query_log appends and "
                "counter increments) are performed and background warm-load "
                "or rebuild passes are skipped."
            ),
            "default": False,
        }

        # Optional toggle to restrict persistence usage to the raw query_log
        # only. When true, aggregate counters are not mirrored into the
        # persistent store (counts table); only query_log appends are
        # performed.
        stats_props["query_log_only"] = {
            "type": "boolean",
            "description": (
                "When true, only the raw query_log is written to the "
                "persistence backend and aggregate counters are kept "
                "in-memory only."
            ),
            "default": False,
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
                    "additionalProperties": True,
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
                                "a BaseStatsStoreBackend implementation)."
                            ),
                        },
                        "config": {
                            "type": "object",
                            "description": (
                                "Backend-specific configuration mapping passed "
                                "verbatim to the selected backend."
                            ),
                        },
                    },
                },
            }
    except Exception:  # pragma: no cover - defensive logging only
        logger.exception("Failed to augment statistics.persistence schema")


def build_document(base_schema_path: Optional[str] = None) -> Dict[str, Any]:
    """Brief: Build a combined JSON Schema including core config and plugins.

    Inputs:
      - base_schema_path: Optional explicit path to a base schema JSON file.

    Outputs:
      - Dict based on the existing config-schema.json with an extra
        ``$defs.plugin_configs`` mapping that contains all discovered plugin
        configuration schemas keyed by canonical alias.

    Notes:
      - This does not change validation behaviour of the main schema; the
        additional definitions are informational only and can be consumed by
        tooling (e.g. UIs or editors) that want per-plugin config schemas.
    """

    base = _load_base_schema(base_schema_path=base_schema_path)

    # Ensure top-level helpers (like `variables`) and statistics persistence
    # backends are visible to tooling that consumes the JSON Schema directly.
    _augment_variables_schema(base)

    # Ensure statistics.persistence documents the backend loader options used
    # by foghorn.plugins.querylog.load_stats_store_backend().
    _augment_statistics_persistence_schema(base)

    plugins = collect_plugin_schemas()

    # Attach plugin schemas under a dedicated defs key so existing references
    # remain untouched.
    defs = base.setdefault("$defs", {})
    defs["plugin_configs"] = plugins

    return base


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
