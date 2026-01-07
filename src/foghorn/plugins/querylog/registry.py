from __future__ import annotations

"""Registry and alias resolution for statistics/query-log backends.

Inputs:
  - None directly; helper functions are used by load_stats_store_backend() to
    discover BaseStatsStore implementations and resolve backend identifiers.

Outputs:
  - discover_stats_backends(): Build a mapping of normalized aliases to
    BaseStatsStore subclasses by walking foghorn.plugins.querylog.* modules.
  - get_stats_backend_class(): Resolve a backend identifier to a concrete
    BaseStatsStore subclass, supporting both aliases and dotted import paths.
"""

import difflib
import importlib
import inspect
import pkgutil
import re
from typing import Dict, Iterable, Type

from .base import BaseStatsStore
from foghorn.utils.register_caches import registered_lru_cached


_CAMEL_1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_2 = re.compile(r"([a-z0-9])([A-Z])")


@registered_lru_cached(maxsize=1024)
def _camel_to_snake(name: str) -> str:
    """Brief: Convert CamelCase class names to snake_case aliases.

    Inputs:
      - name: Original class name.

    Outputs:
      - snake_case alias string.
    """

    s1 = _CAMEL_1.sub(r"\1_\2", name)
    s2 = _CAMEL_2.sub(r"\1_\2", s1)
    return s2.lower()


@registered_lru_cached(maxsize=1024)
def _default_alias_for(cls: Type[BaseStatsStore]) -> str:
    """Brief: Derive a default alias for a BaseStatsStore subclass.

    Inputs:
      - cls: Concrete BaseStatsStore subclass.

    Outputs:
      - snake_case alias derived from the class name with common suffixes
        (StatsStore, Store, Logging) stripped.
    """

    name = cls.__name__
    for suffix in ("StatsStore", "Store", "Logging"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return _camel_to_snake(name)


@registered_lru_cached(maxsize=1024)
def _normalize(alias: str) -> str:
    """Brief: Normalize backend alias strings for registry keys.

    Inputs:
      - alias: Raw alias string.

    Outputs:
      - Normalized alias: lowercase, trimmed, with dashes replaced by underscores.
    """

    return alias.strip().lower().replace("-", "_")


def _iter_backend_modules(
    package_name: str = "foghorn.plugins.querylog",
) -> Iterable[str]:
    """Brief: Yield fully-qualified module names under the querylog package.

    Inputs:
      - package_name: Root package to scan (defaults to foghorn.plugins.querylog).

    Outputs:
      - Iterable of dotted module names.
    """

    pkg = importlib.import_module(package_name)
    for modinfo in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
        yield modinfo.name


@registered_lru_cached(maxsize=8)
def discover_stats_backends(
    package_name: str = "foghorn.plugins.querylog",
) -> Dict[str, Type[BaseStatsStore]]:
    """Brief: Discover BaseStatsStore subclasses and register them by alias.

    Inputs:
      - package_name: Package path to scan for backends.

    Outputs:
      - Dict[str, Type[BaseStatsStore]] mapping normalized aliases to classes.
    """

    registry: Dict[str, Type[BaseStatsStore]] = {}

    for modname in _iter_backend_modules(package_name):
        module = importlib.import_module(modname)

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, BaseStatsStore) or obj is BaseStatsStore:
                continue

            claimed = set(_normalize(a) for a in (getattr(obj, "aliases", ()) or ()))
            claimed.add(_normalize(_default_alias_for(obj)))

            for alias in claimed:
                if not alias:
                    continue
                if alias in registry and registry[alias] is not obj:
                    other = registry[alias]
                    raise ValueError(
                        "Duplicate stats backend alias '%s' claimed by %s.%s and %s.%s"
                        % (
                            alias,
                            obj.__module__,
                            obj.__name__,
                            other.__module__,
                            other.__name__,
                        )
                    )
                registry[alias] = obj

    return registry


def get_stats_backend_class(
    identifier: str, registry: Dict[str, Type[BaseStatsStore]] | None = None
) -> Type[BaseStatsStore]:
    """Brief: Resolve identifier to a BaseStatsStore subclass.

    Inputs:
      - identifier: Dotted import path ("pkg.mod.Class") or alias.
      - registry: Optional precomputed alias registry from discover_stats_backends.

    Outputs:
      - BaseStatsStore subclass corresponding to the identifier.

    Raises:
      - ValueError/TypeError when the identifier is invalid or does not
        correspond to a BaseStatsStore subclass.
    """

    ident = str(identifier or "").strip()
    if "." in ident:
        modname, _, classname = ident.rpartition(".")
        if not modname or not classname:
            raise ValueError(f"Invalid stats backend path '{identifier}'")
        module = importlib.import_module(modname)
        cls = getattr(module, classname)
        if not issubclass(cls, BaseStatsStore):
            raise TypeError(f"{identifier} is not a BaseStatsStore subclass")
        return cls

    reg = registry or discover_stats_backends()
    key = _normalize(ident)
    try:
        return reg[key]
    except KeyError:
        suggestions = difflib.get_close_matches(key, list(reg.keys()), n=3)
        raise KeyError(
            "Unknown stats backend alias '%s'. Known aliases: %s. Suggestions: %s"
            % (identifier, ", ".join(sorted(reg.keys())), suggestions)
        )
