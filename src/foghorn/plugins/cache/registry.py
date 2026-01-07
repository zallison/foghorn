from __future__ import annotations

import difflib
import importlib
import inspect
import pkgutil
import re
from typing import Dict, Iterable, Optional, Type

from .base import CachePlugin
from foghorn.utils.register_caches import registered_lru_cached

_CAMEL_1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_2 = re.compile(r"([a-z0-9])([A-Z])")


@registered_lru_cached(maxsize=1024)
def _camel_to_snake(name: str) -> str:
    s1 = _CAMEL_1.sub(r"\1_\2", name)
    s2 = _CAMEL_2.sub(r"\1_\2", s1)
    return s2.lower()


@registered_lru_cached(maxsize=1024)
def _default_alias_for(cls: Type[CachePlugin]) -> str:
    name = cls.__name__
    # Common suffixes used by cache implementations.
    for suffix in ("CachePlugin", "Cache"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return _camel_to_snake(name)


@registered_lru_cached(maxsize=1024)
def _normalize(alias: str) -> str:
    return alias.strip().lower().replace("-", "_")


def _iter_cache_plugin_modules(
    package_name: str = "foghorn.plugins.cache",
) -> Iterable[str]:
    pkg = importlib.import_module(package_name)
    for modinfo in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
        yield modinfo.name


@registered_lru_cached(maxsize=4)
def discover_cache_plugins(
    package_name: str = "foghorn.plugins.cache",
) -> Dict[str, Type[CachePlugin]]:
    """Brief: Discover CachePlugin subclasses and register them by alias.

    Inputs:
      - package_name: Package path to scan.

    Outputs:
      - Dict[str, Type[CachePlugin]] mapping normalized aliases to classes.
    """

    registry: Dict[str, Type[CachePlugin]] = {}

    for modname in _iter_cache_plugin_modules(package_name):
        module = importlib.import_module(modname)

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, CachePlugin) or obj is CachePlugin:
                continue

            claimed = set(_normalize(a) for a in (getattr(obj, "aliases", ()) or ()))
            claimed.add(_normalize(_default_alias_for(obj)))

            for alias in claimed:
                if alias in registry and registry[alias] is not obj:
                    other = registry[alias]
                    raise ValueError(
                        f"Duplicate cache plugin alias '{alias}' claimed by {obj.__module__}.{obj.__name__} "
                        f"and {other.__module__}.{other.__name__}"
                    )
                registry[alias] = obj

    return registry


def get_cache_plugin_class(identifier: str) -> Type[CachePlugin]:
    """Brief: Resolve identifier to a cache plugin class.

    Inputs:
      - identifier: Dotted import path or alias.

    Outputs:
      - CachePlugin subclass.
    """

    ident = str(identifier).strip()
    if "." in ident:
        modname, _, classname = ident.rpartition(".")
        if not modname or not classname:
            raise ValueError(f"Invalid cache plugin path '{identifier}'")
        module = importlib.import_module(modname)
        cls = getattr(module, classname)
        if not issubclass(cls, CachePlugin):
            raise TypeError(f"{identifier} is not a CachePlugin subclass")
        return cls

    reg = discover_cache_plugins()
    key = _normalize(ident)
    try:
        return reg[key]
    except KeyError:
        suggestions = difflib.get_close_matches(key, list(reg.keys()), n=3)
        raise KeyError(
            f"Unknown cache plugin alias '{identifier}'. "
            f"Known aliases: {', '.join(sorted(reg.keys()))}. "
            f"Suggestions: {suggestions}"
        )


def load_cache_plugin(cfg: Optional[object]) -> CachePlugin:
    """Brief: Build the configured cache plugin.

    Inputs:
      - cfg: Cache config. Supported forms:
        - None: Use default in-memory TTL cache.
        - str: Alias or dotted import path.
        - dict: {"module": <str>, "config": <dict>}.

    Outputs:
      - CachePlugin instance.

    Example:
      cache:
        module: in_memory_ttl
        config: {}
    """

    if cfg is None:
        cls = get_cache_plugin_class("in_memory_ttl")
        return cls()

    if isinstance(cfg, str):
        cls = get_cache_plugin_class(cfg)
        return cls()

    if isinstance(cfg, dict):
        # Special-case explicit null module as an alias for disabling caching.
        # Omitting the cache key entirely still means "use the default cache".
        if "module" in cfg and cfg.get("module") is None:
            module = "none"
        else:
            module = cfg.get("module")
            if isinstance(module, str):
                module = module.strip() or None
            if module is None:
                module = cfg.get("class") or cfg.get("type")
            if module is None:
                module = "in_memory_ttl"

        subcfg = cfg.get("config")
        if not isinstance(subcfg, dict):
            subcfg = {}

        cls = get_cache_plugin_class(str(module))
        return cls(**dict(subcfg))

    raise TypeError("cache config must be a mapping, string, or null")
