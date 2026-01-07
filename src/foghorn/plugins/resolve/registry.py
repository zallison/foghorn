import difflib
import importlib
import inspect
import logging
import pkgutil
import re
from typing import Dict, Iterable, Type

from .base import BasePlugin
from foghorn.utils.register_caches import registered_lru_cached

logger = logging.getLogger(__name__)

_CAMEL_1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_2 = re.compile(r"([a-z0-9])([A-Z])")


@registered_lru_cached(maxsize=1024)
def _camel_to_snake(name: str) -> str:
    s1 = _CAMEL_1.sub(r"\1_\2", name)
    s2 = _CAMEL_2.sub(r"\1_\2", s1)
    return s2.lower()


@registered_lru_cached(maxsize=1024)
def _default_alias_for(cls: Type[BasePlugin]) -> str:
    name = cls.__name__
    if name.endswith("Plugin"):
        name = name[:-6]
    return _camel_to_snake(name)


@registered_lru_cached(maxsize=1024)
def _normalize(alias: str) -> str:
    return alias.strip().lower().replace("-", "_")


def _iter_plugin_modules(package_name: str = "foghorn.plugins") -> Iterable[str]:
    pkg = importlib.import_module(package_name)
    for modinfo in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
        # Only import modules (skip packages unless they contain modules)
        if (
            modinfo.ispkg
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            # Still yield submodules during walk; leave as-is
            pass
        yield modinfo.name


def discover_plugins(
    package_name: str = "foghorn.plugins",
) -> Dict[str, Type[BasePlugin]]:
    """
    Discover and register plugins by importing modules.

    Inputs:
      - package_name (str): Package path to scan for plugins

    Outputs:
      - Dict[str, Type[BasePlugin]]: Mapping from normalized aliases to plugin classes

    Raises ImportError if module import fails. Raises ValueError on duplicate aliases.

    Example:
        >>> registry = discover_plugins("foghorn.plugins")
        >>> "filter" in registry
        True
    """
    registry: Dict[str, Type[BasePlugin]] = {}

    for modname in _iter_plugin_modules(package_name):
        try:
            module = importlib.import_module(modname)
        except ImportError:
            logger.error("Failed importing plugin module %s: fail", modname)
            raise
        except (
            Exception
        ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.error("Failed importing plugin module %s: %s", modname, e)
            raise

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, BasePlugin) or obj is BasePlugin:
                continue

            claimed = set(_normalize(a) for a in (getattr(obj, "aliases", ()) or ()))
            claimed.add(_normalize(_default_alias_for(obj)))

            for alias in claimed:
                if alias in registry and registry[alias] is not obj:
                    other = registry[alias]
                    raise ValueError(
                        f"Duplicate plugin alias '{alias}' claimed by {obj.__module__}.{obj.__name__} "
                        f"and {other.__module__}.{other.__name__}"
                    )
                registry[alias] = obj

    return registry


def get_plugin_class(
    identifier: str, registry: Dict[str, Type[BasePlugin]] | None = None
) -> Type[BasePlugin]:
    """
    Resolve identifier to a plugin class.
    - If identifier contains a dot, treat as dotted import path "pkg.mod.Class".
    - Otherwise, treat as alias and resolve via registry.
    """
    ident = identifier.strip()
    if "." in ident:
        modname, _, classname = ident.rpartition(".")
        if not modname or not classname:
            raise ValueError(f"Invalid plugin path '{identifier}'")
        module = importlib.import_module(modname)
        cls = getattr(module, classname)
        if not issubclass(cls, BasePlugin):
            raise TypeError(f"{identifier} is not a BasePlugin subclass")
        return cls

    reg = registry or discover_plugins()
    key = _normalize(ident)
    try:
        return reg[key]
    except KeyError:
        suggestions = difflib.get_close_matches(key, list(reg.keys()), n=3)
        raise KeyError(
            f"Unknown plugin alias '{identifier}'. "
            f"Known aliases: {', '.join(sorted(reg.keys()))}. "
            f"Suggestions: {suggestions}"
        )
