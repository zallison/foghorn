import difflib
import importlib
import inspect
import logging
import os
import pkgutil
import re
from typing import Dict, Iterable, Type

from .base import BasePlugin

# Module import errors encountered during plugin discovery.
#
# Brief:
#   In minimal/headless builds, some plugins may not be importable because they
#   depend on optional third-party packages. We record those ImportError messages
#   so get_plugin_class() can provide actionable hints when an alias is missing.
#
# Inputs:
#   - Populated by discover_plugins().
#
# Outputs:
#   - Mapping from module name -> ImportError string.
_DISCOVERY_IMPORT_ERRORS: Dict[str, str] = {}
_DISCOVERY_IMPORT_ERRORS_BY_PACKAGE: Dict[str, Dict[str, str]] = {}

# Cached plugin registries by package name.
_DISCOVERY_CACHE: Dict[str, Dict[str, Type[BasePlugin]]] = {}

logger = logging.getLogger(__name__)

_CAMEL_1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_2 = re.compile(r"([a-z0-9])([A-Z])")


def _camel_to_snake(name: str) -> str:
    s1 = _CAMEL_1.sub(r"\1_\2", name)
    s2 = _CAMEL_2.sub(r"\1_\2", s1)
    return s2.lower()


def _default_alias_for(cls: Type[BasePlugin]) -> str:
    name = cls.__name__
    if name.endswith("Plugin"):
        name = name[:-6]
    return _camel_to_snake(name)


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


def _strict_plugin_discovery_enabled() -> bool:
    """Brief: Check whether plugin discovery should be strict about ImportError.

    Inputs:
      - None (reads environment variable FOGHORN_STRICT_PLUGIN_DISCOVERY).

    Outputs:
      - bool: True when strict mode is enabled.

    Notes:
      - When strict mode is enabled, discover_plugins() re-raises ImportError
        rather than skipping missing optional dependencies.
    """

    val = os.getenv("FOGHORN_STRICT_PLUGIN_DISCOVERY", "")
    return str(val).strip().lower() in {"1", "true", "yes", "y", "on"}


def _debug_plugin_discovery_enabled() -> bool:
    """Brief: Check whether debug hints for plugin discovery are enabled.

    Inputs:
      - None (reads environment variable FOGHORN_DEBUG_PLUGIN_DISCOVERY).

    Outputs:
      - bool: True when debug hints are enabled.
    """

    val = os.getenv("FOGHORN_DEBUG_PLUGIN_DISCOVERY", "")
    return str(val).strip().lower() in {"1", "true", "yes", "y", "on"}


def clear_plugin_discovery_cache(package_name: str | None = None) -> None:
    """Brief: Clear cached plugin discovery results.

    Inputs:
      - package_name: Optional package name to clear. When None, clears all.

    Outputs:
      - None

    Example:
      >>> clear_plugin_discovery_cache()
    """

    global _DISCOVERY_CACHE, _DISCOVERY_IMPORT_ERRORS, _DISCOVERY_IMPORT_ERRORS_BY_PACKAGE
    if package_name is None:
        _DISCOVERY_CACHE = {}
        _DISCOVERY_IMPORT_ERRORS_BY_PACKAGE = {}
        _DISCOVERY_IMPORT_ERRORS = {}
        return

    _DISCOVERY_CACHE.pop(package_name, None)
    _DISCOVERY_IMPORT_ERRORS_BY_PACKAGE.pop(package_name, None)
    if package_name == "foghorn.plugins":
        _DISCOVERY_IMPORT_ERRORS = {}


def discover_plugins(
    package_name: str = "foghorn.plugins",
    force_refresh: bool = False,
) -> Dict[str, Type[BasePlugin]]:
    """Brief: Discover and register plugins by importing plugin modules.

    Inputs:
      - package_name: Package path to scan for plugins.
      - force_refresh: When True, bypass cached discovery results.

    Outputs:
      - dict[str, type[BasePlugin]] mapping normalized aliases to plugin classes.

    Behaviour:
      - By default, modules that raise ImportError during discovery are skipped
        and logged as warnings so minimal/headless builds can omit optional
        plugin dependencies.
      - When FOGHORN_STRICT_PLUGIN_DISCOVERY is enabled, ImportError is raised.

    Raises:
      - ValueError on duplicate aliases.
      - ImportError when strict discovery is enabled.

    Example:
      >>> registry = discover_plugins("foghorn.plugins")
      >>> "filter" in registry
      True
    """

    global _DISCOVERY_IMPORT_ERRORS

    if not force_refresh and package_name in _DISCOVERY_CACHE:
        cached = _DISCOVERY_CACHE[package_name]
        cached_errors = _DISCOVERY_IMPORT_ERRORS_BY_PACKAGE.get(package_name, {})
        _DISCOVERY_IMPORT_ERRORS = dict(cached_errors)
        return dict(cached)

    registry: Dict[str, Type[BasePlugin]] = {}

    # Reset per-discovery error registry.
    _DISCOVERY_IMPORT_ERRORS = {}

    strict = _strict_plugin_discovery_enabled()

    for modname in _iter_plugin_modules(package_name):
        try:
            module = importlib.import_module(modname)
        except ImportError as exc:
            _DISCOVERY_IMPORT_ERRORS[modname] = str(exc)
            if strict:
                logger.error("Failed importing plugin module %s: %s", modname, exc)
                raise

            # Only skip imports when the failure indicates a missing third-party
            # dependency (ModuleNotFoundError) rather than a bug inside the
            # plugin module itself.
            missing_name = getattr(exc, "name", None)
            is_missing_third_party = bool(
                isinstance(exc, ModuleNotFoundError)
                and missing_name
                and not str(missing_name).startswith(f"{package_name}.")
                and not str(missing_name).startswith("foghorn.")
            )
            if is_missing_third_party:
                logger.warning(
                    "Skipping plugin module %s due to missing optional dependency: %s",
                    modname,
                    exc,
                )
                continue

            logger.error("Failed importing plugin module %s: %s", modname, exc)
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

    _DISCOVERY_CACHE[package_name] = dict(registry)
    _DISCOVERY_IMPORT_ERRORS_BY_PACKAGE[package_name] = dict(_DISCOVERY_IMPORT_ERRORS)
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

        hint = ""
        if _DISCOVERY_IMPORT_ERRORS:
            logger.debug(
                "Plugin discovery import errors for %s: %s",
                identifier,
                _DISCOVERY_IMPORT_ERRORS,
            )
            if _debug_plugin_discovery_enabled() or _strict_plugin_discovery_enabled():
                # Include only a small sample to keep errors readable.
                sample = list(_DISCOVERY_IMPORT_ERRORS.items())[:5]
                formatted = ", ".join([f"{m} ({err})" for m, err in sample])
                hint = (
                    " Some plugin modules could not be imported due to missing optional "
                    f"dependencies: {formatted}."
                )
            else:
                hint = (
                    " Some plugin modules could not be imported due to missing optional "
                    "dependencies."
                )

        raise KeyError(
            f"Unknown plugin alias '{identifier}'. "
            f"Known aliases: {', '.join(sorted(reg.keys()))}. "
            f"Suggestions: {suggestions}." + hint
        )
