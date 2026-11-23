"""Registry and alias resolution for secrets backends.

Inputs:
  - discover_secrets_backends() walks foghorn.plugins.secrets.* modules.
  - get_secrets_backend_class() resolves alias or dotted import path.

Outputs:
  - Mapping of normalized aliases to SecretsStore subclasses.
"""

from __future__ import annotations

import difflib
import importlib
import inspect
import pkgutil
import re
from collections.abc import Iterable

from foghorn.utils.register_caches import registered_lru_cache

from .base import SecretsStore

_CAMEL_1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_2 = re.compile(r"([a-z0-9])([A-Z])")


@registered_lru_cache(maxsize=1024)
def _camel_to_snake(name: str) -> str:
    """Brief: Convert CamelCase identifier to snake_case.

    Inputs:
      - name: Class or identifier name.

    Outputs:
      - Lowercase snake_case string.
    """

    s1 = _CAMEL_1.sub(r"\1_\2", name)
    s2 = _CAMEL_2.sub(r"\1_\2", s1)
    return s2.lower()


@registered_lru_cache(maxsize=1024)
def _default_alias_for(cls: type[SecretsStore]) -> str:
    """Brief: Derive default alias from SecretsStore class name.

    Inputs:
      - cls: SecretsStore subclass.

    Outputs:
      - snake_case alias with Secrets/Store/SecretsStore suffixes stripped.
    """

    name = cls.__name__
    for suffix in ("SecretsStore", "Secrets", "Store"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return _camel_to_snake(name)


@registered_lru_cache(maxsize=1024)
def _normalize(alias: str) -> str:
    """Brief: Normalize a secrets backend alias for registry lookup.

    Inputs:
      - alias: Raw alias string.

    Outputs:
      - Lowercased alias with hyphens replaced by underscores.
    """

    return alias.strip().lower().replace("-", "_")


def _iter_secrets_modules(
    package_name: str = "foghorn.plugins.secrets",
) -> Iterable[str]:
    """Brief: Yield fully-qualified module names under the secrets package.

    Inputs:
      - package_name: Root package to walk.

    Outputs:
      - Iterable of module dotted paths.
    """

    pkg = importlib.import_module(package_name)
    for modinfo in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
        yield modinfo.name


@registered_lru_cache(maxsize=4)
def discover_secrets_backends(
    package_name: str = "foghorn.plugins.secrets",
) -> dict[str, type[SecretsStore]]:
    """Brief: Discover SecretsStore subclasses and register them by alias.

    Inputs:
      - package_name: Package path to scan.

    Outputs:
      - Dict mapping normalized aliases to classes.
    """

    registry: dict[str, type[SecretsStore]] = {}

    for modname in _iter_secrets_modules(package_name):
        # Avoid importing router/base as backends.
        if modname.rsplit(".", 1)[-1] in {"base", "registry", "router"}:
            continue
        module = importlib.import_module(modname)

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, SecretsStore) or obj is SecretsStore:
                continue

            claimed = set(_normalize(a) for a in (getattr(obj, "aliases", ()) or ()))
            claimed.add(_normalize(_default_alias_for(obj)))

            for alias in claimed:
                if not alias:
                    continue
                if alias in registry and registry[alias] is not obj:
                    other = registry[alias]
                    raise ValueError(
                        f"Duplicate secrets backend alias '{alias}' claimed by "
                        f"{obj.__module__}.{obj.__name__} and "
                        f"{other.__module__}.{other.__name__}"
                    )
                registry[alias] = obj

    return registry


def get_secrets_backend_class(identifier: str) -> type[SecretsStore]:
    """Brief: Resolve identifier to a SecretsStore subclass.

    Inputs:
      - identifier: Dotted import path or alias.

    Outputs:
      - SecretsStore subclass.
    """

    ident = str(identifier).strip()
    if "." in ident:
        modname, _, classname = ident.rpartition(".")
        if not modname or not classname:
            raise ValueError(f"Invalid secrets backend path '{identifier}'")
        module = importlib.import_module(modname)
        cls = getattr(module, classname)
        if not issubclass(cls, SecretsStore):
            raise TypeError(f"{identifier} is not a SecretsStore subclass")
        return cls

    reg = discover_secrets_backends()
    key = _normalize(ident)
    try:
        return reg[key]
    except KeyError:
        suggestions = difflib.get_close_matches(key, list(reg.keys()), n=3)
        raise KeyError(
            f"Unknown secrets backend alias '{identifier}'. "
            f"Known aliases: {', '.join(sorted(reg.keys()))}. "
            f"Suggestions: {suggestions}"
        ) from None
