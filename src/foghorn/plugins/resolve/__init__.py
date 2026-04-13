"""
Lazy-loading package for foghorn.plugins.

Brief: Allows attribute access like foghorn.plugins.some_submodule to auto-import
foghorn.plugins.some_submodule on demand. Also exposes a dynamic __all__ of
available submodules.
"""

from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType
from typing import List

# Expose direct modules for star-import and introspection, but avoid importing
# submodules at package import time (some optional plugins may have extra deps,
# and unit tests should not fail due to unrelated plugin modules).
__all__: List[str] = [m.name for m in pkgutil.iter_modules(__path__) if not m.ispkg]


def __getattr__(name: str) -> ModuleType:
    fullname = f"{__name__}.{name}"
    try:
        return importlib.import_module(fullname)
    except ModuleNotFoundError as e:
        # Only raise AttributeError if the missing module is exactly fullname
        if e.name == fullname:
            raise AttributeError(
                f"module '{__name__}' has no attribute '{name}'"
            ) from e
        raise
