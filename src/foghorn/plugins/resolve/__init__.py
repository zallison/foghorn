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

__all__: List[str] = [
    m.name.split(".")[-1]
    for m in pkgutil.walk_packages(__path__, prefix=__name__ + ".")
    if not m.ispkg
]


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
