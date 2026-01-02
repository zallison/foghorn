"""Cache plugins.

Brief: Defines the CachePlugin interface and default cache implementations.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from .base import CachePlugin, cache_aliases
from .in_memory_ttl import InMemoryTTLCache
from .registry import load_cache_plugin

__all__ = [
    "CachePlugin",
    "InMemoryTTLCache",
    "cache_aliases",
    "load_cache_plugin",
]
