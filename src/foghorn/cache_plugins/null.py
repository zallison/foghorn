"""Backwards-compatible alias for the NullCache plugin.

Brief:
  Historically the null cache implementation lived in `foghorn.cache_plugins.null`.
  The implementation is now in `foghorn.cache_plugins.none`, but we keep this
  module so existing imports (and older config) continue to work.

Inputs:
  - None

Outputs:
  - Exposes NullCache
"""

from __future__ import annotations

from .none import NullCache

__all__ = ["NullCache"]
