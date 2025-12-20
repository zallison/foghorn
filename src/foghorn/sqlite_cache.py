from __future__ import annotations

"""Thin compatibility wrapper for the SQLite TTL cache backend.

This module exists primarily so tests and older callers can import
``foghorn.sqlite_cache`` and monkeypatch its ``time`` module while the real
implementation lives in ``foghorn.cache_backends.sqlite_ttl``.

Exports:
  - SQLite3TTLCache: re-exported from ``cache_backends.sqlite_ttl``.
  - time: stdlib time module, shared with the backend so monkeypatching
    ``foghorn.sqlite_cache.time.time`` also affects expiry logic.
"""

import time  # re-exported for tests that monkeypatch foghorn.sqlite_cache.time  # noqa: E402

from .cache_backends.sqlite_ttl import SQLite3TTLCache  # noqa: E402

__all__ = ["SQLite3TTLCache", "time"]
