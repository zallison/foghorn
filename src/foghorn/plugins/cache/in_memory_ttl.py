from __future__ import annotations

import time
from typing import Any, Optional, Tuple

from foghorn.plugins.cache.backends.foghorn_ttl import FoghornTTLCache

from .base import CachePlugin, cache_aliases


@cache_aliases("in_memory_ttl", "memory", "ttl")
class InMemoryTTLCache(CachePlugin):
    """In-memory TTL cache plugin.

    Brief:
      Default CachePlugin implementation backed by `foghorn.plugins.cache.backends.foghorn_ttl.FoghornTTLCache`.

    Inputs:
      - **config: Optional implementation-specific config.
          - min_cache_ttl: Non-negative int seconds. This is the cache expiry
            floor applied by the resolver when caching responses.

    Outputs:
      - InMemoryTTLCache instance.
    """

    def __init__(self, **config: object) -> None:
        """Brief: Initialize an in-memory TTL cache.

        Inputs:
          - **config:
              - min_cache_ttl: Non-negative int seconds cache TTL floor.

        Outputs:
          - None.
        """

        self.min_cache_ttl = max(0, int(config.get("min_cache_ttl", 0) or 0))
        self._cache = FoghornTTLCache()

    def get(self, key: Tuple[str, int]) -> Any | None:
        """Brief: Return cached value when present.

        Inputs:
          - key: Tuple[str, int] cache key.

        Outputs:
          - Any | None: Cached value, or None.
        """

        return self._cache.get(key)

    def get_with_meta(
        self, key: Tuple[str, int]
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Return cached value plus seconds_remaining and original TTL.

        Inputs:
          - key: Tuple[str, int] cache key.

        Outputs:
          - (value_or_None, seconds_remaining_or_None, original_ttl_or_None)
        """

        return self._cache.get_with_meta(key)

    def set(self, key: Tuple[str, int], ttl: int, value: Any) -> None:
        """Brief: Store a cached value.

        Inputs:
          - key: Tuple[str, int] cache key.
          - ttl: int time-to-live seconds.
          - value: cached payload.

        Outputs:
          - None.
        """

        self._cache.set(key, ttl, value)

    def purge(self) -> int:
        """Brief: Purge expired items from the cache.

        Inputs:
          - None.

        Outputs:
          - int: Number of removed entries.
        """

        return int(self._cache.purge_expired())

    def get_http_snapshot(self) -> dict[str, object]:
        """Brief: Summarize current in-memory cache state for the admin web UI.

        Inputs:
          - None (uses the underlying FoghornTTLCache backing store and
            well-known caches from configured plugins).

        Outputs:
          - dict with keys:
              * summary: High-level statistics for the primary DNS cache.
              * caches: List of per-cache summaries for well-known caches.
        """

        total_entries = 0
        live_entries = 0
        expired_entries = 0
        now_ts = time.time()

        # FoghornTTLCache stores entries in a private _store mapping of
        # (key, (expiry, value)). We introspect this structure under the cache
        # lock to compute lightweight statistics for the admin UI.
        try:
            store = getattr(self._cache, "_store", {}) or {}
            lock = getattr(self._cache, "_lock", None)
        except Exception:
            store = {}
            lock = None

        def _compute_counts(
            mapping: dict[tuple[object, object], tuple[float, Any]],
        ) -> tuple[int, int, int]:
            total = 0
            live = 0
            expired = 0
            for _k, (expiry, _value) in list(mapping.items()):
                total += 1
                try:
                    exp = float(expiry)
                except Exception:
                    # Treat malformed entries as expired for counting purposes.
                    expired += 1
                    continue
                if exp <= now_ts:
                    expired += 1
                else:
                    live += 1
            return total, live, expired

        if hasattr(self._cache, "_lock") and lock is not None:
            try:
                with lock:
                    total_entries, live_entries, expired_entries = _compute_counts(store)  # type: ignore[arg-type]
            except Exception:
                total_entries = live_entries = expired_entries = 0
        else:
            total_entries, live_entries, expired_entries = _compute_counts(store)  # type: ignore[arg-type]

        # Global counters from the primary cache backend, when available.
        calls_total = getattr(self._cache, "calls_total", None)
        cache_hits = getattr(self._cache, "cache_hits", None)
        cache_misses = getattr(self._cache, "cache_misses", None)

        summary: dict[str, object] = {
            "backend": "in_memory",
            "namespace": getattr(self._cache, "namespace", None) or "default",
            "total_entries": int(total_entries),
            "live_entries": int(live_entries),
            "expired_entries": int(expired_entries),
            "min_cache_ttl": int(self.min_cache_ttl),
        }
        if isinstance(calls_total, int):
            summary["calls_total"] = int(calls_total)
        if isinstance(cache_hits, int):
            summary["cache_hits"] = int(cache_hits)
        if isinstance(cache_misses, int):
            summary["cache_misses"] = int(cache_misses)

        # Build a static list of caches to summarize. Today this includes the
        # primary DNS cache plus per-plugin targeting caches when available.
        caches: list[dict[str, object]] = []

        def _summarize_foghorn_ttl(label: str, cache_obj: object) -> dict[str, object]:
            """Brief: Summarize a FoghornTTLCache-style in-memory cache.

            Inputs:
              - label: Human-friendly cache label.
              - cache_obj: Cache instance exposing _store and _lock.

            Outputs:
              - Mapping with label/backend/entries counts.
            """

            try:
                inner_store = getattr(cache_obj, "_store", {}) or {}
                inner_lock = getattr(cache_obj, "_lock", None)
            except Exception:
                inner_store = {}
                inner_lock = None

            entries_total = 0
            entries_live = 0
            entries_expired = 0
            calls_total_local: object = None
            cache_hits_local: object = None
            cache_misses_local: object = None
            # Pull best-effort counters from the backend when present.
            try:
                calls_total_local = getattr(cache_obj, "calls_total", None)
                cache_hits_local = getattr(cache_obj, "cache_hits", None)
                cache_misses_local = getattr(cache_obj, "cache_misses", None)
            except Exception:  # pragma: no cover - defensive only
                calls_total_local = cache_hits_local = cache_misses_local = None

            if inner_lock is not None:
                try:
                    with inner_lock:
                        (
                            entries_total,
                            entries_live,
                            entries_expired,
                        ) = _compute_counts(
                            inner_store
                        )  # type: ignore[arg-type]
                except Exception:
                    entries_total = entries_live = entries_expired = 0
            else:
                (
                    entries_total,
                    entries_live,
                    entries_expired,
                ) = _compute_counts(
                    inner_store
                )  # type: ignore[arg-type]

            # Compute hit percentage when we have both hit/miss counters.
            hit_pct_local: object = None
            try:
                if isinstance(cache_hits_local, int) and isinstance(
                    cache_misses_local, int
                ):
                    total = cache_hits_local + cache_misses_local
                    if total > 0:
                        hit_pct_local = round((cache_hits_local / total) * 100.0, 1)
            except Exception:
                hit_pct_local = None

            row: dict[str, object] = {
                "label": str(label),
                "backend": "in_memory_ttl",
                "entries": int(entries_total),
                "live_entries": int(entries_live),
                "expired_entries": int(entries_expired),
                "hit_pct": hit_pct_local,
            }
            if isinstance(calls_total_local, int):
                row["calls_total"] = int(calls_total_local)
            if isinstance(cache_hits_local, int):
                row["cache_hits"] = int(cache_hits_local)
            if isinstance(cache_misses_local, int):
                row["cache_misses"] = int(cache_misses_local)
            return row

        # Primary DNS cache (this plugin instance)
        # Compute hit percentage for the primary cache when counters are present.
        hit_pct_primary: object = None
        try:
            cache_hits_summary = summary.get("cache_hits")
            cache_misses_summary = summary.get("cache_misses")
            if isinstance(cache_hits_summary, int) and isinstance(
                cache_misses_summary, int
            ):
                total_primary = cache_hits_summary + cache_misses_summary
                if total_primary > 0:
                    hit_pct_primary = round(
                        (cache_hits_summary / total_primary) * 100.0, 1
                    )
        except Exception:
            hit_pct_primary = None

        primary_row: dict[str, object] = {
            "label": "dns_cache (primary)",
            "backend": summary["backend"],
            "entries": summary["total_entries"],
            "live_entries": summary["live_entries"],
            "expired_entries": summary["expired_entries"],
            "hit_pct": hit_pct_primary,
        }
        for key in ("calls_total", "cache_hits", "cache_misses"):
            if key in summary:
                primary_row[key] = summary[key]
        caches.append(primary_row)

        # Per-plugin target caches (BasePlugin._targets_cache) when available via
        # the UDP handler's plugin list.
        try:
            from foghorn.servers.udp_server import DNSUDPHandler  # type: ignore[import]

            plugins_list = getattr(DNSUDPHandler, "plugins", []) or []
        except Exception:
            plugins_list = []

        for plugin in plugins_list:
            try:
                cache_obj = getattr(plugin, "_targets_cache", None)
            except Exception:
                cache_obj = None
            if cache_obj is None:
                continue
            try:
                name = getattr(plugin, "name", None) or plugin.__class__.__name__
            except Exception:
                name = plugin.__class__.__name__
            label = f"plugin_targets:{name}"
            caches.append(_summarize_foghorn_ttl(label, cache_obj))

        # Decorated cache functions registered via registered_cached().
        try:
            from foghorn.utils.register_caches import get_registered_cached

            decorated = get_registered_cached()
        except Exception:
            decorated = []

        decorated_rows: list[dict[str, object]] = []
        for entry in decorated:
            try:
                module = str(entry.get("module", ""))
                name = str(entry.get("name", ""))
                cache_kwargs = entry.get("cache_kwargs", {}) or {}
                # Prefer normalized ttl/maxsize recorded by the registry; fall
                # back to any explicit decorator kwargs if present.
                ttl_val = entry.get("ttl") or cache_kwargs.get("ttl")
                maxsize_val = entry.get("maxsize") or cache_kwargs.get("maxsize")
                size_current = entry.get("size_current")
                calls_total = entry.get("calls_total")
                cache_hits = entry.get("cache_hits")
                cache_misses = entry.get("cache_misses")
            except Exception:
                module = ""
                name = ""
                ttl_val = None
                maxsize_val = None
                size_current = None
                calls_total = None
                cache_hits = None
                cache_misses = None

            if not module or not name:
                continue

            # Compute hit percentage when we have both hit/miss counters.
            hit_pct: object = None
            try:
                if isinstance(cache_hits, int) and isinstance(cache_misses, int):
                    total = cache_hits + cache_misses
                    if total > 0:
                        hit_pct = round((cache_hits / total) * 100.0, 1)
            except Exception:
                hit_pct = None

            decorated_rows.append(
                {
                    "module": module,
                    "name": name,
                    "ttl": int(ttl_val) if isinstance(ttl_val, int) else None,
                    "backend": entry.get("backend") or "ttlcache",
                    "maxsize": (
                        int(maxsize_val) if isinstance(maxsize_val, int) else None
                    ),
                    "size_current": (
                        int(size_current) if isinstance(size_current, int) else None
                    ),
                    "calls_total": (
                        int(calls_total) if isinstance(calls_total, int) else None
                    ),
                    "cache_hits": (
                        int(cache_hits) if isinstance(cache_hits, int) else None
                    ),
                    "cache_misses": (
                        int(cache_misses) if isinstance(cache_misses, int) else None
                    ),
                    "hit_pct": hit_pct,
                }
            )

        return {"summary": summary, "caches": caches, "decorated": decorated_rows}

    def get_admin_ui_descriptor(self) -> dict[str, object]:
        """Brief: Describe in-memory cache admin UI using a generic snapshot layout.

        Inputs:
          - None (uses the active DNS cache instance when configured).

        Outputs:
          - dict with keys compatible with plugin-based admin descriptors.
        """

        plugin_name = getattr(self, "name", "cache") or "cache"
        base_title = "Cache"
        title = f"{base_title} ({plugin_name})" if plugin_name else base_title

        snapshot_url = "/api/v1/cache"
        layout: dict[str, object] = {
            "sections": [
                {
                    "id": "summary",
                    "title": "Summary",
                    "type": "kv",
                    "path": "summary",
                    "align": "right",
                    "rows": [
                        {"key": "backend", "label": "Backend"},
                        {"key": "namespace", "label": "Namespace"},
                        {"key": "min_cache_ttl", "label": "Min cache TTL (s)"},
                        {"key": "total_entries", "label": "Total entries"},
                        {"key": "live_entries", "label": "Live entries"},
                        {"key": "expired_entries", "label": "Expired entries"},
                        {"key": "calls_total", "label": "Calls"},
                        {"key": "cache_hits", "label": "Hits"},
                        {"key": "cache_misses", "label": "Misses"},
                    ],
                },
                {
                    "id": "caches",
                    "title": "DNS and plugin target caches",
                    "type": "table",
                    "path": "caches",
                    "columns": [
                        {"key": "label", "label": "Cache"},
                        {"key": "backend", "label": "Backend"},
                        {"key": "entries", "label": "Entries", "align": "right"},
                        {"key": "live_entries", "label": "Live", "align": "right"},
                        {
                            "key": "expired_entries",
                            "label": "Expired",
                            "align": "right",
                        },
                        {"key": "calls_total", "label": "Calls", "align": "right"},
                        {"key": "cache_hits", "label": "Hits", "align": "right"},
                        {"key": "cache_misses", "label": "Misses", "align": "right"},
                        {"key": "hit_pct", "label": "Hit %", "align": "right"},
                    ],
                },
                {
                    "id": "decorated",
                    "title": "Decorated caches",
                    "type": "table",
                    "path": "decorated",
                    "sort": "by_calls",
                    "filters": [
                        {"id": "hide_zero_calls", "label": "Hide zero-call caches"},
                        {"id": "hide_zero_hits", "label": "Hide zero-hit caches"},
                    ],
                    "columns": [
                        {"key": "module", "label": "Module"},
                        {"key": "name", "label": "Function"},
                        {"key": "backend", "label": "Backend"},
                        {"key": "ttl", "label": "TTL (s)", "align": "right"},
                        {"key": "maxsize", "label": "Max size", "align": "right"},
                        {"key": "size_current", "label": "Size", "align": "right"},
                        {"key": "calls_total", "label": "Calls", "align": "right"},
                        {"key": "cache_hits", "label": "Hits", "align": "right"},
                        {"key": "cache_misses", "label": "Misses", "align": "right"},
                        {"key": "hit_pct", "label": "Hit %", "align": "right"},
                    ],
                },
            ]
        }

        return {
            "name": str(plugin_name),
            "title": str(title),
            "order": 40,
            "kind": "cache_memory",
            "endpoints": {"snapshot": snapshot_url},
            "layout": layout,
        }
