from __future__ import annotations

import time
from typing import Any, Optional, Tuple

from dnslib import RCODE, DNSRecord

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
          - max_size: Maximum number of cached DNS responses (default 65536;
            clamped to <= 65536).
          - pct_nxdomain: Float in [0, 1] describing what portion of max_size is
            reserved for NXDOMAIN responses (default 0.10).
          - eviction_policy: Eviction policy used when max_size is enforced
            (default 'lfu').

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

        max_size_cfg = config.get("max_size", 65536)
        try:
            max_size_val = int(max_size_cfg) if max_size_cfg is not None else 65536
        except Exception:
            max_size_val = 65536
        self.max_size = max(1, min(65536, int(max_size_val)))

        pct_cfg = config.get("pct_nxdomain", 0.10)
        try:
            pct = float(pct_cfg) if pct_cfg is not None else 0.10
        except Exception:
            pct = 0.10
        self.pct_nxdomain = max(0.0, min(1.0, float(pct)))

        eviction_policy_cfg = config.get("eviction_policy", "lfu")
        self.eviction_policy = (
            str(eviction_policy_cfg or "lfu").strip().lower() or "lfu"
        )

        # Reserve a portion of max_size for NXDOMAIN caching to avoid negative
        # cache entries evicting positive ones too aggressively.
        nxdomain_budget = int(round(self.max_size * self.pct_nxdomain))
        nxdomain_budget = max(0, min(self.max_size - 1, int(nxdomain_budget)))
        self.nxdomain_budget = int(nxdomain_budget)
        self.positive_budget = int(self.max_size - self.nxdomain_budget)

        self._cache = FoghornTTLCache(
            maxsize=self.positive_budget,
            eviction_policy=self.eviction_policy,
        )
        self._cache_nxdomain: FoghornTTLCache | None = None
        if self.nxdomain_budget > 0:
            self._cache_nxdomain = FoghornTTLCache(
                maxsize=self.nxdomain_budget,
                eviction_policy=self.eviction_policy,
            )

    @staticmethod
    def _is_nxdomain_wire(value: object) -> bool:
        """Brief: Determine whether a cached value is an NXDOMAIN DNS response.

        Inputs:
          - value: Cached payload; expected to be wire-format bytes for DNS
            response caching.

        Outputs:
          - bool: True when value parses as a DNS response with RCODE.NXDOMAIN.

        Notes:
          - Best-effort only: parse failures return False.
        """

        if not isinstance(value, (bytes, bytearray, memoryview)):
            return False
        try:
            msg = DNSRecord.parse(bytes(value))
            return int(getattr(getattr(msg, "header", None), "rcode", -1)) == int(
                RCODE.NXDOMAIN
            )
        except Exception:
            return False

    @staticmethod
    def _delete_from_foghorn_ttl(cache: FoghornTTLCache, key: Tuple[str, int]) -> None:
        """Brief: Best-effort delete from a FoghornTTLCache (including metadata).

        Inputs:
          - cache: FoghornTTLCache instance.
          - key: Cache key tuple (qname, qtype).

        Outputs:
          - None.
        """

        try:
            ns_key = getattr(cache, "_ns_key", lambda k: k)(key)
            lock = getattr(cache, "_lock", None)
            store = getattr(cache, "_store", None)
            ttls = getattr(cache, "_ttls", None)
            last_access = getattr(cache, "_last_access", None)
            hit_counts = getattr(cache, "_hit_counts", None)
            insert_index = getattr(cache, "_insert_index", None)
        except Exception:
            return

        if not isinstance(store, dict):
            return

        if lock is not None:
            try:
                with lock:
                    store.pop(ns_key, None)
                    if isinstance(ttls, dict):
                        ttls.pop(ns_key, None)
                    if isinstance(last_access, dict):
                        last_access.pop(ns_key, None)
                    if isinstance(hit_counts, dict):
                        hit_counts.pop(ns_key, None)
                    if isinstance(insert_index, dict):
                        insert_index.pop(ns_key, None)
            except Exception:
                return
        else:
            try:
                store.pop(ns_key, None)
                if isinstance(ttls, dict):
                    ttls.pop(ns_key, None)
                if isinstance(last_access, dict):
                    last_access.pop(ns_key, None)
                if isinstance(hit_counts, dict):
                    hit_counts.pop(ns_key, None)
                if isinstance(insert_index, dict):
                    insert_index.pop(ns_key, None)
            except Exception:
                return

    def get(self, key: Tuple[str, int]) -> Any | None:
        """Brief: Return cached value when present.

        Inputs:
          - key: Tuple[str, int] cache key.

        Outputs:
          - Any | None: Cached value, or None.
        """

        val = self._cache.get(key)
        if val is not None:
            return val
        if self._cache_nxdomain is not None:
            return self._cache_nxdomain.get(key)
        return None

    def get_with_meta(
        self, key: Tuple[str, int]
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Return cached value plus seconds_remaining and original TTL.

        Inputs:
          - key: Tuple[str, int] cache key.

        Outputs:
          - (value_or_None, seconds_remaining_or_None, original_ttl_or_None)
        """

        val, remaining, ttl = self._cache.get_with_meta(key)
        if val is not None:
            return val, remaining, ttl
        if self._cache_nxdomain is not None:
            return self._cache_nxdomain.get_with_meta(key)
        return None, None, None

    def set(self, key: Tuple[str, int], ttl: int, value: Any) -> None:
        """Brief: Store a cached value.

        Inputs:
          - key: Tuple[str, int] cache key.
          - ttl: int time-to-live seconds.
          - value: cached payload.

        Outputs:
          - None.
        """

        is_nxdomain = self._is_nxdomain_wire(value)

        # Keep partitions mutually exclusive.
        if is_nxdomain and self._cache_nxdomain is not None:
            self._delete_from_foghorn_ttl(self._cache, key)
            self._cache_nxdomain.set(key, ttl, value)
            return

        if self._cache_nxdomain is not None:
            self._delete_from_foghorn_ttl(self._cache_nxdomain, key)
        self._cache.set(key, ttl, value)

    def purge(self) -> int:
        """Brief: Purge expired items from the cache.

        Inputs:
          - None.

        Outputs:
          - int: Number of removed entries.
        """

        removed = int(self._cache.purge_expired())
        if self._cache_nxdomain is not None:
            removed += int(self._cache_nxdomain.purge_expired())
        return int(removed)

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

        nxdomain_total = 0
        nxdomain_live = 0
        nxdomain_expired = 0
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

        # Optional NXDOMAIN partition.
        if self._cache_nxdomain is not None:
            try:
                nx_store = getattr(self._cache_nxdomain, "_store", {}) or {}
                nx_lock = getattr(self._cache_nxdomain, "_lock", None)
            except Exception:
                nx_store = {}
                nx_lock = None

            if nx_lock is not None:
                try:
                    with nx_lock:
                        (
                            nxdomain_total,
                            nxdomain_live,
                            nxdomain_expired,
                        ) = _compute_counts(
                            nx_store
                        )  # type: ignore[arg-type]
                except Exception:
                    nxdomain_total = nxdomain_live = nxdomain_expired = 0
            else:
                nxdomain_total, nxdomain_live, nxdomain_expired = _compute_counts(nx_store)  # type: ignore[arg-type]

        # Global counters from the primary cache backend, when available.
        calls_total = getattr(self._cache, "calls_total", None)
        cache_hits = getattr(self._cache, "cache_hits", None)
        cache_misses = getattr(self._cache, "cache_misses", None)

        # Derive a backend label for the primary DNS cache from the concrete
        # backing store type so the admin UI can distinguish FoghornTTL from
        # other in-memory backends.
        try:
            cache_type = type(self._cache)
            backend_label = getattr(cache_type, "__name__", "in_memory")
            if backend_label == "FoghornTTLCache":
                backend_label = "FoghornTTL"
        except Exception:  # pragma: nocover - defensive type introspection
            backend_label = "in_memory"

        summary: dict[str, object] = {
            "backend": str(backend_label),
            "namespace": getattr(self._cache, "namespace", None) or "default",
            "total_entries": int(total_entries + nxdomain_total),
            "live_entries": int(live_entries + nxdomain_live),
            "expired_entries": int(expired_entries + nxdomain_expired),
            "min_cache_ttl": int(self.min_cache_ttl),
            "max_size": int(self.max_size),
            "eviction_policy": str(self.eviction_policy),
            "pct_nxdomain": float(self.pct_nxdomain),
            "positive_budget": int(self.positive_budget),
            "nxdomain_budget": int(self.nxdomain_budget),
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
            """Brief: Summarize an in-memory per-entry cache used by plugins.

            Inputs:
              - label: Human-friendly cache label.
              - cache_obj: Cache instance exposing _store and _lock.

            Outputs:
              - Mapping with label/backend/entries counts.
            """

            try:
                inner_store = getattr(cache_obj, "_store", None)
                inner_lock = getattr(cache_obj, "_lock", None)
            except Exception:
                inner_store = None
                inner_lock = None

            entries_total = 0
            entries_live = 0
            entries_expired: object = 0
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

            if isinstance(inner_store, dict):
                # FoghornTTLCache-style backend with explicit expiry metadata.
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
            else:
                # Generic mapping-style cache (for example, an LRUCache) where
                # only current size is known. Treat all entries as live.
                try:
                    entries_total = int(len(cache_obj))  # type: ignore[arg-type]
                except Exception:
                    entries_total = 0
                entries_live = entries_total
                # Non-TTL caches do not expose expired counts; leave expired blank
                # in the admin UI by using a non-int sentinel.
                entries_expired = None

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

            # Derive a backend label from the concrete cache type so the admin
            # UI reflects whether this is a FoghornTTLCache, LRUCache, etc.
            try:
                cache_type = type(cache_obj)
                backend_label = getattr(cache_type, "__name__", "in_memory_ttl")
            except Exception:  # pragma: nocover - defensive type introspection
                backend_label = "in_memory_ttl"

            row: dict[str, object] = {
                "label": str(label),
                "backend": str(backend_label),
                "entries": int(entries_total),
                "live_entries": int(entries_live),
                # When entries_expired is not an int (for example, for non-TTL
                # caches such as LRU), omit a numeric expired count so the
                # "Expired" column renders blank in the admin UI.
                "expired_entries": (
                    int(entries_expired) if isinstance(entries_expired, int) else None
                ),
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

        if self._cache_nxdomain is not None:
            # Snapshot the NXDOMAIN partition as a separate row.
            nxdomain_row = _summarize_foghorn_ttl(
                "dns_cache (nxdomain)",
                self._cache_nxdomain,
            )
            caches.append(nxdomain_row)

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
                        {"key": "max_size", "label": "Max size"},
                        {"key": "eviction_policy", "label": "Eviction"},
                        {"key": "pct_nxdomain", "label": "NXDOMAIN %"},
                        {"key": "positive_budget", "label": "Positive budget"},
                        {"key": "nxdomain_budget", "label": "NXDOMAIN budget"},
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
