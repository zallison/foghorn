from __future__ import annotations

import os
import time
from typing import Any, Optional, Tuple

from foghorn.plugins.cache.backends.sqlite_ttl import SQLite3TTLCache

from .base import CachePlugin, cache_aliases


@cache_aliases("sqlite3", "sqlite", "sqlite_cache", "sqlite3_cache")
class SQLite3Cache(CachePlugin):
    """SQLite3-backed DNS cache plugin.

    Brief:
      Persistent CachePlugin implementation for DNS caching. Internally this
      delegates storage and TTL behavior to `foghorn.plugins.cache.backends.sqlite_ttl.SQLite3TTLCache`
      so other subsystems (plugins, recursive resolver helpers) can reuse the
      same sqlite-backed TTL cache.

    Inputs:
      - **config:
          - db_path (str): Path to sqlite3 DB file.
          - path (str): Alias for db_path.
          - namespace (str): Namespace/table name (default 'dns_cache').
          - table (str): Backward-compatible alias for namespace.
          - min_cache_ttl (int): Optional cache TTL floor used by the resolver.
          - journal_mode (str): SQLite journal mode; defaults to 'WAL'.

    Outputs:
      - SQLite3Cache instance.

    Example:
      cache:
        module: sqlite3
        config:
          db_path: ./config/var/dns_cache.db
          min_cache_ttl: 60
    """

    def __init__(self, **config: object) -> None:
        """Brief: Initialize the sqlite3 cache plugin.

        Inputs:
          - **config:
              - db_path/path: sqlite3 database file path.
              - namespace: Optional namespace/table name.
              - table: Backward-compatible alias for namespace.
              - min_cache_ttl: Optional cache TTL floor used by resolver.
              - journal_mode: SQLite journal mode (e.g., 'WAL').

        Outputs:
          - None.
        """

        cfg_db_path = config.get("db_path")
        used_default_path = False
        if not isinstance(cfg_db_path, str) or not cfg_db_path.strip():
            cfg_db_path = config.get("path")
        if isinstance(cfg_db_path, str) and cfg_db_path.strip():
            db_path = cfg_db_path.strip()
        else:  # pragma: nocover default path only used in production
            db_path = "./config/var/dns_cache.db"
            used_default_path = True

        resolved_db_path = os.path.abspath(os.path.expanduser(str(db_path)))
        self.db_path: str = resolved_db_path
        self.min_cache_ttl: int = max(0, int(config.get("min_cache_ttl", 0) or 0))

        namespace = config.get("namespace", "dns_cache")
        if (
            not isinstance(namespace, str) or not namespace.strip()
        ):  # pragma: nocover validated by config layer
            raise ValueError(
                "sqlite cache config requires a non-empty 'namespace' field"
            )
        journal_mode = config.get("journal_mode", "WAL")

        backend_db_path = resolved_db_path
        if used_default_path:
            dir_path = os.path.dirname(resolved_db_path) or "."
            try:
                # When the default path directory is not writable (e.g. owned by
                # another user), fall back to an in-memory DB so the plugin
                # remains usable in read-only environments.
                if not os.access(dir_path, os.W_OK | os.X_OK):
                    backend_db_path = ":memory:"
            except Exception:  # pragma: nocover - defensive permission check
                pass

        self._cache = SQLite3TTLCache(
            backend_db_path,
            namespace=str(namespace or "dns_cache"),
            journal_mode=str(journal_mode or "WAL"),
            create_dir=True,
        )

    def get_http_snapshot(self) -> dict[str, object]:
        """Brief: Summarize current SQLite3 cache state for the admin web UI.

        Inputs:
          - None (uses the underlying SQLite3TTLCache connection and
            well-known caches from configured plugins).

        Outputs:
          - dict with keys:
              * summary: High-level statistics for the primary DNS cache.
              * caches: List of per-cache summaries for well-known caches.
        """

        total_entries = 0
        live_entries = 0
        expired_entries = 0
        now_ts: float | None = None

        try:
            conn = getattr(self._cache, "_conn", None)
            namespace = getattr(self._cache, "namespace", "ttl_cache")
            if conn is not None:
                cur = conn.cursor()
                cur.execute(f"SELECT COUNT(*) FROM {namespace}")
                row = cur.fetchone()
                total_entries = int(row[0]) if row and row[0] is not None else 0
                now_ts = time.time()
                cur.execute(
                    f"SELECT COUNT(*) FROM {namespace} WHERE expiry <= ?",
                    (float(now_ts),),
                )
                row2 = cur.fetchone()
                expired_entries = int(row2[0]) if row2 and row2[0] is not None else 0
        except (
            Exception
        ):  # pragma: nocover - defensive snapshot query handling; zero-fill on any failure
            # Best-effort only; fallback to zeros on any failure.
            total_entries = max(total_entries, 0)
            expired_entries = max(expired_entries, 0)

        live_entries = max(0, total_entries - expired_entries)

        db_size_bytes = 0
        try:
            if os.path.isfile(self.db_path):
                db_size_bytes = max(0, int(os.path.getsize(self.db_path)))
        except Exception:  # pragma: nocover - filesystem errors treated as size=0
            db_size_bytes = 0

        # Global counters from the primary cache backend, when available.
        calls_total = getattr(self._cache, "calls_total", None)
        cache_hits = getattr(self._cache, "cache_hits", None)
        cache_misses = getattr(self._cache, "cache_misses", None)

        summary: dict[str, object] = {
            "db_path": self.db_path,
            "namespace": getattr(self._cache, "namespace", "dns_cache"),
            "journal_mode": getattr(self._cache, "journal_mode", "WAL"),
            "total_entries": int(total_entries),
            "live_entries": int(live_entries),
            "expired_entries": int(expired_entries),
            "db_size_bytes": int(db_size_bytes),
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
            current_ts = time.time()
            calls_total_local: object = None
            cache_hits_local: object = None
            cache_misses_local: object = None

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
                        expired += 1
                        continue
                    if exp <= current_ts:
                        expired += 1
                    else:
                        live += 1
                return total, live, expired

            # Pull best-effort counters from the backend when present.
            try:
                calls_total_local = getattr(cache_obj, "calls_total", None)
                cache_hits_local = getattr(cache_obj, "cache_hits", None)
                cache_misses_local = getattr(cache_obj, "cache_misses", None)
            except (
                Exception
            ):  # pragma: nocover - defensive only; cache_obj may not expose counters
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
                    total_local = cache_hits_local + cache_misses_local
                    if total_local > 0:
                        hit_pct_local = round(
                            (cache_hits_local / total_local) * 100.0, 1
                        )
            except Exception:  # pragma: nocover - defensive percentage computation
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
        except Exception:  # pragma: nocover - defensive percentage computation
            hit_pct_primary = None

        primary_row: dict[str, object] = {
            "label": "dns_cache (primary)",
            "backend": "sqlite3",
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
        except (
            Exception
        ):  # pragma: nocover - import/attribute errors leave plugins_list empty
            plugins_list = []

        for plugin in plugins_list:
            try:
                cache_obj = getattr(plugin, "_targets_cache", None)
            except (
                Exception
            ):  # pragma: nocover - defensive getattr on plugin._targets_cache
                cache_obj = None
            if cache_obj is None:
                continue
            try:
                name = getattr(plugin, "name", None) or plugin.__class__.__name__
            except Exception:  # pragma: nocover - defensive getattr on plugin.name
                name = plugin.__class__.__name__
            label = f"plugin_targets:{name}"
            caches.append(_summarize_foghorn_ttl(label, cache_obj))

        # Decorated cache functions registered via registered_cached().
        try:
            from foghorn.utils.register_caches import get_registered_cached

            decorated = get_registered_cached()
        except Exception:  # pragma: nocover - registry import failure is non-critical
            decorated = []

        decorated_rows: list[dict[str, object]] = []
        for entry in decorated:
            try:
                module = str(entry.get("module", ""))
                name = str(entry.get("name", ""))
                cache_kwargs = entry.get("cache_kwargs", {}) or {}
                ttl_val = entry.get("ttl") or cache_kwargs.get("ttl")
                maxsize_val = entry.get("maxsize") or cache_kwargs.get("maxsize")
                size_current = entry.get("size_current")
                calls_total = entry.get("calls_total")
                cache_hits = entry.get("cache_hits")
                cache_misses = entry.get("cache_misses")
            except (
                Exception
            ):  # pragma: nocover - defensive against malformed registry entries
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

            hit_pct: object = None
            try:
                if isinstance(cache_hits, int) and isinstance(cache_misses, int):
                    total = cache_hits + cache_misses
                    if total > 0:
                        hit_pct = round((cache_hits / total) * 100.0, 1)
            except Exception:  # pragma: nocover - defensive percentage computation
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
        """Brief: Describe SQLite cache admin UI using a generic snapshot layout.

        Inputs:
          - None (uses the global DNS cache instance when configured).

        Outputs:
          - dict with keys compatible with plugin-based admin descriptors.
        """

        # Cache plugins do not participate in the plugin ordering by name, so we
        # expose a single logical tab named "cache".
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
                        {"key": "db_path", "label": "Database path"},
                        {"key": "namespace", "label": "Namespace"},
                        {"key": "journal_mode", "label": "Journal mode"},
                        {"key": "total_entries", "label": "Total entries"},
                        {"key": "live_entries", "label": "Live entries"},
                        {"key": "expired_entries", "label": "Expired entries"},
                        {"key": "db_size_bytes", "label": "DB size (bytes)"},
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
            "kind": "cache_sqlite",
            "endpoints": {"snapshot": snapshot_url},
            "layout": layout,
        }

    def get(self, key: Tuple[str, int]) -> Any | None:
        """Brief: Lookup a cached entry enforcing expiry.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - Any | None: Cached value if present and not expired; otherwise None.
        """

        return self._cache.get(key)

    def get_with_meta(
        self, key: Tuple[str, int]
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Lookup a cached entry and return metadata.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - (value_or_None, seconds_remaining_or_None, original_ttl_or_None)
        """

        return self._cache.get_with_meta(key)

    def set(self, key: Tuple[str, int], ttl: int, value: Any) -> None:
        """Brief: Store a value under key with a TTL.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).
          - ttl: int time-to-live in seconds.
          - value: Cached value.

        Outputs:
          - None.
        """

        self._cache.set(key, ttl, value)

    def purge(self) -> int:
        """Brief: Purge expired entries.

        Inputs:
          - None.

        Outputs:
          - int: Number of entries removed (best-effort).
        """

        return int(self._cache.purge())

    def close(self) -> None:
        """Brief: Close underlying sqlite resources.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        try:
            self._cache.close()
        except (
            Exception
        ):  # pragma: nocover - defensive close during interpreter shutdown
            pass

    def __del__(self) -> None:
        try:
            self.close()
        except (
            Exception
        ):  # pragma: nocover - defensive __del__ during interpreter shutdown
            pass
