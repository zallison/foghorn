"""Shared business logic for the admin webserver.

This module contains framework-neutral helpers used by both:
- the FastAPI/uvicorn implementation (routes_*.py), and
- the threaded stdlib http.server fallback (threaded_handlers.py).

The functions here deliberately avoid importing FastAPI or http.server types.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from functools import cmp_to_key
from typing import Any, Dict, Iterable, List, Optional

from ...plugins.resolve.base import AdminPageSpec
from ...stats import StatsCollector
from ..udp_server import DNSUDPHandler
from .config_helpers import _ts_to_utc_iso


@dataclass(frozen=True)
class AdminLogicHttpError(Exception):
    """Brief: Error type for mapping logic failures to HTTP responses.

    Inputs:
      - status_code: HTTP status code that should be returned.
      - detail: Human-readable error message.

    Outputs:
      - An exception that can be caught by FastAPI/threaded glue code.

    Example:
      >>> raise AdminLogicHttpError(status_code=404, detail='not found')
    """

    status_code: int
    detail: str


def _get_store_from_collector(collector: StatsCollector | None) -> Any | None:
    """Brief: Return the stats store from a StatsCollector-like object.

    Inputs:
      - collector: StatsCollector instance (or None).

    Outputs:
      - The store object (typically StatsSQLiteStore) if present, else None.
    """

    if collector is None:
        return None
    return getattr(collector, "_store", None)


def build_query_log_payload(
    store: Any,
    *,
    client_ip: str | None,
    qtype: str | None,
    qname: str | None,
    rcode: str | None,
    start_ts: float | None,
    end_ts: float | None,
    page: int,
    page_size: int,
) -> Dict[str, Any]:
    """Brief: Build the query-log list payload from a store result.

    Inputs:
      - store: Stats store object that exposes select_query_log(**kwargs).
      - client_ip/qtype/qname/rcode: Optional filters.
      - start_ts/end_ts: Optional unix timestamps in seconds (UTC).
      - page: 1-indexed page number.
      - page_size: page size (already clamped).

    Outputs:
      - Dict with keys: total, page, page_size, total_pages, items.
        Each dict item with a 'ts' key is copied and gets a 'timestamp' field.
    """

    res = store.select_query_log(
        client_ip=client_ip,
        qtype=qtype,
        qname=qname,
        rcode=rcode,
        start_ts=start_ts,
        end_ts=end_ts,
        page=page,
        page_size=page_size,
    )

    items: list[Any] = []
    for item in res.get("items", []) or []:
        if isinstance(item, dict) and "ts" in item:
            out = dict(item)
            out["timestamp"] = _ts_to_utc_iso(float(out.get("ts") or 0.0))
            items.append(out)
        else:
            items.append(item)

    return {
        "total": res.get("total", 0),
        "page": res.get("page", page),
        "page_size": res.get("page_size", page_size),
        "total_pages": res.get("total_pages", 0),
        "items": items,
    }


def build_query_log_aggregate_payload(
    store: Any,
    *,
    start_dt: datetime,
    end_dt: datetime,
    interval_seconds: int,
    client_ip: str | None,
    qtype: str | None,
    qname: str | None,
    rcode: str | None,
    group_by: str | None,
) -> Dict[str, Any]:
    """Brief: Build query-log aggregate payload from a store result.

    Inputs:
      - store: Stats store object exposing aggregate_query_log_counts(**kwargs).
      - start_dt/end_dt: Datetimes representing the aggregate window.
      - interval_seconds: Bucket size in seconds.
      - client_ip/qtype/qname/rcode/group_by: Optional aggregation filters.

    Outputs:
      - Dict with keys: start, end, interval_seconds, items.
        Each dict item may get bucket_start/bucket_end ISO fields when *_ts keys exist.
    """

    res = store.aggregate_query_log_counts(
        start_ts=start_dt.timestamp(),
        end_ts=end_dt.timestamp(),
        interval_seconds=interval_seconds,
        client_ip=client_ip,
        qtype=qtype,
        qname=qname,
        rcode=rcode,
        group_by=group_by,
    )

    items: list[dict[str, Any]] = []
    for item in res.get("items", []) or []:
        if not isinstance(item, dict):
            continue
        out = dict(item)
        if "bucket_start_ts" in out:
            out["bucket_start"] = _ts_to_utc_iso(
                float(out.get("bucket_start_ts") or 0.0)
            )
        if "bucket_end_ts" in out:
            out["bucket_end"] = _ts_to_utc_iso(float(out.get("bucket_end_ts") or 0.0))
        items.append(out)

    return {
        "start": start_dt.isoformat().replace("+00:00", "Z"),
        "end": end_dt.isoformat().replace("+00:00", "Z"),
        "interval_seconds": int(interval_seconds),
        "items": items,
    }


def _resolve_path(obj: Any, path: str) -> Any:
    """Brief: Resolve a dotted path into a nested mapping/object.

    Inputs:
      - obj: Source object (typically a dict).
      - path: Dotted key path, e.g. "config.host".

    Outputs:
      - Resolved value or None.
    """

    if obj is None:
        return None
    if not path:
        return obj

    cur: Any = obj
    for part in str(path).split("."):
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            cur = getattr(cur, part, None)
    return cur


def build_table_page_payload(
    rows: Iterable[dict[str, Any]] | None,
    *,
    page: int = 1,
    page_size: int = 50,
    sort_key: str | None = None,
    sort_dir: str | None = None,
    search: str | None = None,
    hide_zero_calls: bool = False,  # noqa: ARG001
    hide_zero_hits: bool = False,  # noqa: ARG001
    show_down_services: bool = True,  # noqa: ARG001
    hide_hash_like: bool = False,  # noqa: ARG001
    default_sort_key: str | None = None,
    default_sort_dir: str = "asc",
) -> Dict[str, Any]:
    """Brief: Server-side pagination/sorting/search for list-of-dict tables.

    Inputs:
      - rows: Iterable of dict rows.
      - page: 1-indexed page.
      - page_size: Page size.
      - sort_key/sort_dir: Optional sort configuration.
      - search: Optional substring filter applied across stringified row values.
      - default_sort_key/default_sort_dir: Used when sort_key/dir are missing.
      - hide_* / show_* flags: Reserved for future table-specific filters.

    Outputs:
      - Dict with keys: total, page, page_size, total_pages, sort_key, sort_dir,
        search, items.
    """

    items: list[dict[str, Any]] = []
    for row in rows or []:
        if isinstance(row, dict):
            items.append(row)

    # Normalize paging.
    try:
        page_i = int(page)
    except Exception:
        page_i = 1
    if page_i < 1:
        page_i = 1

    try:
        page_size_i = int(page_size)
    except Exception:
        page_size_i = 50
    if page_size_i < 1:
        page_size_i = 1
    if page_size_i > 500:
        page_size_i = 500

    # Search filtering.
    q = (str(search).strip().lower() if search else "").strip()
    if q:
        filtered: list[dict[str, Any]] = []
        for row in items:
            try:
                values = row.values()
            except Exception:
                values = []
            matched = False
            for v in values:
                if v is None:
                    continue
                try:
                    if q in str(v).lower():
                        matched = True
                        break
                except Exception:
                    continue
            if matched:
                filtered.append(row)
        items = filtered

    # Sorting.
    key = (sort_key or default_sort_key or "").strip()
    direction = (sort_dir or default_sort_dir or "asc").strip().lower()
    if direction not in {"asc", "desc"}:
        direction = "asc"

    indexed: list[tuple[int, dict[str, Any]]] = list(enumerate(items))

    def _norm(v: Any) -> tuple[int, Any]:
        # 0: numeric/bool, 1: string/other, 2: None (always last)
        if v is None:
            return (2, 0)
        if isinstance(v, bool):
            return (0, int(v))
        if isinstance(v, (int, float)):
            return (0, float(v))
        if isinstance(v, str):
            try:
                return (0, float(v))
            except Exception:
                return (1, v.lower())
        return (1, str(v).lower())

    def _cmp(a: tuple[int, dict[str, Any]], b: tuple[int, dict[str, Any]]) -> int:
        ia, ra = a
        ib, rb = b
        if not key:
            return -1 if ia < ib else (1 if ia > ib else 0)
        va = _resolve_path(ra, key)
        vb = _resolve_path(rb, key)
        na = _norm(va)
        nb = _norm(vb)
        if na < nb:
            res = -1
        elif na > nb:
            res = 1
        else:
            res = 0
        if res == 0:
            res = -1 if ia < ib else (1 if ia > ib else 0)
        if direction == "desc":
            res = -res
        return res

    indexed.sort(key=cmp_to_key(_cmp))
    items = [row for _, row in indexed]

    total = len(items)
    total_pages = int(math.ceil(total / page_size_i)) if total else 0

    start = (page_i - 1) * page_size_i
    end = start + page_size_i
    page_items = items[start:end] if start < total else []

    return {
        "total": total,
        "page": page_i,
        "page_size": page_size_i,
        "total_pages": total_pages,
        "sort_key": key,
        "sort_dir": direction,
        "search": str(search) if search is not None else "",
        "items": page_items,
    }


def build_upstream_status_payload(
    config: Dict[str, Any] | None, *, now_ts: float | None = None
) -> Dict[str, Any]:
    """Brief: Build upstream status payload using DNSUDPHandler state.

    Inputs:
      - config: Full configuration mapping, used to read config['upstreams'].
      - now_ts: Optional unix timestamp (seconds) used for determining up/down.

    Outputs:
      - Dict with keys: strategy, max_concurrent, items.
        Items include configured upstreams plus health-only entries.
    """

    cfg = config or {}
    upstream_cfg = cfg.get("upstreams") or []
    if not isinstance(upstream_cfg, list):
        upstream_cfg = []

    health = getattr(DNSUDPHandler, "upstream_health", {}) or {}
    strategy = str(getattr(DNSUDPHandler, "upstream_strategy", "failover"))
    try:
        max_concurrent = int(getattr(DNSUDPHandler, "upstream_max_concurrent", 1) or 1)
    except Exception:  # pragma: nocover - defensive: runtime may provide invalid config
        max_concurrent = 1  # pragma: nocover - safe fallback
    if max_concurrent < 1:
        max_concurrent = 1

    import time as _time

    now = float(now_ts) if now_ts is not None else _time.time()
    items: list[Dict[str, Any]] = []
    seen_ids: set[str] = set()

    for up in upstream_cfg:
        if not isinstance(up, dict):
            continue
        up_id = DNSUDPHandler._upstream_id(up)
        if not up_id:
            continue
        seen_ids.add(up_id)
        entry = health.get(up_id) or {}
        try:
            fail_count = int(entry.get("fail_count", 0))
        except Exception:  # pragma: nocover - defensive: should already be int-ish
            fail_count = 0  # pragma: nocover - safe fallback
        try:
            down_until = float(entry.get("down_until", 0.0) or 0.0)
        except Exception:  # pragma: nocover - defensive: should already be float-ish
            down_until = 0.0  # pragma: nocover - safe fallback
        state = "down" if entry and down_until > now else "up"

        cfg_view: Dict[str, Any] = {}
        for key in ("host", "port", "transport", "url"):
            if key in up:
                cfg_view[key] = up[key]

        items.append(
            {
                "id": up_id,
                "config": cfg_view,
                "state": state,
                "fail_count": fail_count,
                "down_until": down_until if down_until else None,
            }
        )

    for up_id, entry in (health or {}).items():
        if up_id in seen_ids or not up_id:
            continue
        try:
            fail_count = int(entry.get("fail_count", 0))
        except Exception:  # pragma: nocover - defensive: should already be int-ish
            fail_count = 0  # pragma: nocover - safe fallback
        try:
            down_until = float(entry.get("down_until", 0.0) or 0.0)
        except Exception:  # pragma: nocover - defensive: should already be float-ish
            down_until = 0.0  # pragma: nocover - safe fallback
        state = "down" if down_until > now else "up"
        items.append(
            {
                "id": up_id,
                "config": {},
                "state": state,
                "fail_count": fail_count,
                "down_until": down_until if down_until else None,
            }
        )

    return {
        "strategy": strategy,
        "max_concurrent": max_concurrent,
        "items": items,
    }


def collect_admin_pages_for_response(plugins: Iterable[object]) -> list[dict[str, Any]]:
    """Brief: Collect plugin-provided admin pages into a JSON-friendly structure.

    Inputs:
      - plugins: Iterable of plugin instances.

    Outputs:
      - List of dicts with keys: plugin, slug, title, description, layout, kind.

    Notes:
      - Ignores plugins without a truthy 'name'.
      - Ignores page specs lacking slug/title.
    """

    pages: list[dict[str, Any]] = []
    for plugin in plugins or []:
        try:
            plugin_name = getattr(plugin, "name", None)
        except (
            Exception
        ):  # pragma: nocover - defensive against misbehaving plugin objects
            plugin_name = None  # pragma: nocover - defensive default
        if not plugin_name:
            continue

        get_pages = getattr(plugin, "get_admin_pages", None)
        if not callable(get_pages):
            continue

        try:
            specs = get_pages()
        except Exception:  # pragma: nocover - plugin code should not break admin UI
            continue  # pragma: nocover - best-effort: ignore plugin failures

        for spec in specs or []:
            slug = None
            title = None
            description = None
            layout = None
            kind = None
            try:
                if isinstance(spec, AdminPageSpec):
                    slug = spec.slug
                    title = spec.title
                    description = spec.description
                    layout = spec.layout or "one_column"
                    kind = spec.kind
                elif isinstance(spec, dict):
                    slug = spec.get("slug")
                    title = spec.get("title")
                    description = spec.get("description")
                    layout = spec.get("layout") or "one_column"
                    kind = spec.get("kind")
                else:
                    slug = getattr(spec, "slug", None)
                    title = getattr(spec, "title", None)
                    description = getattr(spec, "description", None)
                    layout = getattr(spec, "layout", "one_column")
                    kind = getattr(spec, "kind", None)
            except (
                Exception
            ):  # pragma: nocover - plugin page spec parsing is best-effort
                continue  # pragma: nocover - ignore malformed plugin specs

            slug_str = str(slug or "").strip()
            title_str = str(title or "").strip()
            if not slug_str or not title_str:
                continue

            layout_str = str(layout or "one_column").strip().lower()
            if layout_str not in {"one_column", "two_column"}:
                layout_str = "one_column"

            pages.append(
                {
                    "plugin": str(plugin_name),
                    "slug": slug_str,
                    "title": title_str,
                    "description": (
                        str(description) if description is not None else None
                    ),
                    "layout": layout_str,
                    "kind": str(kind) if kind is not None else None,
                }
            )

    return pages


def find_admin_page_detail(
    plugins: Iterable[object], plugin_name: str, page_slug: str
) -> dict[str, Any] | None:
    """Brief: Find a specific plugin admin page detail.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Target plugin instance name.
      - page_slug: Admin page slug.

    Outputs:
      - Dict for the page, or None if not found.

    Notes:
      - Mirrors logic used by both FastAPI and threaded implementations.
    """

    target = None
    for plugin in plugins or []:
        try:
            if getattr(plugin, "name", None) == plugin_name:
                target = plugin
                break
        except (
            Exception
        ):  # pragma: nocover - defensive against misbehaving plugin objects
            continue  # pragma: nocover - ignore plugin failures
    if target is None:
        return None

    get_pages = getattr(target, "get_admin_pages", None)
    if not callable(get_pages):
        return None

    try:
        specs = get_pages()
    except Exception:  # pragma: nocover - plugin code should not break admin UI
        return None  # pragma: nocover - best-effort: treat as missing

    for spec in specs or []:
        slug = None
        title = None
        description = None
        layout = None
        kind = None
        html_left = None
        html_right = None
        try:
            if isinstance(spec, AdminPageSpec):
                slug = spec.slug
                title = spec.title
                description = spec.description
                layout = spec.layout or "one_column"
                kind = spec.kind
                html_left = spec.html_left
                html_right = spec.html_right
            elif isinstance(spec, dict):
                slug = spec.get("slug")
                title = spec.get("title")
                description = spec.get("description")
                layout = spec.get("layout") or "one_column"
                kind = spec.get("kind")
                html_left = spec.get("html_left")
                html_right = spec.get("html_right")
            else:
                slug = getattr(spec, "slug", None)
                title = getattr(spec, "title", None)
                description = getattr(spec, "description", None)
                layout = getattr(spec, "layout", "one_column")
                kind = getattr(spec, "kind", None)
                html_left = getattr(spec, "html_left", None)
                html_right = getattr(spec, "html_right", None)
        except Exception:  # pragma: nocover - plugin page spec parsing is best-effort
            continue  # pragma: nocover - ignore malformed plugin specs

        slug_str = str(slug or "").strip()
        if slug_str != str(page_slug or "").strip():
            continue
        title_str = str(title or "").strip()
        if not title_str:
            continue

        layout_str = str(layout or "one_column").strip().lower()
        if layout_str not in {"one_column", "two_column"}:
            layout_str = "one_column"

        return {
            "plugin": str(plugin_name),
            "slug": slug_str,
            "title": title_str,
            "description": str(description) if description is not None else None,
            "layout": layout_str,
            "kind": str(kind) if kind is not None else None,
            "html_left": str(html_left) if html_left is not None else None,
            "html_right": str(html_right) if html_right is not None else None,
        }

    return None


def collect_plugin_ui_descriptors(plugins: Iterable[object]) -> list[dict[str, Any]]:
    """Brief: Collect plugin admin UI descriptors.

    Inputs:
      - plugins: Iterable of plugin instances.

    Outputs:
      - List of normalized descriptor dicts, sorted by (order, title) and with
        multi-instance title normalization applied.

    Notes:
      - This does not consult global DNS_CACHE. Callers may append a cache-like
        object to the plugins list before calling if they want it included.
    """

    items: list[dict[str, Any]] = []

    def _normalise_descriptor(
        source: object, desc: dict[str, Any]
    ) -> dict[str, Any] | None:
        if not isinstance(desc, dict):
            return None
        try:
            source_name = getattr(source, "name", "")
        except (
            Exception
        ):  # pragma: nocover - defensive against misbehaving plugin objects
            source_name = ""  # pragma: nocover - defensive default

        name = str(desc.get("name") or source_name or "").strip()
        title_raw = desc.get("title")
        title = str(title_raw or "").strip()
        if not name or not title:
            return None

        kind = desc.get("kind")
        order_val = desc.get("order")
        try:
            order = int(order_val) if order_val is not None else 100
        except (
            Exception
        ):  # pragma: nocover - defensive: plugins should provide int-ish order
            order = 100  # pragma: nocover - defensive default

        item = dict(desc)
        item["name"] = name
        item["title"] = title
        item["kind"] = str(kind) if kind is not None else None
        item["order"] = order
        return item

    for plugin in plugins or []:
        get_desc = None
        try:
            get_desc = getattr(plugin, "get_admin_ui_descriptor", None)
        except (
            Exception
        ):  # pragma: nocover - defensive against misbehaving plugin objects
            get_desc = None  # pragma: nocover - treat as missing
        if not callable(get_desc):
            continue
        try:
            desc = get_desc()
        except Exception:  # pragma: nocover - plugin code should not break admin UI
            continue  # pragma: nocover - ignore plugin failures
        if isinstance(desc, dict):
            item = _normalise_descriptor(plugin, desc)
            if item is not None:
                items.append(item)

    # Title normalization for multiple instances.
    title_counts: dict[str, int] = {}
    for it in items:
        raw_title = str(it.get("title", ""))
        name = str(it.get("name", ""))
        base_title = raw_title
        if raw_title and name and raw_title.endswith(f" ({name})"):
            base_title = raw_title[: -len(f" ({name})")]
        it["_base_title"] = base_title
        if base_title:
            title_counts[base_title] = title_counts.get(base_title, 0) + 1

    for it in items:
        base_title = str(it.get("_base_title", ""))
        name = str(it.get("name", ""))
        if not base_title:
            continue
        if title_counts.get(base_title, 0) > 1 and name:
            it["title"] = f"{base_title} ({name})"
        else:
            it["title"] = base_title
        it.pop("_base_title", None)

    items.sort(key=lambda d: (int(d.get("order", 100) or 100), str(d.get("title", ""))))
    return items


def find_plugin_instance_by_name(
    plugins: Iterable[object], plugin_name: str
) -> object | None:
    """Brief: Find a plugin instance by its configured name.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Name to match against plugin.name.

    Outputs:
      - The plugin instance if found, else None.
    """

    for p in plugins or []:
        try:
            if getattr(p, "name", None) == plugin_name:
                return p
        except (
            Exception
        ):  # pragma: nocover - defensive against misbehaving plugin objects
            continue  # pragma: nocover - ignore plugin failures
    return None


def build_named_plugin_snapshot(
    plugins: Iterable[object], plugin_name: str, *, label: str
) -> Dict[str, Any]:
    """Brief: Build a snapshot payload for a named plugin.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Target plugin name.
      - label: Human label used in error messages (e.g. 'DockerHosts').

    Outputs:
      - Dict with keys: plugin, data.

    Raises:
      - AdminLogicHttpError(404) when plugin missing or snapshot method absent.
      - AdminLogicHttpError(500) when get_http_snapshot() fails.
    """

    target = find_plugin_instance_by_name(plugins, plugin_name)
    if target is None or not hasattr(target, "get_http_snapshot"):
        raise AdminLogicHttpError(
            status_code=404,
            detail="plugin not found or does not expose get_http_snapshot",
        )

    try:
        snapshot = target.get_http_snapshot()  # type: ignore[call-arg]
    except Exception as exc:
        raise AdminLogicHttpError(
            status_code=500,
            detail=f"failed to build {label} snapshot: {exc}",
        ) from exc

    return {
        "plugin": plugin_name,
        "data": snapshot,
    }
