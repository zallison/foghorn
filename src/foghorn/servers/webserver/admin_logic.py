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
from dnslib import QTYPE

from ...plugins.resolve.base import AdminPageSpec
from ...security_limits import (
    enforce_query_log_aggregate_bucket_limit,
    enforce_query_log_aggregate_grouped_result_limit,
)
from ...stats import StatsCollector
from ...utils import dns_names
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


def _derive_query_log_error_value(item: Dict[str, Any]) -> Any | None:
    """Brief: Resolve query-log error text with nested and EDE fallbacks.

    Inputs:
      - item: Query-log row mapping from a stats backend.

    Outputs:
      - Existing item.error when present.
      - Else result.error when present.
      - Else synthesized EDE text using result.ede_code/result.ede_text.
      - None when no error details are available.
    """

    top_level_error = item.get("error")
    if top_level_error is not None:
        return top_level_error

    result = item.get("result")
    if not isinstance(result, dict):
        return None

    nested_error = result.get("error")
    if nested_error is not None:
        return nested_error

    ede_code_raw = result.get("ede_code")
    ede_text_raw = result.get("ede_text")
    ede_code = str(ede_code_raw).strip() if ede_code_raw is not None else ""
    ede_text = str(ede_text_raw).strip() if ede_text_raw is not None else ""

    if ede_code and ede_text:
        return f"EDE {ede_code}: {ede_text}"
    if ede_code:
        return f"EDE {ede_code}"
    if ede_text:
        return ede_text
    return None


def build_query_log_payload(
    store: Any,
    *,
    client_ip: str | None,
    qtype: str | None,
    qname: str | None,
    rcode: str | None,
    status: str | None,
    source: str | None,
    start_ts: float | None,
    end_ts: float | None,
    page: int,
    page_size: int,
    ede_code: str | None = None,
) -> Dict[str, Any]:
    """Brief: Build the query-log list payload from a store result.

    Inputs:
      - store: Stats store object that exposes select_query_log(**kwargs).
      - client_ip/qtype/qname/rcode: Optional filters.
      - status/source: Optional filters for query status and result source.
      - ede_code: Optional filter for result.ede_code in query-log rows.
      - start_ts/end_ts: Optional unix timestamps in seconds (UTC).
      - page: 1-indexed page number.
      - page_size: page size (already clamped).

    Outputs:
      - Dict with keys: total, page, page_size, total_pages, items.
        Each dict item with a 'ts' key is copied and gets a 'timestamp' field.
        The item error value follows precedence:
        item.error -> result.error -> EDE details.
    """

    res = store.select_query_log(
        client_ip=client_ip,
        qtype=qtype,
        qname=qname,
        rcode=rcode,
        status=status,
        source=source,
        ede_code=ede_code,
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
            resolved_error = _derive_query_log_error_value(out)
            if resolved_error is not None:
                out["error"] = resolved_error
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
    group_by_text = str(group_by).strip() if group_by is not None else ""
    try:
        enforce_query_log_aggregate_bucket_limit(
            start_dt.timestamp(),
            end_dt.timestamp(),
            interval_seconds,
        )
    except ValueError as exc:
        raise AdminLogicHttpError(status_code=400, detail=str(exc)) from exc

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

    raw_items = res.get("items", []) or []
    if group_by_text:
        try:
            enforce_query_log_aggregate_grouped_result_limit(len(raw_items))
        except ValueError as exc:
            raise AdminLogicHttpError(status_code=400, detail=str(exc)) from exc

    items: list[dict[str, Any]] = []
    for item in raw_items:
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
    """Brief: Build upstream status payload using shared resolver health state.

    Inputs:
      - config: Full configuration mapping (currently unused; kept for API
        compatibility).
      - now_ts: Optional unix timestamp (seconds) used for determining health.

    Outputs:
      - Dict with keys: strategy, max_concurrent, items.

    Notes:
      - The shared resolver (foghorn.servers.server) owns upstream health state.
      - Items include both primary and backup upstreams.
    """

    import time as _time

    now = float(now_ts) if now_ts is not None else _time.time()

    def _safe_int(value: Any) -> int:
        """Brief: Coerce a value to a non-negative integer count.

        Inputs:
          - value: Any numeric-ish object.

        Outputs:
          - int >= 0 suitable for counter fields.
        """

        try:
            return max(0, int(float(value)))
        except Exception:
            return 0

    def _collect_run_upstream_counts(stats_collector: Any) -> Dict[str, Dict[str, int]]:
        """Brief: Build per-upstream run counters from the live stats collector.

        Inputs:
          - stats_collector: Collector object expected to expose snapshot().

        Outputs:
          - Mapping keyed by upstream id with:
              - run_query_count
              - run_failed_count
        """

        counts: Dict[str, Dict[str, int]] = {}
        if stats_collector is None:
            return counts
        snapshot_fn = getattr(stats_collector, "snapshot", None)
        if not callable(snapshot_fn):
            return counts

        snap = None
        try:
            snap = snapshot_fn(reset=False)
        except TypeError:
            try:
                snap = snapshot_fn()
            except Exception:
                snap = None
        except Exception:
            snap = None

        upstream_outcomes = getattr(snap, "upstreams", None)
        if not isinstance(upstream_outcomes, dict):
            return counts

        for upstream_id, outcomes in upstream_outcomes.items():
            if not isinstance(outcomes, dict):
                continue
            total = 0
            failed = 0
            for outcome_key, raw_count in outcomes.items():
                count = _safe_int(raw_count)
                if count <= 0:
                    continue
                total += count
                key = str(outcome_key or "").strip().lower()
                if key not in {"success", "ok"}:
                    failed += count
            counts[str(upstream_id)] = {
                "run_query_count": total,
                "run_failed_count": failed,
            }
        return counts

    def _legacy_upstream_key(upstream: Any) -> str:
        """Brief: Build the pre-id upstream key shape used by older stats snapshots.

        Inputs:
          - upstream: Upstream configuration mapping.

        Outputs:
          - str legacy key (url/endpoint, else host:port, else host), or empty.
        """

        if not isinstance(upstream, dict):
            return ""
        try:
            url = upstream.get("url") or upstream.get("endpoint")
        except Exception:
            url = None
        if url:
            return str(url)
        try:
            host = upstream.get("host")
        except Exception:
            host = None
        try:
            port = upstream.get("port")
        except Exception:
            port = None
        if host or port:
            try:
                return f"{host}:{int(port) if port is not None else 0}"
            except Exception:
                return str(host) if host is not None else ""
        return ""

    def _resolve_run_count(
        run_counts_map: Dict[str, Dict[str, int]],
        *,
        upstream: Any,
        record_id: Any,
    ) -> Dict[str, int]:
        """Brief: Resolve run counters for an upstream with legacy-key fallback.

        Inputs:
          - run_counts_map: Per-upstream counters from _collect_run_upstream_counts.
          - upstream: Upstream configuration mapping used to derive legacy key.
          - record_id: Current upstream id used in upstream_status payload.

        Outputs:
          - Dict with run_query_count/run_failed_count, or empty dict.
        """

        rec_key = str(record_id or "")
        if rec_key:
            direct = run_counts_map.get(rec_key)
            if isinstance(direct, dict):
                return direct
        legacy_key = _legacy_upstream_key(upstream)
        if legacy_key:
            legacy = run_counts_map.get(legacy_key)
            if isinstance(legacy, dict):
                # Best-effort in-request migration so subsequent lookups in this
                # payload build use the current id key.
                if rec_key and rec_key != legacy_key:
                    run_counts_map[rec_key] = legacy
                return legacy
        return {}

    try:
        from foghorn.runtime_config import get_runtime_snapshot

        snap = get_runtime_snapshot()
        primary = list(getattr(snap, "upstream_addrs", []) or [])
        backup = list(getattr(snap, "upstream_backup_addrs", []) or [])
        strategy = str(getattr(snap, "upstream_strategy", "failover") or "failover")
        try:
            max_concurrent = int(getattr(snap, "upstream_max_concurrent", 1) or 1)
        except Exception:
            max_concurrent = 1
        if max_concurrent < 1:
            max_concurrent = 1
        from foghorn.runtime_config import (
            UpstreamHealthConfig,
            parse_upstream_health_config,
        )

        health_cfg = getattr(snap, "upstream_health", None)
        if not isinstance(health_cfg, UpstreamHealthConfig):
            health_cfg = parse_upstream_health_config({})

        import foghorn.servers.server as server_mod

        run_counts = _collect_run_upstream_counts(
            getattr(snap, "stats_collector", None)
        )

        items: list[Dict[str, Any]] = []
        for up in primary:
            if not isinstance(up, dict):
                continue
            rec = server_mod._UPSTREAM_HEALTH.describe_upstream(
                role="primary", upstream=up, now=now, cfg=health_cfg
            )
            if rec:
                run_count = _resolve_run_count(
                    run_counts, upstream=up, record_id=rec.get("id")
                )
                rec["run_query_count"] = _safe_int(run_count.get("run_query_count"))
                rec["run_failed_count"] = _safe_int(run_count.get("run_failed_count"))
                items.append(rec)
        for up in backup:
            if not isinstance(up, dict):
                continue
            rec = server_mod._UPSTREAM_HEALTH.describe_upstream(
                role="backup", upstream=up, now=now, cfg=health_cfg
            )
            if rec:
                run_count = _resolve_run_count(
                    run_counts, upstream=up, record_id=rec.get("id")
                )
                rec["run_query_count"] = _safe_int(run_count.get("run_query_count"))
                rec["run_failed_count"] = _safe_int(run_count.get("run_failed_count"))
                items.append(rec)

        return {
            "strategy": strategy,
            "max_concurrent": max_concurrent,
            "items": items,
        }
    except Exception:
        # Best-effort fallback when runtime snapshot is unavailable.
        return {"strategy": "failover", "max_concurrent": 1, "items": []}


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


def build_plugin_snapshot_payload(
    plugins: Iterable[object], plugin_name: str
) -> Dict[str, Any]:
    """Brief: Build a generic snapshot payload for a named plugin.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Target plugin name.

    Outputs:
      - Dict with keys: plugin, data.
    """

    return build_named_plugin_snapshot(plugins, plugin_name, label="Plugin")


def build_plugin_access_control_rules_payload(
    plugins: Iterable[object], plugin_name: str
) -> Dict[str, Any]:
    """Brief: Return explicit access-control CIDR rules and effective policy.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Target AccessControl plugin name.

    Outputs:
      - Dict with keys: plugin, rules.
    """

    target = find_plugin_instance_by_name(plugins, plugin_name)
    if target is None:
        raise AdminLogicHttpError(status_code=404, detail="plugin not found")

    allow_nets = getattr(target, "allow_nets", []) or []
    deny_nets = getattr(target, "deny_nets", []) or []
    allow_cidrs = sorted({str(net) for net in allow_nets if net is not None})
    deny_cidrs = sorted({str(net) for net in deny_nets if net is not None})

    return {
        "plugin": str(plugin_name),
        "rules": {
            "allow_cidrs": allow_cidrs,
            "deny_cidrs": deny_cidrs,
            "default": str(getattr(target, "default", "allow") or "allow"),
            "deny_response": str(
                getattr(target, "deny_response", "refused") or "refused"
            ),
        },
    }


def build_plugin_etc_hosts_lookup_payload(
    plugins: Iterable[object], plugin_name: str, *, name: str
) -> Dict[str, Any]:
    """Brief: Resolve a normalized EtcHosts in-memory mapping entry by name.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Target EtcHosts plugin name.
      - name: Query name to resolve.

    Outputs:
      - Dict with keys: plugin, entry.
    """

    target = find_plugin_instance_by_name(plugins, plugin_name)
    if target is None:
        raise AdminLogicHttpError(status_code=404, detail="plugin not found")

    name_norm = dns_names.normalize_name(name)
    if not name_norm:
        raise AdminLogicHttpError(status_code=400, detail="name is required")

    lock = getattr(target, "_hosts_lock", None)
    if lock is None:
        mapping = dict(getattr(target, "hosts", {}) or {})
        src_map = dict(getattr(target, "_entry_sources", {}) or {})
    else:
        with lock:
            mapping = dict(getattr(target, "hosts", {}) or {})
            src_map = dict(getattr(target, "_entry_sources", {}) or {})

    if name_norm not in mapping:
        raise AdminLogicHttpError(status_code=404, detail="host entry not found")

    return {
        "plugin": str(plugin_name),
        "entry": {
            "name": name_norm,
            "value": str(mapping.get(name_norm)),
            "source": src_map.get(name_norm),
        },
    }


def build_plugin_docker_container_payload(
    plugins: Iterable[object], plugin_name: str, *, name: str
) -> Dict[str, Any]:
    """Brief: Return Docker snapshot container rows filtered by container name.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Target DockerHosts plugin name.
      - name: Container display name to match (case-insensitive).

    Outputs:
      - Dict with keys: plugin, containers.
    """

    name_text = str(name or "").strip()
    if not name_text:
        raise AdminLogicHttpError(status_code=400, detail="container name is required")

    snap = build_named_plugin_snapshot(plugins, plugin_name, label="DockerHosts")
    data = snap.get("data")
    containers_raw = data.get("containers") if isinstance(data, dict) else None
    containers = (
        [it for it in containers_raw if isinstance(it, dict)]
        if isinstance(containers_raw, list)
        else []
    )
    needle = name_text.lower()
    matches = [it for it in containers if str(it.get("name", "")).lower() == needle]
    if not matches:
        raise AdminLogicHttpError(status_code=404, detail="container not found")
    return {
        "plugin": str(plugin_name),
        "containers": matches,
    }


def build_plugin_mdns_services_payload(
    plugins: Iterable[object],
    plugin_name: str,
    *,
    status: str | None,
    service_type: str | None,
) -> Dict[str, Any]:
    """Brief: Filter mDNS service rows by status and/or service type.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Target mDNS plugin name.
      - status: Optional status filter (up/down).
      - service_type: Optional service type filter (case-insensitive exact match).

    Outputs:
      - Dict with keys: plugin, status, type, services.
    """

    snap = build_named_plugin_snapshot(plugins, plugin_name, label="MdnsBridge")
    data = snap.get("data")
    up_raw = data.get("services") if isinstance(data, dict) else None
    down_raw = data.get("down_services") if isinstance(data, dict) else None
    up_rows = [it for it in (up_raw or []) if isinstance(it, dict)]
    down_rows = [it for it in (down_raw or []) if isinstance(it, dict)]

    status_norm = str(status or "").strip().lower()
    if status_norm and status_norm not in {"up", "down"}:
        raise AdminLogicHttpError(
            status_code=400, detail="status must be 'up' or 'down'"
        )

    if status_norm == "up":
        rows = up_rows
    elif status_norm == "down":
        rows = down_rows
    else:
        rows = up_rows + down_rows

    type_norm = str(service_type or "").strip().lower()
    if type_norm:
        rows = [
            it for it in rows if str(it.get("type", "")).strip().lower() == type_norm
        ]

    return {
        "plugin": str(plugin_name),
        "status": status_norm or None,
        "type": type_norm or None,
        "services": rows,
    }


def _parse_qtype_value(raw: str | None) -> int | None:
    """Brief: Parse qtype text/code into an integer QTYPE value.

    Inputs:
      - raw: QTYPE string or integer-like value.

    Outputs:
      - Parsed integer QTYPE value, or None when omitted/invalid.
    """

    text = str(raw or "").strip()
    if not text:
        return None
    if text.isdigit():
        try:
            return int(text)
        except Exception:
            return None
    upper = text.upper()
    try:
        attr_val = getattr(QTYPE, upper)
    except Exception:
        attr_val = None
    if isinstance(attr_val, int):
        return int(attr_val)
    try:
        qtype_val = QTYPE.get(upper, None)
    except Exception:
        qtype_val = None
    return int(qtype_val) if isinstance(qtype_val, int) else None


def build_plugin_zone_records_lookup_payload(
    plugins: Iterable[object], plugin_name: str, *, owner: str, qtype: str | None
) -> Dict[str, Any]:
    """Brief: Lookup zone records by normalized owner and optional qtype.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Target ZoneRecords plugin name.
      - owner: Record owner name.
      - qtype: Optional record type filter.

    Outputs:
      - Dict with keys: plugin, owner, qtype, records.
    """

    target = find_plugin_instance_by_name(plugins, plugin_name)
    if target is None:
        raise AdminLogicHttpError(status_code=404, detail="plugin not found")

    owner_norm = dns_names.normalize_name(owner)
    if not owner_norm:
        raise AdminLogicHttpError(status_code=400, detail="owner is required")

    qtype_code = _parse_qtype_value(qtype)
    if qtype and qtype_code is None:
        raise AdminLogicHttpError(status_code=400, detail="invalid qtype")

    lock = getattr(target, "_records_lock", None)
    if lock is not None:
        with lock:
            name_index = dict(getattr(target, "_name_index", {}) or {})
    else:
        name_index = dict(getattr(target, "_name_index", {}) or {})

    per_owner_raw = name_index.get(owner_norm)
    per_owner = per_owner_raw if isinstance(per_owner_raw, dict) else {}
    if not per_owner:
        raise AdminLogicHttpError(status_code=404, detail="owner not found")

    records: list[dict[str, Any]] = []
    for code, entry in sorted(per_owner.items(), key=lambda kv: int(kv[0])):
        if qtype_code is not None and int(code) != int(qtype_code):
            continue
        try:
            ttl, values, sources = entry
        except Exception:
            continue
        records.append(
            {
                "owner": owner_norm,
                "qtype": int(code),
                "qtype_name": str(QTYPE.get(int(code), str(int(code)))),
                "ttl": int(ttl),
                "values": list(values or []),
                "sources": list(sources or []),
            }
        )

    return {
        "plugin": str(plugin_name),
        "owner": owner_norm,
        "qtype": int(qtype_code) if qtype_code is not None else None,
        "records": records,
    }


def _parse_sort_expression(sort: str | None) -> tuple[str, bool]:
    """Brief: Parse profile sort expressions into field and descending flag.

    Inputs:
      - sort: Sort expression (e.g. '-avg_rps', 'avg_rps:desc').

    Outputs:
      - (field, descending) tuple.
    """

    text = str(sort or "").strip()
    if not text:
        return ("avg_rps", True)
    if text.startswith("-"):
        return (text[1:].strip() or "avg_rps", True)
    if ":" in text:
        field, _, dir_text = text.partition(":")
        return (field.strip() or "avg_rps", dir_text.strip().lower() == "desc")
    return (text, False)


def build_plugin_rate_limit_profiles_payload(
    plugins: Iterable[object],
    plugin_name: str,
    *,
    limit: int | None,
    sort: str | None,
) -> Dict[str, Any]:
    """Brief: Return deterministic profile rows from a RateLimit plugin DB.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Target RateLimit plugin name.
      - limit: Optional max rows.
      - sort: Optional sort expression.

    Outputs:
      - Dict with keys: plugin, total, limit, sort, profiles.
    """

    target = find_plugin_instance_by_name(plugins, plugin_name)
    if target is None:
        raise AdminLogicHttpError(status_code=404, detail="plugin not found")

    db_lock = getattr(target, "_db_lock", None)
    conn = getattr(target, "_conn", None)
    if db_lock is None or conn is None:
        raise AdminLogicHttpError(
            status_code=404, detail="rate-limit profile storage is unavailable"
        )

    try:
        lim = int(limit or 50)
    except Exception:
        lim = 50
    lim = max(1, min(lim, 5000))

    field, desc = _parse_sort_expression(sort)
    allowed_sort_fields = {
        "key",
        "avg_rps",
        "max_rps",
        "samples",
        "last_update",
        "current_rps",
    }
    if field not in allowed_sort_fields:
        raise AdminLogicHttpError(status_code=400, detail="unsupported sort field")

    try:
        with db_lock:
            cur = conn.cursor()
            cur.execute(
                "SELECT key, avg_rps, max_rps, samples, last_update FROM rate_profiles"
            )
            rows = list(cur.fetchall() or [])
    except Exception as exc:
        raise AdminLogicHttpError(
            status_code=500, detail=f"failed to read rate-limit profiles: {exc}"
        ) from exc

    current_rps_map: dict[str, float] = {}
    get_current_snapshot = getattr(target, "_get_current_window_rps_snapshot", None)
    if callable(get_current_snapshot):
        try:
            raw_current = get_current_snapshot(limit=0)
        except Exception:
            raw_current = {}
        if isinstance(raw_current, dict):
            current_rps_map = {
                str(k): float(v)
                for k, v in raw_current.items()
                if k is not None and v is not None
            }

    out_rows: list[dict[str, Any]] = []
    for key_text, avg_rps, max_rps, samples, last_update in rows:
        key_norm = str(key_text or "")
        out_rows.append(
            {
                "key": key_norm,
                "avg_rps": float(avg_rps or 0.0),
                "max_rps": float(max_rps or 0.0),
                "samples": int(samples or 0),
                "last_update": int(last_update or 0),
                "last_update_iso": _ts_to_utc_iso(float(last_update or 0)),
                "current_rps": float(current_rps_map.get(key_norm, 0.0)),
            }
        )

    def _sort_key_fn(item: dict[str, Any]) -> tuple[Any, str]:
        raw_val = item.get(field)
        if raw_val is None:
            return (0, str(item.get("key", "")))
        return (raw_val, str(item.get("key", "")))

    out_rows.sort(key=_sort_key_fn, reverse=bool(desc))

    return {
        "plugin": str(plugin_name),
        "total": len(out_rows),
        "limit": int(lim),
        "sort": {
            "field": field,
            "direction": "desc" if desc else "asc",
        },
        "profiles": out_rows[:lim],
    }


def build_plugin_reload_payload(
    plugins: Iterable[object], plugin_name: str, *, plugin_kind: str
) -> Dict[str, Any]:
    """Brief: Trigger EtcHosts/DockerHosts reload and return post-reload summary.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Target plugin instance name.
      - plugin_kind: One of 'etc_hosts' or 'docker_hosts'.

    Outputs:
      - Dict with keys: plugin, action, data.
    """

    target = find_plugin_instance_by_name(plugins, plugin_name)
    if target is None:
        raise AdminLogicHttpError(status_code=404, detail="plugin not found")

    if plugin_kind == "etc_hosts":
        reload_fn = getattr(target, "_load_hosts", None)
    elif plugin_kind == "docker_hosts":
        reload_fn = getattr(target, "_reload_from_docker", None)
    else:
        raise AdminLogicHttpError(status_code=400, detail="unsupported plugin kind")

    if not callable(reload_fn):
        raise AdminLogicHttpError(
            status_code=404, detail="plugin reload is unavailable"
        )

    try:
        reload_fn()
        snapshot = (
            target.get_http_snapshot() if hasattr(target, "get_http_snapshot") else {}
        )
    except Exception as exc:
        raise AdminLogicHttpError(
            status_code=500, detail=f"reload failed: {exc}"
        ) from exc

    return {
        "plugin": str(plugin_name),
        "action": "reload",
        "data": snapshot,
    }


def build_plugin_upstream_evaluate_payload(
    plugins: Iterable[object], plugin_name: str, *, qname: str
) -> Dict[str, Any]:
    """Brief: Evaluate upstream candidates for qname without forwarding a query.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Target UpstreamRouter plugin name.
      - qname: DNS query name to evaluate.

    Outputs:
      - Dict with keys: plugin, qname, matched, candidates.
    """

    target = find_plugin_instance_by_name(plugins, plugin_name)
    if target is None:
        raise AdminLogicHttpError(status_code=404, detail="plugin not found")

    qname_norm = dns_names.normalize_name(qname)
    if not qname_norm:
        raise AdminLogicHttpError(status_code=400, detail="qname is required")

    matcher = getattr(target, "_match_upstream_candidates", None)
    if not callable(matcher):
        raise AdminLogicHttpError(
            status_code=404, detail="upstream evaluation is unavailable"
        )

    try:
        candidates = matcher(qname_norm)
    except Exception as exc:
        raise AdminLogicHttpError(
            status_code=500, detail=f"upstream evaluation failed: {exc}"
        ) from exc

    out_candidates = list(candidates or []) if isinstance(candidates, list) else []
    return {
        "plugin": str(plugin_name),
        "qname": qname_norm,
        "matched": bool(out_candidates),
        "candidates": out_candidates,
    }
