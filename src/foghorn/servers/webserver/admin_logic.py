"""Shared business logic for the admin webserver.

This module contains framework-neutral helpers used by both:
- the FastAPI/uvicorn implementation (routes_*.py), and
- the threaded stdlib http.server fallback (threaded_handlers.py).

The functions here deliberately avoid importing FastAPI or http.server types.
"""

from __future__ import annotations

import math
import time
import json
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
      - page_size: Requested page size passed through to the store.

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
    except Exception:  # pragma: nocover - runtime snapshot import/state can be unavailable in minimal test environments
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
      - plugin_kind: One of 'etc_hosts', 'docker_hosts', or 'zone_records'.

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
    elif plugin_kind == "zone_records":
        reload_fn = getattr(target, "_reload_records_from_watchdog", None)
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


def build_plugin_zone_records_compact_payload(
    plugins: Iterable[object],
    plugin_name: str,
    *,
    zone: str | None,
) -> Dict[str, Any]:
    """Brief: Compact ZoneRecords DNS UPDATE journals for one/all zones.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Target ZoneRecords plugin name.
      - zone: Optional zone apex filter. When omitted, compacts all configured zones.

    Outputs:
      - Dict with keys: plugin, action, zone, result, summary.
    """

    target = find_plugin_instance_by_name(plugins, plugin_name)
    if target is None:
        raise AdminLogicHttpError(status_code=404, detail="plugin not found")

    compact_fn = getattr(target, "compact_dns_update_journals", None)
    if not callable(compact_fn):
        raise AdminLogicHttpError(
            status_code=409, detail="zone_records journal compaction is unavailable"
        )

    zone_text = str(zone or "").strip()
    zone_norm: str | None = None
    if zone_text:
        zone_norm = dns_names.normalize_name(zone_text)
        if not zone_norm:
            raise AdminLogicHttpError(status_code=400, detail="invalid zone")

    try:
        result_raw = compact_fn(zone_apex=zone_norm)
    except Exception as exc:
        raise AdminLogicHttpError(
            status_code=500, detail=f"zone_records compaction failed: {exc}"
        ) from exc

    result_map: Dict[str, bool] = {}
    if isinstance(result_raw, dict):
        for k, v in result_raw.items():
            result_map[str(k)] = bool(v)

    requested = len(result_map)
    successful = sum(1 for ok in result_map.values() if bool(ok))
    failed = max(0, int(requested - successful))

    return {
        "plugin": str(plugin_name),
        "action": "compact_journals",
        "zone": zone_norm,
        "result": result_map,
        "summary": {
            "requested_zones": int(requested),
            "successful": int(successful),
            "failed": int(failed),
        },
    }


def build_plugin_zone_records_dns_update_zone_payload(
    plugins: Iterable[object],
    plugin_name: str,
    *,
    zone: str,
) -> Dict[str, Any]:
    """Brief: Return DNS UPDATE status for one ZoneRecords zone.

    Inputs:
      - plugins: Iterable of plugin instances.
      - plugin_name: Target ZoneRecords plugin name.
      - zone: Zone apex name.

    Outputs:
      - Dict with keys: plugin, zone, dns_update.
    """

    target = find_plugin_instance_by_name(plugins, plugin_name)
    if target is None:
        raise AdminLogicHttpError(status_code=404, detail="plugin not found")

    zone_norm = dns_names.normalize_name(zone)
    if not zone_norm:
        raise AdminLogicHttpError(status_code=400, detail="invalid zone")

    dns_update_cfg = getattr(target, "_dns_update_config", None)
    if not isinstance(dns_update_cfg, dict):
        raise AdminLogicHttpError(status_code=409, detail="dns_update is disabled")
    persistence_cfg = dns_update_cfg.get("persistence")
    if not isinstance(persistence_cfg, dict) or not bool(
        persistence_cfg.get("enabled", False)
    ):
        raise AdminLogicHttpError(status_code=409, detail="dns_update is disabled")

    zones_raw = dns_update_cfg.get("zones")
    configured_zones: set[str] = set()
    if isinstance(zones_raw, list):
        for item in zones_raw:
            if not isinstance(item, dict):
                continue
            zone_name = dns_names.normalize_name(item.get("zone", ""))
            if zone_name:
                configured_zones.add(zone_name)
    if zone_norm not in configured_zones:
        raise AdminLogicHttpError(status_code=404, detail="zone not configured")

    state_dir = getattr(target, "_dns_update_journal_state_dir", None)
    if not state_dir:
        raise AdminLogicHttpError(
            status_code=409, detail="dns_update persistence state is unavailable"
        )

    last_seq = int(
        getattr(target, "_dynamic_last_seq_by_zone", {}).get(zone_norm, 0) or 0
    )
    snapshot_seq: int | None = None
    journal_bytes: int | None = None
    try:
        from ...plugins.resolve.zone_records.journal import load_manifest

        manifest = load_manifest(zone_apex=zone_norm, base_dir=str(state_dir))
        snapshot_seq = int(getattr(manifest, "snapshot_seq", 0) or 0)
        journal_bytes = int(getattr(manifest, "journal_bytes", 0) or 0)
    except Exception:
        snapshot_seq = None
        journal_bytes = None

    return {
        "plugin": str(plugin_name),
        "zone": zone_norm,
        "dns_update": {
            "enabled": True,
            "last_seq": int(last_seq),
            "snapshot_seq": snapshot_seq,
            "journal_bytes": journal_bytes,
            "replay_entries": int(
                getattr(target, "_dns_update_replay_entries", 0) or 0
            ),
            "compactions": int(
                getattr(target, "_dns_update_compact_count", 0) or 0
            ),
            "rate_limit_hits": int(
                getattr(target, "_dns_update_rate_limit_hits", 0) or 0
            ),
        },
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


def get_admin_runtime_state(obj: object) -> object | None:
    """Brief: Return the attached admin runtime state object when present.

    Inputs:
      - obj: FastAPI app.state or threaded server instance.

    Outputs:
      - Admin runtime state object, or None when not configured.
    """

    try:
        state = getattr(obj, "admin_runtime", None)
    except Exception:  # pragma: nocover - defensive getattr guard on foreign objects
        state = None
    return state


def add_admin_audit_event(
    runtime_state: object | None,
    *,
    action: str,
    target: str,
    ok: bool,
    details: Dict[str, Any] | None = None,
) -> None:
    """Brief: Best-effort append to admin action audit state.

    Inputs:
      - runtime_state: Admin runtime state object.
      - action: Audit action identifier.
      - target: Audit action target identifier.
      - ok: Action success indicator.
      - details: Optional compact details payload.

    Outputs:
      - None.
    """

    if runtime_state is None:
        return
    add_fn = getattr(runtime_state, "add_audit_event", None)
    if not callable(add_fn):
        return
    try:
        add_fn(action=action, target=target, ok=bool(ok), details=details or {})
    except Exception:  # pragma: nocover - audit sink must never break admin actions
        return


def build_admin_status_payload(
    *,
    cfg: Dict[str, Any],
    config_path: str | None = None,
    stats_collector: object | None,
    plugins: Iterable[object],
    admin_runtime_state: object | None,
) -> Dict[str, Any]:
    """Brief: Build unified admin runtime status payload.

    Inputs:
      - cfg: Current runtime config mapping.
      - config_path: Active config path.
      - stats_collector: Current stats collector object (optional).
      - plugins: Loaded plugin instances.
      - admin_runtime_state: Optional AdminRuntimeState object.

    Outputs:
      - Dict with runtime status, plugin count, queue metrics, and restart metadata.
    """

    queue_metrics: Dict[str, Any] | None = None
    store = (
        getattr(stats_collector, "_store", None)
        if stats_collector is not None
        else None
    )
    if store is not None:
        get_metrics = getattr(store, "get_async_queue_metrics", None)
        if callable(get_metrics):
            try:
                raw = get_metrics()
                if isinstance(raw, dict):
                    queue_metrics = dict(raw)
            except Exception:
                queue_metrics = None

    restart_pending: Dict[str, Any] | None = None
    if admin_runtime_state is not None:
        get_restart = getattr(admin_runtime_state, "get_restart_pending", None)
        if callable(get_restart):
            try:
                raw = get_restart()
                if isinstance(raw, dict):
                    restart_pending = dict(raw)
            except Exception:
                restart_pending = None

    try:
        from foghorn import runtime_config as _runtime_config

        snap = _runtime_config.get_runtime_snapshot()
        runtime_generation = int(getattr(snap, "generation", 0) or 0)
    except Exception:
        runtime_generation = 0

    return {
        "status": "ok",
        "runtime_generation": int(runtime_generation),
        "plugin_count": int(len(list(plugins or []))),
        "stats_enabled": bool(stats_collector is not None),
        "query_log_enabled": bool(
            store is not None and hasattr(store, "select_query_log")
        ),
        "config_path_configured": bool(str(config_path or "").strip()),
        "restart_pending": restart_pending,
        "query_log_queue": queue_metrics,
        "timestamp_ts": float(time.time()),
    }


def build_admin_capabilities_payload(
    *,
    stats_collector: object | None,
    plugins: Iterable[object],
) -> Dict[str, Any]:
    """Brief: Build capabilities payload for admin actions.

    Inputs:
      - stats_collector: Current stats collector object (optional).
      - plugins: Loaded plugin instances.

    Outputs:
      - Dict describing action-level support flags.
    """

    store = (
        getattr(stats_collector, "_store", None)
        if stats_collector is not None
        else None
    )
    query_log_clear_supported = False
    if store is not None:
        supports_clear_fn = getattr(store, "supports_query_log_clear", None)
        if callable(supports_clear_fn):
            try:
                query_log_clear_supported = bool(supports_clear_fn())
            except Exception:
                query_log_clear_supported = False

    rate_limit_plugins = []
    etc_hosts_plugins = []
    zone_records_plugins = []
    for plugin in plugins or []:
        name = str(getattr(plugin, "name", "") or "")
        klass = str(type(plugin).__name__ or "")
        if klass == "RateLimit":
            rate_limit_plugins.append(name or klass)
        if klass == "EtcHosts":
            etc_hosts_plugins.append(name or klass)
        if klass == "ZoneRecords":
            zone_records_plugins.append(name or klass)

    return {
        "query_log": {
            "clear_supported": bool(query_log_clear_supported),
        },
        "rate_limit": {
            "plugin_count": int(len(rate_limit_plugins)),
            "clear_supported": bool(rate_limit_plugins),
            "list_keys_supported": bool(rate_limit_plugins),
            "plugins": list(rate_limit_plugins),
        },
        "records": {
            "etc_hosts_plugins": list(etc_hosts_plugins),
            "zone_records_plugins": list(zone_records_plugins),
            "validate_supported": bool(etc_hosts_plugins or zone_records_plugins),
            "apply_supported": bool(etc_hosts_plugins or zone_records_plugins),
            "delete_supported": bool(etc_hosts_plugins or zone_records_plugins),
        },
        "restart": {
            "schedule_supported": True,
            "pending_supported": True,
        },
        "config": {
            "verify_supported": True,
        },
        "audit": {
            "list_supported": True,
            "clear_supported": True,
        },
    }


def build_config_verify_payload(
    *,
    raw_yaml: str | None,
    config_path: str | None,
    current_cfg: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """Brief: Parse and verify config input without applying runtime changes.

    Inputs:
      - raw_yaml: Optional raw YAML text to verify. When absent, verifies on-disk config.
      - config_path: Active runtime config path.
      - current_cfg: Current effective runtime config.

    Outputs:
      - Dict containing verify status, source path, and analyze_config_change output.
    """

    from foghorn import runtime_config as _runtime_config
    import os
    import tempfile

    cfg_path_text = str(config_path or "")
    if not cfg_path_text:
        raise AdminLogicHttpError(status_code=500, detail="config_path not configured")

    desired_cfg: Dict[str, Any]
    path_used = os.path.abspath(cfg_path_text)

    if isinstance(raw_yaml, str):
        fd: int | None = None
        tmp_path: str | None = None
        try:
            fd, tmp_path = tempfile.mkstemp(
                prefix="foghorn-admin-verify-", suffix=".yaml"
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = None
                f.write(raw_yaml)
            desired_cfg = _runtime_config.load_config_from_disk(
                config_path=str(tmp_path)
            )
            path_used = str(tmp_path)
        except AdminLogicHttpError:
            raise
        except Exception as exc:
            raise AdminLogicHttpError(
                status_code=400,
                detail=f"failed to parse/validate config: {exc}",
            ) from exc
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:  # pragma: nocover - defensive cleanup after tempfile parse failure
                    pass
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except Exception:  # pragma: nocover - defensive cleanup after tempfile parse failure
                    pass
    else:
        try:
            desired_cfg = _runtime_config.load_config_from_disk(
                config_path=cfg_path_text
            )
        except Exception as exc:
            raise AdminLogicHttpError(
                status_code=400,
                detail=f"failed to parse/validate config: {exc}",
            ) from exc

    analysis = _runtime_config.analyze_config_change(
        desired_cfg,
        current_cfg=current_cfg or {},
    )

    return {
        "status": "ok",
        "path": str(path_used),
        "analysis": dict(analysis or {}),
    }


def execute_query_log_clear(
    *,
    store: object | None,
    filters: Dict[str, Any],
    dry_run: bool,
) -> Dict[str, Any]:
    """Brief: Execute query-log clear operation through backend abstraction.

    Inputs:
      - store: Query-log backend object.
      - filters: Clear filter mapping.
      - dry_run: Whether to only compute matched rows.

    Outputs:
      - Dict with matched/deleted metadata from the backend.
    """

    if store is None:
        raise AdminLogicHttpError(status_code=404, detail="query_log store unavailable")
    supports_clear_fn = getattr(store, "supports_query_log_clear", None)
    if not callable(supports_clear_fn) or not bool(supports_clear_fn()):
        raise AdminLogicHttpError(
            status_code=400,
            detail="query_log clearing is not supported by active backend",
        )

    clear_fn = getattr(store, "clear_query_log", None)
    if not callable(clear_fn):
        raise AdminLogicHttpError(
            status_code=400,
            detail="query_log clearing is not supported by active backend",
        )
    try:
        result = clear_fn(filters=dict(filters or {}), dry_run=bool(dry_run))
    except Exception as exc:
        raise AdminLogicHttpError(
            status_code=500,
            detail=f"query_log clear failed: {exc}",
        ) from exc
    if not isinstance(result, dict):
        return {
            "status": "ok",
            "matched": 0,
            "deleted": 0,
            "dry_run": bool(dry_run),
        }
    return {
        "status": "ok",
        "matched": int(result.get("matched", 0) or 0),
        "deleted": int(result.get("deleted", 0) or 0),
        "dry_run": bool(result.get("dry_run", dry_run)),
        "filters": dict(result.get("filters", filters or {})),
    }


def _find_plugins_by_class_name(
    plugins: Iterable[object],
    class_name: str,
) -> List[object]:
    """Brief: Return plugin instances whose class name matches class_name.

    Inputs:
      - plugins: Plugin iterable.
      - class_name: Exact class name string.

    Outputs:
      - Matching plugin instances list.
    """

    out: List[object] = []
    for plugin in plugins or []:
        try:
            if str(type(plugin).__name__) == str(class_name):
                out.append(plugin)
        except Exception:  # pragma: nocover - defensive against malformed plugin objects
            continue
    return out


def execute_rate_limit_keys_list(
    *,
    plugins: Iterable[object],
    plugin_name: str | None,
    page: int,
    page_size: int,
    search: str | None,
) -> Dict[str, Any]:
    """Brief: List rate-limit keys from one or all RateLimit plugin instances.

    Inputs:
      - plugins: Loaded plugin instances.
      - plugin_name: Optional target plugin instance name.
      - page: 1-based page number.
      - page_size: Requested page size.
      - search: Optional search filter.

    Outputs:
      - Dict with plugin list and per-plugin paginated key payloads.
    """

    targets = _find_plugins_by_class_name(plugins, "RateLimit")
    if plugin_name is not None and str(plugin_name).strip():
        name_text = str(plugin_name).strip()
        targets = [p for p in targets if str(getattr(p, "name", "")) == name_text]
    if not targets:
        raise AdminLogicHttpError(status_code=404, detail="rate-limit plugin not found")

    out_items: List[Dict[str, Any]] = []
    for plugin in targets:
        list_fn = getattr(plugin, "admin_list_profile_keys", None)
        if not callable(list_fn):
            raise AdminLogicHttpError(
                status_code=400,
                detail="rate-limit key listing is unsupported by plugin",
            )
        try:
            payload = list_fn(page=page, page_size=page_size, search=search)
        except Exception as exc:
            raise AdminLogicHttpError(
                status_code=500,
                detail=f"failed to list rate-limit keys: {exc}",
            ) from exc
        out_items.append(
            {
                "plugin": str(getattr(plugin, "name", "RateLimit")),
                "data": dict(payload or {}),
            }
        )
    return {
        "status": "ok",
        "items": out_items,
    }


def execute_rate_limit_clear(
    *,
    plugins: Iterable[object],
    plugin_name: str | None,
    key: str | None,
    include_global: bool,
) -> Dict[str, Any]:
    """Brief: Clear learned rate-limit profiles/windows for one or more plugins.

    Inputs:
      - plugins: Loaded plugin instances.
      - plugin_name: Optional target plugin instance name.
      - key: Optional specific key.
      - include_global: Whether global profile rows can be removed.

    Outputs:
      - Dict with per-plugin clear results.
    """

    targets = _find_plugins_by_class_name(plugins, "RateLimit")
    if plugin_name is not None and str(plugin_name).strip():
        name_text = str(plugin_name).strip()
        targets = [p for p in targets if str(getattr(p, "name", "")) == name_text]
    if not targets:
        raise AdminLogicHttpError(status_code=404, detail="rate-limit plugin not found")

    out_items: List[Dict[str, Any]] = []
    for plugin in targets:
        clear_fn = getattr(plugin, "admin_clear_profiles", None)
        if not callable(clear_fn):
            raise AdminLogicHttpError(
                status_code=400,
                detail="rate-limit clearing is unsupported by plugin",
            )
        try:
            payload = clear_fn(key=key, include_global=bool(include_global))
        except Exception as exc:
            raise AdminLogicHttpError(
                status_code=500,
                detail=f"failed to clear rate-limit profiles: {exc}",
            ) from exc
        out_items.append(
            {
                "plugin": str(getattr(plugin, "name", "RateLimit")),
                "data": dict(payload or {}),
            }
        )

    return {"status": "ok", "items": out_items}


def execute_records_validate(
    *,
    plugins: Iterable[object],
    target: str,
    plugin_name: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Brief: Validate etc_hosts/zone_records mutation request payload.

    Inputs:
      - plugins: Loaded plugin instances.
      - target: One of 'etc_hosts' or 'zone_records'.
      - plugin_name: Target plugin instance name.
      - payload: Request payload.

    Outputs:
      - Dict with normalized validation result.
    """

    plugin = find_plugin_instance_by_name(plugins, plugin_name)
    if plugin is None:
        raise AdminLogicHttpError(status_code=404, detail="plugin not found")
    if target == "etc_hosts":
        fn = getattr(plugin, "admin_validate_record_mutation", None)
        if not callable(fn):
            raise AdminLogicHttpError(
                status_code=400,
                detail="etc_hosts validation unsupported by plugin",
            )
        try:
            out = fn(
                name=str(payload.get("name", "")), value=str(payload.get("value", ""))
            )
        except Exception as exc:
            raise AdminLogicHttpError(status_code=400, detail=str(exc)) from exc
        return {"status": "ok", "target": target, "plugin": plugin_name, "result": out}
    if target == "zone_records":
        fn = getattr(plugin, "admin_validate_record_mutation", None)
        if not callable(fn):
            raise AdminLogicHttpError(
                status_code=400,
                detail="zone_records validation unsupported by plugin",
            )
        try:
            out = fn(
                owner=str(payload.get("owner", "")),
                qtype=payload.get("qtype", ""),
                value=str(payload.get("value", "")),
                ttl=int(payload.get("ttl", 300) or 300),
            )
        except Exception as exc:
            raise AdminLogicHttpError(status_code=400, detail=str(exc)) from exc
        return {"status": "ok", "target": target, "plugin": plugin_name, "result": out}
    raise AdminLogicHttpError(status_code=400, detail="unknown records target")


def _runtime_add_task(
    runtime_state: object | None,
    *,
    task_type: str,
    status: str,
    details: Dict[str, Any] | None = None,
) -> None:
    """Brief: Best-effort append of an admin task/event record.

    Inputs:
      - runtime_state: Admin runtime state object.
      - task_type: Task category identifier.
      - status: Task status string.
      - details: Optional compact task metadata.

    Outputs:
      - None.
    """

    if runtime_state is None:
        return
    add_fn = getattr(runtime_state, "add_task", None)
    if not callable(add_fn):
        return
    try:
        add_fn(task_type=str(task_type), status=str(status), details=details or {})
    except Exception:  # pragma: nocover - best-effort task logging must not break admin actions
        return


def _build_temporary_record_tracking_key(
    *,
    target: str,
    plugin_name: str,
    payload: Dict[str, Any],
) -> str:
    """Brief: Build a stable temporary-record tracking key.

    Inputs:
      - target: Record target namespace.
      - plugin_name: Target plugin instance name.
      - payload: Apply/delete payload mapping.

    Outputs:
      - Stable key string.
    """

    target_text = str(target or "").strip().lower()
    plugin_text = str(plugin_name or "").strip()
    if target_text == "etc_hosts":
        name_text = dns_names.normalize_name(str(payload.get("name", "")))
        return f"{target_text}:{plugin_text}:{name_text}"
    owner_text = dns_names.normalize_name(str(payload.get("owner", "")))
    qtype_text = str(payload.get("qtype", "")).strip().upper()
    value_text = str(payload.get("value", "")).strip()
    return f"{target_text}:{plugin_text}:{owner_text}:{qtype_text}:{value_text}"


def build_admin_restart_status_payload(
    *,
    runtime_state: object | None,
) -> Dict[str, Any]:
    """Brief: Build restart scheduling status payload.

    Inputs:
      - runtime_state: Optional admin runtime state object.

    Outputs:
      - Dict containing pending restart metadata.
    """

    pending = None
    if runtime_state is not None:
        get_fn = getattr(runtime_state, "get_restart_pending", None)
        if callable(get_fn):
            try:
                raw = get_fn()
                if isinstance(raw, dict):
                    pending = dict(raw)
            except Exception:
                pending = None

    if not isinstance(pending, dict):
        return {
            "status": "ok",
            "pending": False,
            "restart": None,
        }

    scheduled_at_ts = float(pending.get("scheduled_at_ts", 0.0) or 0.0)
    expected_at_ts = float(pending.get("expected_at_ts", 0.0) or 0.0)
    return {
        "status": "ok",
        "pending": bool(pending.get("scheduled", False)),
        "restart": {
            "signal": str(pending.get("signal", "SIGHUP")),
            "delay_seconds": float(pending.get("delay_seconds", 0.0) or 0.0),
            "reason": pending.get("reason"),
            "scheduled_at_ts": scheduled_at_ts,
            "scheduled_at": _ts_to_utc_iso(scheduled_at_ts) if scheduled_at_ts > 0.0 else None,
            "expected_at_ts": expected_at_ts,
            "expected_at": _ts_to_utc_iso(expected_at_ts) if expected_at_ts > 0.0 else None,
        },
    }


def build_admin_tasks_payload(
    *,
    runtime_state: object | None,
    limit: int,
    task_type: str | None,
    status: str | None,
) -> Dict[str, Any]:
    """Brief: Build payload listing recent admin task/event records.

    Inputs:
      - runtime_state: Optional admin runtime state object.
      - limit: Maximum number of items requested.
      - task_type: Optional task-type filter.
      - status: Optional status filter.

    Outputs:
      - Dict containing task/event list.
    """

    items: List[Dict[str, Any]] = []
    if runtime_state is not None:
        list_fn = getattr(runtime_state, "list_tasks", None)
        if callable(list_fn):
            try:
                raw = list_fn(limit=int(limit), task_type=task_type, status=status)
                if isinstance(raw, list):
                    items = [dict(it) for it in raw if isinstance(it, dict)]
            except Exception:
                items = []
    for item in items:
        created_at_ts = float(item.get("created_at_ts", 0.0) or 0.0)
        item["created_at"] = _ts_to_utc_iso(created_at_ts) if created_at_ts > 0.0 else None
    return {"status": "ok", "items": items, "count": len(items)}


def build_admin_version_compat_payload(
    *,
    plugins: Iterable[object],
    stats_collector: object | None,
) -> Dict[str, Any]:
    """Brief: Build feature compatibility payload by plugin class and runtime support.

    Inputs:
      - plugins: Loaded plugin instances.
      - stats_collector: Optional stats collector.

    Outputs:
      - Dict with plugin capability matrix and query-log support details.
    """

    items: List[Dict[str, Any]] = []
    for plugin in plugins or []:
        plugin_name = str(getattr(plugin, "name", type(plugin).__name__) or type(plugin).__name__)
        class_name = str(type(plugin).__name__)
        item: Dict[str, Any] = {
            "plugin": plugin_name,
            "class_name": class_name,
            "capabilities": {
                "records_validate": bool(callable(getattr(plugin, "admin_validate_record_mutation", None))),
                "records_apply": bool(callable(getattr(plugin, "admin_apply_record_mutation", None))),
                "records_delete": bool(callable(getattr(plugin, "admin_delete_record_mutation", None))),
                "rate_limit_list_keys": bool(callable(getattr(plugin, "admin_list_profile_keys", None))),
                "rate_limit_clear": bool(callable(getattr(plugin, "admin_clear_profiles", None))),
            },
        }
        items.append(item)

    store = _get_store_from_collector(stats_collector) if stats_collector is not None else None
    query_log: Dict[str, Any] = {"enabled": bool(store is not None), "clear_supported": False}
    if store is not None:
        supports_clear_fn = getattr(store, "supports_query_log_clear", None)
        if callable(supports_clear_fn):
            try:
                query_log["clear_supported"] = bool(supports_clear_fn())
            except Exception:
                query_log["clear_supported"] = False

    return {
        "status": "ok",
        "api_surface_version": "admin-v2",
        "query_log": query_log,
        "plugins": items,
    }


def build_config_diff_payload(
    *,
    raw_yaml: str | None,
    config_path: str | None,
    current_cfg: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """Brief: Build a structured config diff summary without applying changes.

    Inputs:
      - raw_yaml: Optional YAML text to compare against runtime config.
      - config_path: Active on-disk config path.
      - current_cfg: Current runtime config mapping.

    Outputs:
      - Dict containing changed flag, analyze_config_change output, and path diffs.
    """

    import os
    import tempfile
    from foghorn import runtime_config as _runtime_config

    cfg_path_text = str(config_path or "").strip()
    if not cfg_path_text and raw_yaml is None:
        raise AdminLogicHttpError(status_code=500, detail="config_path not configured")

    desired_cfg: Dict[str, Any]
    path_used = os.path.abspath(cfg_path_text) if cfg_path_text else None
    if isinstance(raw_yaml, str):
        fd: int | None = None
        tmp_path: str | None = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix="foghorn-admin-diff-", suffix=".yaml")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = None
                f.write(raw_yaml)
            desired_cfg = _runtime_config.load_config_from_disk(config_path=str(tmp_path))
            path_used = str(tmp_path)
        except Exception as exc:
            raise AdminLogicHttpError(
                status_code=400, detail=f"failed to parse/validate config: {exc}"
            ) from exc
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:  # pragma: nocover - defensive cleanup after tempfile parse failure
                    pass
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except Exception:  # pragma: nocover - defensive cleanup after tempfile parse failure
                    pass
    else:
        try:
            desired_cfg = _runtime_config.load_config_from_disk(config_path=str(cfg_path_text))
        except Exception as exc:
            raise AdminLogicHttpError(
                status_code=400, detail=f"failed to parse/validate config: {exc}"
            ) from exc

    current = current_cfg if isinstance(current_cfg, dict) else {}
    analysis = _runtime_config.analyze_config_change(desired_cfg, current_cfg=current)

    def _flatten_paths(obj: Any, prefix: str = "") -> Dict[str, str]:
        out: Dict[str, str] = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = str(k)
                p = f"{prefix}.{key}" if prefix else key
                out.update(_flatten_paths(v, p))
            if not obj and prefix:
                out[prefix] = "{}"
            return out
        if isinstance(obj, list):
            if prefix:
                out[prefix] = f"[len={len(obj)}]"
            return out
        if prefix:
            out[prefix] = repr(obj)
        return out

    current_flat = _flatten_paths(current)
    desired_flat = _flatten_paths(desired_cfg)
    current_paths = set(current_flat.keys())
    desired_paths = set(desired_flat.keys())
    added = sorted(desired_paths - current_paths)
    removed = sorted(current_paths - desired_paths)
    modified = sorted(
        p for p in (current_paths & desired_paths) if current_flat.get(p) != desired_flat.get(p)
    )

    return {
        "status": "ok",
        "path": path_used,
        "changed": bool(analysis.get("changed", False)),
        "analysis": dict(analysis or {}),
        "diff": {
            "added_paths": added,
            "removed_paths": removed,
            "modified_paths": modified,
            "added_count": len(added),
            "removed_count": len(removed),
            "modified_count": len(modified),
        },
    }


def build_config_lint_payload(
    *,
    raw_yaml: str | None,
    config_path: str | None,
    current_cfg: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """Brief: Build non-fatal lint advisories for config changes.

    Inputs:
      - raw_yaml: Optional YAML text to lint.
      - config_path: Active on-disk config path.
      - current_cfg: Current runtime config mapping.

    Outputs:
      - Dict containing lint issues and summary fields.
    """

    diff_payload = build_config_diff_payload(
        raw_yaml=raw_yaml,
        config_path=config_path,
        current_cfg=current_cfg,
    )
    analysis = diff_payload.get("analysis", {}) if isinstance(diff_payload.get("analysis"), dict) else {}
    diff_obj = diff_payload.get("diff", {}) if isinstance(diff_payload.get("diff"), dict) else {}
    issues: List[Dict[str, Any]] = []

    if not bool(diff_payload.get("changed", False)):
        issues.append(
            {
                "level": "info",
                "rule_id": "no_changes",
                "path": "",
                "message": "No effective config changes detected.",
            }
        )
    if bool(analysis.get("restart_required", False)):
        issues.append(
            {
                "level": "warning",
                "rule_id": "restart_required",
                "path": "",
                "message": "Changes require restart for full effect.",
            }
        )
    if bool(analysis.get("reload_required", False)) and not bool(analysis.get("restart_required", False)):
        issues.append(
            {
                "level": "info",
                "rule_id": "reload_recommended",
                "path": "",
                "message": "Changes are reloadable without restart.",
            }
        )
    modified_count = int(diff_obj.get("modified_count", 0) or 0)
    if modified_count > 50:
        issues.append(
            {
                "level": "warning",
                "rule_id": "large_change_set",
                "path": "",
                "message": f"Large change set detected ({modified_count} modified paths).",
            }
        )

    return {
        "status": "ok",
        "path": diff_payload.get("path"),
        "changed": bool(diff_payload.get("changed", False)),
        "issues": issues,
        "analysis": analysis,
        "diff_summary": {
            "added_count": int(diff_obj.get("added_count", 0) or 0),
            "removed_count": int(diff_obj.get("removed_count", 0) or 0),
            "modified_count": modified_count,
        },
    }


def execute_query_log_export(
    *,
    store: object | None,
    filters: Dict[str, Any],
    export_format: str,
    limit: int,
) -> Dict[str, Any]:
    """Brief: Export query-log rows via existing select_query_log pagination.

    Inputs:
      - store: Query-log store object.
      - filters: Filter mapping (client_ip/qtype/qname/rcode/status/source/ede_code/start_ts/end_ts).
      - export_format: One of jsonl/csv.
      - limit: Maximum rows to export.

    Outputs:
      - Dict containing export rows and text payload.
    """

    if store is None or not callable(getattr(store, "select_query_log", None)):
        raise AdminLogicHttpError(status_code=404, detail="query_log store unavailable")

    fmt = str(export_format or "jsonl").strip().lower()
    if fmt not in {"jsonl", "csv"}:
        raise AdminLogicHttpError(status_code=400, detail="format must be jsonl or csv")
    max_rows = max(1, min(int(limit or 1000), 100000))
    page_size = min(1000, max_rows)
    page = 1
    rows: List[Dict[str, Any]] = []

    while len(rows) < max_rows:
        try:
            payload = store.select_query_log(
                client_ip=filters.get("client_ip"),
                qtype=filters.get("qtype"),
                qname=filters.get("qname"),
                rcode=filters.get("rcode"),
                status=filters.get("status"),
                source=filters.get("source"),
                ede_code=filters.get("ede_code"),
                start_ts=filters.get("start_ts"),
                end_ts=filters.get("end_ts"),
                page=page,
                page_size=page_size,
            )
        except Exception as exc:
            raise AdminLogicHttpError(status_code=500, detail=f"query_log export failed: {exc}") from exc

        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list) or not items:
            break
        for item in items:
            if isinstance(item, dict):
                rows.append(dict(item))
            if len(rows) >= max_rows:
                break
        if len(items) < page_size:
            break
        page += 1

    if fmt == "jsonl":
        lines = [json.dumps(row, sort_keys=True, default=str) for row in rows]
        return {
            "status": "ok",
            "format": "jsonl",
            "count": len(rows),
            "truncated": len(rows) >= max_rows,
            "content_type": "application/x-ndjson",
            "data": "\n".join(lines),
        }

    csv_columns = ["id", "ts", "timestamp", "client_ip", "qname", "qtype", "rcode", "status", "upstream_id", "error", "first"]
    csv_lines = [",".join(csv_columns)]
    for row in rows:
        values = []
        for col in csv_columns:
            raw = row.get(col)
            text = str(raw) if raw is not None else ""
            text = text.replace('"', '""')
            if "," in text or "\n" in text or '"' in text:
                text = f'"{text}"'
            values.append(text)
        csv_lines.append(",".join(values))
    return {
        "status": "ok",
        "format": "csv",
        "count": len(rows),
        "truncated": len(rows) >= max_rows,
        "content_type": "text/csv",
        "data": "\n".join(csv_lines),
    }


def execute_query_log_compact(
    *,
    store: object | None,
    mode: str,
    dry_run: bool,
) -> Dict[str, Any]:
    """Brief: Run query-log backend maintenance operations.

    Inputs:
      - store: Query-log store object.
      - mode: One of vacuum/optimize/prune_only.
      - dry_run: Whether to report only without mutating.

    Outputs:
      - Dict containing maintenance outcome.
    """

    if store is None:
        raise AdminLogicHttpError(status_code=404, detail="query_log store unavailable")
    mode_text = str(mode or "vacuum").strip().lower()
    if mode_text not in {"vacuum", "optimize", "prune_only"}:
        raise AdminLogicHttpError(status_code=400, detail="mode must be vacuum, optimize, or prune_only")

    if str(type(store).__name__) != "StatsSQLiteStore":
        raise AdminLogicHttpError(status_code=400, detail="query_log compact is supported only for sqlite backend")

    conn = getattr(store, "_conn", None)
    if conn is None:
        raise AdminLogicHttpError(status_code=500, detail="sqlite backend connection unavailable")
    lock = getattr(store, "_lock", None)
    if lock is None:
        raise AdminLogicHttpError(status_code=500, detail="sqlite backend lock unavailable")

    def _count_rows() -> int:
        cur = conn.execute("SELECT COUNT(1) FROM query_log")
        row = cur.fetchone()
        return int(row[0] or 0) if row else 0  # pragma: nocover - COUNT(1) in sqlite returns a row unless cursor/driver is corrupted

    with lock:
        try:
            if bool(getattr(store, "_batch_writes", False)):
                flush_fn = getattr(store, "_flush_locked", None)
                if callable(flush_fn):
                    flush_fn()
            before_rows = _count_rows()
            if dry_run:
                return {"status": "ok", "mode": mode_text, "dry_run": True, "before_rows": before_rows, "after_rows": before_rows}
            if mode_text == "vacuum":
                conn.execute("VACUUM")
            elif mode_text == "optimize":
                conn.execute("PRAGMA optimize")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            after_rows = _count_rows()
            return {"status": "ok", "mode": mode_text, "dry_run": False, "before_rows": before_rows, "after_rows": after_rows}
        except Exception as exc:
            raise AdminLogicHttpError(status_code=500, detail=f"query_log compact failed: {exc}") from exc


def execute_rate_limit_hot_keys(
    *,
    plugins: Iterable[object],
    plugin_name: str | None,
    limit: int,
) -> Dict[str, Any]:
    """Brief: Return current/highest RPS keys from RateLimit plugin state.

    Inputs:
      - plugins: Loaded plugin instances.
      - plugin_name: Optional plugin instance filter.
      - limit: Maximum rows.

    Outputs:
      - Dict with per-plugin hot-key rows.
    """

    targets = _find_plugins_by_class_name(plugins, "RateLimit")
    if plugin_name is not None and str(plugin_name).strip():
        n = str(plugin_name).strip()
        targets = [p for p in targets if str(getattr(p, "name", "")) == n]
    if not targets:
        raise AdminLogicHttpError(status_code=404, detail="rate-limit plugin not found")

    lim = max(1, min(int(limit or 50), 1000))
    out_items: List[Dict[str, Any]] = []
    for plugin in targets:
        snapshot_fn = getattr(plugin, "_get_current_window_rps_snapshot", None)
        rps_rows: Dict[str, float] = {}
        if callable(snapshot_fn):
            try:
                raw = snapshot_fn(limit=int(lim * 4))
                if isinstance(raw, dict):
                    rps_rows = {str(k): float(v or 0.0) for k, v in raw.items()}
            except Exception:
                rps_rows = {}

        profile_meta: Dict[str, Dict[str, Any]] = {}
        db_lock = getattr(plugin, "_db_lock", None)
        conn = getattr(plugin, "_conn", None)
        if db_lock is not None and conn is not None:
            try:
                with db_lock:
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT key, avg_rps, max_rps, samples, last_update FROM rate_profiles WHERE key != ?",
                        ("global",),
                    )
                    for key, avg_rps, max_rps, samples, last_update in list(cur.fetchall() or []):
                        profile_meta[str(key)] = {
                            "avg_rps": float(avg_rps or 0.0),
                            "max_rps": float(max_rps or 0.0),
                            "samples": int(samples or 0),
                            "last_update": int(last_update or 0),
                        }
            except Exception:
                profile_meta = {}

        combined_keys = set(rps_rows.keys()) | set(profile_meta.keys())
        rows: List[Dict[str, Any]] = []
        for key_text in combined_keys:
            meta = profile_meta.get(key_text, {})
            last_update_ts = int(meta.get("last_update", 0) or 0)
            rows.append(
                {
                    "key": str(key_text),
                    "current_rps": float(rps_rows.get(key_text, 0.0)),
                    "avg_rps": float(meta.get("avg_rps", 0.0) or 0.0),
                    "max_rps": float(meta.get("max_rps", 0.0) or 0.0),
                    "samples": int(meta.get("samples", 0) or 0),
                    "last_seen_ts": last_update_ts,
                    "last_seen": _ts_to_utc_iso(float(last_update_ts)) if last_update_ts > 0 else None,
                    "denies": 0,
                }
            )
        rows.sort(key=lambda r: (float(r.get("current_rps", 0.0)), float(r.get("avg_rps", 0.0))), reverse=True)
        out_items.append({"plugin": str(getattr(plugin, "name", "RateLimit")), "items": rows[:lim]})

    return {"status": "ok", "items": out_items}


def execute_rate_limit_reset_counters(
    *,
    plugins: Iterable[object],
    plugin_name: str | None,
) -> Dict[str, Any]:
    """Brief: Reset in-memory RateLimit counters while preserving persisted profiles.

    Inputs:
      - plugins: Loaded plugin instances.
      - plugin_name: Optional plugin instance name filter.

    Outputs:
      - Dict with per-plugin reset summary.
    """

    targets = _find_plugins_by_class_name(plugins, "RateLimit")
    if plugin_name is not None and str(plugin_name).strip():
        n = str(plugin_name).strip()
        targets = [p for p in targets if str(getattr(p, "name", "")) == n]
    if not targets:
        raise AdminLogicHttpError(status_code=404, detail="rate-limit plugin not found")

    out_items: List[Dict[str, Any]] = []
    for plugin in targets:
        active_count = 0
        active_lock = getattr(plugin, "_active_window_lock", None)
        active_map = getattr(plugin, "_active_window_counts", None)
        if active_lock is not None and isinstance(active_map, dict):
            with active_lock:
                active_count = len(active_map)
                active_map.clear()
                setattr(plugin, "_active_window_id", None)

        for attr in ["_deny_episode_count", "_burst_exceeded_count", "_below_threshold_count"]:
            m = getattr(plugin, attr, None)
            if isinstance(m, dict):
                m.clear()

        out_items.append(
            {
                "plugin": str(getattr(plugin, "name", "RateLimit")),
                "active_window_keys_cleared": int(active_count),
            }
        )
    return {"status": "ok", "items": out_items}


def execute_records_list(
    *,
    runtime_state: object | None,
    target: str,
    plugin_name: str,
    include_expired: bool = True,
    limit: int = 500,
) -> Dict[str, Any]:
    """Brief: List tracked temporary records for one plugin/target.

    Inputs:
      - runtime_state: Optional admin runtime state.
      - target: Record target namespace.
      - plugin_name: Plugin instance name.
      - include_expired: Whether expired items are included.
      - limit: Maximum rows.

    Outputs:
      - Dict with temporary-record rows.
    """

    if runtime_state is None:
        return {"status": "ok", "items": [], "count": 0}
    list_fn = getattr(runtime_state, "list_temporary_records", None)
    if not callable(list_fn):
        return {"status": "ok", "items": [], "count": 0}
    try:
        raw = list_fn(
            target=str(target),
            plugin=str(plugin_name),
            include_expired=bool(include_expired),
            limit=int(limit),
        )
    except Exception as exc:
        raise AdminLogicHttpError(status_code=500, detail=f"failed to list temporary records: {exc}") from exc
    items = [dict(it) for it in raw if isinstance(it, dict)] if isinstance(raw, list) else []
    for item in items:
        expires_at_ts = float(item.get("expires_at_ts", 0.0) or 0.0)
        created_at_ts = float(item.get("created_at_ts", 0.0) or 0.0)
        updated_at_ts = float(item.get("updated_at_ts", 0.0) or 0.0)
        item["expires_at"] = _ts_to_utc_iso(expires_at_ts) if expires_at_ts > 0.0 else None
        item["created_at"] = _ts_to_utc_iso(created_at_ts) if created_at_ts > 0.0 else None
        item["updated_at"] = _ts_to_utc_iso(updated_at_ts) if updated_at_ts > 0.0 else None
    return {"status": "ok", "items": items, "count": len(items)}


def execute_records_purge_expired(
    *,
    runtime_state: object | None,
    plugins: Iterable[object],
    target: str,
    plugin_name: str,
) -> Dict[str, Any]:
    """Brief: Purge expired tracked temporary records and delete plugin entries.

    Inputs:
      - runtime_state: Optional admin runtime state.
      - plugins: Loaded plugin instances.
      - target: Record target namespace.
      - plugin_name: Plugin instance name.

    Outputs:
      - Dict summarizing removed/failed items.
    """

    if runtime_state is None:
        return {"status": "ok", "removed": 0, "failed": 0, "items": []}
    purge_fn = getattr(runtime_state, "purge_expired_temporary_records", None)
    if not callable(purge_fn):
        return {"status": "ok", "removed": 0, "failed": 0, "items": []}

    plugin = find_plugin_instance_by_name(plugins, plugin_name)
    if plugin is None:
        raise AdminLogicHttpError(status_code=404, detail="plugin not found")

    try:
        raw_items = purge_fn()
    except Exception as exc:
        raise AdminLogicHttpError(status_code=500, detail=f"failed to purge expired records: {exc}") from exc
    candidates = [dict(it) for it in raw_items if isinstance(it, dict)]
    candidates = [it for it in candidates if str(it.get("target", "")) == str(target) and str(it.get("plugin", "")) == str(plugin_name)]

    removed = 0
    failed = 0
    out_items: List[Dict[str, Any]] = []
    for item in candidates:
        payload = item.get("payload", {}) if isinstance(item.get("payload"), dict) else {}
        try:
            if str(target) == "etc_hosts":
                delete_fn = getattr(plugin, "admin_delete_record_mutation", None)
                if not callable(delete_fn):
                    raise ValueError("etc_hosts delete unsupported")
                delete_fn(
                    name=str(payload.get("name", "")),
                    persist=False,
                    file_path=None,
                )
            else:
                delete_fn = getattr(plugin, "admin_delete_record_mutation", None)
                if not callable(delete_fn):
                    raise ValueError("zone_records delete unsupported")
                delete_fn(
                    owner=str(payload.get("owner", "")),
                    qtype=payload.get("qtype"),
                    value=payload.get("value"),
                    persist=False,
                    file_path=None,
                )
            removed += 1
            out_items.append({"key": item.get("key"), "status": "removed"})
        except Exception as exc:
            failed += 1
            out_items.append({"key": item.get("key"), "status": "failed", "detail": str(exc)})
    return {"status": "ok", "removed": int(removed), "failed": int(failed), "items": out_items}


def build_admin_diag_runtime_snapshot(
    *,
    cfg: Dict[str, Any],
    config_path: str | None,
    stats_collector: object | None,
    plugins: Iterable[object],
    runtime_state: object | None,
) -> Dict[str, Any]:
    """Brief: Build compact diagnostics payload for runtime triage.

    Inputs:
      - cfg: Current runtime config mapping.
      - config_path: Active config path.
      - stats_collector: Optional stats collector.
      - plugins: Loaded plugins.
      - runtime_state: Optional admin runtime state.

    Outputs:
      - Dict with compact status/capabilities/restart/task summaries.
    """

    status_payload = build_admin_status_payload(
        cfg=cfg,
        config_path=config_path,
        stats_collector=stats_collector,
        plugins=plugins,
        admin_runtime_state=runtime_state,
    )
    capabilities_payload = build_admin_capabilities_payload(
        stats_collector=stats_collector,
        plugins=plugins,
    )
    restart_payload = build_admin_restart_status_payload(runtime_state=runtime_state)
    tasks_payload = build_admin_tasks_payload(
        runtime_state=runtime_state,
        limit=20,
        task_type=None,
        status=None,
    )
    return {
        "status": "ok",
        "status_overview": status_payload,
        "capabilities": capabilities_payload,
        "restart": restart_payload,
        "tasks": tasks_payload.get("items", []),
    }


def execute_records_apply(
    *,
    plugins: Iterable[object],
    target: str,
    plugin_name: str,
    payload: Dict[str, Any],
    runtime_state: object | None = None,
) -> Dict[str, Any]:
    """Brief: Apply etc_hosts/zone_records mutation request.

    Inputs:
      - plugins: Loaded plugin instances.
      - target: One of 'etc_hosts' or 'zone_records'.
      - plugin_name: Target plugin instance name.
      - payload: Request payload.
      - runtime_state: Optional runtime-state object used for temporary-record tracking.

    Outputs:
      - Dict with apply result.
    """

    plugin = find_plugin_instance_by_name(plugins, plugin_name)
    if plugin is None:
        raise AdminLogicHttpError(status_code=404, detail="plugin not found")
    persist = bool(payload.get("persist", False))
    ttl_seconds = int(payload.get("ttl", 300) or 300)
    file_path = payload.get("file_path")
    if target == "etc_hosts":
        fn = getattr(plugin, "admin_apply_record_mutation", None)
        if not callable(fn):
            raise AdminLogicHttpError(
                status_code=400, detail="etc_hosts apply unsupported"
            )
        try:
            out = fn(
                name=str(payload.get("name", "")),
                value=str(payload.get("value", "")),
                persist=persist,
                file_path=(str(file_path) if file_path is not None else None),
            )
        except Exception as exc:
            raise AdminLogicHttpError(status_code=400, detail=str(exc)) from exc
        result_payload = {"status": "ok", "target": target, "plugin": plugin_name, "result": out}
        if runtime_state is not None:
            key_text = _build_temporary_record_tracking_key(
                target=target,
                plugin_name=plugin_name,
                payload=payload,
            )
            if persist:
                remove_fn = getattr(runtime_state, "remove_temporary_record", None)
                if callable(remove_fn):
                    try:
                        remove_fn(key=key_text)
                    except Exception:  # pragma: nocover - best-effort state cleanup must not fail request
                        pass
            else:
                upsert_fn = getattr(runtime_state, "upsert_temporary_record", None)
                if callable(upsert_fn):
                    try:
                        upsert_fn(
                            key=key_text,
                            target=str(target),
                            plugin=str(plugin_name),
                            payload={"name": str(payload.get("name", ""))},
                            ttl_seconds=int(ttl_seconds),
                            persist=False,
                        )
                    except Exception:  # pragma: nocover - best-effort state tracking must not fail request
                        pass
        return result_payload
    if target == "zone_records":
        fn = getattr(plugin, "admin_apply_record_mutation", None)
        if not callable(fn):
            raise AdminLogicHttpError(
                status_code=400, detail="zone_records apply unsupported"
            )
        try:
            out = fn(
                owner=str(payload.get("owner", "")),
                qtype=payload.get("qtype", ""),
                value=str(payload.get("value", "")),
                ttl=int(payload.get("ttl", 300) or 300),
                persist=persist,
                file_path=(str(file_path) if file_path is not None else None),
            )
        except Exception as exc:
            raise AdminLogicHttpError(status_code=400, detail=str(exc)) from exc
        result_payload = {"status": "ok", "target": target, "plugin": plugin_name, "result": out}
        if runtime_state is not None:
            key_text = _build_temporary_record_tracking_key(
                target=target,
                plugin_name=plugin_name,
                payload=payload,
            )
            if persist:
                remove_fn = getattr(runtime_state, "remove_temporary_record", None)
                if callable(remove_fn):
                    try:
                        remove_fn(key=key_text)
                    except Exception:  # pragma: nocover - best-effort state cleanup must not fail request
                        pass
            else:
                upsert_fn = getattr(runtime_state, "upsert_temporary_record", None)
                if callable(upsert_fn):
                    try:
                        upsert_fn(
                            key=key_text,
                            target=str(target),
                            plugin=str(plugin_name),
                            payload={
                                "owner": str(payload.get("owner", "")),
                                "qtype": payload.get("qtype"),
                                "value": str(payload.get("value", "")),
                            },
                            ttl_seconds=int(ttl_seconds),
                            persist=False,
                        )
                    except Exception:  # pragma: nocover - best-effort state tracking must not fail request
                        pass
        return result_payload
    raise AdminLogicHttpError(status_code=400, detail="unknown records target")


def execute_records_delete(
    *,
    plugins: Iterable[object],
    target: str,
    plugin_name: str,
    payload: Dict[str, Any],
    runtime_state: object | None = None,
) -> Dict[str, Any]:
    """Brief: Delete etc_hosts/zone_records mutation target entries.

    Inputs:
      - plugins: Loaded plugin instances.
      - target: One of 'etc_hosts' or 'zone_records'.
      - plugin_name: Target plugin instance name.
      - payload: Request payload.
      - runtime_state: Optional runtime-state object used for temporary-record cleanup.

    Outputs:
      - Dict with delete result.
    """

    plugin = find_plugin_instance_by_name(plugins, plugin_name)
    if plugin is None:
        raise AdminLogicHttpError(status_code=404, detail="plugin not found")
    persist = bool(payload.get("persist", False))
    file_path = payload.get("file_path")
    if target == "etc_hosts":
        fn = getattr(plugin, "admin_delete_record_mutation", None)
        if not callable(fn):
            raise AdminLogicHttpError(
                status_code=400, detail="etc_hosts delete unsupported"
            )
        try:
            out = fn(
                name=str(payload.get("name", "")),
                persist=persist,
                file_path=(str(file_path) if file_path is not None else None),
            )
        except Exception as exc:
            raise AdminLogicHttpError(status_code=400, detail=str(exc)) from exc
        result_payload = {"status": "ok", "target": target, "plugin": plugin_name, "result": out}
        if runtime_state is not None:
            key_text = _build_temporary_record_tracking_key(
                target=target,
                plugin_name=plugin_name,
                payload=payload,
            )
            remove_fn = getattr(runtime_state, "remove_temporary_record", None)
            if callable(remove_fn):
                try:
                    remove_fn(key=key_text)
                except Exception:  # pragma: nocover - best-effort state cleanup must not fail request
                    pass
        return result_payload
    if target == "zone_records":
        fn = getattr(plugin, "admin_delete_record_mutation", None)
        if not callable(fn):
            raise AdminLogicHttpError(
                status_code=400, detail="zone_records delete unsupported"
            )
        try:
            out = fn(
                owner=str(payload.get("owner", "")),
                qtype=payload.get("qtype"),
                value=payload.get("value"),
                persist=persist,
                file_path=(str(file_path) if file_path is not None else None),
            )
        except Exception as exc:
            raise AdminLogicHttpError(status_code=400, detail=str(exc)) from exc
        result_payload = {"status": "ok", "target": target, "plugin": plugin_name, "result": out}
        if runtime_state is not None:
            remove_fn = getattr(runtime_state, "remove_temporary_record", None)
            list_fn = getattr(runtime_state, "list_temporary_records", None)
            if callable(remove_fn):
                if str(payload.get("qtype", "")).strip() or str(payload.get("value", "")).strip():
                    key_text = _build_temporary_record_tracking_key(
                        target=target,
                        plugin_name=plugin_name,
                        payload=payload,
                    )
                    try:
                        remove_fn(key=key_text)
                    except Exception:  # pragma: nocover - best-effort state cleanup must not fail request
                        pass
                elif callable(list_fn):
                    try:
                        raw_items = list_fn(
                            target=str(target),
                            plugin=str(plugin_name),
                            include_expired=True,
                            limit=5000,
                        )
                    except Exception:  # pragma: nocover - best-effort listing fallback
                        raw_items = []
                    owner_norm = dns_names.normalize_name(str(payload.get("owner", "")))
                    if isinstance(raw_items, list):
                        for item in raw_items:
                            if not isinstance(item, dict):
                                continue
                            payload_map = item.get("payload", {})
                            if not isinstance(payload_map, dict):
                                continue
                            if dns_names.normalize_name(str(payload_map.get("owner", ""))) != owner_norm:
                                continue
                            key_text = str(item.get("key", "")).strip()
                            if not key_text:
                                continue
                            try:
                                remove_fn(key=key_text)
                            except Exception:  # pragma: nocover - best-effort per-key cleanup
                                continue
        return result_payload
    raise AdminLogicHttpError(status_code=400, detail="unknown records target")
