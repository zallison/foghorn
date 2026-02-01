from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi import status

import sys as _sys

from ...stats import StatsCollector
from .config_helpers import (
    _get_redact_keys,
    _get_config_raw_text,
    _get_config_raw_json,
    _ts_to_utc_iso,
    _parse_utc_datetime,
    sanitize_config,
    _get_sanitized_config_yaml_cached,
)
from .runtime import RuntimeState, evaluate_readiness
from .stats_helpers import _utc_now_iso


def _json_safe(value: Any) -> Any:
    """Return a JSON-serializable representation of value.

    This delegates to the canonical implementation in _core while avoiding a
    top-level import that would recreate the circular dependency between
    routes_core and _core.
    """

    import importlib

    web_core = importlib.import_module("foghorn.servers.webserver._core")
    return web_core._json_safe(value)


def _schedule_sighup_after_config_save(delay_seconds: float = 1.0) -> None:
    """Schedule SIGHUP delivery using the helper defined in _core.

    A small wrapper is used here so that FastAPI routes can trigger the shared
    behaviour without importing _core at module import time.
    """

    import importlib

    web_core = importlib.import_module("foghorn.servers.webserver._core")
    web_core._schedule_sighup_after_config_save(delay_seconds=delay_seconds)


def _get_about_payload() -> Dict[str, Any]:
    """Build the /about payload using the canonical helper from _core."""

    import importlib

    web_core = importlib.import_module("foghorn.servers.webserver._core")
    return web_core._get_about_payload()


def _register_core_routes(app: FastAPI) -> None:
    """Register core health/about/ready endpoints on the FastAPI app."""

    @app.get("/api/v1/health")
    @app.get("/health")
    async def health() -> Dict[str, Any]:
        return {"status": "ok", "server_time": _utc_now_iso()}

    @app.get("/api/v1/about")
    @app.get("/about")
    async def about() -> Dict[str, Any]:
        return _get_about_payload()

    @app.get("/api/v1/status")
    @app.get("/status")
    @app.get("/api/v1/ready")
    @app.get("/ready")
    async def ready() -> JSONResponse:
        state: RuntimeState | None = getattr(app.state, "runtime_state", None)
        ready_ok, _not_ready, details = evaluate_readiness(
            stats=getattr(app.state, "stats_collector", None),
            config=getattr(app.state, "config", None),
            runtime_state=state,
        )
        payload = {
            "server_time": _utc_now_iso(),
            "ready": bool(ready_ok),
            "details": details,
        }
        return JSONResponse(
            content=_json_safe(payload), status_code=200 if ready_ok else 503
        )


def _register_config_routes(app: FastAPI, auth_dep: Any) -> None:
    """Register configuration management endpoints."""

    @app.get("/api/v1/config", dependencies=[Depends(auth_dep)])
    @app.get("/apti/v1/config", dependencies=[Depends(auth_dep)])
    @app.get("/config", dependencies=[Depends(auth_dep)])
    async def get_config() -> PlainTextResponse:
        cfg = app.state.config or {}
        redact_keys = _get_redact_keys(cfg)
        cfg_path = getattr(app.state, "config_path", None)
        body = _get_sanitized_config_yaml_cached(cfg, cfg_path, redact_keys)
        return PlainTextResponse(body, media_type="application/x-yaml")

    @app.get("/api/v1/config/raw", dependencies=[Depends(auth_dep)])
    @app.get("/config/raw", dependencies=[Depends(auth_dep)])
    async def get_config_raw() -> PlainTextResponse:
        cfg_path = getattr(app.state, "config_path", None)
        if not cfg_path:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="config_path not configured",
            )
        try:
            raw_text = _get_config_raw_text(cfg_path)
        except (
            Exception
        ) as exc:  # pragma: no cover - I/O errors are environment-specific
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to read config from {cfg_path}: {exc}",
            ) from exc
        return PlainTextResponse(raw_text, media_type="application/x-yaml")

    @app.get("/api/v1/config.json", dependencies=[Depends(auth_dep)])
    @app.get("/apti/v1/config.json", dependencies=[Depends(auth_dep)])
    @app.get("/config.json", dependencies=[Depends(auth_dep)])
    async def get_config_json() -> Dict[str, Any]:
        cfg = app.state.config or {}
        redact_keys = _get_redact_keys(cfg)
        clean = sanitize_config(cfg, redact_keys=redact_keys)
        return {"server_time": _utc_now_iso(), "config": clean}

    @app.get("/api/v1/config/raw.json", dependencies=[Depends(auth_dep)])
    @app.get("/config/raw.json", dependencies=[Depends(auth_dep)])
    async def get_config_raw_json() -> Dict[str, Any]:
        cfg_path = getattr(app.state, "config_path", None)
        if not cfg_path:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="config_path not configured",
            )
        try:
            raw = _get_config_raw_json(cfg_path)
        except (
            Exception
        ) as exc:  # pragma: no cover - I/O errors are environment-specific
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to read config from {cfg_path}: {exc}",
            ) from exc

        return {
            "server_time": _utc_now_iso(),
            "config": raw["config"],
            "raw_yaml": raw["raw_yaml"],
        }

    @app.post("/api/v1/config/save", dependencies=[Depends(auth_dep)])
    @app.post("/config/save", dependencies=[Depends(auth_dep)])
    async def save_config(body: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(body, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="request body must be a JSON object",
            )

        cfg_path = getattr(app.state, "config_path", None)
        if not cfg_path:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="config_path not configured",
            )

        cfg_path_abs = os.path.abspath(cfg_path)
        cfg_dir = os.path.dirname(cfg_path_abs)
        ts = datetime.now(timezone.utc).isoformat().replace(":", "-")
        backup_path = f"{cfg_path_abs}.bak.{ts}"
        tmp_path = os.path.join(cfg_dir, f".tmp-{os.path.basename(cfg_path_abs)}-{ts}")

        try:
            if os.path.exists(cfg_path_abs):
                shutil.copy(cfg_path_abs, backup_path)

            raw_yaml = body.get("raw_yaml")
            if not isinstance(raw_yaml, str):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="request body must include 'raw_yaml' string field",
                )

            with open(cfg_path_abs + ".new", "w", encoding="utf-8") as tmp:
                tmp.write(raw_yaml)

            shutil.copy(cfg_path_abs + ".new", cfg_path_abs)

        except Exception as exc:  # pragma: no cover - file system specific
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to write config to {cfg_path_abs}: {exc}",
            ) from exc

        _schedule_sighup_after_config_save(delay_seconds=0.1)

        return {
            "status": "ok",
            "server_time": _utc_now_iso(),
            "path": cfg_path_abs,
            "backed_up_to": backup_path,
        }


def _register_query_log_routes(app: FastAPI, auth_dep: Any) -> None:
    """Register query_log and query_log/aggregate endpoints."""

    @app.get("/api/v1/query_log", dependencies=[Depends(auth_dep)])
    @app.get("/query_log", dependencies=[Depends(auth_dep)])
    async def get_query_log(
        client_ip: str | None = None,
        qtype: str | None = None,
        qname: str | None = None,
        rcode: str | None = None,
        start: str | None = None,
        end: str | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        collector: Optional[StatsCollector] = app.state.stats_collector
        store = getattr(collector, "_store", None) if collector is not None else None
        if store is None:
            return {
                "status": "disabled",
                "server_time": _utc_now_iso(),
                "items": [],
                "total": 0,
                "page": int(page) if isinstance(page, int) else 1,
                "page_size": int(page_size) if isinstance(page_size, int) else 100,
                "total_pages": 0,
            }

        start_ts: float | None = None
        end_ts: float | None = None
        if start:
            try:
                start_ts = _parse_utc_datetime(start).timestamp()
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"invalid start datetime: {exc}",
                ) from exc
        if end:
            try:
                end_ts = _parse_utc_datetime(end).timestamp()
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"invalid end datetime: {exc}",
                ) from exc

        try:
            ps = int(page_size)
        except Exception:
            ps = 100
        if ps <= 0:
            ps = 100
        if ps > 1000:
            ps = 1000

        res = store.select_query_log(
            client_ip=client_ip,
            qtype=qtype,
            qname=qname,
            rcode=rcode,
            start_ts=start_ts,
            end_ts=end_ts,
            page=page,
            page_size=ps,
        )

        items = []
        for item in res.get("items", []) or []:
            if isinstance(item, dict) and "ts" in item:
                item = dict(item)
                item["timestamp"] = _ts_to_utc_iso(float(item.get("ts") or 0.0))
            items.append(item)

        return {
            "server_time": _utc_now_iso(),
            "total": res.get("total", 0),
            "page": res.get("page", 1),
            "page_size": res.get("page_size", ps),
            "total_pages": res.get("total_pages", 0),
            "items": items,
        }

    @app.get("/api/v1/query_log/aggregate", dependencies=[Depends(auth_dep)])
    async def get_query_log_aggregate(
        interval: int,
        interval_units: str,
        start: str,
        end: str,
        client_ip: str | None = None,
        qtype: str | None = None,
        qname: str | None = None,
        rcode: str | None = None,
        group_by: str | None = None,
    ) -> Dict[str, Any]:
        collector: Optional[StatsCollector] = app.state.stats_collector
        store = getattr(collector, "_store", None) if collector is not None else None
        if store is None:
            return {"status": "disabled", "server_time": _utc_now_iso(), "items": []}

        try:
            start_dt = _parse_utc_datetime(start)
            end_dt = _parse_utc_datetime(end)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

        try:
            interval_i = int(interval)
        except Exception:
            interval_i = 0
        if interval_i <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="interval must be a positive integer",
            )

        units = str(interval_units or "").strip().lower()
        unit_seconds = {
            "seconds": 1,
            "second": 1,
            "minutes": 60,
            "minute": 60,
            "hours": 3600,
            "hour": 3600,
            "days": 86400,
            "day": 86400,
        }.get(units)
        if not unit_seconds:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="interval_units must be one of seconds, minutes, hours, days",
            )

        interval_seconds = interval_i * int(unit_seconds)
        if interval_seconds <= 0:  # pragma: no cover - defensive
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="interval_seconds must be > 0",
            )

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

        items = []
        for item in res.get("items", []) or []:
            if isinstance(item, dict):
                out = dict(item)
                if "bucket_start_ts" in out:
                    out["bucket_start"] = _ts_to_utc_iso(
                        float(out.get("bucket_start_ts") or 0.0)
                    )
                if "bucket_end_ts" in out:
                    out["bucket_end"] = _ts_to_utc_iso(
                        float(out.get("bucket_end_ts") or 0.0)
                    )
                items.append(out)

        return {
            "server_time": _utc_now_iso(),
            "start": start_dt.isoformat().replace("+00:00", "Z"),
            "end": end_dt.isoformat().replace("+00:00", "Z"),
            "interval_seconds": interval_seconds,
            "items": items,
        }


def _register_plugin_routes(app: FastAPI, auth_dep: Any) -> None:
    """Register plugin-related admin, cache, logs, and snapshot endpoints."""

    from ...plugins.resolve.base import AdminPageSpec  # local to avoid cycles

    def _collect_admin_pages_for_response() -> list[dict[str, Any]]:
        plugins_list = getattr(app.state, "plugins", []) or []
        pages: list[dict[str, Any]] = []

        for plugin in plugins_list:
            try:
                plugin_name = getattr(plugin, "name", None)
            except Exception:
                plugin_name = None
            if not plugin_name:
                continue

            get_pages = getattr(plugin, "get_admin_pages", None)
            if not callable(get_pages):
                continue
            try:
                specs = get_pages()
            except Exception:
                continue

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
                except Exception:
                    continue

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

    def _find_admin_page_detail(
        plugin_name: str, page_slug: str
    ) -> dict[str, Any] | None:
        """Look up a specific admin page spec for a plugin.

        This mirrors the threaded helper in _core and consults app.state.plugins.
        """

        plugins_list = getattr(app.state, "plugins", []) or []
        target = None
        for plugin in plugins_list:
            try:
                if getattr(plugin, "name", None) == plugin_name:
                    target = plugin
                    break
            except Exception:
                continue
        if target is None:
            return None

        get_pages = getattr(target, "get_admin_pages", None)
        if not callable(get_pages):
            return None

        try:
            specs = get_pages()
        except Exception:
            return None

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
            except Exception:
                continue

            slug_str = str(slug or "").strip()
            if slug_str != page_slug:
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

    def _collect_plugin_ui_descriptors() -> list[dict[str, Any]]:
        def _normalise_descriptor(
            source: object, desc: dict[str, Any]
        ) -> dict[str, Any] | None:
            try:
                name = getattr(source, "name", None)
            except Exception:
                name = None
            try:
                order_raw = desc.get("order", 100)
                order = int(order_raw) if order_raw is not None else 100
            except Exception:
                order = 100

            title = desc.get("title")
            kind = desc.get("kind")
            if not title:
                return None

            item: dict[str, Any] = dict(desc)
            item["name"] = name
            item["title"] = title
            item["kind"] = str(kind) if kind is not None else None
            item["order"] = order
            return item

        plugins_list = getattr(app.state, "plugins", []) or []
        items: list[dict[str, Any]] = []
        for plugin in plugins_list:
            try:
                get_desc = getattr(plugin, "get_admin_ui_descriptor", None)
            except Exception:
                continue
            if not callable(get_desc):
                continue
            try:
                desc = get_desc()
            except Exception:
                continue

            if isinstance(desc, dict):
                item = _normalise_descriptor(plugin, desc)  # type: ignore[arg-type]
                if item is not None:
                    items.append(item)

        # Also surface the global DNS cache plugin when it exposes admin UI.
        try:
            from ..plugins.resolve import base as plugin_base  # type: ignore

            cache = getattr(plugin_base, "DNS_CACHE", None)
        except Exception:
            cache = None

        if cache is not None:
            try:
                get_desc = getattr(cache, "get_admin_ui_descriptor", None)
            except Exception:
                get_desc = None
            if callable(get_desc):
                try:
                    desc = get_desc()
                except Exception:
                    desc = None
                if isinstance(desc, dict):
                    item = _normalise_descriptor(cache, desc)  # type: ignore[arg-type]
                    if item is not None:
                        items.append(item)

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

        items.sort(
            key=lambda d: (int(d.get("order", 100) or 100), str(d.get("title", "")))
        )
        return items

    @app.get("/api/v1/plugin_pages", dependencies=[Depends(auth_dep)])
    async def list_plugin_pages() -> Dict[str, Any]:
        pages = _collect_admin_pages_for_response()
        return {"server_time": _utc_now_iso(), "pages": _json_safe(pages)}

    @app.get("/api/v1/plugins/ui", dependencies=[Depends(auth_dep)])
    async def list_plugin_ui_descriptors() -> Dict[str, Any]:
        items = _collect_plugin_ui_descriptors()
        return {"server_time": _utc_now_iso(), "items": _json_safe(items)}

    @app.get("/api/v1/cache", dependencies=[Depends(auth_dep)])
    async def get_cache_snapshot() -> Dict[str, Any]:
        cache_mod = _sys.modules.get("foghorn.plugins.resolve.base")
        cache = getattr(cache_mod, "DNS_CACHE", None) if cache_mod is not None else None
        if cache is None or not hasattr(cache, "get_http_snapshot"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="cache plugin not found or does not expose get_http_snapshot",
            )

        try:
            snapshot = cache.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to build cache snapshot: {exc}",
            ) from exc

        cache_name = getattr(cache, "name", None) or cache.__class__.__name__

        return {
            "server_time": _utc_now_iso(),
            "cache": str(cache_name),
            "data": _json_safe(snapshot),
        }

    @app.get(
        "/api/v1/plugin_pages/{plugin_name}/{page_slug}",
        dependencies=[Depends(auth_dep)],
    )
    async def get_plugin_page_detail(
        plugin_name: str, page_slug: str
    ) -> Dict[str, Any]:
        detail = _find_admin_page_detail(plugin_name, page_slug)
        if detail is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="plugin page not found",
            )
        out: Dict[str, Any] = {
            "server_time": _utc_now_iso(),
            "page": _json_safe(detail),
        }
        return out

    @app.get("/api/v1/logs", dependencies=[Depends(auth_dep)])
    @app.get("/logs", dependencies=[Depends(auth_dep)])
    async def get_logs(limit: int = 100) -> Dict[str, Any]:
        buf = app.state.log_buffer
        entries = buf.snapshot(limit=max(0, int(limit)))
        return {"server_time": _utc_now_iso(), "entries": entries}

    @app.get(
        "/api/v1/plugins/{plugin_name}/docker_hosts", dependencies=[Depends(auth_dep)]
    )
    async def get_docker_hosts_snapshot(plugin_name: str) -> Dict[str, Any]:
        plugins_list = getattr(app.state, "plugins", []) or []
        target = None
        for p in plugins_list:
            try:
                if getattr(p, "name", None) == plugin_name:
                    target = p
                    break
            except Exception:
                continue

        if target is None or not hasattr(target, "get_http_snapshot"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="plugin not found or does not expose get_http_snapshot",
            )

        try:
            snapshot = target.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to build DockerHosts snapshot: {exc}",
            ) from exc

        return {
            "server_time": _utc_now_iso(),
            "plugin": plugin_name,
            "data": _json_safe(snapshot),
        }

    @app.get(
        "/api/v1/plugins/{plugin_name}/etc_hosts", dependencies=[Depends(auth_dep)]
    )
    async def get_etc_hosts_snapshot(plugin_name: str) -> Dict[str, Any]:
        plugins_list = getattr(app.state, "plugins", []) or []
        target = None
        for p in plugins_list:
            try:
                if getattr(p, "name", None) == plugin_name:
                    target = p
                    break
            except Exception:
                continue

        if target is None or not hasattr(target, "get_http_snapshot"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="plugin not found or does not expose get_http_snapshot",
            )

        try:
            snapshot = target.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to build EtcHosts snapshot: {exc}",
            ) from exc

        return {
            "server_time": _utc_now_iso(),
            "plugin": plugin_name,
            "data": _json_safe(snapshot),
        }

    @app.get("/api/v1/plugins/{plugin_name}/mdns", dependencies=[Depends(auth_dep)])
    async def get_mdns_snapshot(plugin_name: str) -> Dict[str, Any]:
        plugins_list = getattr(app.state, "plugins", []) or []
        target = None
        for p in plugins_list:
            try:
                if getattr(p, "name", None) == plugin_name:
                    target = p
                    break
            except Exception:
                continue

        if target is None or not hasattr(target, "get_http_snapshot"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="plugin not found or does not expose get_http_snapshot",
            )

        try:
            snapshot = target.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to build MdnsBridge snapshot: {exc}",
            ) from exc

        return {
            "server_time": _utc_now_iso(),
            "plugin": plugin_name,
            "data": _json_safe(snapshot),
        }
