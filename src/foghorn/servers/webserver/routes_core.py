from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from . import admin_logic as _admin_logic
from . import config_persistence as _config_persistence

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi import status

import sys as _sys

from ...stats import StatsCollector
from .config_helpers import (
    _get_redact_keys,
    _get_config_raw_text,
    _get_config_raw_json,
    _parse_utc_datetime,
    sanitize_config,
    _get_sanitized_config_yaml_cached,
)
from .runtime import RuntimeState, evaluate_readiness
from .stats_helpers import _utc_now_iso


def _json_safe(value: Any) -> Any:
    """Return a JSON-serializable representation of value.

    This delegates to the canonical implementation in core while avoiding a
    top-level import that would recreate the circular dependency between
    routes_core and core.
    """

    import importlib

    web_core = importlib.import_module("foghorn.servers.webserver.core")
    return web_core._json_safe(value)


def _schedule_sighup_after_config_save(delay_seconds: float = 1.0) -> None:
    """Schedule SIGHUP delivery using the helper defined in core.

    A small wrapper is used here so that FastAPI routes can trigger the shared
    behaviour without importing core at module import time.
    """

    import importlib

    web_core = importlib.import_module("foghorn.servers.webserver.core")
    web_core._schedule_sighup_after_config_save(delay_seconds=delay_seconds)


def _get_about_payload() -> Dict[str, Any]:
    """Build the /about payload using the canonical helper from core."""

    import importlib

    web_core = importlib.import_module("foghorn.servers.webserver.core")
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
        ts = datetime.now(timezone.utc).isoformat().replace(":", "-")
        backup_path = f"{cfg_path_abs}.bak.{ts}"

        try:
            raw_yaml = body.get("raw_yaml")
            if not isinstance(raw_yaml, str):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="request body must include 'raw_yaml' string field",
                )

            # Preserve historic FastAPI behaviour: write to <cfg>.new and then
            # copy over the destination.
            _config_persistence.safe_write_raw_yaml(
                dst_path=cfg_path_abs,
                raw_yaml=raw_yaml,
                backup_path=backup_path,
                tmp_path=cfg_path_abs + ".new",
                strategy="copy",
                cleanup_tmp=False,
            )

        except Exception as exc:  # pragma: no cover - file system specific
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

        payload = _admin_logic.build_query_log_payload(
            store,
            client_ip=client_ip,
            qtype=qtype,
            qname=qname,
            rcode=rcode,
            start_ts=start_ts,
            end_ts=end_ts,
            page=int(page) if isinstance(page, int) else 1,
            page_size=ps,
        )
        payload["server_time"] = _utc_now_iso()
        return payload

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

        payload = _admin_logic.build_query_log_aggregate_payload(
            store,
            start_dt=start_dt,
            end_dt=end_dt,
            interval_seconds=int(interval_seconds),
            client_ip=client_ip,
            qtype=qtype,
            qname=qname,
            rcode=rcode,
            group_by=group_by,
        )
        payload["server_time"] = _utc_now_iso()
        return payload


def _register_plugin_routes(app: FastAPI, auth_dep: Any) -> None:
    """Register plugin-related admin, cache, logs, and snapshot endpoints."""

    def _collect_admin_pages_for_response() -> list[dict[str, Any]]:
        plugins_list = getattr(app.state, "plugins", []) or []
        return _admin_logic.collect_admin_pages_for_response(plugins_list)

    def _find_admin_page_detail(
        plugin_name: str, page_slug: str
    ) -> dict[str, Any] | None:
        """Look up a specific admin page spec for a plugin.

        Inputs:
          - plugin_name: target plugin instance name
          - page_slug: admin page slug

        Outputs:
          - dict if found, else None.
        """

        plugins_list = getattr(app.state, "plugins", []) or []
        return _admin_logic.find_admin_page_detail(plugins_list, plugin_name, page_slug)

    def _collect_plugin_ui_descriptors() -> list[dict[str, Any]]:
        plugins_list = list(getattr(app.state, "plugins", []) or [])

        # Optionally include the global DNS cache plugin when it exposes admin UI.
        try:
            from ...plugins.resolve import base as plugin_base  # local to avoid cycles

            cache = getattr(plugin_base, "DNS_CACHE", None)
        except Exception:
            cache = None

        if cache is not None:
            try:
                get_desc = getattr(cache, "get_admin_ui_descriptor", None)
            except Exception:
                get_desc = None
            if callable(get_desc):
                plugins_list.append(cache)

        return _admin_logic.collect_plugin_ui_descriptors(plugins_list)

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
        try:
            snap = _admin_logic.build_named_plugin_snapshot(
                plugins_list, plugin_name, label="DockerHosts"
            )
        except _admin_logic.AdminLogicHttpError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

        return {
            "server_time": _utc_now_iso(),
            "plugin": snap["plugin"],
            "data": _json_safe(snap["data"]),
        }

    @app.get(
        "/api/v1/plugins/{plugin_name}/etc_hosts", dependencies=[Depends(auth_dep)]
    )
    async def get_etc_hosts_snapshot(plugin_name: str) -> Dict[str, Any]:
        plugins_list = getattr(app.state, "plugins", []) or []
        try:
            snap = _admin_logic.build_named_plugin_snapshot(
                plugins_list, plugin_name, label="EtcHosts"
            )
        except _admin_logic.AdminLogicHttpError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

        return {
            "server_time": _utc_now_iso(),
            "plugin": snap["plugin"],
            "data": _json_safe(snap["data"]),
        }

    @app.get("/api/v1/plugins/{plugin_name}/mdns", dependencies=[Depends(auth_dep)])
    async def get_mdns_snapshot(plugin_name: str) -> Dict[str, Any]:
        plugins_list = getattr(app.state, "plugins", []) or []
        try:
            snap = _admin_logic.build_named_plugin_snapshot(
                plugins_list, plugin_name, label="MdnsBridge"
            )
        except _admin_logic.AdminLogicHttpError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

        return {
            "server_time": _utc_now_iso(),
            "plugin": snap["plugin"],
            "data": _json_safe(snap["data"]),
        }
