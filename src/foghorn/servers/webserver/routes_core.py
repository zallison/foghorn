from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from . import admin_logic as _admin_logic
from . import config_persistence as _config_persistence

from fastapi import Depends, FastAPI, HTTPException
from fastapi import File, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi import status

from ...utils.config_mermaid import (
    diagram_png_candidate_paths_for_config,
    diagram_mmd_candidate_paths_for_config,
    find_first_existing_path,
    stale_diagram_warning,
    generate_mermaid_text_from_config_path,
)

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

    @app.get("/api/v1/config/diagram.png", dependencies=[Depends(auth_dep)])
    @app.get("/config/diagram.png", dependencies=[Depends(auth_dep)])
    async def get_config_diagram_png(meta: int | None = None):
        """Serve the config diagram PNG (when available).

        Inputs:
          - meta: When truthy, do not return the PNG body; instead return an empty
            200 response with metadata headers.

        Outputs:
          - FileResponse (image/png) when the PNG exists and meta is not set.
          - PlainTextResponse (empty) when meta is set, with:
              - X-Foghorn-Exists: '1' or '0'
              - X-Foghorn-Warning (optional): staleness warning.
        """

        cfg_path = getattr(app.state, "config_path", None)
        if not cfg_path:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="config_path not configured",
            )

        # Allow a best-effort on-demand build attempt, but only once per config
        # signature for this process.
        try:
            st = os.stat(str(cfg_path))
            cfg_sig = f"{cfg_path}:{int(st.st_mtime_ns)}:{int(st.st_size)}"
        except Exception:
            cfg_sig = str(cfg_path)

        attempted_sig = getattr(app.state, "_config_diagram_build_attempt_sig", None)

        png_file = find_first_existing_path(
            diagram_png_candidate_paths_for_config(cfg_path)
        )

        # If missing and mmdc exists, attempt an on-demand build once.
        if png_file is None and attempted_sig != cfg_sig:
            from ...utils.config_mermaid import (
                _find_mmdc_cmd,
                ensure_config_diagram_png,
            )

            if _find_mmdc_cmd() is not None:
                setattr(app.state, "_config_diagram_build_attempt_sig", cfg_sig)
                ensure_config_diagram_png(config_path=str(cfg_path))
                png_file = find_first_existing_path(
                    diagram_png_candidate_paths_for_config(cfg_path)
                )

        warn: str | None = None
        if png_file is not None:
            warn = stale_diagram_warning(
                config_path=str(cfg_path), diagram_path=str(png_file)
            )

            # If stale and mmdc exists, try to refresh it in-place once.
            if (
                warn
                and getattr(app.state, "_config_diagram_build_attempt_sig", None)
                != cfg_sig
            ):
                from ...utils.config_mermaid import (
                    _find_mmdc_cmd,
                    ensure_config_diagram_png,
                )

                if _find_mmdc_cmd() is not None:
                    setattr(app.state, "_config_diagram_build_attempt_sig", cfg_sig)
                    ok, _detail, refreshed = ensure_config_diagram_png(
                        config_path=str(cfg_path)
                    )
                    if ok and refreshed:
                        from pathlib import Path

                        png_file = Path(str(refreshed))
                        warn = stale_diagram_warning(
                            config_path=str(cfg_path), diagram_path=str(png_file)
                        )

        headers: dict[str, str] = {
            "X-Foghorn-Exists": "1" if png_file is not None else "0",
        }

        if warn:
            headers["X-Foghorn-Warning"] = warn

        if meta:
            return PlainTextResponse("", media_type="text/plain", headers=headers)

        if png_file is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="config diagram not found",
            )

        return FileResponse(str(png_file), media_type="image/png", headers=headers)

    @app.post("/api/v1/config/diagram.png", dependencies=[Depends(auth_dep)])
    @app.post("/config/diagram.png", dependencies=[Depends(auth_dep)])
    async def upload_config_diagram_png(file: UploadFile = File(...)) -> Dict[str, Any]:
        """Brief: Upload a custom config diagram PNG.

        Inputs:
          - file: UploadFile (multipart/form-data) named "file".

        Outputs:
          - dict: Status payload including the saved path.

        Notes:
          - Saves to <config_dir>/diagram.png.
          - Enforces a 1,000,000 byte max size.
        """

        cfg_path = getattr(app.state, "config_path", None)
        if not cfg_path:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="config_path not configured",
            )

        filename = str(getattr(file, "filename", "") or "")
        if filename and not filename.lower().endswith(".png"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="file must have .png extension",
            )

        max_bytes = 1_000_000
        try:
            data = await file.read(max_bytes + 1)
        except Exception as exc:  # pragma: no cover - environment dependent
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"failed to read upload: {exc}",
            ) from exc
        finally:
            try:
                await file.close()
            except Exception:
                pass

        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid upload payload",
            )

        payload = bytes(data)
        if len(payload) > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="file too large (max 1,000,000 bytes)",
            )

        # PNG signature: 89 50 4E 47 0D 0A 1A 0A
        if not payload.startswith(b"\x89PNG\r\n\x1a\n"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="file does not look like a PNG",
            )

        from pathlib import Path

        cfg_dir = Path(str(cfg_path)).resolve().parent
        dst_path = cfg_dir / "diagram.png"
        tmp_path = cfg_dir / "diagram.png.new"

        try:
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path.write_bytes(payload)
            os.replace(str(tmp_path), str(dst_path))
        except Exception as exc:  # pragma: no cover - environment dependent
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except Exception:
                pass
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to write diagram png: {exc}",
            ) from exc

        return {
            "status": "ok",
            "server_time": _utc_now_iso(),
            "path": str(dst_path),
            "size_bytes": len(payload),
        }

    @app.get("/api/v1/config/diagram.mmd", dependencies=[Depends(auth_dep)])
    @app.get("/config/diagram.mmd", dependencies=[Depends(auth_dep)])
    async def get_config_diagram_mmd(meta: int | None = None) -> PlainTextResponse:
        cfg_path = getattr(app.state, "config_path", None)
        if not cfg_path:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="config_path not configured",
            )

        headers: dict[str, str] = {}

        # If we have any on-disk diagram artifacts, surface staleness via headers.
        png_file = find_first_existing_path(
            diagram_png_candidate_paths_for_config(cfg_path)
        )
        if png_file is not None:
            warn_png = stale_diagram_warning(
                config_path=str(cfg_path), diagram_path=str(png_file)
            )
            if warn_png:
                headers["X-Foghorn-Warning"] = warn_png

        mmd_file = find_first_existing_path(
            diagram_mmd_candidate_paths_for_config(cfg_path)
        )
        if mmd_file is not None:
            warn_mmd = stale_diagram_warning(
                config_path=str(cfg_path), diagram_path=str(mmd_file)
            )
            if warn_mmd and "X-Foghorn-Warning" not in headers:
                headers["X-Foghorn-Warning"] = warn_mmd

        if meta:
            return PlainTextResponse("", media_type="text/plain", headers=headers)

        if mmd_file is not None:
            try:
                text = mmd_file.read_text(encoding="utf-8")
            except Exception as exc:  # pragma: no cover - environment dependent
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"failed to read config diagram from {mmd_file}: {exc}",
                ) from exc
            return PlainTextResponse(text, media_type="text/plain", headers=headers)

        try:
            text = generate_mermaid_text_from_config_path(str(cfg_path))
        except Exception as exc:  # pragma: no cover - environment dependent
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to generate config diagram: {exc}",
            ) from exc

        return PlainTextResponse(text, media_type="text/plain", headers=headers)

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

    def _flag_int(value: int | None) -> bool:
        """Brief: Convert an int-ish query parameter into a boolean flag.

        Inputs:
          - value: Optional int-like value.

        Outputs:
          - bool: True when value is a non-zero integer.
        """

        try:
            return bool(int(value or 0))
        except Exception:
            return False

    def _get_dns_cache() -> object | None:
        """Brief: Return the global DNS cache instance if present.

        Inputs:
          - None.

        Outputs:
          - Cache instance (typically CachePlugin) or None.
        """

        cache_mod = _sys.modules.get("foghorn.plugins.resolve.base")
        cache = getattr(cache_mod, "DNS_CACHE", None) if cache_mod is not None else None
        return cache

    def _is_hex_hash_like(name: object) -> bool:
        """Brief: Return True for hash-like labels (12–64 hex characters).

        Inputs:
          - name: Hostname-like value; only the left-most label is inspected.

        Outputs:
          - bool: True when the first label looks like a short/long hex hash.
        """

        token = str(name or "").split(".", 1)[0].lower().strip()
        if len(token) < 12 or len(token) > 64:
            return False
        return all(ch in "0123456789abcdef" for ch in token)

    def _table_path_from_descriptor(
        desc: object, table_id: str
    ) -> tuple[str, str | None, str]:
        """Brief: Resolve a table section path and default sort from an admin descriptor.

        Inputs:
          - desc: Plugin/cache admin UI descriptor (dict-like).
          - table_id: Section id from the frontend.

        Outputs:
          - (path, default_sort_key, default_sort_dir)
        """

        table_id_norm = str(table_id or "").strip()
        default_sort_key: str | None = None
        default_sort_dir = "asc"

        if not isinstance(desc, dict):
            return table_id_norm, default_sort_key, default_sort_dir

        layout = desc.get("layout")
        if not isinstance(layout, dict):
            return table_id_norm, default_sort_key, default_sort_dir

        sections = layout.get("sections")
        if not isinstance(sections, list):
            return table_id_norm, default_sort_key, default_sort_dir

        for sec in sections:
            if not isinstance(sec, dict):
                continue
            if str(sec.get("id") or "") != table_id_norm:
                continue
            if str(sec.get("type") or "") != "table":
                continue

            path = str(sec.get("path") or "").strip()

            sort_hint = sec.get("sort")
            if sort_hint == "by_calls":
                default_sort_key = "calls_total"
                default_sort_dir = "desc"

            return path, default_sort_key, default_sort_dir

        # Descriptor exists but does not define this table_id.
        return "", default_sort_key, default_sort_dir

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
        cache = _get_dns_cache()
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

    @app.get("/api/v1/cache/table/{table_id}", dependencies=[Depends(auth_dep)])
    async def get_cache_table(
        table_id: str,
        page: int = 1,
        page_size: int = 50,
        sort_key: str | None = None,
        sort_dir: str | None = None,
        search: str | None = None,
        hide_zero_calls: int | None = None,
        hide_zero_hits: int | None = None,
    ) -> Dict[str, Any]:
        """Brief: Return a server-side paginated cache table for the admin UI.

        Inputs:
          - table_id: Section id from the cache admin descriptor (e.g. 'caches').
          - page/page_size/sort_key/sort_dir/search: Standard table controls.
          - hide_zero_calls/hide_zero_hits: Optional boolean-ish filters (0/1).

        Outputs:
          - A table payload compatible with admin_logic.build_table_page_payload.
        """

        cache = _get_dns_cache()
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

        desc = None
        get_desc = getattr(cache, "get_admin_ui_descriptor", None)
        if callable(get_desc):
            try:
                desc = get_desc()
            except Exception:
                desc = None

        path, default_sort_key, default_sort_dir = _table_path_from_descriptor(
            desc, str(table_id)
        )
        if not path:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="cache table not found",
            )

        raw_rows = _admin_logic._resolve_path(snapshot, path)
        rows: list[dict[str, Any]] = (
            [r for r in (raw_rows or []) if isinstance(r, dict)]
            if isinstance(raw_rows, list)
            else []
        )

        if _flag_int(hide_zero_calls):
            rows = [
                r
                for r in rows
                if not (
                    isinstance(r.get("calls_total"), int)
                    and int(r.get("calls_total") or 0) == 0
                )
            ]
        if _flag_int(hide_zero_hits):
            rows = [
                r
                for r in rows
                if not (
                    isinstance(r.get("cache_hits"), int)
                    and int(r.get("cache_hits") or 0) == 0
                )
            ]

        payload = _admin_logic.build_table_page_payload(
            rows,
            page=page,
            page_size=page_size,
            sort_key=sort_key,
            sort_dir=sort_dir,
            search=search,
            hide_zero_calls=_flag_int(hide_zero_calls),
            hide_zero_hits=_flag_int(hide_zero_hits),
            show_down_services=True,
            hide_hash_like=False,
            default_sort_key=default_sort_key,
            default_sort_dir=default_sort_dir,
        )
        payload["server_time"] = _utc_now_iso()
        payload["table_id"] = str(table_id)
        return payload

    @app.get(
        "/api/v1/plugins/{plugin_name}/table/{table_id}",
        dependencies=[Depends(auth_dep)],
    )
    async def get_plugin_table(
        plugin_name: str,
        table_id: str,
        page: int = 1,
        page_size: int = 50,
        sort_key: str | None = None,
        sort_dir: str | None = None,
        search: str | None = None,
        hide_hash_like: int | None = None,
    ) -> Dict[str, Any]:
        """Brief: Return a server-side paginated table for a plugin snapshot page.

        Inputs:
          - plugin_name: Target plugin instance name.
          - table_id: Section id from the plugin admin descriptor.
          - page/page_size/sort_key/sort_dir/search: Standard table controls.
          - hide_hash_like: Optional boolean-ish filter (0/1) used by some plugins.

        Outputs:
          - A table payload compatible with admin_logic.build_table_page_payload.
        """

        plugins_list = getattr(app.state, "plugins", []) or []
        target = _admin_logic.find_plugin_instance_by_name(plugins_list, plugin_name)
        if target is None or not hasattr(target, "get_http_snapshot"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="plugin not found or does not expose get_http_snapshot",
            )

        get_desc = getattr(target, "get_admin_ui_descriptor", None)
        desc = None
        if callable(get_desc):
            try:
                desc = get_desc()
            except Exception:
                desc = None

        path, default_sort_key, default_sort_dir = _table_path_from_descriptor(
            desc, str(table_id)
        )
        if not path:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="plugin table not found",
            )

        try:
            snapshot = target.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to build plugin snapshot: {exc}",
            ) from exc

        raw_rows = _admin_logic._resolve_path(snapshot, path)
        rows: list[dict[str, Any]] = (
            [r for r in (raw_rows or []) if isinstance(r, dict)]
            if isinstance(raw_rows, list)
            else []
        )

        if _flag_int(hide_hash_like):
            rows = [r for r in rows if not _is_hex_hash_like(r.get("name"))]

        payload = _admin_logic.build_table_page_payload(
            rows,
            page=page,
            page_size=page_size,
            sort_key=sort_key,
            sort_dir=sort_dir,
            search=search,
            hide_zero_calls=False,
            hide_zero_hits=False,
            show_down_services=True,
            hide_hash_like=_flag_int(hide_hash_like),
            default_sort_key=default_sort_key,
            default_sort_dir=default_sort_dir,
        )
        payload["server_time"] = _utc_now_iso()
        payload["plugin"] = str(plugin_name)
        payload["table_id"] = str(table_id)
        return payload

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
