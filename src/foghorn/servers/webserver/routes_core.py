from __future__ import annotations

import os
import shutil
import signal
import sys as _sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from ...stats import StatsCollector
from ...utils.config_diagram import (
    diagram_dark_png_candidate_paths_for_config,
    diagram_dot_candidate_paths_for_config,
    diagram_png_candidate_paths_for_config,
    find_first_existing_path,
    generate_dot_text_from_config_path,
    stale_diagram_warning,
)
from . import admin_logic as _admin_logic
from . import config_persistence as _config_persistence
from .config_helpers import (
    _get_config_raw_json,
    _get_config_raw_text,
    _get_redact_keys,
    _get_sanitized_config_yaml_cached,
    _parse_utc_datetime,
    sanitize_config,
)
from .http_helpers import _schedule_process_signal
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


def _get_about_payload() -> Dict[str, Any]:
    """Build the /about payload using the canonical helper from core."""

    import importlib

    web_core = importlib.import_module("foghorn.servers.webserver.core")
    return web_core._get_about_payload()


def _register_core_routes(app: FastAPI) -> None:
    """Register core health/about/ready endpoints on the FastAPI app."""

    @app.get("/api/v1/health")
    @app.get("/health", include_in_schema=False)
    async def health() -> Dict[str, Any]:
        """Health check.

        Aliases:
          - /health
        """

        return {"status": "ok", "server_time": _utc_now_iso()}

    @app.get("/api/v1/about")
    @app.get("/about", include_in_schema=False)
    async def about() -> Dict[str, Any]:
        """About/build metadata.

        Aliases:
          - /about
        """

        return _get_about_payload()

    @app.get("/api/v1/ready")
    @app.get("/ready", include_in_schema=False)
    async def ready() -> JSONResponse:
        state: RuntimeState | None = getattr(app.state, "runtime_state", None)
        ready_ok, not_ready, details = evaluate_readiness(
            stats=getattr(app.state, "stats_collector", None),
            config=getattr(app.state, "config", None),
            runtime_state=state,
        )
        payload = {
            "server_time": _utc_now_iso(),
            "ready": bool(ready_ok),
            "not_ready": list(not_ready or []),
            "details": details,
        }
        return JSONResponse(
            content=_json_safe(payload), status_code=200 if ready_ok else 503
        )


def _register_config_routes(app: FastAPI, auth_dep: Any) -> None:
    """Register configuration management endpoints."""

    @app.get("/api/v1/config", dependencies=[Depends(auth_dep)])
    @app.get("/config", dependencies=[Depends(auth_dep)], include_in_schema=False)
    async def get_config() -> PlainTextResponse:
        cfg = app.state.config or {}
        redact_keys = _get_redact_keys(cfg)
        cfg_path = getattr(app.state, "config_path", None)
        body = _get_sanitized_config_yaml_cached(cfg, cfg_path, redact_keys)
        return PlainTextResponse(body, media_type="application/x-yaml")

    @app.get("/api/v1/config/raw", dependencies=[Depends(auth_dep)])
    @app.get("/config/raw", dependencies=[Depends(auth_dep)], include_in_schema=False)
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
    @app.get("/config.json", dependencies=[Depends(auth_dep)], include_in_schema=False)
    async def get_config_json() -> Dict[str, Any]:
        cfg = app.state.config or {}
        redact_keys = _get_redact_keys(cfg)
        clean = sanitize_config(cfg, redact_keys=redact_keys)
        return {"server_time": _utc_now_iso(), "config": clean}

    @app.get("/api/v1/config/diagram.png", dependencies=[Depends(auth_dep)])
    @app.get(
        "/config/diagram.png",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
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

        # If missing and dot exists, attempt an on-demand build once.
        if png_file is None and attempted_sig != cfg_sig:
            from ...utils.config_diagram import (
                _find_dot_cmd,
                ensure_config_diagram_png,
            )

            if _find_dot_cmd() is not None:
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

            # If stale and dot exists, try to refresh it in-place once.
            if (
                warn
                and getattr(app.state, "_config_diagram_build_attempt_sig", None)
                != cfg_sig
            ):
                from ...utils.config_diagram import (
                    _find_dot_cmd,
                    ensure_config_diagram_png,
                )

                if _find_dot_cmd() is not None:
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

    @app.get("/api/v1/config/diagram-dark.png", dependencies=[Depends(auth_dep)])
    @app.get(
        "/config/diagram-dark.png",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    async def get_config_diagram_png_dark(meta: int | None = None):
        """Serve the config diagram dark-theme PNG (when available).

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

        try:
            st = os.stat(str(cfg_path))
            cfg_sig = f"{cfg_path}:{int(st.st_mtime_ns)}:{int(st.st_size)}"
        except Exception:
            cfg_sig = str(cfg_path)

        attempted_sig = getattr(app.state, "_config_diagram_build_attempt_sig", None)

        png_file = find_first_existing_path(
            diagram_dark_png_candidate_paths_for_config(cfg_path)
        )

        # If missing and dot exists, attempt an on-demand build once.
        if png_file is None and attempted_sig != cfg_sig:
            from ...utils.config_diagram import (
                _find_dot_cmd,
                ensure_config_diagram_png,
            )

            if _find_dot_cmd() is not None:
                setattr(app.state, "_config_diagram_build_attempt_sig", cfg_sig)
                ensure_config_diagram_png(config_path=str(cfg_path))
                png_file = find_first_existing_path(
                    diagram_dark_png_candidate_paths_for_config(cfg_path)
                )

        warn: str | None = None
        if png_file is not None:
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
    @app.post(
        "/config/diagram.png",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
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

    @app.get("/api/v1/config/diagram.dot", dependencies=[Depends(auth_dep)])
    @app.get(
        "/config/diagram.dot",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    async def get_config_diagram_dot(meta: int | None = None) -> PlainTextResponse:
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

        dot_file = find_first_existing_path(
            diagram_dot_candidate_paths_for_config(cfg_path)
        )
        if dot_file is not None:
            warn_dot = stale_diagram_warning(
                config_path=str(cfg_path), diagram_path=str(dot_file)
            )
            if warn_dot and "X-Foghorn-Warning" not in headers:
                headers["X-Foghorn-Warning"] = warn_dot

        if meta:
            return PlainTextResponse("", media_type="text/plain", headers=headers)

        if dot_file is not None:
            try:
                text = dot_file.read_text(encoding="utf-8")
            except Exception as exc:  # pragma: no cover - environment dependent
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"failed to read config diagram from {dot_file}: {exc}",
                ) from exc
            return PlainTextResponse(text, media_type="text/plain", headers=headers)

        try:
            text = generate_dot_text_from_config_path(str(cfg_path))
        except Exception as exc:  # pragma: no cover - environment dependent
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to generate config diagram: {exc}",
            ) from exc

        return PlainTextResponse(text, media_type="text/plain", headers=headers)

    @app.get("/api/v1/config/raw.json", dependencies=[Depends(auth_dep)])
    @app.get(
        "/config/raw.json",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
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

    def _schedule_restart(*, delay_seconds: float = 1.0) -> None:
        """Brief: Schedule a process restart by delivering SIGHUP.

        Inputs:
          - delay_seconds: Delay before sending SIGHUP so HTTP responses can flush.

        Outputs:
          - None.
        """

        _schedule_process_signal(signal.SIGHUP, delay_seconds=float(delay_seconds))

    def _save_config_to_disk(*, body: Dict[str, Any]) -> Dict[str, Any]:
        """Brief: Persist raw YAML to disk and validate it.

        Inputs:
          - body: JSON object containing required 'raw_yaml' string.

        Outputs:
          - Dict containing:
              - cfg_path_abs
              - backup_path
              - desired_cfg (parsed/validated)
              - analysis (restart/reload recommendation)

        Notes:
          - On validation failure, restores the backup and raises HTTPException.
        """

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

        raw_yaml = body.get("raw_yaml")
        if not isinstance(raw_yaml, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="request body must include 'raw_yaml' string field",
            )

        try:
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

        from foghorn import runtime_config as _runtime_config

        restored = False
        try:
            desired_cfg = _runtime_config.load_config_from_disk(
                config_path=cfg_path_abs
            )
        except Exception as exc:
            try:
                if os.path.exists(backup_path):
                    shutil.copy(backup_path, cfg_path_abs)
                    restored = True
            except Exception:
                restored = False

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"failed to parse/validate saved config (restored_backup={restored}): {exc}",
            ) from exc

        analysis = _runtime_config.analyze_config_change(
            desired_cfg,
            current_cfg=getattr(app.state, "config", None) or {},
        )

        # Best-effort: keep the config diagram in sync with the on-disk config.
        # This should never block config persistence.
        if analysis.get("changed"):
            try:
                from ...utils.config_diagram import ensure_config_diagram_png

                ensure_config_diagram_png(config_path=str(cfg_path_abs))
            except Exception:
                pass

        return {
            "cfg_path_abs": cfg_path_abs,
            "backup_path": backup_path,
            "desired_cfg": desired_cfg,
            "analysis": analysis,
        }

    @app.post("/api/v1/config/save", dependencies=[Depends(auth_dep)])
    @app.post(
        "/config/save",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    async def save_config(body: Dict[str, Any]) -> JSONResponse:
        """Brief: Persist config YAML without applying reload or restart.

        Inputs:
          - body: JSON object containing required 'raw_yaml' string.

        Outputs:
          - JSONResponse describing whether a reload or restart is recommended.

        Notes:
          - This endpoint is intentionally side-effect free (no reload, no restart)
            so operators can save now and choose when to reload/restart.
        """

        saved = _save_config_to_disk(body=body)
        analysis = saved["analysis"]

        msg = "saved"
        if analysis.get("restart_required"):
            msg = "saved (restart required to apply some changes)"
        elif analysis.get("reload_required"):
            msg = "saved (reload recommended to apply changes without downtime)"

        payload = {
            "status": "ok",
            "server_time": _utc_now_iso(),
            "path": saved["cfg_path_abs"],
            "backed_up_to": saved["backup_path"],
            "message": msg,
            "analysis": analysis,
        }
        return JSONResponse(content=_json_safe(payload), status_code=200)

    @app.post("/api/v1/config/save_and_reload", dependencies=[Depends(auth_dep)])
    @app.post(
        "/config/save_and_reload",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    async def save_and_reload_config(body: Dict[str, Any]) -> JSONResponse:
        """Brief: Persist config YAML and apply an in-process reload when possible.

        Inputs:
          - body: JSON object containing required 'raw_yaml' string.

        Outputs:
          - JSONResponse with save metadata and reload outcome.

        Notes:
          - If the saved config implies restart_required, reload is refused with
            HTTP 409 and no restart is scheduled by this endpoint.
        """

        saved = _save_config_to_disk(body=body)
        analysis = saved["analysis"]

        from foghorn import runtime_config as _runtime_config

        if analysis.get("restart_required"):
            payload = {
                "status": "error",
                "server_time": _utc_now_iso(),
                "path": saved["cfg_path_abs"],
                "backed_up_to": saved["backup_path"],
                "message": "saved but reload refused (restart required; call /restart or /config/save_and_restart)",
                "analysis": analysis,
            }
            return JSONResponse(content=_json_safe(payload), status_code=409)

        reload_res = _runtime_config.reload_from_disk(
            config_path=saved["cfg_path_abs"],
            mode="reload_only",
        )

        if reload_res.ok:
            try:
                snap = _runtime_config.get_runtime_snapshot()
                app.state.config = snap.cfg
                app.state.plugins = list(snap.plugins or [])
            except Exception:
                pass

        # reload_from_disk(mode='reload_only') can report restart_required when
        # listener/http changes are present. Under /save_and_reload semantics we
        # refuse to apply reload in that case.
        if reload_res.ok and reload_res.restart_required:
            payload = {
                "status": "error",
                "server_time": _utc_now_iso(),
                "path": saved["cfg_path_abs"],
                "backed_up_to": saved["backup_path"],
                "message": "saved but reload refused (restart required; call /restart or /config/save_and_restart)",
                "analysis": analysis,
                "reload": {
                    "ok": bool(reload_res.ok),
                    "generation": int(reload_res.generation),
                    "restart_required": bool(reload_res.restart_required),
                    "restart_reasons": list(reload_res.restart_reasons or []),
                    "error": reload_res.error,
                    "mode": "reload_only",
                },
            }
            return JSONResponse(content=_json_safe(payload), status_code=409)

        msg = "saved and reloaded" if reload_res.ok else "saved but reload failed"

        payload = {
            "status": "ok" if reload_res.ok else "error",
            "server_time": _utc_now_iso(),
            "path": saved["cfg_path_abs"],
            "backed_up_to": saved["backup_path"],
            "message": msg,
            "analysis": analysis,
            "reload": {
                "ok": bool(reload_res.ok),
                "generation": int(reload_res.generation),
                "restart_required": bool(reload_res.restart_required),
                "restart_reasons": list(reload_res.restart_reasons or []),
                "error": reload_res.error,
                "mode": "reload_only",
            },
            "restart": {
                "scheduled": bool(reload_res.ok and reload_res.restart_required),
                "signal": (
                    "SIGHUP" if reload_res.ok and reload_res.restart_required else None
                ),
            },
        }

        return JSONResponse(
            content=_json_safe(payload),
            status_code=200 if reload_res.ok else status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    @app.post("/api/v1/config/save_and_restart", dependencies=[Depends(auth_dep)])
    @app.post(
        "/config/save_and_restart",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    async def save_and_restart_config(body: Dict[str, Any]) -> JSONResponse:
        """Brief: Persist config YAML and schedule a restart (SIGHUP).

        Inputs:
          - body: JSON object containing required 'raw_yaml' string.

        Outputs:
          - JSONResponse with save metadata.
        """

        saved = _save_config_to_disk(body=body)
        _schedule_restart(delay_seconds=1.0)

        payload = {
            "status": "ok",
            "server_time": _utc_now_iso(),
            "path": saved["cfg_path_abs"],
            "backed_up_to": saved["backup_path"],
            "message": "saved; restart scheduled (SIGHUP)",
            "analysis": saved["analysis"],
            "restart": {"scheduled": True, "signal": "SIGHUP"},
        }
        return JSONResponse(content=_json_safe(payload), status_code=200)

    @app.post(
        "/api/v1/config/reload",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    @app.post(
        "/config/reload",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    @app.post("/api/v1/reload", dependencies=[Depends(auth_dep)])
    @app.post(
        "/reload",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    async def reload_config() -> JSONResponse:
        """Brief: Reload runtime config from the on-disk YAML.

        Inputs:
          - None (uses app.state.config_path).

        Outputs:
          - JSONResponse with reload metadata.

        Notes:
          - If restart_required is detected, reload is refused (HTTP 409) so the
            operator can restart explicitly via /restart.
        """

        cfg_path = getattr(app.state, "config_path", None)
        if not cfg_path:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="config_path not configured",
            )

        cfg_path_abs = os.path.abspath(cfg_path)

        from foghorn import runtime_config as _runtime_config

        try:
            desired_cfg = _runtime_config.load_config_from_disk(
                config_path=cfg_path_abs
            )
        except Exception as exc:
            payload = {
                "status": "error",
                "server_time": _utc_now_iso(),
                "path": cfg_path_abs,
                "message": f"failed to parse/validate config: {exc}",
            }
            return JSONResponse(content=_json_safe(payload), status_code=400)

        analysis = _runtime_config.analyze_config_change(
            desired_cfg,
            current_cfg=getattr(app.state, "config", None) or {},
        )

        if analysis.get("restart_required"):
            payload = {
                "status": "error",
                "server_time": _utc_now_iso(),
                "path": cfg_path_abs,
                "message": "reload refused (restart required; call /restart)",
                "analysis": analysis,
            }
            return JSONResponse(content=_json_safe(payload), status_code=409)

        reload_res = _runtime_config.reload_from_config(desired_cfg, mode="reload_only")

        if reload_res.ok:
            try:
                snap = _runtime_config.get_runtime_snapshot()
                app.state.config = snap.cfg
                app.state.plugins = list(snap.plugins or [])
            except Exception:
                pass

        msg = "reloaded" if reload_res.ok else "reload failed"

        payload = {
            "status": "ok" if reload_res.ok else "error",
            "server_time": _utc_now_iso(),
            "path": cfg_path_abs,
            "message": msg,
            "analysis": analysis,
            "reload": {
                "ok": bool(reload_res.ok),
                "generation": int(reload_res.generation),
                "restart_required": bool(reload_res.restart_required),
                "restart_reasons": list(reload_res.restart_reasons or []),
                "error": reload_res.error,
                "mode": "reload_only",
            },
        }

        return JSONResponse(
            content=_json_safe(payload),
            status_code=200 if reload_res.ok else status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    @app.post("/api/v1/reload_reloadable", dependencies=[Depends(auth_dep)])
    @app.post(
        "/reload_reloadable",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    @app.post(
        "/api/v1/config/reload_reloadable",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    @app.post(
        "/config/reload_reloadable",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    async def reload_reloadable() -> JSONResponse:
        """Brief: Reload only zero-downtime-safe settings, even if restart is required.

        Inputs:
          - None (uses app.state.config_path).

        Outputs:
          - JSONResponse with reload metadata.

        Notes:
          - When restart-required changes are present (listener/http), this still
            applies reloadable settings and returns restart_required=true.
          - This endpoint never schedules a restart; callers may invoke /restart
            later when convenient.
        """

        cfg_path = getattr(app.state, "config_path", None)
        if not cfg_path:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="config_path not configured",
            )

        cfg_path_abs = os.path.abspath(cfg_path)

        from foghorn import runtime_config as _runtime_config

        try:
            desired_cfg = _runtime_config.load_config_from_disk(
                config_path=cfg_path_abs
            )
        except Exception as exc:
            payload = {
                "status": "error",
                "server_time": _utc_now_iso(),
                "path": cfg_path_abs,
                "message": f"failed to parse/validate config: {exc}",
            }
            return JSONResponse(content=_json_safe(payload), status_code=400)

        analysis = _runtime_config.analyze_config_change(
            desired_cfg,
            current_cfg=getattr(app.state, "config", None) or {},
        )

        reload_res = _runtime_config.reload_from_config(desired_cfg, mode="reload_only")

        if reload_res.ok:
            try:
                snap = _runtime_config.get_runtime_snapshot()
                app.state.config = snap.cfg
                app.state.plugins = list(snap.plugins or [])
            except Exception:
                pass

        msg = "reloaded" if reload_res.ok else "reload failed"
        if reload_res.ok and analysis.get("restart_required"):
            msg = "reloaded reloadable settings (restart required for some changes)"

        payload = {
            "status": "ok" if reload_res.ok else "error",
            "server_time": _utc_now_iso(),
            "path": cfg_path_abs,
            "message": msg,
            "analysis": analysis,
            "reload": {
                "ok": bool(reload_res.ok),
                "generation": int(reload_res.generation),
                "restart_required": bool(reload_res.restart_required),
                "restart_reasons": list(reload_res.restart_reasons or []),
                "error": reload_res.error,
                "mode": "reload_only",
            },
        }

        return JSONResponse(
            content=_json_safe(payload),
            status_code=200 if reload_res.ok else status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    @app.post("/api/v1/restart", dependencies=[Depends(auth_dep)])
    @app.post(
        "/restart",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    async def restart_process(body: Dict[str, Any] | None = None) -> JSONResponse:
        """Brief: Schedule a process restart (SIGHUP) without saving or reloading.

        Inputs:
          - body: Optional JSON object that may include delay_seconds.

        Outputs:
          - JSONResponse indicating restart has been scheduled.
        """

        delay_seconds = 1.0
        if isinstance(body, dict):
            try:
                delay_seconds = float(body.get("delay_seconds", delay_seconds))
            except Exception:
                delay_seconds = 1.0

        _schedule_restart(delay_seconds=delay_seconds)

        payload = {
            "status": "ok",
            "server_time": _utc_now_iso(),
            "message": f"restart scheduled via SIGHUP (delay_seconds={delay_seconds})",
            "restart": {
                "scheduled": True,
                "signal": "SIGHUP",
                "delay_seconds": float(delay_seconds),
            },
        }
        return JSONResponse(content=_json_safe(payload), status_code=200)


def _register_query_log_routes(app: FastAPI, auth_dep: Any) -> None:
    """Register query_log and query_log/aggregate endpoints."""

    @app.get("/api/v1/query_log", dependencies=[Depends(auth_dep)])
    @app.get(
        "/query_log",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    async def get_query_log(
        client_ip: str | None = None,
        qtype: str | None = None,
        qname: str | None = None,
        rcode: str | None = None,
        query_status: str | None = Query(default=None, alias="status"),
        source: str | None = None,
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
        status_filter = query_status if isinstance(query_status, str) else None

        payload = _admin_logic.build_query_log_payload(
            store,
            client_ip=client_ip,
            qtype=qtype,
            qname=qname,
            rcode=rcode,
            status=status_filter,
            source=source,
            start_ts=start_ts,
            end_ts=end_ts,
            page=int(page) if isinstance(page, int) else 1,
            page_size=ps,
        )
        payload["server_time"] = _utc_now_iso()
        return payload

    @app.get("/api/v1/query_log/aggregate", dependencies=[Depends(auth_dep)])
    @app.get(
        "/query_log/aggregate",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
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
        except Exception:  # pragma: no cover - import/env failure is runtime-dependent
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
    @app.get("/logs", dependencies=[Depends(auth_dep)], include_in_schema=False)
    async def get_logs(limit: int = 100) -> Dict[str, Any]:
        buf = app.state.log_buffer
        entries = buf.snapshot(limit=max(0, int(limit)))
        return {"server_time": _utc_now_iso(), "entries": entries}

    @app.get(
        "/api/v1/plugins/{plugin_name}/access_control", dependencies=[Depends(auth_dep)]
    )
    async def get_access_control_snapshot(plugin_name: str) -> Dict[str, Any]:
        plugins_list = getattr(app.state, "plugins", []) or []
        try:
            snap = _admin_logic.build_named_plugin_snapshot(
                plugins_list, plugin_name, label="AccessControl"
            )
        except _admin_logic.AdminLogicHttpError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

        return {
            "server_time": _utc_now_iso(),
            "plugin": snap["plugin"],
            "data": _json_safe(snap["data"]),
        }

    @app.get(
        "/api/v1/plugins/{plugin_name}/rate_limit", dependencies=[Depends(auth_dep)]
    )
    async def get_rate_limit_snapshot(plugin_name: str) -> Dict[str, Any]:
        plugins_list = getattr(app.state, "plugins", []) or []
        try:
            snap = _admin_logic.build_named_plugin_snapshot(
                plugins_list, plugin_name, label="RateLimit"
            )
        except _admin_logic.AdminLogicHttpError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

        return {
            "server_time": _utc_now_iso(),
            "plugin": snap["plugin"],
            "data": _json_safe(snap["data"]),
        }

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
