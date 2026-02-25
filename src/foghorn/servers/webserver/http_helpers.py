from __future__ import annotations

import json
import os
import signal
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, Request, status

import logging
from .stats_helpers import _utc_now_iso


logger = logging.getLogger("foghorn.webserver")


def _json_safe(value: Any) -> Any:
    """Brief: Return a JSON-serializable representation of value.

    Inputs:
      - value: Arbitrary Python object that may not be JSON serializable.

    Outputs:
      - JSON-serializable structure where non-serializable objects (including
        exceptions) have been converted to strings or simple dicts.
    """

    # Fast path for primitives
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    # Preserve mapping and sequence structure
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]

    # Represent exceptions explicitly
    if isinstance(value, Exception):
        return {"type": type(value).__name__, "message": str(value)}

    # Fallback: string representation for anything else (e.g., datetime, Path).
    return str(value)


def resolve_www_root(config: Dict[str, Any] | None = None) -> str:
    """Brief: Resolve absolute html root directory for static admin assets.

    Inputs:
      - config: Optional full configuration mapping (e.g. loaded from YAML).

    Outputs:
      - str absolute path to the directory from which static files are served.
    """

    # 1) Config override: server.http.www_root
    if isinstance(config, dict):
        server_cfg = config.get("server") or {}
        http_cfg = server_cfg.get("http") or {}
        if isinstance(http_cfg, dict):
            candidate = http_cfg.get("www_root")
            if isinstance(candidate, str) and candidate:
                cfg_path = Path(candidate).expanduser()
                if cfg_path.is_dir():
                    return str(cfg_path.resolve())

    # 2) Environment variable override
    env_root = os.environ.get("FOGHORN_WWW_ROOT")
    if env_root:
        env_path = Path(env_root).expanduser()
        if env_path.is_dir():
            return str(env_path.resolve())

    # 3) Current working directory ./html
    cwd_html = Path(os.getcwd()) / "html"
    if cwd_html.is_dir():
        return str(cwd_html.resolve())

    # 4) Fallback to package-relative html directory within the installed
    #    foghorn package. This resolves to:
    #      - src/foghorn/html when running from source, or
    #      - <site-packages>/foghorn/html when installed.
    here = Path(__file__).resolve()
    try:
        import foghorn  # type: ignore[import]

        pkg_root = Path(foghorn.__file__).resolve().parent
    except Exception:  # pragma: no cover - defensive: import/path edge cases
        # Fallback to resolving relative to this module:
        # .../foghorn/servers/webserver/http_helpers.py -> .../foghorn
        pkg_root = here.parent.parent
    pkg_html = pkg_root / "html"
    return str(pkg_html.resolve())


def _build_auth_dependency(web_cfg: Dict[str, Any]):
    """Build a FastAPI dependency enforcing optional admin auth.

    Inputs:
      - web_cfg: webserver config dict from YAML (or {}).

    Outputs:
      - Dependency callable usable with FastAPI Depends().

    Modes:
      - none (default): no authentication.
      - token: require Authorization: Bearer <token> or X-API-Key header.
      - basic: require HTTP Basic credentials (not implemented yet; reserved).
    """

    auth_cfg = (web_cfg.get("auth") or {}) if isinstance(web_cfg, dict) else {}
    mode = str(auth_cfg.get("mode", "none")).lower()
    token = auth_cfg.get("token")

    async def _no_auth(_request: Request) -> None:  # noqa: D401
        """FastAPI dependency that performs no authentication."""

        return None

    async def _token_auth(request: Request) -> None:
        if not token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="webserver.auth.token not configured",
            )
        hdr = request.headers.get("authorization") or ""
        api_key = request.headers.get("x-api-key")
        if hdr.lower().startswith("bearer "):
            provided = hdr[7:].strip()
        else:
            provided = api_key.strip() if api_key else ""
        if not provided or provided != str(token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="unauthorized",
                headers={"WWW-Authenticate": "Bearer"},
            )

    if mode == "token":
        return _token_auth
    # basic or unknown -> treat as none for now; can be expanded later.
    return _no_auth


def _schedule_process_signal(
    sig: int,
    *,
    delay_seconds: float = 1.0,
    pid: int | None = None,
) -> None:
    """Brief: Schedule delivery of a Unix signal to this process.

    Inputs:
      - sig: Integer signal number (e.g., signal.SIGHUP).
      - delay_seconds: Seconds to wait before sending. When <= 0, sends
        synchronously.
      - pid: Optional explicit PID; defaults to os.getpid().

    Outputs:
      - None; best-effort scheduling of os.kill(pid, sig). Failures are logged.

    Notes:
      - The delayed mode is used by HTTP handlers so they can return a response
        before the signal terminates the process.
    """

    target_pid = int(pid or os.getpid())

    def _send() -> None:
        try:
            os.kill(target_pid, int(sig))
        except Exception as exc:  # pragma: no cover - platform specific
            logger.error("Failed to send signal %s to pid=%s: %s", sig, target_pid, exc)

    if delay_seconds <= 0:
        _send()
        return

    timer = threading.Timer(float(delay_seconds), _send)
    timer.daemon = True
    timer.start()
