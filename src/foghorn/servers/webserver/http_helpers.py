from __future__ import annotations

import hmac
import json
import logging
import os
import signal
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, Request, status

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


def _extract_provided_auth_token(
    authorization_header: str | None,
    api_key_header: str | None,
) -> str:
    """Brief: Extract a provided auth token from bearer or API key headers.

    Inputs:
      - authorization_header: Raw Authorization header value.
      - api_key_header: Raw X-API-Key header value.

    Outputs:
      - Token string when present; empty string when absent.
    """

    auth_value = str(authorization_header or "")
    if auth_value.lower().startswith("bearer "):
        return auth_value[7:].strip()
    if api_key_header is None:
        return ""
    return str(api_key_header).strip()


def _evaluate_web_auth(
    web_cfg: Dict[str, Any] | None,
    *,
    authorization_header: str | None,
    api_key_header: str | None,
) -> tuple[bool, int | None, str | None, Dict[str, str] | None]:
    """Brief: Evaluate configured web auth for a single request.

    Inputs:
      - web_cfg: webserver config dict from YAML (or {}).
      - authorization_header: Raw Authorization header value.
      - api_key_header: Raw X-API-Key header value.

    Outputs:
      - Tuple of:
          - authorized: True when request is allowed.
          - status_code: HTTP status for denied requests; None when authorized.
          - detail: Error detail for denied requests; None when authorized.
          - headers: Optional response headers for denied requests.

    Behaviour:
      - ``mode=none`` allows all requests.
      - ``mode=token`` enforces a static bearer/API key token.
      - Unknown auth modes fail closed.
    """

    auth_cfg = (web_cfg.get("auth") or {}) if isinstance(web_cfg, dict) else {}
    mode = str(auth_cfg.get("mode", "none")).strip().lower()
    if mode in {"", "none"}:
        return True, None, None, None
    if mode != "token":
        return False, 500, f"unsupported webserver.auth.mode: {mode}", None

    token = auth_cfg.get("token")
    if not token:
        return False, 500, "webserver.auth.token not configured", None

    provided = _extract_provided_auth_token(
        authorization_header=authorization_header,
        api_key_header=api_key_header,
    )
    token_text = str(token)
    if not provided or not hmac.compare_digest(provided, token_text):
        return False, 401, "unauthorized", {"WWW-Authenticate": "Bearer"}

    return True, None, None, None


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

    async def _auth(request: Request) -> None:
        authorized, status_code, detail, headers = _evaluate_web_auth(
            web_cfg,
            authorization_header=request.headers.get("authorization"),
            api_key_header=request.headers.get("x-api-key"),
        )
        if authorized:
            return None
        raise HTTPException(
            status_code=int(status_code or status.HTTP_401_UNAUTHORIZED),
            detail=str(detail or "unauthorized"),
            headers=headers,
        )

    return _auth


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
