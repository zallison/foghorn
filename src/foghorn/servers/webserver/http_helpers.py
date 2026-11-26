from __future__ import annotations

import base64
import binascii
import hmac
import json
import logging
import os
import secrets
import signal
import string
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


def resolve_www_root(config: dict[str, Any] | None = None) -> str:
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


_AUTO_TOKEN_ALPHABET = string.ascii_letters + string.digits


def ensure_web_auth_token(
    web_cfg: dict[str, Any] | None,
    *,
    length: int = 32,
) -> str | None:
    """Brief: Ensure server.http.auth.token exists when auth.mode is token.

    Inputs:
      - web_cfg: server.http mapping (mutated in place when a token is generated).
      - length: Generated token length (default 32).

    Outputs:
      - str | None: Newly generated token when one was created; otherwise None.

    Notes:
      - Acts when auth.mode is 'token' (the default when unset) and token is
        missing/blank.
      - Resolves auth.token_secret via secrets backends when present.
      - Logs the generated token at WARNING so operators can retrieve it once.
    """

    if not isinstance(web_cfg, dict):
        return None

    auth_cfg = web_cfg.get("auth")
    if not isinstance(auth_cfg, dict):
        auth_cfg = {}
        web_cfg["auth"] = auth_cfg

    mode = str(auth_cfg.get("mode", "token") or "token").strip().lower()
    if mode != "token":
        return None

    # Prefer secrets-backed token when configured and inline token is blank.
    existing = str(auth_cfg.get("token") or "").strip()
    if not existing and auth_cfg.get("token_secret") is not None:
        try:
            from foghorn.plugins.secrets.resolve import resolve_token_value

            resolved = resolve_token_value(auth_cfg)
        except Exception:
            resolved = None
        if resolved:
            auth_cfg["token"] = str(resolved)
            web_cfg["auth"] = auth_cfg
            return None

    existing = str(auth_cfg.get("token") or "").strip()
    if existing:
        return None

    try:
        token_len = max(16, int(length))
    except Exception:
        token_len = 32

    generated = "".join(secrets.choice(_AUTO_TOKEN_ALPHABET) for _ in range(token_len))
    auth_cfg["token"] = generated
    web_cfg["auth"] = auth_cfg

    logger.warning(
        "server.http.auth.mode=token but no token was configured; "
        "generated a **session** token (store this securely): %s",
        generated,
    )
    return generated


def ensure_web_auth_basic_password(web_cfg: dict[str, Any] | None) -> str | None:
    """Brief: Materialize server.http.auth.password from password_secret when needed.

    Inputs:
      - web_cfg: server.http mapping (mutated when a secret resolves).

    Outputs:
      - Resolved password string when loaded from secrets; otherwise None.

    Notes:
      - Only runs for auth.mode=basic with blank/missing inline password.
      - Supports auth.password_secret refs and mapping-form auth.password.
      - Leaves inline non-empty password unchanged.
    """

    if not isinstance(web_cfg, dict):
        return None

    auth_cfg = web_cfg.get("auth")
    if not isinstance(auth_cfg, dict):
        return None

    mode = str(auth_cfg.get("mode", "token") or "token").strip().lower()
    if mode != "basic":
        return None

    existing = auth_cfg.get("password")
    if isinstance(existing, str) and existing.strip():
        return None

    try:
        from foghorn.plugins.secrets.resolve import resolve_secret_string
    except Exception:
        return None

    resolved: str | None = None
    if auth_cfg.get("password_secret") is not None:
        try:
            resolved = resolve_secret_string(
                auth_cfg.get("password_secret"),
                prefer=("token", "secret"),
            )
        except Exception:
            resolved = None
    elif isinstance(existing, dict):
        try:
            resolved = resolve_secret_string(existing, prefer=("token", "secret"))
        except Exception:
            resolved = None

    if not resolved:
        return None

    auth_cfg["password"] = str(resolved)
    web_cfg["auth"] = auth_cfg
    return str(resolved)


# Fixed Basic username accepted in auth.mode=token when allow_basic_token
# (password must be the token).
_TOKEN_MODE_BASIC_USERNAME = "foghorn"
# 401 challenges for token mode (with/without optional Basic browser prompt).
_TOKEN_MODE_WWW_AUTHENTICATE_BEARER = "Bearer"
_TOKEN_MODE_WWW_AUTHENTICATE_BEARER_AND_BASIC = 'Bearer, Basic realm="foghorn"'

_BASIC_MODE_WITH_TOKEN_ERROR = (
    "server.http.auth.mode=basic must not set auth.token "
    "(token is only valid with mode=token); remove token or switch mode"
)


def validate_web_auth_config(web_cfg: dict[str, Any] | None) -> None:
    """Brief: Fail closed on unclear server.http.auth combinations.

    Inputs:
      - web_cfg: server.http mapping (or None).

    Outputs:
      - None when auth settings are coherent or absent.

    Raises:
      - ValueError: when mode=basic is combined with a non-empty token (ambiguous
        whether Basic password or token auth is intended).
    """

    if not isinstance(web_cfg, dict):
        return
    auth_cfg = web_cfg.get("auth")
    if not isinstance(auth_cfg, dict):
        return
    mode = str(auth_cfg.get("mode", "token") or "token").strip().lower()
    token = str(auth_cfg.get("token") or "").strip()
    if mode == "basic" and token:
        raise ValueError(_BASIC_MODE_WITH_TOKEN_ERROR)


def _auth_allow_basic_token(auth_cfg: dict[str, Any] | None) -> bool:
    """Brief: Whether token mode may accept Basic foghorn:<token>.

    Inputs:
      - auth_cfg: server.http.auth mapping (or None).

    Outputs:
      - True when allow_basic_token is enabled (default true when unset).
    """

    if not isinstance(auth_cfg, dict):
        return True
    if "allow_basic_token" not in auth_cfg:
        return True
    return bool(auth_cfg.get("allow_basic_token"))


def _extract_provided_auth_token(
    authorization_header: str | None,
    api_key_header: str | None,
    *,
    allow_basic_token: bool = True,
) -> str:
    """Brief: Extract a provided auth token from bearer, Basic, or API key headers.

    Inputs:
      - authorization_header: Raw Authorization header value.
      - api_key_header: Raw X-API-Key header value.
      - allow_basic_token: When true, accept Basic foghorn:<token>.

    Outputs:
      - Token string when present; empty string when absent.

    Notes:
      - Bearer and X-API-Key supply the token directly.
      - When allow_basic_token is true, Basic is accepted only as
        ``foghorn:<token>`` (username must be exactly ``foghorn``); the password
        is treated as the token for browser prompts.
    """

    auth_value = str(authorization_header or "")
    if auth_value.lower().startswith("bearer "):
        return auth_value[7:].strip()

    if allow_basic_token:
        basic = _decode_basic_credentials(authorization_header)
        if basic is not None:
            username, password = basic
            if hmac.compare_digest(
                username.encode("utf-8"),
                _TOKEN_MODE_BASIC_USERNAME.encode("utf-8"),
            ):
                return str(password)

    if api_key_header is None:
        return ""
    return str(api_key_header).strip()


def _decode_basic_credentials(
    authorization_header: str | None,
) -> tuple[str, str] | None:
    """Brief: Decode an Authorization: Basic header into (username, password).

    Inputs:
      - authorization_header: Raw Authorization header value.

    Outputs:
      - Tuple of (username, password) when the header is a well-formed
        ``Basic base64(user:pass)`` credential; None when the header is
        absent, uses another scheme, or fails to decode.

    Notes:
      - Scheme matching is case-insensitive per RFC 7235.
      - The decoded payload must contain at least one ':' (RFC 7617); a
        password may itself contain further ':' characters.
      - Decoding failures (bad base64, non-UTF-8) return None so callers can
        fail closed with HTTP 401 instead of raising.
    """

    auth_value = str(authorization_header or "").strip()
    if len(auth_value) < 7 or auth_value[:6].lower() != "basic ":
        return None
    token = auth_value[6:].strip()
    if not token:
        return None
    try:
        decoded = base64.b64decode(
            token.replace("-", "+").replace("_", "/"), validate=True
        ).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    username, sep, password = decoded.partition(":")
    if not sep:
        return None
    return username, password


def _evaluate_web_auth(
    web_cfg: dict[str, Any] | None,
    *,
    authorization_header: str | None,
    api_key_header: str | None,
    default_mode: str = "token",
) -> tuple[bool, int | None, str | None, dict[str, str] | None]:
    """Brief: Evaluate configured web auth for a single request.

    Inputs:
      - web_cfg: webserver config dict from YAML (or {}).
      - authorization_header: Raw Authorization header value.
      - api_key_header: Raw X-API-Key header value.
      - default_mode: Fallback auth mode when webserver.auth.mode is unset.

    Outputs:
      - Tuple of:
          - authorized: True when request is allowed.
          - status_code: HTTP status for denied requests; None when authorized.
          - detail: Error detail for denied requests; None when authorized.
          - headers: Optional response headers for denied requests.

    Behaviour:
      - ``mode=none`` allows all requests.
      - ``mode=token`` (default) enforces a static token via Bearer or X-API-Key;
        when ``allow_basic_token`` is true (default), also accepts Basic
        ``foghorn:<token>`` and advertises Basic on 401.
      - ``mode=basic`` enforces HTTP Basic credentials
        (``Authorization: Basic base64(user:pass)``).
      - Unknown auth modes fail closed.
    """

    auth_cfg = (web_cfg.get("auth") or {}) if isinstance(web_cfg, dict) else {}
    mode = str(auth_cfg.get("mode", default_mode)).strip().lower()
    if mode in {"", "none"}:
        return True, None, None, None
    if mode not in {"token", "basic"}:
        return False, 500, f"unsupported webserver.auth.mode: {mode}", None

    if mode == "basic":
        username = str(auth_cfg.get("username") or "")
        password_raw = auth_cfg.get("password")
        if (not isinstance(password_raw, str) or not str(password_raw).strip()) and (
            auth_cfg.get("password_secret") is not None
        ):
            try:
                from foghorn.plugins.secrets.resolve import resolve_secret_string

                password_raw = resolve_secret_string(
                    auth_cfg.get("password_secret"),
                    prefer=("token", "secret"),
                )
            except Exception:
                password_raw = None
        elif isinstance(password_raw, dict):
            try:
                from foghorn.plugins.secrets.resolve import resolve_secret_string

                password_raw = resolve_secret_string(
                    password_raw, prefer=("token", "secret")
                )
            except Exception:
                password_raw = None
        password = str(password_raw or "")
        if not username.strip() or not password:
            return (
                False,
                500,
                "webserver.auth.username and webserver.auth.password must be set when auth.mode=basic",
                None,
            )

        provided = _decode_basic_credentials(authorization_header)
        if provided is None or not (
            hmac.compare_digest(provided[0].encode("utf-8"), username.encode("utf-8"))
            and hmac.compare_digest(
                provided[1].encode("utf-8"), password.encode("utf-8")
            )
        ):
            return (
                False,
                401,
                "unauthorized",
                {"WWW-Authenticate": 'Basic realm="foghorn"'},
            )

        return True, None, None, None

    token = auth_cfg.get("token")
    if not token and auth_cfg.get("token_secret") is not None:
        try:
            from foghorn.plugins.secrets.resolve import resolve_token_value

            token = resolve_token_value(auth_cfg)
        except Exception:
            token = None
    if not token:
        return False, 500, "webserver.auth.token not configured", None

    allow_basic_token = _auth_allow_basic_token(auth_cfg)
    provided = _extract_provided_auth_token(
        authorization_header=authorization_header,
        api_key_header=api_key_header,
        allow_basic_token=allow_basic_token,
    )
    token_text = str(token)
    if not provided or not hmac.compare_digest(provided, token_text):
        www_authenticate = (
            _TOKEN_MODE_WWW_AUTHENTICATE_BEARER_AND_BASIC
            if allow_basic_token
            else _TOKEN_MODE_WWW_AUTHENTICATE_BEARER
        )
        return (
            False,
            401,
            "unauthorized",
            {"WWW-Authenticate": www_authenticate},
        )

    return True, None, None, None


def _build_auth_dependency(web_cfg: dict[str, Any], *, default_mode: str = "token"):
    """Build a FastAPI dependency enforcing optional admin auth.

    Inputs:
      - web_cfg: webserver config dict from YAML (or {}).
      - default_mode: Fallback auth mode when webserver.auth.mode is unset.

    Outputs:
      - Dependency callable usable with FastAPI Depends().

    Modes:
      - token (default): require Authorization: Bearer <token> or X-API-Key;
        with allow_basic_token (default true) also Basic foghorn:<token>.
      - none: no authentication.
      - basic: require HTTP Basic credentials (Authorization: Basic base64(user:pass))
        matching server.http.auth.username/password.
    """

    async def _auth(request: Request) -> None:
        authorized, status_code, detail, headers = _evaluate_web_auth(
            web_cfg,
            authorization_header=request.headers.get("authorization"),
            api_key_header=request.headers.get("x-api-key"),
            default_mode=str(default_mode or "token"),
        )
        if authorized:
            return
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
