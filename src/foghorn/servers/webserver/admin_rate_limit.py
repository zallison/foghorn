"""Shared admin API rate-limiting abstraction and backend adapters.

Brief:
  This module centralizes admin HTTP rate-limiting logic so both FastAPI and
  the threaded fallback can enforce identical behaviour.

Inputs:
  - Runtime config (`server.http.admin_rate_limit`)
  - Loaded plugin instances (optional)
  - Request identity inputs (client IP, auth headers, action/path)

Outputs:
  - Deterministic allow/deny decisions and response headers
"""

from __future__ import annotations

import hashlib
import logging
import math
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Protocol

from .config_helpers import _get_web_cfg


logger = logging.getLogger("foghorn.webserver")


@dataclass(frozen=True)
class AdminRateLimitDecision:
    """Brief: Value object describing one admin rate-limit decision.

    Inputs:
      - allowed: Whether request should proceed.
      - limit: Effective request limit for the key in current window.
      - remaining: Remaining requests for the key in current window.
      - retry_after_seconds: Whole-second retry hint when blocked.
      - backend: Backend label used for this decision.

    Outputs:
      - Immutable decision object plus header-render helper.
    """

    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int
    backend: str

    def to_headers(self) -> Dict[str, str]:
        """Brief: Render standard response headers for rate-limit visibility.

        Inputs:
          - None.

        Outputs:
          - Mapping with X-RateLimit headers and Retry-After when blocked.
        """

        headers = {
            "X-RateLimit-Limit": str(max(0, int(self.limit))),
            "X-RateLimit-Remaining": str(max(0, int(self.remaining))),
            "X-RateLimit-Backend": str(self.backend),
        }
        if not bool(self.allowed):
            headers["Retry-After"] = str(max(0, int(self.retry_after_seconds)))
        return headers


class AdminRateLimitBackend(Protocol):
    """Brief: Protocol for admin API rate-limit backend implementations.

    Inputs:
      - key: Stable key for one principal/action bucket.
      - now_ts: Epoch seconds timestamp.

    Outputs:
      - AdminRateLimitDecision.
    """

    @property
    def name(self) -> str:
        """Backend display name."""

    def evaluate(self, *, key: str, now_ts: float) -> AdminRateLimitDecision:
        """Evaluate one request against the backend."""


class InMemoryAdminRateLimitBackend:
    """Brief: In-process fixed-window backend used for admin API limiting.

    Inputs:
      - requests_per_window: Allowed requests per window (>=1).
      - window_seconds: Window length in seconds (>=1).
      - burst: Additional allowance layered on top of requests_per_window.

    Outputs:
      - Fixed-window decision for each key, isolated to this process.
    """

    def __init__(
        self,
        *,
        requests_per_window: int,
        window_seconds: int,
        burst: int = 0,
        backend_name: str = "memory",
    ) -> None:
        self._requests_per_window = max(1, int(requests_per_window))
        self._window_seconds = max(1, int(window_seconds))
        self._burst = max(0, int(burst))
        self._name = str(backend_name or "memory")
        self._lock = threading.Lock()
        self._state: Dict[str, tuple[int, int]] = {}

    @property
    def name(self) -> str:
        """Brief: Return backend display name.

        Inputs:
          - None.

        Outputs:
          - str backend name.
        """

        return self._name

    def evaluate(self, *, key: str, now_ts: float) -> AdminRateLimitDecision:
        """Brief: Evaluate one key within the current fixed window.

        Inputs:
          - key: Stable key for one principal/action bucket.
          - now_ts: Epoch seconds timestamp.

        Outputs:
          - AdminRateLimitDecision with remaining quota or Retry-After.
        """

        limit = int(self._requests_per_window + self._burst)
        now_i = int(now_ts)
        window_start = now_i - (now_i % int(self._window_seconds))
        with self._lock:
            prior_window, prior_count = self._state.get(str(key), (window_start, 0))
            if int(prior_window) != int(window_start):
                count = 0
            else:
                count = int(prior_count)
            count += 1
            self._state[str(key)] = (int(window_start), int(count))
        allowed = int(count) <= int(limit)
        remaining = max(0, int(limit - count))
        retry_after = (
            max(0, int(window_start + int(self._window_seconds) - now_i))
            if not allowed
            else 0
        )
        return AdminRateLimitDecision(
            allowed=bool(allowed),
            limit=int(limit),
            remaining=int(remaining),
            retry_after_seconds=int(retry_after),
            backend=self.name,
        )


def _plugin_window_fallback(plugin: object | None) -> tuple[int, int, int]:
    """Brief: Derive fallback fixed-window knobs from a RateLimit plugin.

    Inputs:
      - plugin: Optional RateLimit plugin instance.

    Outputs:
      - Tuple (requests_per_window, window_seconds, burst).
    """

    if plugin is None:
        return (60, 60, 0)

    try:
        window_seconds = max(1, int(getattr(plugin, "window_seconds", 60) or 60))
    except Exception:  # pragma: nocover - defensive fallback for malformed plugin window settings
        window_seconds = 60

    # Prefer global_max_rps when explicitly configured; otherwise use a
    # conservative floor from min_enforce_rps.
    try:
        global_max_rps = float(getattr(plugin, "global_max_rps", 0.0) or 0.0)
    except Exception:  # pragma: nocover - defensive fallback for malformed plugin limiter settings
        global_max_rps = 0.0
    try:
        min_enforce_rps = float(getattr(plugin, "min_enforce_rps", 50.0) or 50.0)
    except Exception:  # pragma: nocover - defensive fallback for malformed plugin limiter settings
        min_enforce_rps = 50.0
    base_rps = float(global_max_rps if global_max_rps > 0.0 else min_enforce_rps)
    requests_per_window = max(1, int(math.ceil(base_rps * float(window_seconds))))
    return (requests_per_window, window_seconds, 0)


def _get_numeric_plugin_attr(plugin: object, attr_name: str, default: float) -> float:
    """Brief: Read a numeric plugin attribute with safe fallback.

    Inputs:
      - plugin: Plugin instance to inspect.
      - attr_name: Attribute name expected to hold a numeric value.
      - default: Fallback numeric value when conversion fails.

    Outputs:
      - float numeric value from the plugin or default.
    """

    try:
        value = getattr(plugin, attr_name, default)
        return float(value if value is not None else default)
    except Exception:  # pragma: nocover - defensive fallback for malformed plugin numeric attrs
        return float(default)


class PluginAdminRateLimitBackend:
    """Brief: Backend adapter that integrates with the existing RateLimit plugin.

    Inputs:
      - plugins: Loaded plugin instances.
      - fallback_backend: In-memory backend used when plugin hooks are absent.

    Outputs:
      - AdminRateLimit decisions backed by plugin hook when available, else
        fallback fixed-window decisions derived from plugin settings.
    """

    def __init__(
        self,
        *,
        plugins: Iterable[object] | None,
        fallback_backend: InMemoryAdminRateLimitBackend | None = None,
    ) -> None:
        self._plugin = self._find_rate_limit_plugin(plugins)
        if fallback_backend is not None:
            self._fallback_backend = fallback_backend
        else:
            requests_per_window, window_seconds, burst = _plugin_window_fallback(
                self._plugin
            )
            self._fallback_backend = InMemoryAdminRateLimitBackend(
                requests_per_window=requests_per_window,
                window_seconds=window_seconds,
                burst=burst,
                backend_name="plugin-fallback-memory",
            )

    @property
    def name(self) -> str:
        """Brief: Return backend display name.

        Inputs:
          - None.

        Outputs:
          - str backend label.
        """

        return "plugin"

    @staticmethod
    def _find_rate_limit_plugin(plugins: Iterable[object] | None) -> object | None:
        """Brief: Return the first loaded RateLimit plugin instance.

        Inputs:
          - plugins: Loaded plugin instances.

        Outputs:
          - Matching plugin object or None.
        """

        named_candidate: object | None = None
        for plugin in plugins or []:
            try:
                if callable(getattr(plugin, "check_admin_rate_limit", None)):
                    return plugin
                if named_candidate is None and str(type(plugin).__name__) == "RateLimit":
                    named_candidate = plugin
            except Exception:  # pragma: nocover - defensive against malformed plugin objects
                continue
        return named_candidate

    def evaluate(self, *, key: str, now_ts: float) -> AdminRateLimitDecision:
        """Brief: Evaluate one request, preferring plugin-native hook when present.

        Inputs:
          - key: Stable key for one principal/action bucket.
          - now_ts: Epoch seconds timestamp.

        Outputs:
          - AdminRateLimitDecision from plugin hook or fallback backend.
        """

        hook = getattr(self._plugin, "check_admin_rate_limit", None)
        if callable(hook):
            try:
                payload = hook(key=str(key), now_ts=float(now_ts))
                return _decision_from_plugin_payload(payload)
            except Exception:  # pragma: nocover - defensive: plugin hook failures must fail closed to fallback backend
                logger.debug(
                    "admin rate-limit plugin hook failed; using fallback backend",
                    exc_info=True,
                )
        return self._fallback_backend.evaluate(key=str(key), now_ts=float(now_ts))


def _decision_from_plugin_payload(payload: object) -> AdminRateLimitDecision:
    """Brief: Normalize plugin hook payload into AdminRateLimitDecision.

    Inputs:
      - payload: Hook return value (bool, tuple, or dict).

    Outputs:
      - Normalized AdminRateLimitDecision.
    """

    if isinstance(payload, bool):
        return AdminRateLimitDecision(
            allowed=bool(payload),
            limit=0,
            remaining=0,
            retry_after_seconds=0 if bool(payload) else 1,
            backend="plugin",
        )
    if isinstance(payload, tuple) and len(payload) == 2:
        return AdminRateLimitDecision(
            allowed=bool(payload[0]),
            limit=0,
            remaining=0,
            retry_after_seconds=max(0, int(payload[1] or 0)),
            backend="plugin",
        )
    if isinstance(payload, dict):
        return AdminRateLimitDecision(
            allowed=bool(payload.get("allowed", False)),
            limit=max(0, int(payload.get("limit", 0) or 0)),
            remaining=max(0, int(payload.get("remaining", 0) or 0)),
            retry_after_seconds=max(0, int(payload.get("retry_after_seconds", 0) or 0)),
            backend=str(payload.get("backend", "plugin") or "plugin"),
        )
    raise ValueError(f"unsupported admin rate-limit payload type: {type(payload).__name__}")


@dataclass(frozen=True)
class AdminRateLimitSettings:
    """Brief: Parsed settings for admin API request rate limiting.

    Inputs:
      - Parsed from `server.http.admin_rate_limit`.

    Outputs:
      - Immutable settings used by AdminRateLimitService.
    """

    enabled: bool
    backend: str
    requests_per_window: int
    window_seconds: int
    burst: int
    key_mode: str
    excluded_actions: tuple[str, ...]


def parse_admin_rate_limit_settings(config: Dict[str, Any] | None) -> AdminRateLimitSettings:
    """Brief: Parse `server.http.admin_rate_limit` settings with safe defaults.

    Inputs:
      - config: Full runtime config mapping.

    Outputs:
      - AdminRateLimitSettings with normalized fields.
    """

    web_cfg = _get_web_cfg(config)
    admin_cfg_obj = web_cfg.get("admin_rate_limit")
    admin_cfg = admin_cfg_obj if isinstance(admin_cfg_obj, dict) else {}
    enabled = bool(admin_cfg.get("enabled", False))
    backend = str(admin_cfg.get("backend", "plugin") or "plugin").strip().lower()
    if backend not in {"plugin", "memory"}:
        backend = "plugin"
    try:
        requests_per_window = max(1, int(admin_cfg.get("requests_per_window", 60)))
    except Exception:  # pragma: nocover - defensive fallback for malformed config values
        requests_per_window = 60
    try:
        window_seconds = max(1, int(admin_cfg.get("window_seconds", 60)))
    except Exception:  # pragma: nocover - defensive fallback for malformed config values
        window_seconds = 60
    try:
        burst = max(0, int(admin_cfg.get("burst", 0)))
    except Exception:  # pragma: nocover - defensive fallback for malformed config values
        burst = 0
    key_mode = str(admin_cfg.get("key_mode", "client_action") or "client_action").strip()
    key_mode = key_mode.lower()
    if key_mode not in {"client", "client_action"}:
        key_mode = "client_action"
    raw_excluded = admin_cfg.get("excluded_actions", [])
    excluded_actions: list[str] = []
    if isinstance(raw_excluded, list):
        excluded_actions = [str(item).strip() for item in raw_excluded if str(item).strip()]
    return AdminRateLimitSettings(
        enabled=bool(enabled),
        backend=str(backend),
        requests_per_window=int(requests_per_window),
        window_seconds=int(window_seconds),
        burst=int(burst),
        key_mode=str(key_mode),
        excluded_actions=tuple(sorted(set(excluded_actions))),
    )


def _auth_identity_fragment(
    authorization_header: str | None,
    api_key_header: str | None,
) -> str:
    """Brief: Return a stable, non-secret auth identity fragment.

    Inputs:
      - authorization_header: Optional Authorization header.
      - api_key_header: Optional X-API-Key header.

    Outputs:
      - Stable hash-based identity string; empty when no auth token is present.
    """

    token = ""
    auth_text = str(authorization_header or "")
    if auth_text.lower().startswith("bearer "):
        token = auth_text[7:].strip()
    elif api_key_header is not None:
        token = str(api_key_header).strip()
    if not token:
        return ""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
    return f"token:{digest}"


class AdminRateLimitService:
    """Brief: Shared service that evaluates admin request rate-limit decisions.

    Inputs:
      - settings: Parsed settings from config.
      - backend: Backend implementation.

    Outputs:
      - Per-request AdminRateLimitDecision.
    """

    def __init__(
        self,
        *,
        settings: AdminRateLimitSettings,
        backend: AdminRateLimitBackend,
    ) -> None:
        self._settings = settings
        self._backend = backend

    @property
    def settings(self) -> AdminRateLimitSettings:
        """Brief: Return parsed immutable settings.

        Inputs:
          - None.

        Outputs:
          - AdminRateLimitSettings.
        """

        return self._settings

    def evaluate(
        self,
        *,
        action: str,
        client_ip: str,
        authorization_header: str | None,
        api_key_header: str | None,
        now_ts: float | None = None,
    ) -> AdminRateLimitDecision:
        """Brief: Evaluate one admin request for allow/deny status.

        Inputs:
          - action: Stable action identifier for the endpoint.
          - client_ip: Request client IP string.
          - authorization_header: Optional Authorization header.
          - api_key_header: Optional X-API-Key header.
          - now_ts: Optional epoch timestamp override.

        Outputs:
          - AdminRateLimitDecision.
        """

        if not bool(self._settings.enabled):
            return AdminRateLimitDecision(
                allowed=True,
                limit=0,
                remaining=0,
                retry_after_seconds=0,
                backend="disabled",
            )
        action_text = str(action or "").strip()
        if action_text and action_text in set(self._settings.excluded_actions):
            return AdminRateLimitDecision(
                allowed=True,
                limit=0,
                remaining=0,
                retry_after_seconds=0,
                backend="excluded",
            )

        principal = _auth_identity_fragment(authorization_header, api_key_header)
        if not principal:
            principal = str(client_ip or "unknown")
        if self._settings.key_mode == "client":
            key = principal
        else:
            key = f"{principal}:{action_text or 'admin'}"
        ts = float(now_ts) if now_ts is not None else time.time()
        return self._backend.evaluate(key=str(key), now_ts=float(ts))


def _build_backend(
    *,
    settings: AdminRateLimitSettings,
    plugins: Iterable[object] | None,
) -> AdminRateLimitBackend:
    """Brief: Build backend implementation according to parsed settings.

    Inputs:
      - settings: Parsed AdminRateLimitSettings.
      - plugins: Loaded plugin instances.

    Outputs:
      - Concrete AdminRateLimitBackend implementation.
    """

    memory_backend = InMemoryAdminRateLimitBackend(
        requests_per_window=int(settings.requests_per_window),
        window_seconds=int(settings.window_seconds),
        burst=int(settings.burst),
        backend_name="memory",
    )
    if settings.backend == "memory":
        return memory_backend
    return PluginAdminRateLimitBackend(
        plugins=plugins,
        fallback_backend=memory_backend,
    )


def _service_signature(
    *,
    settings: AdminRateLimitSettings,
    plugins: Iterable[object] | None,
) -> tuple[Any, ...]:
    """Brief: Compute cache signature for service reuse across requests.

    Inputs:
      - settings: Parsed settings object.
      - plugins: Loaded plugin instances.

    Outputs:
      - Hashable signature tuple.
    """

    plugin_fingerprint_items: list[tuple[Any, ...]] = []
    for plugin in (plugins or []):
        plugin_name = str(getattr(plugin, "name", type(plugin).__name__))
        plugin_fingerprint_items.append(
            (
                plugin_name,
                str(type(plugin).__name__),
                bool(callable(getattr(plugin, "check_admin_rate_limit", None))),
                int(
                    max(
                        1,
                        int(_get_numeric_plugin_attr(plugin, "window_seconds", 60.0)),
                    )
                ),
                _get_numeric_plugin_attr(plugin, "global_max_rps", 0.0),
                _get_numeric_plugin_attr(plugin, "min_enforce_rps", 50.0),
            )
        )
    plugin_fingerprint = tuple(sorted(plugin_fingerprint_items))
    return (
        bool(settings.enabled),
        str(settings.backend),
        int(settings.requests_per_window),
        int(settings.window_seconds),
        int(settings.burst),
        str(settings.key_mode),
        tuple(settings.excluded_actions),
        plugin_fingerprint,
    )


def get_admin_rate_limit_service(
    *,
    state_obj: object,
    config: Dict[str, Any] | None,
    plugins: Iterable[object] | None,
) -> AdminRateLimitService:
    """Brief: Return cached admin rate-limit service for runtime state object.

    Inputs:
      - state_obj: Object used to cache the service (e.g. app.state or server).
      - config: Full runtime config mapping.
      - plugins: Loaded plugin instances.

    Outputs:
      - AdminRateLimitService instance.
    """

    settings = parse_admin_rate_limit_settings(config)
    signature = _service_signature(settings=settings, plugins=plugins)
    cached_signature = getattr(state_obj, "_admin_rate_limit_service_signature", None)
    cached_service = getattr(state_obj, "_admin_rate_limit_service", None)
    if cached_service is not None and cached_signature == signature:
        return cached_service

    service = AdminRateLimitService(
        settings=settings,
        backend=_build_backend(settings=settings, plugins=plugins),
    )
    setattr(state_obj, "_admin_rate_limit_service", service)
    setattr(state_obj, "_admin_rate_limit_service_signature", signature)
    return service
