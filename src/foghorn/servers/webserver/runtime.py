"""Runtime and readiness helpers for the Foghorn admin webserver.

This module hosts the small set of classes and helpers that track listener
runtime state and implement the logic behind the /ready endpoints.

Historically these lived directly in :mod:`foghorn.servers.webserver.core`.
They are split out here to keep the main implementation module smaller while
preserving the public/semi-public API via re-exports from ``core``.
"""

from __future__ import annotations

from dataclasses import dataclass
import threading
from typing import Any, Dict, Optional, Tuple, List

from cachetools import TTLCache

from foghorn.stats import StatsCollector
from foghorn.utils.register_caches import registered_cached

from .config_helpers import _get_web_cfg


@dataclass
class _ListenerRuntime:
    """Track the runtime state of a single listener for readiness checks.

    Inputs (fields):
      - name: Logical listener name (e.g. "udp", "tcp", "dot", "doh", "webserver").
      - enabled: Whether this listener is expected to be running.
      - thread: Optional thread-like object that may implement ``is_alive()`` or
        ``is_running()``.
      - error: Optional string describing a startup/runtime error.

    Outputs:
      - ``_ListenerRuntime`` instance used inside :class:`RuntimeState`.
    """

    name: str
    enabled: bool
    thread: Any | None = None
    error: str | None = None


class RuntimeState:
    """Shared, thread-safe runtime state used by /ready endpoints.

    Inputs (constructor):
      - startup_complete: Optional bool indicating whether main startup has
        completed.

    Outputs:
      - :class:`RuntimeState` instance whose :meth:`snapshot` method returns a
        JSON-safe mapping describing listener readiness.

    Example::

      state = RuntimeState()
      state.set_listener("udp", enabled=True, thread=None)
      state.mark_startup_complete()
    """

    def __init__(self, startup_complete: bool = False) -> None:
        self._lock = threading.Lock()
        self._startup_complete = bool(startup_complete)
        self._listeners: Dict[str, _ListenerRuntime] = {}

    def mark_startup_complete(self) -> None:
        """Mark the process as having completed startup.

        Inputs: none
        Outputs: none
        """

        with self._lock:
            self._startup_complete = True

    def set_listener(self, name: str, *, enabled: bool, thread: Any | None) -> None:
        """Register or update a listener entry.

        Inputs:
          - name: Listener name string.
          - enabled: Whether the listener is expected to be running.
          - thread: Optional thread/handle object.

        Outputs:
          - None.
        """

        if not name:
            return
        with self._lock:
            current = self._listeners.get(name)
            error = current.error if current is not None else None
            self._listeners[name] = _ListenerRuntime(
                name=str(name),
                enabled=bool(enabled),
                thread=thread,
                error=error,
            )

    def set_listener_error(self, name: str, exc: Exception | str) -> None:
        """Attach an error message to a listener entry.

        Inputs:
          - name: Listener name string.
          - exc: Exception instance or error string.

        Outputs:
          - None.
        """

        if not name:
            return
        msg = str(exc)
        with self._lock:
            current = self._listeners.get(name)
            enabled = current.enabled if current is not None else True
            thread = current.thread if current is not None else None
            self._listeners[name] = _ListenerRuntime(
                name=str(name),
                enabled=bool(enabled),
                thread=thread,
                error=msg,
            )

    @registered_cached(cache=TTLCache(maxsize=1, ttl=10))
    def snapshot(self) -> Dict[str, Any]:
        """Return a JSON-safe snapshot of current runtime state.

        Inputs: none

        Outputs:
          - dict with keys:
              * startup_complete: bool
              * listeners: mapping of listener name -> {enabled, running, error}
        """

        with self._lock:
            listeners = {
                name: {
                    "enabled": entry.enabled,
                    "running": _thread_is_alive(entry.thread),
                    "error": entry.error,
                }
                for name, entry in self._listeners.items()
            }
            return {
                "startup_complete": bool(self._startup_complete),
                "listeners": listeners,
            }


def _thread_is_alive(obj: Any | None) -> bool:
    """Best-effort check whether a thread/handle is alive.

    Inputs:
      - obj: Thread-like object (may implement ``is_alive()`` or
        ``is_running()``) or None.

    Outputs:
      - bool: True when ``obj`` appears to be running; False otherwise.
    """

    if obj is None:
        return False
    try:
        fn = getattr(obj, "is_alive", None)
        if callable(fn):
            return bool(fn())
    except Exception:
        return False
    # Some handles expose is_running instead of is_alive.
    try:
        fn = getattr(obj, "is_running", None)
        if callable(fn):
            return bool(fn())
    except Exception:
        return False
    return False


def _expected_listeners_from_config(config: Dict[str, Any] | None) -> Dict[str, bool]:
    """Determine which listeners should be running based on config.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - dict mapping listener name -> enabled bool.

    Notes:
      - Mirrors the defaults in ``foghorn.main``: UDP defaults to enabled, others
        default to disabled.
    """

    cfg = config if isinstance(config, dict) else {}
    listen = cfg.get("listen") or {}
    if not isinstance(listen, dict):
        listen = {}

    def _enabled(subkey: str, default: bool) -> bool:
        sub = listen.get(subkey)
        if not isinstance(sub, dict):
            return bool(default)
        return bool(sub.get("enabled", default))

    web_cfg = _get_web_cfg(cfg)
    # If a webserver block exists, treat it as enabled by default unless
    # explicitly disabled with enabled: false.
    has_web_cfg = bool(web_cfg)
    raw_web_enabled = web_cfg.get("enabled") if isinstance(web_cfg, dict) else None
    web_enabled = bool(raw_web_enabled) if raw_web_enabled is not None else has_web_cfg

    return {
        "udp": _enabled("udp", True),
        "tcp": _enabled("tcp", False),
        "dot": _enabled("dot", False),
        "doh": _enabled("doh", False),
        "webserver": web_enabled,
    }


def evaluate_readiness(
    *,
    stats: Optional[StatsCollector],
    config: Dict[str, Any] | None,
    runtime_state: RuntimeState | None,
) -> Tuple[bool, List[str], Dict[str, Any]]:
    """Compute readiness result and reasons for /ready endpoints.

    Inputs:
      - stats: Optional StatsCollector instance.
      - config: Full configuration mapping loaded from YAML (or None).
      - runtime_state: Optional RuntimeState populated by foghorn.main.

    Outputs:
      - (ready, reasons, details)
        * ready: bool
        * reasons: list of human-readable not-ready reasons
        * details: dict with structured readiness details for the UI.

    Notes:
      - Readiness is stricter than liveness: it verifies expected listeners are
        running, required upstream configuration exists, and optional
        persistence-store health checks pass.
    """

    cfg = config if isinstance(config, dict) else {}
    expected = _expected_listeners_from_config(cfg)

    not_ready: List[str] = []

    state_snapshot = (
        runtime_state.snapshot()
        if runtime_state is not None
        else {
            "startup_complete": True,
            "listeners": {},
        }
    )

    if not state_snapshot.get("startup_complete"):
        not_ready.append("startup not complete")

    # Upstream configuration: required in forwarder mode.
    fog_cfg = cfg.get("foghorn") or {}
    resolver_cfg = (
        (fog_cfg.get("resolver") if isinstance(fog_cfg, dict) else None)
        or cfg.get("resolver")
        or {}
    )
    if not isinstance(resolver_cfg, dict):
        resolver_cfg = {}
    mode = str(resolver_cfg.get("mode", "forward")).lower()

    if mode == "forward":
        upstreams = cfg.get("upstreams") or []
        if not isinstance(upstreams, list) or not any(
            isinstance(u, dict) for u in upstreams
        ):
            not_ready.append("no upstreams configured")

    # Listener threads/handles.
    listeners_state = state_snapshot.get("listeners") or {}
    for name, enabled in expected.items():
        if not enabled:
            continue
        entry = listeners_state.get(name) or {}
        running = bool(entry.get("running"))
        err = entry.get("error")
        if err:
            not_ready.append(f"{name} error: {err}")
        elif not running:
            not_ready.append(f"{name} listener not running")

    # Store availability (only when persistence is configured).
    stats_cfg = cfg.get("statistics") or {}
    if not isinstance(stats_cfg, dict):
        stats_cfg = {}
    persistence_cfg = stats_cfg.get("persistence") or {}
    if not isinstance(persistence_cfg, dict):
        persistence_cfg = {}

    stats_enabled = bool(stats_cfg.get("enabled", False))
    persistence_enabled = bool(persistence_cfg.get("enabled", True))

    if stats_enabled and persistence_enabled:
        store = getattr(stats, "_store", None) if stats is not None else None
        if store is None:
            not_ready.append("statistics persistence store not available")
        else:
            try:
                # Prefer an explicit health_check() when available.
                fn = getattr(store, "health_check", None)
                ok = bool(fn()) if callable(fn) else True
                if not ok:
                    not_ready.append("statistics persistence store not healthy")
            except Exception as exc:
                not_ready.append(f"statistics persistence store error: {exc}")

    details: Dict[str, Any] = {
        "mode": mode,
        "expected_listeners": expected,
        "runtime": state_snapshot,
    }

    ready = len(not_ready) == 0
    return ready, not_ready, details
