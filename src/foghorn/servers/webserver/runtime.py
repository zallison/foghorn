"""Runtime and readiness helpers for the Foghorn admin webserver.

This module hosts the small set of classes and helpers that track listener
runtime state and implement the logic behind the /ready endpoints.

Historically these lived directly in :mod:`foghorn.servers.webserver.core`.
They are split out here to keep the main implementation module smaller while
preserving the public/semi-public API via re-exports from ``core``.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional, Tuple

# Re-export shared types from the FastAPI-free servers.runtime_state module so
# minimal/headless builds can import foghorn.main without pulling in the web UI.
from foghorn.servers.runtime_state import (
    RingBuffer,  # kept for backwards compatibility; some callers import it from webserver
)
from foghorn.servers.runtime_state import (  # noqa: F401
    RuntimeState,
    _ListenerRuntime,
    _thread_is_alive,
)
from foghorn.stats import StatsCollector

from .config_helpers import _get_web_cfg


def _expected_listeners_from_config(config: Dict[str, Any] | None) -> Dict[str, bool]:
    """Determine which listeners should be running based on config.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - dict mapping listener name -> enabled bool.

    Notes:
      - Mirrors the defaults in ``foghorn.main``: UDP defaults to enabled, others
        default to disabled.
      - Preferred v2 location is ``config['server']['listen']`` with legacy
        fallback to root-level ``listen``.
    """

    cfg = config if isinstance(config, dict) else {}

    server_cfg = cfg.get("server") or {}
    listen: Any
    if isinstance(server_cfg, dict) and isinstance(server_cfg.get("listen"), dict):
        listen = server_cfg.get("listen") or {}
    else:
        # Legacy fallback: root-level listen (used in older tests/configs).
        listen = cfg.get("listen") or {}
    if not isinstance(listen, dict):
        listen = {}

    dns_cfg = listen.get("dns")
    if not isinstance(dns_cfg, dict):
        dns_cfg = {}

    def _enabled_section(section_name: str, *, default_enabled: bool) -> bool:
        section = listen.get(section_name)
        if isinstance(section, dict):
            return bool(section.get("enabled", default_enabled))
        return bool(default_enabled)

    # Match foghorn.main defaults, including dns.{udp,tcp} legacy booleans.
    udp_section = listen.get("udp")
    if isinstance(udp_section, dict):
        udp_default_enabled = bool(udp_section.get("enabled", True))
    else:
        udp_default_enabled = bool(dns_cfg.get("udp")) if "udp" in dns_cfg else True

    tcp_section = listen.get("tcp")
    if isinstance(tcp_section, dict):
        tcp_default_enabled = bool(tcp_section.get("enabled", True))
    else:
        tcp_default_enabled = bool(dns_cfg.get("tcp")) if "tcp" in dns_cfg else False

    dot_section = listen.get("dot")
    dot_default_enabled = True if isinstance(dot_section, dict) else False

    doh_section = listen.get("doh")
    doh_default_enabled = True if isinstance(doh_section, dict) else False

    web_cfg = _get_web_cfg(cfg)
    has_web_cfg = bool(web_cfg)
    raw_web_enabled = web_cfg.get("enabled") if isinstance(web_cfg, dict) else None
    web_enabled = bool(raw_web_enabled) if raw_web_enabled is not None else has_web_cfg

    return {
        "udp": _enabled_section("udp", default_enabled=udp_default_enabled),
        "tcp": _enabled_section("tcp", default_enabled=tcp_default_enabled),
        "dot": _enabled_section("dot", default_enabled=dot_default_enabled),
        "doh": _enabled_section("doh", default_enabled=doh_default_enabled),
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
    server_cfg = cfg.get("server") or {}
    if not isinstance(server_cfg, dict):
        server_cfg = {}

    fog_cfg = cfg.get("foghorn") or {}
    resolver_cfg = (
        (server_cfg.get("resolver") if isinstance(server_cfg, dict) else None)
        or (fog_cfg.get("resolver") if isinstance(fog_cfg, dict) else None)
        or cfg.get("resolver")
        or {}
    )
    if not isinstance(resolver_cfg, dict):
        resolver_cfg = {}
    mode = str(resolver_cfg.get("mode", "forward")).lower()
    if mode == "none":
        mode = "master"

    if mode == "forward":
        upstream_block = cfg.get("upstreams")
        if isinstance(upstream_block, dict) and "endpoints" in upstream_block:
            upstreams = upstream_block.get("endpoints")
        else:
            upstreams = upstream_block or []
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
    # Prefer v2 root 'stats' but keep legacy 'statistics' support.
    stats_cfg = (
        cfg.get("stats")
        if isinstance(cfg.get("stats"), dict)
        else (cfg.get("statistics") or {})
    )
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
