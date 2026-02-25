"""Server management for Foghorn admin webserver.

This module contains server startup and management functions including:
- _AdminHTTPServer: ThreadingHTTPServer subclass with shared state
- _start_admin_server_threaded: Start threaded fallback server
- start_webserver: Main entry point that chooses uvicorn or threaded mode
"""

from __future__ import annotations

import http.server
import logging
import os
import socket
import threading
from typing import Any, Dict, Optional

from ...stats import StatsCollector
from .logging_utils import RingBuffer
from .runtime import RuntimeState
from .types_and_buffers import WebServerHandle
from .threaded_handlers import _ThreadedAdminRequestHandler

# Forward declaration for create_app - actual import happens in start_webserver
# to avoid circular dependency
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI


logger = logging.getLogger("foghorn.webserver")


class _AdminHTTPServer(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer carrying shared admin state (stats, config, logs).

    Inputs (constructor):
      - server_address: (host, port) tuple
      - RequestHandlerClass: handler class (typically _ThreadedAdminRequestHandler)
      - stats: Optional StatsCollector
      - config: Configuration dict loaded from YAML
      - log_buffer: Optional RingBuffer instance

    Outputs:
      - Initialized HTTP server suitable for use with serve_forever().

    Example:
      >>> # internal use by _start_admin_server_threaded()
    """

    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[http.server.BaseHTTPRequestHandler],
        stats: Optional[StatsCollector],
        config: Dict[str, Any],
        log_buffer: Optional[RingBuffer],
        config_path: str | None = None,
        runtime_state: RuntimeState | None = None,
        plugins: list[object] | None = None,
    ) -> None:
        """Initialize admin HTTP server with shared state and host metadata.

        Inputs:
          - server_address: (host, port) tuple for the HTTP server bind.
          - RequestHandlerClass: Request handler type.
          - stats: Optional StatsCollector instance.
          - config: Loaded configuration mapping.
          - log_buffer: Optional RingBuffer for recent log entries.
          - config_path: Optional path to the active YAML config file.

        Outputs:
          - None. The instance exposes attributes used by request handlers,
            including cached hostname/ip values that are stable for the
            lifetime of the process.
        """

        super().__init__(server_address, RequestHandlerClass)
        self.stats = stats
        self.config = config
        self.log_buffer = log_buffer
        self.config_path = config_path
        self.runtime_state = runtime_state
        # Preserve the plugin list so threaded handlers can look up plugin
        # instances by name when serving plugin-specific pages or APIs.
        self.plugins = list(plugins or [])

        if runtime_state is not None:
            runtime_state.set_listener("webserver", enabled=True, thread=None)

        # Cache hostname and IP once; they are stable for the process lifetime
        # and may be relatively expensive to resolve repeatedly in hot paths
        # such as /stats.
        try:
            self.hostname = socket.gethostname()
        except Exception:  # pragma: no cover - environment specific
            self.hostname = "unknown-host"
        try:
            self.host_ip = socket.gethostbyname(self.hostname)
        except Exception:  # pragma: no cover - environment specific
            self.host_ip = "0.0.0.0"


def _start_admin_server_threaded(
    stats: Optional[StatsCollector],
    config: Dict[str, Any],
    log_buffer: Optional[RingBuffer],
    config_path: str | None = None,
    runtime_state: RuntimeState | None = None,
    plugins: list[object] | None = None,
) -> Optional[
    "WebServerHandle"
]:  # pragma: no cover - environment-dependent threaded fallback; exercised via start_webserver tests
    """Brief: Start threaded admin HTTP server without using asyncio.

    Inputs:
      - stats: Optional StatsCollector
      - config: Full configuration dict
      - log_buffer: Optional RingBuffer for log entries

    Outputs:
      - WebServerHandle if server started successfully, else None.

    Example:
      >>> handle = _start_admin_server_threaded(
      ...     None,
      ...     {"server": {"http": {"enabled": True}}},
      ...     None,
      ... )
    """

    if isinstance(config, dict):
        server_cfg = config.get("server") or {}
        web_cfg = server_cfg.get("http") or {}
    else:
        web_cfg = {}
    if not web_cfg.get("enabled"):
        return None

    host = str(web_cfg.get("host", "127.0.0.1"))
    port = int(web_cfg.get("port", 5380))

    try:
        httpd = _AdminHTTPServer(
            (host, port),
            _ThreadedAdminRequestHandler,
            stats=stats,
            config=config,
            log_buffer=log_buffer,
            config_path=config_path,
            runtime_state=runtime_state,
            plugins=plugins,
        )
    except (
        OSError
    ) as exc:  # pragma: no cover - binding failures are environment-specific
        logger.error(
            "Failed to bind threaded admin webserver on %s:%d: %s", host, port, exc
        )
        return None

    def _serve() -> None:
        try:
            httpd.serve_forever()
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.exception("Unhandled exception in threaded admin webserver")
        finally:
            try:
                httpd.server_close()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

    thread = threading.Thread(
        target=_serve,
        name="foghorn-webserver-threaded",
        daemon=True,
    )
    thread.start()
    logger.info("Started threaded admin webserver on %s:%d", host, port)
    return WebServerHandle(thread, server=httpd)


def start_webserver(
    stats: Optional[StatsCollector],
    config: Dict[str, Any],
    log_buffer: Optional[RingBuffer] = None,
    config_path: str | None = None,
    runtime_state: RuntimeState | None = None,
    plugins: list[object] | None = None,
) -> Optional[WebServerHandle]:
    """Start admin HTTP server, preferring uvicorn and falling back to threaded HTTP."""

    if isinstance(config, dict):
        # Only accept webserver enable/host/port configuration from the
        # v2-style server-level ``server.http`` block. Root-level ``http`` and
        # ``webserver`` blocks are intentionally ignored.
        server_cfg = config.get("server") or {}
        web_cfg = server_cfg.get("http") or {}
    else:
        web_cfg = {}

    # Treat presence of a webserver block as enabled by default so that
    # configurations that declare webserver: {} behave as "on" unless
    # explicitly disabled with enabled: false.
    has_web_cfg = bool(web_cfg)
    raw_enabled = web_cfg.get("enabled") if isinstance(web_cfg, dict) else None
    enabled = bool(raw_enabled) if raw_enabled is not None else has_web_cfg
    if not enabled:
        return None

    allow_threaded_fallback = bool(web_cfg.get("allow_threaded_fallback", True))

    # Best-effort: generate a config diagram PNG for the active config when
    # possible. This is intentionally non-fatal (e.g., dot missing).
    if config_path:
        try:
            from ...utils.config_diagram import ensure_config_diagram_png

            ok, detail, png_path = ensure_config_diagram_png(config_path=config_path)
            if ok:
                logger.info("Config diagram: %s (%s)", png_path, detail)
            else:
                logger.warning("Config diagram not generated: %s", detail)
        except Exception:  # pragma: no cover - defensive
            logger.exception("Config diagram generation failed")

    foghorn_cfg = (config.get("foghorn") or {}) if isinstance(config, dict) else {}
    use_asyncio = bool(foghorn_cfg.get("use_asyncio", True))

    # Helper: call the threaded fallback in a way that remains compatible with
    # legacy tests that monkeypatch _start_admin_server_threaded() with a
    # simplified signature. When the real implementation is present, we pass
    # plugins/runtime_state so that threaded and uvicorn paths see the same
    # plugin instances.
    def _call_threaded(
        *,
        stats_obj: Optional[StatsCollector],
        cfg_obj: Dict[str, Any],
        buf_obj: Optional[RingBuffer],
        cfg_path_obj: str | None,
        rt_state: RuntimeState | None,
        plugins_obj: list[object] | None,
    ) -> Optional["WebServerHandle"]:
        try:
            import inspect as _inspect  # local import to avoid module-level cost
            import sys

            # Look up the function dynamically to support monkeypatching.
            # Tests may patch foghorn.servers.webserver._start_admin_server_threaded.
            core_mod = sys.modules.get("foghorn.servers.webserver.core")
            if core_mod and hasattr(core_mod, "_start_admin_server_threaded"):
                fn = getattr(core_mod, "_start_admin_server_threaded")
            else:
                fn = _start_admin_server_threaded

            sig = _inspect.signature(fn)
            params = sig.parameters
            kwargs: Dict[str, Any] = {}
            if "config_path" in params:
                kwargs["config_path"] = cfg_path_obj
            if rt_state is not None and "runtime_state" in params:
                kwargs["runtime_state"] = rt_state
            if "plugins" in params:
                kwargs["plugins"] = plugins_obj
            return fn(stats_obj, cfg_obj, buf_obj, **kwargs)
        except Exception:
            # Best-effort fallback: use the original minimal calling convention.
            # Look up dynamically again for the fallback path.
            import sys

            core_mod = sys.modules.get("foghorn.servers.webserver.core")
            if core_mod and hasattr(core_mod, "_start_admin_server_threaded"):
                fn = getattr(core_mod, "_start_admin_server_threaded")
            else:
                fn = _start_admin_server_threaded
            return fn(
                stats_obj,
                cfg_obj,
                buf_obj,
                config_path=cfg_path_obj,
            )

    # Detect restricted environments where asyncio cannot create its self-pipe
    # and skip uvicorn entirely in that case, or when explicitly disabled via
    # foghorn.use_asyncio.
    can_use_asyncio = use_asyncio
    if can_use_asyncio:
        try:  # pragma: no cover - difficult to exercise PermissionError in CI
            import asyncio

            loop = asyncio.new_event_loop()
            loop.close()

        except PermissionError as exc:  # pragma: no cover - best effort
            logger.warning(
                "Asyncio loop creation failed for admin webserver: %s falling back to threaded HTTP server.",
                exc,
            )
            # Always disable asyncio path on PermissionError, regardless of whether
            # we are running inside a container. This mirrors the DoH server logic
            # and ensures we reliably use the threaded fallback when self-pipe
            # creation is not permitted.
            can_use_asyncio = False
            container_path = "/.dockerenv"
            if os.path.exists(container_path):
                logger.warning(
                    "Possible container permission issues. Update, check seccomp settings, or run with --privileged "
                )
                logger.warning(
                    "Now enjoy this exception and wait for the threaded server to start: \n"
                )
        except Exception:
            can_use_asyncio = use_asyncio

    if not can_use_asyncio:
        if not allow_threaded_fallback:
            logger.warning(
                "Admin webserver threaded fallback is disabled (allow_threaded_fallback=false). "
                "Refusing to start admin webserver without uvicorn/FastAPI."
            )
            return None
        logger.warning(
            "Starting admin webserver using threaded stdlib HTTP fallback. This mode lacks full DoS/DDoS hardening and is not recommended for production."
        )
        handle = _call_threaded(
            stats_obj=stats,
            cfg_obj=config,
            buf_obj=log_buffer,
            cfg_path_obj=config_path,
            rt_state=runtime_state,
            plugins_obj=plugins,
        )
        if runtime_state is not None and handle is not None:
            runtime_state.set_listener("webserver", enabled=True, thread=handle)
        return handle

    try:
        import uvicorn
    except Exception as exc:  # pragma: no cover - missing optional dependency
        if not allow_threaded_fallback:
            logger.warning(
                "webserver.enabled=true but uvicorn is not available (%s) and threaded fallback is disabled (allow_threaded_fallback=false)",
                exc,
            )
            return None
        logger.warning(
            "webserver.enabled=true but uvicorn is not available (%s); starting threaded stdlib HTTP fallback (not recommended for production)",
            exc,
        )
        handle = _call_threaded(
            stats_obj=stats,
            cfg_obj=config,
            buf_obj=log_buffer,
            cfg_path_obj=config_path,
            rt_state=runtime_state,
            plugins_obj=plugins,
        )
        if runtime_state is not None and handle is not None:
            runtime_state.set_listener("webserver", enabled=True, thread=handle)
        return handle

    host = str(web_cfg.get("host", "127.0.0.1"))
    port = int(web_cfg.get("port", 5380))

    # Warn if unauthenticated and binding to all interfaces
    auth_cfg = web_cfg.get("auth") or {}
    mode = str(auth_cfg.get("mode", "none")).lower()
    if mode == "none" and host in ("0.0.0.0", "::"):
        logger.warning(
            "Foghorn webserver is bound to %s without authentication; consider using auth.mode or restricting host",
            host,
        )

    # Import create_app lazily to avoid circular dependency
    from .core import create_app

    app = create_app(
        stats,
        config,
        log_buffer,
        config_path=config_path,
        runtime_state=runtime_state,
        plugins=plugins,
    )

    config_uvicorn = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config_uvicorn)

    def _runner() -> None:
        try:
            server.run()
        except (
            PermissionError
        ) as exc:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.error(
                "Webserver disabled: PermissionError while creating asyncio self-pipe/socketpair: %s; "
                "this usually indicates a restricted container or seccomp profile.",
                exc,
            )
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.exception("Unhandled exception in webserver thread")

    thread = threading.Thread(target=_runner, name="foghorn-webserver", daemon=True)
    thread.start()

    if runtime_state is not None:
        runtime_state.set_listener("webserver", enabled=True, thread=thread)

    logger.info("Started Foghorn webserver on %s:%d", host, port)
    return WebServerHandle(thread)
