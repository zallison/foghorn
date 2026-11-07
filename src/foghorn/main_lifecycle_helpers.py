# Copyright (c) 2025 Zack Allison
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Callable
from typing import Any

from .plugins.setup import run_shutdown_plugins
from .servers.runtime_state import RuntimeState


def _resolve_udp(query_bytes: bytes, client_ip: str) -> bytes:
    """Brief: Resolve a DNS query received via UDP listener.

    Inputs:
      - query_bytes: Wire-format DNS query bytes.
      - client_ip: Client IP address string.

    Outputs:
      - bytes: Wire-format DNS response produced by the shared resolver.

    Notes:
      - Enforces the UDP response size ceiling (TC=1) after resolution so
        both asyncio and threaded UDP paths share consistent truncation
        behavior.
    """

    logger = logging.getLogger("foghorn.main")
    # Import at call time so tests can monkeypatch foghorn.servers.server.resolve_query_bytes.
    from .servers.server import resolve_query_bytes as _resolve_query_bytes

    wire = _resolve_query_bytes(
        query_bytes,
        client_ip,
        listener="udp",
        secure=False,
    )

    try:
        from foghorn.runtime_config import get_runtime_snapshot

        from .servers.udp_server import enforce_udp_response_size_ceiling

        server_max = get_runtime_snapshot().udp_max_response_bytes
        wire = enforce_udp_response_size_ceiling(
            query_wire=query_bytes,
            response_wire=wire,
            server_max_bytes=server_max,
        )
    except Exception as exc:
        logger.warning(
            "UDP response size ceiling enforcement failed (returning original wire bytes): %s",
            exc,
            exc_info=True,
        )

    return wire


def _resolve_tcp(query_bytes: bytes, client_ip: str) -> bytes:
    """Brief: Resolve a DNS query received via TCP listener.

    Inputs:
      - query_bytes: Wire-format DNS query bytes.
      - client_ip: Client IP address string.

    Outputs:
      - bytes: Wire-format DNS response produced by the shared resolver.
    """

    from .servers.server import resolve_query_bytes as _resolve_query_bytes

    return _resolve_query_bytes(
        query_bytes,
        client_ip,
        listener="tcp",
        secure=False,
    )


def _resolve_dot(query_bytes: bytes, client_ip: str) -> bytes:
    """Brief: Resolve a DNS query received via DoT (TLS) listener.

    Inputs:
      - query_bytes: Wire-format DNS query bytes.
      - client_ip: Client IP address string.

    Outputs:
      - bytes: Wire-format DNS response produced by the shared resolver.
    """

    from .servers.server import resolve_query_bytes as _resolve_query_bytes

    return _resolve_query_bytes(
        query_bytes,
        client_ip,
        listener="dot",
        secure=True,
    )


def _resolve_doh(query_bytes: bytes, client_ip: str) -> bytes:
    """Brief: Resolve a DNS query received via DoH (HTTPS) listener.

    Inputs:
      - query_bytes: Wire-format DNS query bytes.
      - client_ip: Client IP address string.

    Outputs:
      - bytes: Wire-format DNS response produced by the shared resolver.
    """

    from .servers.server import resolve_query_bytes as _resolve_query_bytes

    return _resolve_query_bytes(
        query_bytes,
        client_ip,
        listener="doh",
        secure=True,
    )


def _start_asyncio_server(
    coro_factory: Callable[[], Any],
    name: str,
    *,
    listener_key: str,
    on_permission_error=None,
    record_listener_error: Callable[..., None],
    loop_threads: list[threading.Thread],
    runtime_state: RuntimeState,
    threading_module: Any | None = None,
    dot_cfg: dict | None = None,
    doh_cfg: dict | None = None,
) -> threading.Thread:
    """Brief: Start an asyncio listener in a daemon background thread.

    Inputs:
      - coro_factory: Zero-arg callable returning the awaitable server coroutine.
      - name: Thread name for the listener.
      - listener_key: Runtime-state key (udp/tcp/dot/doh).
      - on_permission_error: Optional fallback invoked on PermissionError.
      - record_listener_error: Callback to record listener failures.
      - loop_threads: Shared list of background listener threads.
      - runtime_state: Process RuntimeState for readiness tracking.
      - threading_module: Threading module used to construct Thread. Pass
        foghorn.main.threading so tests can monkeypatch that symbol.
      - dot_cfg: Optional DoT config for TLS missing-file messages.
      - doh_cfg: Optional DoH config for TLS missing-file messages.

    Outputs:
      - threading.Thread: The started listener thread.
    """

    def runner() -> None:
        try:
            asyncio.set_event_loop(asyncio.new_event_loop())
            loop = asyncio.get_event_loop()
            try:
                loop.run_until_complete(coro_factory())
            finally:
                loop.close()
        except PermissionError as e:
            # Environment forbids creating asyncio self-pipe/socketpair (e.g., restricted seccomp).
            # When a fallback is provided, treat it as a successful start and
            # do not mark the listener as failed.
            if callable(on_permission_error):
                try:
                    on_permission_error()
                except Exception as fallback_exc:
                    record_listener_error(listener_key, fallback_exc)
                    logging.getLogger("foghorn.main").exception(
                        "Asyncio listener %s failed while handling PermissionError fallback: %s",
                        name,
                        fallback_exc,
                    )
            else:
                record_listener_error(listener_key, e)
                logging.getLogger("foghorn.main").error(
                    "Asyncio loop creation failed with PermissionError for %s; no fallback provided",
                    name,
                )
        except Exception as e:  # pragma: no cover - best-effort readiness tracking
            record_listener_error(listener_key, e)
            _log = logging.getLogger("foghorn.main")
            try:
                from .servers.webserver.tls_certs import (
                    format_missing_tls_files_message,
                    is_missing_tls_file_error,
                )

                if is_missing_tls_file_error(e):
                    # Prefer a one-line operator message over a traceback dump
                    # when TLS material is simply missing on disk.
                    cert_hint = None
                    key_hint = None
                    if listener_key == "dot" and isinstance(dot_cfg, dict):
                        cert_hint = dot_cfg.get("cert_file")
                        key_hint = dot_cfg.get("key_file")
                    elif listener_key == "doh" and isinstance(doh_cfg, dict):
                        cert_hint = doh_cfg.get("cert_file")
                        key_hint = doh_cfg.get("key_file")
                    _log.error(
                        "%s",
                        format_missing_tls_files_message(
                            location=f"server.listen.{listener_key}",
                            cert_file=str(cert_hint) if cert_hint else None,
                            key_file=str(key_hint) if key_hint else None,
                            detail=f"{name}: {e}",
                        ),
                    )
                else:
                    _log.exception(
                        "Asyncio listener %s failed to start or exited with an unhandled exception: %s",
                        name,
                        e,
                    )
            except Exception:
                _log.exception(
                    "Asyncio listener %s failed to start or exited with an unhandled exception: %s",
                    name,
                    e,
                )

    # Prefer the caller-provided threading module (typically foghorn.main.threading)
    # so unit tests can monkeypatch Thread without patching this helper module.
    _threading = threading_module or threading
    t = _threading.Thread(target=runner, name=name, daemon=True)
    t.start()
    loop_threads.append(t)
    runtime_state.set_listener(listener_key, enabled=True, thread=t)
    return t


def _listener_thread_is_dead(t: threading.Thread, *, logger: logging.Logger) -> bool:
    """Best-effort liveness check for background listener threads.

    Inputs:
      - t: Thread instance (or test stub) representing a listener.
      - logger: Logger for defensive failure diagnostics.

    Outputs:
      - bool: True when the thread is known to have exited.

    Notes:
      - Test stubs may not implement is_alive(); in that case we
        treat the thread as already exited so tests can terminate the
        keepalive loop promptly.
    """

    try:
        return not t.is_alive()
    except AttributeError:
        # Test doubles used in unit tests may not implement is_alive();
        # treat them as already exited so the keepalive loop can
        # terminate promptly.
        return True
    except (
        Exception
    ):  # pragma: nocover - defensive: mocked thread objects may raise unexpectedly in liveness probes
        logger.debug(
            "Failed to check listener thread liveness; treating thread as dead",
            exc_info=True,
        )
        return True


def _run_keepalive_loop(
    *,
    logger: logging.Logger,
    shutdown_event: threading.Event,
    exit_code_state: list[int],
    sigusr1_pending: threading.Event,
    sigusr2_pending: threading.Event,
    process_usr_signal: Callable[[str], None],
    get_udp_error: Callable[[], Exception | None],
    listener_failures: dict[str, str],
    enabled_listeners: dict[str, bool],
    loop_threads: list[threading.Thread],
) -> int:
    """Brief: Run the main-thread keepalive loop until shutdown.

    Inputs:
      - logger: Main logger.
      - shutdown_event: Event set when shutdown is requested.
      - exit_code_state: Single-element list holding the desired process exit
        code. Shared with signal handlers so SIGTERM/SIGINT updates are visible.
      - sigusr1_pending/sigusr2_pending: Coalesced USR signal flags.
      - process_usr_signal: Handler invoked for drained USR signals.
      - get_udp_error: Callable returning any UDP thread exception.
      - listener_failures: Fatal listener error map.
      - enabled_listeners: Which listeners are expected to be up.
      - loop_threads: Background listener threads to monitor.

    Outputs:
      - int: Updated exit code after the loop ends (or KeyboardInterrupt).
    """

    try:
        # Import inside the loop setup so tests can replace sys.modules['time']
        # (and still affect sleep) the same way the original inlined keepalive did.
        import time as _time

        # Keep the main thread in a lightweight keepalive loop while UDP/TCP/DoT
        # listeners run in the background. This ensures alfoghorn.servers.transports are
        # treated consistently and that shutdown is always driven by
        # shutdown_event/termination signals rather than a blocking
        # serve_forever() call.
        while not shutdown_event.is_set():
            # Drain SIGUSR1/SIGUSR2 work outside of the signal handler context.
            if sigusr1_pending.is_set():
                sigusr1_pending.clear()
                try:
                    process_usr_signal("SIGUSR1")
                except Exception:
                    logger.exception("SIGUSR1: unhandled error while processing signal")

            if sigusr2_pending.is_set():
                sigusr2_pending.clear()
                try:
                    process_usr_signal("SIGUSR2")
                except Exception:
                    logger.exception("SIGUSR2: unhandled error while processing signal")

            # If the UDP server thread has reported an unhandled exception,
            # mirror the legacy behaviour by logging it and treating it as a
            # server-level failure for main()'s exit code.
            udp_error = get_udp_error()
            if udp_error is not None:
                logger.exception(
                    "Unhandled exception during UDP server operation %s", udp_error
                )
                if exit_code_state[0] == 0:
                    exit_code_state[0] = 1
                break

            fatal_listener_errors = [
                f"{name}: {error}"
                for name, error in listener_failures.items()
                if enabled_listeners.get(name, False)
            ]
            if fatal_listener_errors:
                logger.error(
                    "Fatal listener failure detected: %s",
                    "; ".join(fatal_listener_errors),
                )
                if exit_code_state[0] == 0:
                    exit_code_state[0] = 1
                break

            # When any background listener threads (UDP, TCP, DoT, etc.) have
            # all exited—for example because their serve_forever loops
            # returned—break out of the loop so coordinated shutdown can
            # proceed. This avoids treating the UDP listener as a special case
            # for keepalive behaviour.
            if loop_threads and all(
                _listener_thread_is_dead(t, logger=logger) for t in loop_threads
            ):
                break

            _time.sleep(1.0)
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down")
        if not shutdown_event.is_set():
            # KeyboardInterrupt maps to a clean shutdown and exit code 0 unless
            # an explicit termination-like signal has already set a code.
            shutdown_event.set()
            exit_code_state[0] = 0
    except (
        Exception
    ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        logger.exception(
            f"Unhandled exception during server operation {e}"
        )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        # Preserve a non-zero exit when an unhandled exception occurs unless a
        # stronger exit code (e.g., from SIGTERM) is already in place.
        if exit_code_state[0] == 0:
            exit_code_state[0] = 1
    return exit_code_state[0]


def _teardown_main_process(
    *,
    logger: logging.Logger,
    udp_handle: object | None,
    server: object | None,
    udp_thread: threading.Thread | None,
    stats_reporter: object | None,
    stats_persistence_store: object | None,
    web_handle: object | None,
    cache_plugin: object | None,
    plugins: list,
    shutdown_complete: threading.Event,
    shutdown_plugins: Callable[..., None] | None = None,
) -> None:
    """Brief: Coordinated process teardown used by main()'s finally block.

    Inputs:
      - logger: Main logger.
      - udp_handle: Optional asyncio UDP handle with stop().
      - server: Optional threaded UDP server object.
      - udp_thread: Optional UDP listener thread.
      - stats_reporter: Optional StatsReporter.
      - stats_persistence_store: Optional persistence store.
      - web_handle: Optional admin webserver handle.
      - cache_plugin: Optional cache plugin instance.
      - plugins: Active plugin list.
      - shutdown_complete: Event set when teardown finishes.
      - shutdown_plugins: Optional plugin shutdown callable (defaults to
        run_shutdown_plugins). Pass foghorn.main.run_shutdown_plugins so tests
        can monkeypatch that symbol.

    Outputs:
      - None.
    """

    # Request UDP server shutdown and close sockets before tearing down
    # statistics and web components so that no new requests are processed
    # during shutdown.
    if udp_handle is not None:
        try:
            udp_handle.stop()  # type: ignore[union-attr]
        except Exception:
            logger.exception("Unexpected error while stopping asyncio UDP listener")

    if server is not None:
        try:
            if hasattr(server, "stop"):
                # Preferred path: delegate shutdown/close to the UDP server
                # abstraction so all UDP-specific details live in the UDP
                # module.
                server.stop()  # type: ignore[union-attr]
            elif hasattr(server, "shutdown") and hasattr(server, "server_close"):
                # socketserver.ThreadingUDPServer and compatible servers.
                try:
                    server.shutdown()  # type: ignore[union-attr]
                except Exception:
                    logger.exception("Error while shutting down UDP server")
                try:
                    server.server_close()  # type: ignore[union-attr]
                except Exception:
                    logger.exception("Error while closing UDP server socket")
            else:
                # Backwards-compatible path for legacy server stubs that
                # expose a .server attribute with shutdown/server_close
                # methods (used in tests and older call sites).
                inner = getattr(server, "server", None)
                if inner is not None:
                    try:
                        inner.shutdown()
                    except Exception:
                        logger.exception("Error while shutting down UDP server")
                    try:
                        inner.server_close()
                    except Exception:
                        logger.exception("Error while closing UDP server socket")
        except Exception:
            logger.exception("Unexpected error during UDP server teardown")

    if udp_thread is not None:
        try:
            udp_thread.join(timeout=5.0)
        except Exception:
            logger.exception("Error while waiting for UDP server thread to exit")

    # Stop statistics reporter on shutdown so background reporting threads
    # never outlive the main process and do not keep it alive.
    if stats_reporter is not None:
        logger.info("Stopping statistics reporter")
        stats_reporter.stop()  # type: ignore[union-attr]

    if stats_persistence_store is not None:
        logger.info("Closing statistics persistence store")
        stats_persistence_store.close()  # type: ignore[union-attr]
    # Stop webserver thread on shutdown. The handle abstraction lets both
    # the FastAPI-based web UI and the threaded admin HTTP server share the
    # same shutdown semantics (is_running/stop).
    if web_handle is not None:
        logger.info("Stopping webserver")
        web_handle.stop()  # type: ignore[union-attr]

    # Shutdown best-effort background executor so pending refresh/notify
    # tasks do not outlive controlled process termination.
    try:
        from .servers.bg_executor import shutdown_bg_executor

        shutdown_bg_executor(wait=False)
    except Exception:
        logger.exception("Unexpected error while shutting down background executor")

    # Best-effort lifecycle teardown for loaded resolver plugins, optional
    # query-log backend, and cache plugin. Errors are logged inside the
    # helper and must not abort process shutdown.
    _shutdown = shutdown_plugins or run_shutdown_plugins
    _shutdown([cache_plugin, stats_persistence_store, *plugins])

    # Clear in-process runtime snapshot state. This is mostly relevant for
    # unit tests that call main() multiple times in one Python process.
    try:
        from foghorn import runtime_config as _runtime_config

        _runtime_config.clear_runtime()
    except (
        Exception
    ):  # pragma: nocover - best effort: runtime cleanup should not block shutdown
        pass

    # Mark shutdown as complete so any pending hard-kill timers can detect
    # successful termination and avoid forcing an unnecessary SIGKILL.
    shutdown_complete.set()
