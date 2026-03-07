"""Branch-focused tests for foghorn.servers.server_runtime.DNSServer."""

from __future__ import annotations

import builtins
from typing import Any

import pytest

from foghorn.plugins.resolve import base as plugin_base
from foghorn.servers.server_runtime import DNSServer
from foghorn.servers.udp_server import DNSUDPHandler
import foghorn.servers.server_runtime as runtime_mod


@pytest.fixture(autouse=True)
def _restore_runtime_handler_state():
    """Brief: Restore DNSUDPHandler and cache globals mutated by DNSServer init.

    Inputs:
      - None

    Outputs:
      - None; resets class/module globals after each test.
    """

    attrs = [
        "upstream_addrs",
        "plugins",
        "timeout",
        "timeout_ms",
        "min_cache_ttl",
        "stats_collector",
        "dnssec_mode",
        "dnssec_validation",
        "upstream_strategy",
        "resolver_mode",
        "recursive_max_depth",
        "recursive_timeout_ms",
        "recursive_per_try_timeout_ms",
        "cache_prefetch_enabled",
        "cache_prefetch_min_ttl",
        "cache_prefetch_max_ttl",
        "cache_prefetch_refresh_before_expiry",
        "cache_prefetch_allow_stale_after_expiry",
        "upstream_max_concurrent",
        "edns_udp_payload",
        "max_response_bytes",
        "enable_ede",
        "forward_local",
        "axfr_enabled",
        "axfr_allow_clients",
    ]
    had_attr = {name: hasattr(DNSUDPHandler, name) for name in attrs}
    prior = {
        name: getattr(DNSUDPHandler, name)
        for name in attrs
        if hasattr(DNSUDPHandler, name)
    }
    old_cache = getattr(plugin_base, "DNS_CACHE", None)
    yield
    for name in attrs:
        if had_attr[name]:
            setattr(DNSUDPHandler, name, prior[name])
        else:
            try:
                delattr(DNSUDPHandler, name)
            except Exception:  # pragma: nocover - best-effort fixture cleanup
                pass
    plugin_base.DNS_CACHE = old_cache


class _BadBool:
    """Helper whose boolean conversion raises."""

    def __bool__(self) -> bool:
        raise ValueError("bad bool")


class _BadIterable:
    """Helper whose iteration raises."""

    def __iter__(self):
        raise ValueError("bad iter")


def test_init_configures_handler_state_without_binding_socket() -> None:
    """Brief: create_server=False configures DNSUDPHandler and skips UDP bind.

    Inputs:
      - None

    Outputs:
      - None; asserts key runtime knobs are normalized and assigned.
    """

    cache_obj = object()
    upstreams = [{"host": "1.1.1.1", "port": 53}]
    plugins: list[Any] = []

    server = DNSServer(
        "127.0.0.1",
        5300,
        upstreams,
        plugins,
        timeout=1.25,
        timeout_ms=1250,
        min_cache_ttl=-9,
        cache=cache_obj,
        dnssec_mode="validate",
        dnssec_validation="local",
        upstream_strategy="ROUND_ROBIN",
        upstream_max_concurrent=3,
        resolver_mode="RECURSIVE",
        recursive_max_depth=22,
        recursive_timeout_ms=3100,
        recursive_per_try_timeout_ms=400,
        cache_prefetch_enabled=True,
        cache_prefetch_min_ttl=10,
        cache_prefetch_max_ttl=120,
        cache_prefetch_refresh_before_expiry=4.5,
        cache_prefetch_allow_stale_after_expiry=2.0,
        enable_ede=True,
        forward_local=True,
        max_response_bytes=4096,
        axfr_enabled=True,
        axfr_allow_clients=["127.0.0.1/32"],
        create_server=False,
    )

    assert server.server is None
    assert plugin_base.DNS_CACHE is cache_obj
    assert DNSUDPHandler.upstream_addrs == upstreams
    assert DNSUDPHandler.plugins == plugins
    assert DNSUDPHandler.timeout == 1.25
    assert DNSUDPHandler.timeout_ms == 1250
    assert DNSUDPHandler.min_cache_ttl == 0
    assert DNSUDPHandler.dnssec_mode == "validate"
    assert DNSUDPHandler.dnssec_validation == "local"
    assert DNSUDPHandler.upstream_strategy == "round_robin"
    assert DNSUDPHandler.resolver_mode == "recursive"
    assert DNSUDPHandler.recursive_max_depth == 22
    assert DNSUDPHandler.recursive_timeout_ms == 3100
    assert DNSUDPHandler.recursive_per_try_timeout_ms == 400
    assert DNSUDPHandler.cache_prefetch_enabled is True
    assert DNSUDPHandler.cache_prefetch_min_ttl == 10
    assert DNSUDPHandler.cache_prefetch_max_ttl == 120
    assert DNSUDPHandler.cache_prefetch_refresh_before_expiry == 4.5
    assert DNSUDPHandler.cache_prefetch_allow_stale_after_expiry == 2.0
    assert DNSUDPHandler.upstream_max_concurrent == 3
    assert DNSUDPHandler.edns_udp_payload == 1232
    assert DNSUDPHandler.max_response_bytes == 4096
    assert DNSUDPHandler.enable_ede is True
    assert DNSUDPHandler.forward_local is True
    assert DNSUDPHandler.axfr_enabled is True
    assert DNSUDPHandler.axfr_allow_clients == ["127.0.0.1/32"]


def test_init_uses_safe_defaults_for_invalid_inputs() -> None:
    """Brief: Invalid conversion/boolean inputs fall back to defensive defaults.

    Inputs:
      - None

    Outputs:
      - None; asserts fallback values on conversion/boolean failures.
    """

    DNSServer(
        "127.0.0.1",
        5300,
        [],
        [],
        cache=object(),
        cache_prefetch_min_ttl=object(),
        cache_prefetch_max_ttl=object(),
        cache_prefetch_refresh_before_expiry=object(),
        cache_prefetch_allow_stale_after_expiry=object(),
        upstream_max_concurrent="bad",
        edns_udp_payload="bad",
        max_response_bytes="bad",
        enable_ede=_BadBool(),
        forward_local=_BadBool(),
        axfr_enabled=_BadBool(),
        axfr_allow_clients=_BadIterable(),
        create_server=False,
    )

    assert DNSUDPHandler.cache_prefetch_min_ttl == 0
    assert DNSUDPHandler.cache_prefetch_max_ttl == 0
    assert DNSUDPHandler.cache_prefetch_refresh_before_expiry == 0.0
    assert DNSUDPHandler.cache_prefetch_allow_stale_after_expiry == 0.0
    assert DNSUDPHandler.upstream_max_concurrent == 1
    assert DNSUDPHandler.edns_udp_payload == 1232
    assert DNSUDPHandler.max_response_bytes is None
    assert DNSUDPHandler.enable_ede is False
    assert DNSUDPHandler.forward_local is False
    assert DNSUDPHandler.axfr_enabled is False
    assert DNSUDPHandler.axfr_allow_clients == []


def test_init_when_cache_import_fails_sets_dns_cache_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: cache=None with failing InMemoryTTLCache import degrades to DNS_CACHE=None.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts import failure path does not raise and sets cache to None.
    """

    original_import = builtins.__import__

    def _boom_import(
        name, globals=None, locals=None, fromlist=(), level=0
    ):  # noqa: ANN001
        if name == "foghorn.plugins.cache.in_memory_ttl":
            raise ImportError("boom")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _boom_import)

    DNSServer("127.0.0.1", 5300, [], [], cache=None, create_server=False)
    assert plugin_base.DNS_CACHE is None


def test_init_ignores_dns_cache_assignment_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: plugin_base assignment failures are swallowed by defensive branch.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts constructor still completes when DNS_CACHE assignment fails.
    """

    class _BadPluginBase:
        def __setattr__(self, name: str, value: Any) -> None:
            if name == "DNS_CACHE":
                raise RuntimeError("cannot assign")
            object.__setattr__(self, name, value)

    monkeypatch.setattr(runtime_mod, "plugin_base", _BadPluginBase())
    server = DNSServer("127.0.0.1", 5300, [], [], cache=object(), create_server=False)
    assert server.server is None


def test_init_create_server_binds_threading_udp_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: create_server=True binds ThreadingUDPServer and enables daemon threads.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts bind target and daemon_threads configuration.
    """

    created: dict[str, Any] = {}

    class _DummyThreadingUDPServer:
        def __init__(self, addr, handler_cls):  # noqa: ANN001
            created["addr"] = addr
            created["handler_cls"] = handler_cls
            self.daemon_threads = False

    monkeypatch.setattr(
        runtime_mod.socketserver,
        "ThreadingUDPServer",
        _DummyThreadingUDPServer,
    )

    server = DNSServer(
        "127.0.0.1",
        5310,
        [{"host": "9.9.9.9", "port": 53}],
        [],
        create_server=True,
    )

    assert isinstance(server.server, _DummyThreadingUDPServer)
    assert created["addr"] == ("127.0.0.1", 5310)
    assert created["handler_cls"] is DNSUDPHandler
    assert server.server.daemon_threads is True


def test_init_create_server_permission_error_is_logged_and_reraised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: PermissionError during bind is logged then re-raised.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts bind failure path preserves exception semantics.
    """

    calls: list[tuple[Any, ...]] = []

    def _raise_permission_error(*_args: Any, **_kwargs: Any) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr(
        runtime_mod.socketserver,
        "ThreadingUDPServer",
        _raise_permission_error,
    )
    monkeypatch.setattr(
        runtime_mod.logger, "error", lambda *args, **kwargs: calls.append(args)
    )

    with pytest.raises(PermissionError):
        DNSServer("127.0.0.1", 53, [], [], create_server=True)
    assert calls, "Expected logger.error call for permission failure"


def test_serve_forever_handles_none_normal_and_keyboard_interrupt() -> None:
    """Brief: serve_forever handles no-server, normal loop, and KeyboardInterrupt.

    Inputs:
      - None

    Outputs:
      - None; asserts expected control-flow without propagating KeyboardInterrupt.
    """

    server = DNSServer("127.0.0.1", 5300, [], [], create_server=False)

    # No underlying server configured.
    server.serve_forever()

    state = {"calls": 0}

    class _LoopServer:
        def serve_forever(self) -> None:
            state["calls"] += 1

    class _KeyboardInterruptServer:
        def __init__(self) -> None:
            self.called = False

        def serve_forever(self) -> None:
            self.called = True
            raise KeyboardInterrupt

    server.server = _LoopServer()
    server.serve_forever()
    assert state["calls"] == 1

    kb_server = _KeyboardInterruptServer()
    server.server = kb_server
    server.serve_forever()
    assert kb_server.called is True


def test_stop_handles_none_success_and_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: stop() no-ops on None and is best-effort for shutdown/close failures.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts success and exception-logging paths.
    """

    server = DNSServer("127.0.0.1", 5300, [], [], create_server=False)

    # No underlying server configured.
    server.stop()

    calls: list[str] = []

    class _HealthyServer:
        def shutdown(self) -> None:
            calls.append("shutdown")

        def server_close(self) -> None:
            calls.append("server_close")

    server.server = _HealthyServer()
    server.stop()
    assert calls == ["shutdown", "server_close"]

    errors: list[str] = []

    class _BrokenServer:
        def shutdown(self) -> None:
            raise RuntimeError("shutdown failed")

        def server_close(self) -> None:
            raise RuntimeError("close failed")

    monkeypatch.setattr(
        runtime_mod.logger,
        "exception",
        lambda msg, *args, **kwargs: errors.append(str(msg)),
    )

    server.server = _BrokenServer()
    server.stop()
    assert "Error while shutting down UDP server" in errors
    assert "Error while closing UDP server socket" in errors
