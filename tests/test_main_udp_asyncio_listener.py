"""Tests for asyncio-based UDP listener wiring in foghorn.main.

Inputs:
  - monkeypatch/pytest fixtures.
  - YAML config via mock_open.

Outputs:
  - Coverage that UDP uses asyncio when listen.udp.use_asyncio is enabled.
  - Coverage of PermissionError fallback to ThreadingUDPServer.
  - Coverage of exit_on_asyncio_failure refusing fallback.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from unittest.mock import mock_open, patch

import foghorn.main as main_mod


def test_main_udp_defaults_to_asyncio_and_stops_handle(monkeypatch: Any) -> None:
    """Brief: UDP starts asyncio listener when listen.udp.use_asyncio is true.

    Inputs:
      - monkeypatch: patches start_udp_asyncio_threaded and DNSServer to avoid real sockets.

    Outputs:
      - None; asserts start_udp_asyncio_threaded was called and the returned handle
        stop() is invoked during shutdown.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "      use_asyncio: true\n"
        "      max_inflight_by_cidr:\n"
        "        - cidr: 10.0.0.0/8\n"
        "          max_inflight: 5\n"
        "        - cidr: 10.1.0.0/16\n"
        "          max_inflight: 2\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "    use_asyncio: true\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
        "plugins: []\n"
    )

    called: dict[str, object] = {"start": 0, "stop": 0}

    class DummyThread:
        def is_alive(self) -> bool:
            return False

        def join(self, timeout: float | None = None) -> None:
            return

    class DummyHandle:
        def __init__(self) -> None:
            self.thread = DummyThread()

        def stop(self) -> None:
            called["stop"] = int(called["stop"]) + 1

    def fake_start_udp_asyncio_threaded(host: str, port: int, resolver, **kw):  # type: ignore[no-untyped-def]
        called["start"] = int(called["start"]) + 1
        assert host == "127.0.0.1"
        assert int(port) == 5354
        assert kw.get("thread_name") == "foghorn-udp"
        assert kw.get("max_inflight_by_cidr") == [
            {"cidr": "10.0.0.0/8", "max_inflight": 5},
            {"cidr": "10.1.0.0/16", "max_inflight": 2},
        ]
        return DummyHandle()

    from foghorn.servers import udp_asyncio_server as udp_mod

    monkeypatch.setattr(
        udp_mod, "start_udp_asyncio_threaded", fake_start_udp_asyncio_threaded
    )

    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **k: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert called["start"] == 1
    assert called["stop"] == 1


def test_main_udp_asyncio_permissionerror_falls_back_to_threaded(
    monkeypatch: Any, caplog
) -> None:
    """Brief: PermissionError during asyncio UDP startup falls back to threaded.

    Inputs:
      - monkeypatch: forces asyncio.new_event_loop() to raise PermissionError.
      - caplog: captures warning logs.

    Outputs:
      - None; asserts warning about fallback was emitted and threaded DNSServer was
        instantiated (create_server=True).
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "      use_asyncio: true\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "    use_asyncio: true\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
        "plugins: []\n"
    )

    # Force the UDP asyncio listener startup to fail with PermissionError.
    from foghorn.servers import udp_asyncio_server as udp_mod

    def boom_start(*_a: Any, **_kw: Any) -> object:
        raise PermissionError("no self-pipe")

    monkeypatch.setattr(udp_mod, "start_udp_asyncio_threaded", boom_start)

    created: list[str] = []

    import socketserver as real_socketserver

    class DummyThreadingUDPServer:
        def __init__(self, addr, handler_cls):  # type: ignore[no-untyped-def]
            created.append("threaded")
            self.daemon_threads = True

        def serve_forever(self) -> None:
            return

        def shutdown(self) -> None:
            return

        def server_close(self) -> None:
            return

    monkeypatch.setattr(real_socketserver, "ThreadingUDPServer", DummyThreadingUDPServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **k: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.DEBUG, logger="foghorn.main"):
            rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 0
    assert any("ThreadingUDPServer" in r.message for r in caplog.records)
    assert created == ["threaded"]


def test_main_udp_asyncio_permissionerror_exit_on_failure(
    monkeypatch: Any, caplog
) -> None:
    """Brief: exit_on_asyncio_failure refuses threaded fallback and exits non-zero.

    Inputs:
      - monkeypatch: forces asyncio.new_event_loop() to raise PermissionError.
      - caplog: captures error logs.

    Outputs:
      - None; asserts main() returns 1 and does not start threaded UDP.
    """

    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "      use_asyncio: true\n"
        "      exit_on_asyncio_failure: true\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "    use_asyncio: true\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
        "plugins: []\n"
    )

    # Force the UDP asyncio listener startup to fail with PermissionError.
    from foghorn.servers import udp_asyncio_server as udp_mod

    def boom_start(*_a: Any, **_kw: Any) -> object:
        raise PermissionError("no self-pipe")

    monkeypatch.setattr(udp_mod, "start_udp_asyncio_threaded", boom_start)

    created: list[str] = []

    import socketserver as real_socketserver

    class DummyThreadingUDPServer:
        def __init__(self, addr, handler_cls):  # type: ignore[no-untyped-def]
            created.append("threaded")
            self.daemon_threads = True

        def serve_forever(self) -> None:
            return

        def shutdown(self) -> None:
            return

        def server_close(self) -> None:
            return

    monkeypatch.setattr(real_socketserver, "ThreadingUDPServer", DummyThreadingUDPServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **k: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.ERROR, logger="foghorn.main"):
            rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 1
    assert any("threaded fallback is disabled" in r.message for r in caplog.records)
    assert created == []
