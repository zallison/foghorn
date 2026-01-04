"""
Brief: Ensure main() uses legacy_host for TCP/DoT listener defaults (no NameError) and starts TCP when enabled.

Inputs:
  - None

Outputs:
  - None
"""

from unittest.mock import mock_open, patch

import foghorn.main as main_mod


def test_main_tcp_listener_uses_legacy_host_and_starts(monkeypatch):
    """
    Brief: Enabling listen.tcp should not reference undefined 'host' and should call serve_tcp.

    Inputs:
      - monkeypatch: patches DNSServer, init_logging, and serve_tcp

    Outputs:
      - None: Asserts main() returns 0 without NameError and serve_tcp was invoked once
    """
    # Config: UDP enabled (so main exits via KeyboardInterrupt), TCP enabled
    # using v2 server/upstreams layout.
    yaml_data = (
        "upstreams:\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "    tcp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "    use_asyncio: true\n"
    )

    class DummyServer:
        def __init__(self, *a, **kw):
            pass

        def serve_forever(self):
            # Exit main quickly
            raise KeyboardInterrupt

    called = {"tcp_start": 0}

    class DummyThread:
        def __init__(self, target=None, name=None, daemon=None):
            self._target = target
            self.name = name
            self.daemon = daemon

        def start(self):
            # Count TCP start attempts by thread name
            if self.name == "foghorn-tcp":
                called["tcp_start"] += 1
            # Do not actually run the target

        def join(self, timeout=None):
            return

    import sys
    import threading as real_threading

    class _FakeThreadingModule:
        """Test helper: module-like shim that overrides Thread but proxies others."""

        def __init__(self, real_module, thread_cls):  # type: ignore[no-untyped-def]
            self._real = real_module
            self.Thread = thread_cls

        def __getattr__(self, name):  # type: ignore[no-untyped-def]
            return getattr(self._real, name)

    fake_threading = _FakeThreadingModule(real_threading, DummyThread)

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    # Ensure `import threading` inside main() gets our shim
    monkeypatch.setitem(sys.modules, "threading", fake_threading)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "x.yaml"])

    assert rc == 0
    assert called["tcp_start"] == 1


def test_listen_dns_populates_udp_and_tcp(monkeypatch):
    """Brief: server.listen.dns host/port and flags drive UDP/TCP defaults.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts DNSServer and TCP listener receive the dns.host/port
        values when no explicit udp/tcp blocks are present.
    """

    yaml_data = (
        "upstreams:\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "server:\n"
        "  listen:\n"
        "    dns:\n"
        "      host: 0.0.0.0\n"
        "      port: 5300\n"
        "      udp: true\n"
        "      tcp: true\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "    use_asyncio: false\n"
    )

    udp_info = {"host": None, "port": None}

    class DummyServer:
        def __init__(
            self,
            host,
            port,
            upstreams,
            plugins,
            timeout,
            timeout_ms,
            min_cache_ttl,
            stats_collector=None,
            **_extra,
        ):
            udp_info["host"] = host
            udp_info["port"] = port

        def serve_forever(self):  # pragma: no cover - exercised via thread wrapper
            return

    tcp_calls = {"count": 0, "host": None, "port": None}

    def fake_serve_tcp_threaded(host, port, resolver):  # type: ignore[no-untyped-def]
        tcp_calls["count"] += 1
        tcp_calls["host"] = host
        tcp_calls["port"] = port

    class DummyThread:
        def __init__(self, target=None, name=None, daemon=None):
            self._target = target
            self.name = name
            self.daemon = daemon
            self._alive = False

        def start(self):
            self._alive = True
            if self._target is not None:
                self._target()
            self._alive = False

        def is_alive(self):  # pragma: no cover - trivial getter
            return self._alive

        def join(self, timeout=None):  # pragma: no cover - no-op for tests
            return

    import threading as real_threading
    import sys

    class _FakeThreadingModule:
        """Test helper: module-like shim that overrides Thread but proxies others."""

        def __init__(self, real_module, thread_cls):  # type: ignore[no-untyped-def]
            self._real = real_module
            self.Thread = thread_cls

        def __getattr__(self, name):  # type: ignore[no-untyped-def]
            return getattr(self._real, name)

    fake_threading = _FakeThreadingModule(real_threading, DummyThread)

    from foghorn.servers import tcp_server as tcp_server_mod

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **k: None)
    monkeypatch.setattr(tcp_server_mod, "serve_tcp_threaded", fake_serve_tcp_threaded)
    monkeypatch.setattr(tcp_server_mod, "serve_tcp", lambda *a, **k: None)
    # Ensure imports of threading inside main() see our fake module and that
    # the already-imported main_mod.threading uses DummyThread.Thread.
    monkeypatch.setitem(sys.modules, "threading", fake_threading)
    monkeypatch.setattr(main_mod, "threading", fake_threading)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "dns.yaml"])

    assert rc == 0
    assert udp_info["host"] == "0.0.0.0"
    assert udp_info["port"] == 5300
    assert tcp_calls["count"] == 1
    assert tcp_calls["host"] == "0.0.0.0"
    assert tcp_calls["port"] == 5300
