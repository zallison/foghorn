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
    yaml_data = (
        "listen:\n"
        "  host: 127.0.0.1\n"
        "  port: 5354\n"
        "  tcp:\n"
        "    enabled: true\n"
        "    host: 127.0.0.1\n"
        "    port: 5354\n"
        "upstream:\n"
        "  - host: 1.1.1.1\n"
        "    port: 53\n"
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
    import types

    fake_threading = types.SimpleNamespace(Thread=DummyThread)

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    # Ensure `import threading` inside main() gets our shim
    monkeypatch.setitem(sys.modules, "threading", fake_threading)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "x.yaml"])

    assert rc == 0
    assert called["tcp_start"] == 1
