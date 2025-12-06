"""
Brief: Ensure main() starts DoH listener when enabled and does not crash.

Inputs:
  - None

Outputs:
  - None
"""

from unittest.mock import mock_open, patch

import foghorn.main as main_mod


def test_main_doh_listener_starts(monkeypatch):
    """
    Brief: Enabling listen.doh should lead to a thread named foghorn-doh being started.

    Inputs:
      - monkeypatch: replaces threading.Thread with a counter stub, DNSServer, and init_logging

    Outputs:
      - None: Asserts main() returns 0 and doh thread started once
    """
    yaml_data = (
        "listen:\n"
        "  host: 127.0.0.1\n"
        "  port: 5354\n"
        "  doh:\n"
        "    enabled: true\n"
        "    host: 127.0.0.1\n"
        "    port: 8053\n"
        "upstreams:\n"
        "  - host: 1.1.1.1\n"
        "    port: 53\n"
    )

    class DummyServer:
        def __init__(self, *a, **kw):
            pass

        def serve_forever(self):
            # Exit quickly
            raise KeyboardInterrupt

    called = {"doh_start": 0}

    class DummyThread:
        def __init__(self, target=None, name=None, daemon=None):
            self._target = target
            self.name = name
            self.daemon = daemon

        def start(self):
            if self.name == "foghorn-doh":
                called["doh_start"] += 1

        def join(self, timeout=None):
            return

    import sys
    import types

    fake_threading = types.SimpleNamespace(Thread=DummyThread)

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setitem(sys.modules, "threading", fake_threading)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "x.yaml"])

    assert rc == 0
    assert called["doh_start"] == 1
