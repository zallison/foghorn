"""
Brief: Tests fatal behavior when DoH or webserver fail to start while enabled.

Inputs:
  - monkeypatch: to patch DNSServer, start_doh_server, start_webserver, init_logging

Outputs:
  - None: asserts main() returns 1 and logs errors when startup fails
"""

from unittest.mock import mock_open, patch

import foghorn.main as main_mod


def _basic_yaml_base() -> str:
    """Brief: Return minimal YAML config shared by tests.

    Inputs:
      - None

    Outputs:
      - str: YAML configuration string with basic listen/upstream.
    """

    return (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n"
        "  - host: 1.1.1.1\n"
        "    port: 53\n"
    )


def _patch_minimal_server(monkeypatch):
    """Brief: Patch DNSServer and init_logging so main() exits quickly.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture

    Outputs:
      - None
    """

    class DummyServer:
        def __init__(self, *a, **kw):
            pass

        def serve_forever(self):
            # Exit main loop immediately
            raise KeyboardInterrupt

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)


def test_doh_enabled_start_returns_none_is_fatal(monkeypatch, caplog):
    """Brief: When listen.doh.enabled is true and start_doh_server returns None, main() returns 1.

    Inputs:
      - monkeypatch, caplog

    Outputs:
      - None: asserts rc == 1 and fatal error logged.
    """

    yaml_data = (
        "listen:\n"
        "  host: 127.0.0.1\n"
        "  port: 5354\n"
        "  doh:\n"
        "    enabled: true\n"
        "    host: 127.0.0.1\n"
        "    port: 8053\n"
        "upstream:\n"
        "  - host: 1.1.1.1\n"
        "    port: 53\n"
    )

    _patch_minimal_server(monkeypatch)

    def fake_start_doh_server(*a, **kw):  # pragma: no cover - behavior tested via main
        return None

    monkeypatch.setattr(main_mod, "start_doh_server", fake_start_doh_server)

    caplog.set_level("ERROR")
    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "doh_fail.yaml"])

    assert rc == 1
    assert any(
        "Fatal: listen.doh.enabled=true" in rec.message for rec in caplog.records
    )


def test_webserver_enabled_start_returns_none_is_fatal(monkeypatch, caplog):
    """Brief: When webserver.enabled is true and start_webserver returns None, main() returns 1.

    Inputs:
      - monkeypatch, caplog

    Outputs:
      - None: asserts rc == 1 and fatal error logged.
    """

    yaml_data = _basic_yaml_base() + ("webserver:\n" "  enabled: true\n")

    _patch_minimal_server(monkeypatch)

    def fake_start_webserver(*a, **kw):  # pragma: no cover - behavior tested via main
        return None

    monkeypatch.setattr(main_mod, "start_webserver", fake_start_webserver)

    caplog.set_level("ERROR")
    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main_mod.main(["--config", "web_fail.yaml"])

    assert rc == 1
    assert any("Fatal: webserver.enabled=true" in rec.message for rec in caplog.records)
