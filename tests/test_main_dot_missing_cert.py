"""
Brief: Ensure DoT listener startup is fatal with an error log when cert/key are missing.

Inputs:
  - None

Outputs:
  - None
"""

import logging
from unittest.mock import mock_open, patch

import foghorn.main as main_mod


def test_main_dot_missing_cert_logs_error(monkeypatch, caplog):
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
        "    dot:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 8853\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "    use_asyncio: false\n"
    )

    import socketserver

    class DummyUDPServer:
        def __init__(self, *_a, **_kw):
            self.daemon_threads = True

        def serve_forever(self) -> None:
            return None

        def shutdown(self) -> None:
            return None

        def server_close(self) -> None:
            return None

    class DummyThread:
        def __init__(self, target=None, name=None, daemon=None) -> None:  # noqa: D401
            """Thread stub that avoids starting real background threads."""

            self._target = target
            self.name = name
            self.daemon = daemon

        def start(self) -> None:
            # Do not execute target (which would run UDP serve_forever()).
            return None

        def is_alive(self) -> bool:
            return False

        def join(self, timeout=None) -> None:  # noqa: ARG002
            return None

    monkeypatch.setattr(socketserver, "ThreadingUDPServer", DummyUDPServer)
    monkeypatch.setattr(main_mod.threading, "Thread", DummyThread)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **k: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.ERROR, logger="foghorn.main"):
            rc = main_mod.main(["--config", "x.yaml"])
            assert rc == 1
            assert any(
                "cert_file/key_file not provided" in r.message for r in caplog.records
            )
