"""
Brief: Ensure DoT listener is skipped with error log when cert/key missing.

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
        "listen:\n"
        "  host: 127.0.0.1\n"
        "  port: 5354\n"
        "  dot:\n"
        "    enabled: true\n"
        "    host: 127.0.0.1\n"
        "    port: 8853\n"
        "upstream:\n"
        "  - host: 1.1.1.1\n"
        "    port: 53\n"
    )

    class DummyServer:
        def __init__(self, *a, **kw):
            pass

        def serve_forever(self):
            raise KeyboardInterrupt

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        with caplog.at_level(logging.ERROR, logger="foghorn.main"):
            main_mod.main(["--config", "x.yaml"])
            assert any(
                "cert_file/key_file not provided" in r.message for r in caplog.records
            )
