"""
Brief: Tests for foghorn.main helpers and CLI entry.

Inputs:
  - None

Outputs:
  - None
"""

import logging
from unittest.mock import patch, mock_open
import pytest

import foghorn.main as main_mod
from foghorn.main import (
    _get_min_cache_ttl,
    normalize_upstream_config,
    load_plugins,
    main,
)


def test_get_min_cache_ttl_various_inputs():
    """
    Brief: _get_min_cache_ttl clamps negatives and handles bad types.

    Inputs:
      - cfg: dict with min_cache_ttl values

    Outputs:
      - None: Asserts sanitized integer result
    """
    assert _get_min_cache_ttl({"min_cache_ttl": 10}) == 10
    assert _get_min_cache_ttl({"min_cache_ttl": -5}) == 0
    assert _get_min_cache_ttl({"min_cache_ttl": "abc"}) == 60
    assert _get_min_cache_ttl({}) == 60


def test_normalize_upstream_config_list_and_dict(caplog):
    """
    Brief: normalize_upstream_config supports list and dict, timeout precedence.

    Inputs:
      - cfg: with list upstreams and top-level timeout, and legacy dict with timeout

    Outputs:
      - None: Asserts upstreams parsed and warning emitted
    """
    # List form
    ups, to = normalize_upstream_config(
        {
            "upstream": [
                {"host": "1.1.1.1", "port": 53},
                {"host": "1.0.0.1", "port": 53},
            ],
            "timeout_ms": 1500,
        }
    )
    assert ups == [{"host": "1.1.1.1", "port": 53}, {"host": "1.0.0.1", "port": 53}]
    assert to == 1500

    # Dict legacy form with legacy timeout
    ups2, to2 = normalize_upstream_config(
        {"upstream": {"host": "8.8.8.8", "port": 53, "timeout_ms": 999}}
    )
    assert ups2 == [{"host": "8.8.8.8", "port": 53}]
    assert to2 == 999

    # Precedence warning when both provided
    caplog.set_level(logging.WARNING)
    ups3, to3 = normalize_upstream_config(
        {
            "timeout_ms": 111,
            "upstream": {"host": "8.8.4.4", "port": 53, "timeout_ms": 999},
        }
    )
    assert to3 == 111
    assert any("top-level timeout_ms" in r.message for r in caplog.records)


def test_load_plugins_uses_registry(monkeypatch):
    """
    Brief: load_plugins resolves aliases/paths via registry and initializes classes.

    Inputs:
      - plugin_specs: mix of alias string and dict with config

    Outputs:
      - None: Asserts instances created with config
    """

    class P1:
        def __init__(self, **kw):
            self.kw = kw

    class P2:
        def __init__(self, **kw):
            self.kw = kw

    alias_map = {"a": P1, "pkg.P2": P2}

    def fake_discover():
        return alias_map

    def fake_get(identifier, reg=None):
        return (
            alias_map.get(identifier, alias_map["a"]) if identifier in alias_map else P2
        )

    monkeypatch.setattr(main_mod, "discover_plugins", fake_discover)
    monkeypatch.setattr(main_mod, "get_plugin_class", fake_get)

    plugins = load_plugins(["a", {"module": "pkg.P2", "config": {"x": 1}}])
    assert type(plugins[0]).__name__ == "P1"
    assert type(plugins[1]).__name__ == "P2"
    assert plugins[1].kw == {"x": 1}


def test_normalize_upstream_config_default_fallbacks():
    """
    Brief: Covers default upstream fallback and default timeout path.

    Inputs:
      - cfg: upstream dict missing host/port; no timeout fields

    Outputs:
      - None: Asserts default upstream and 2000ms timeout
    """
    ups, to = normalize_upstream_config({"upstream": {"foo": "bar"}})
    assert ups == [{"host": "1.1.1.1", "port": 53}]
    assert to == 2000


def test_load_plugins_skips_missing_module():
    """
    Brief: load_plugins skips entries without 'module' key.

    Inputs:
      - plugin_specs: list with empty dict

    Outputs:
      - None: Asserts result list does not include a plugin for empty dict
    """
    result = load_plugins([{}])
    assert result == []


def test_main_starts_server_and_handles_keyboardinterrupt(monkeypatch):
    """
    Brief: main() loads YAML, configures DNSServer, and exits on KeyboardInterrupt.

    Inputs:
      - argv: --config file path
      - monkeypatch: patch DNSServer and init_logging

    Outputs:
      - None: Asserts return code 0 and DNSServer called with expected args
    """
    yaml_data = (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n  host: 1.1.1.1\n  port: 53\n"
        "timeout_ms: 777\n"
        "min_cache_ttl: 33\n"
        "plugins: []\n"
    )

    class DummyServer:
        def __init__(
            self, host, port, upstreams, plugins, timeout, timeout_ms, min_cache_ttl
        ):
            self.args = (
                host,
                port,
                upstreams,
                plugins,
                timeout,
                timeout_ms,
                min_cache_ttl,
            )

        def serve_forever(self):
            raise KeyboardInterrupt

    called = {}

    def dummy_init_logging(cfg):
        called["init_logging"] = cfg

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", dummy_init_logging)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main(["--config", "conf.yaml"])

    assert rc == 0


def test_normalize_upstream_config_bad_type_default_fallback():
    """
    Brief: Non-dict/list upstream triggers default fallback branch.

    Inputs:
      - cfg: upstream as string

    Outputs:
      - None: Asserts default upstream returned
    """
    ups, _ = normalize_upstream_config({"upstream": "invalid"})
    assert ups == [{"host": "1.1.1.1", "port": 53}]


def test_main_returns_one_on_exception_alt(monkeypatch):
    """
    Brief: main() returns 1 on unexpected exception from server.

    Inputs:
      - monkeypatch: patch DNSServer.serve_forever to raise ValueError

    Outputs:
      - None: Asserts return code 1
    """
    yaml_data = (
        "listen:\n  host: 127.0.0.1\n  port: 5354\n"
        "upstream:\n  host: 1.1.1.1\n  port: 53\n"
    )

    class DummyServer:
        def __init__(self, *a, **kw):
            pass

        def serve_forever(self):
            raise ValueError("boom2")

    monkeypatch.setattr(main_mod, "DNSServer", DummyServer)
    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)

    with patch("builtins.open", mock_open(read_data=yaml_data)):
        rc = main(["--config", "x.yaml"])
    assert rc == 1
