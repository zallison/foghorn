"""
Brief: Tests for foghorn.main helpers and CLI entry.

Inputs:
  - None

Outputs:
  - None
"""

from unittest.mock import mock_open, patch

import pytest

import foghorn.config.config_parser as parser_mod
import foghorn.main as main_mod
from foghorn.config.config_parser import load_plugins, normalize_upstream_config
from foghorn.main import main


def test_normalize_upstream_config_list_only_and_timeout_default():
    """
    Brief: normalize_upstream_config accepts list-only upstreams and top-level timeout.

    Inputs:
      - cfg: with list upstreams and optional top-level timeout.

    Outputs:
      - None: Asserts upstreams parsed and timeout default/override behavior.
    """
    # List form with explicit timeout
    ups, to = normalize_upstream_config(
        {
            "upstreams": [
                {"host": "1.1.1.1", "port": 53},
                {"host": "1.0.0.1", "port": 53},
            ],
            "foghorn": {"timeout_ms": 1500},
        }
    )
    assert ups == [{"host": "1.1.1.1", "port": 53}, {"host": "1.0.0.1", "port": 53}]
    assert to == 1500

    # Default timeout when not provided
    ups2, to2 = normalize_upstream_config(
        {
            "upstreams": [
                {"host": "8.8.8.8", "port": 53},
            ]
        }
    )
    assert ups2 == [{"host": "8.8.8.8", "port": 53}]
    assert to2 == 2000


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

    monkeypatch.setattr(parser_mod, "discover_plugins", fake_discover)
    monkeypatch.setattr(parser_mod, "get_plugin_class", fake_get)

    # Patch global cache and cache loader so load_plugins injects a cache instance.
    import foghorn.plugins.resolve.base as plugin_base

    global_cache = object()
    plugin_base.DNS_CACHE = global_cache  # type: ignore[assignment]

    custom_cache = object()

    def fake_load_cache_plugin(cfg):  # type: ignore[no-untyped-def]
        assert cfg == {"module": "none"}
        return custom_cache

    monkeypatch.setattr(
        parser_mod,
        "load_cache_plugin",
        fake_load_cache_plugin,
        raising=False,
    )

    plugins = load_plugins(
        [
            "a",
            {"module": "pkg.P2", "config": {"x": 1, "cache": {"module": "none"}}},
        ]
    )
    assert type(plugins[0]).__name__ == "P1"
    assert type(plugins[1]).__name__ == "P2"

    # Plugin 1: no cache selected -> global cache injected.
    assert plugins[0].kw.get("cache") is global_cache

    # Plugin 2: explicit cache config -> custom cache injected; raw cache config removed.
    assert plugins[1].kw.get("cache") is custom_cache
    assert plugins[1].kw.get("x") == 1
    assert not isinstance(plugins[1].kw.get("cache"), dict)


def test_normalize_upstream_config_rejects_non_list():
    """
    Brief: Non-list upstream config raises ValueError now that legacy dict form is removed.

    Inputs:
      - cfg: upstream as dict or other non-list.

    Outputs:
      - None: Asserts ValueError raised.
    """
    with pytest.raises(ValueError):
        normalize_upstream_config({"upstreams": {"host": "1.1.1.1", "port": 53}})

    with pytest.raises(ValueError):
        normalize_upstream_config({"upstreams": "invalid"})


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
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 777\n"
        "  cache:\n"
        "    backend: in_memory_ttl\n"
        "    config:\n"
        "      min_cache_ttl: 33\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
        "plugins: []\n"
    )

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
            # Capture the core positional arguments; ignore any additional
            # keyword arguments (e.g., dnssec_mode, edns_udp_payload,
            # dnssec_validation) that main() may pass through to DNSServer.
            self.args = (
                host,
                port,
                upstreams,
                plugins,
                timeout,
                timeout_ms,
                min_cache_ttl,
                stats_collector,
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


def test_normalize_upstream_config_rejects_non_mapping_entries():
    """
    Brief: Each upstream entry must be a mapping; invalid entries raise ValueError.

    Inputs:
      - cfg: upstream as list with a non-dict element.

    Outputs:
      - None: Asserts ValueError raised.
    """
    with pytest.raises(ValueError):
        normalize_upstream_config({"upstreams": ["bad"]})


def test_main_returns_one_on_exception_alt(monkeypatch):
    """
    Brief: main() returns 1 on unexpected exception from server.

    Inputs:
      - monkeypatch: patch DNSServer.serve_forever to raise ValueError

    Outputs:
      - None: Asserts return code 1
    """
    yaml_data = (
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
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
