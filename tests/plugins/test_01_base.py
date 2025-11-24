"""
Brief: Tests for foghorn.plugins.base module.

Inputs:
  - None

Outputs:
  - None
"""

import logging

from foghorn.plugins.base import (
    BasePlugin,
    PluginContext,
    PluginDecision,
    inheritable_ttl_cache,
)
from foghorn.plugins.base import logger as base_logger
from foghorn.plugins.base import plugin_aliases


def test_plugin_decision_creation():
    """
    Brief: Verify PluginDecision dataclass initialization.

    Inputs:
      - action: string action type
      - response: optional bytes response

    Outputs:
      - None: Asserts correct attribute assignment
    """
    decision = PluginDecision(action="deny")
    assert decision.action == "deny"
    assert decision.response is None

    decision_with_response = PluginDecision(action="override", response=b"test")
    assert decision_with_response.action == "override"
    assert decision_with_response.response == b"test"


def test_plugin_context_initialization():
    """
    Brief: Verify PluginContext initializes correctly.

    Inputs:
      - client_ip: string IP address

    Outputs:
      - None: Asserts context attributes
    """
    ctx = PluginContext(client_ip="192.0.2.1")
    assert ctx.client_ip == "192.0.2.1"
    assert ctx.upstream_candidates is None
    assert ctx.upstream_override is None


def test_plugin_context_upstream_candidates():
    """
    Brief: Verify upstream_candidates can be set on context.

    Inputs:
      - None

    Outputs:
      - None: Asserts list assignment
    """
    ctx = PluginContext(client_ip="10.0.0.1")
    candidates = [{"host": "1.1.1.1", "port": 53}, {"host": "8.8.8.8", "port": 53}]
    ctx.upstream_candidates = candidates
    assert ctx.upstream_candidates == candidates


def test_plugin_context_upstream_override():
    """
    Brief: Verify upstream_override can be set on context.

    Inputs:
      - None

    Outputs:
      - None: Asserts tuple assignment
    """
    ctx = PluginContext(client_ip="10.0.0.1")
    ctx.upstream_override = ("1.1.1.1", 53)
    assert ctx.upstream_override == ("1.1.1.1", 53)


def test_base_plugin_initialization():
    """
    Brief: Verify BasePlugin stores config.

    Inputs:
      - **config: arbitrary configuration dict

    Outputs:
      - None: Asserts config stored
    """
    config = {"key1": "value1", "key2": 42}
    plugin = BasePlugin(**config)
    assert plugin.config == config


def test_base_plugin_pre_resolve_returns_none():
    """
    Brief: Verify default pre_resolve returns None.

    Inputs:
      - qname, qtype, req, ctx: standard plugin hook parameters

    Outputs:
      - None: Asserts None returned
    """
    plugin = BasePlugin()
    ctx = PluginContext(client_ip="127.0.0.1")
    result = plugin.pre_resolve("example.com", 1, b"", ctx)
    assert result is None


def test_base_plugin_post_resolve_returns_none():
    """
    Brief: Verify default post_resolve returns None.

    Inputs:
      - qname, qtype, response_wire, ctx: standard plugin hook parameters

    Outputs:
      - None: Asserts None returned
    """
    plugin = BasePlugin()
    ctx = PluginContext(client_ip="127.0.0.1")
    result = plugin.post_resolve("example.com", 1, b"response", ctx)
    assert result is None


def test_base_plugin_get_aliases_empty():
    """
    Brief: Verify get_aliases returns empty tuple by default.

    Inputs:
      - None

    Outputs:
      - None: Asserts empty sequence
    """
    assert BasePlugin.get_aliases() == ()


def test_plugin_aliases_decorator():
    """
    Brief: Verify plugin_aliases decorator sets aliases attribute.

    Inputs:
      - *aliases: variable alias strings

    Outputs:
      - None: Asserts aliases attribute set correctly
    """

    @plugin_aliases("test", "example")
    class TestPlugin(BasePlugin):
        pass

    assert hasattr(TestPlugin, "aliases")
    assert TestPlugin.aliases == ("test", "example")
    assert TestPlugin.get_aliases() == ("test", "example")


def test_plugin_aliases_decorator_single():
    """
    Brief: Verify plugin_aliases works with single alias.

    Inputs:
      - Single alias string

    Outputs:
      - None: Asserts single-element tuple
    """

    @plugin_aliases("solo")
    class SoloPlugin(BasePlugin):
        pass

    assert SoloPlugin.aliases == ("solo",)


def test_plugin_aliases_decorator_none():
    """
    Brief: Verify plugin_aliases works with no aliases.

    Inputs:
      - No arguments

    Outputs:
      - None: Asserts empty tuple
    """

    @plugin_aliases()
    class NoAliasPlugin(BasePlugin):
        pass

    assert NoAliasPlugin.aliases == ()


def test_base_plugin_priority_default():
    """
    Brief: Verify BasePlugin has default pre and post priorities.

    Inputs:
      - None

    Outputs:
      - None: Asserts priority values
    """
    assert BasePlugin.pre_priority == 50
    assert BasePlugin.post_priority == 50


def test_base_plugin_subclass_inheritance():
    """
    Brief: Verify subclass inherits base behavior.

    Inputs:
      - None

    Outputs:
      - None: Asserts inheritance works
    """

    class CustomPlugin(BasePlugin):
        pass

    plugin = CustomPlugin(test_config="value")
    assert plugin.config == {"test_config": "value"}
    ctx = PluginContext(client_ip="10.0.0.1")
    assert plugin.pre_resolve("test.com", 1, b"", ctx) is None


def test_base_plugin_priority_from_config_and_fallback(caplog):
    """Brief: BasePlugin __init__ parses priorities and falls back via pre_priority.

    Inputs:
      - caplog fixture to capture warnings/info.

    Outputs:
      - None; asserts pre/post/setup priorities honor config and fallback rules.
    """

    caplog.set_level(logging.WARNING, logger=base_logger.name)

    class P(BasePlugin):
        pre_priority = 5
        post_priority = 7
        setup_priority = 9

    # Explicit pre/post, no setup_priority: setup should fall back to configured pre.
    p = P(pre_priority=10, post_priority="200")
    assert p.pre_priority == 10
    assert p.post_priority == 200
    assert p.setup_priority == 10

    # Invalid post_priority is logged and defaults to 50.
    p2 = P(post_priority="not-an-int")
    assert p2.post_priority == 50
    assert any("Invalid post_priority" in r.message for r in caplog.records)


def test_parse_priority_value_valid_and_clamped(caplog):
    """Brief: _parse_priority_value handles invalid, low, and high values.

    Inputs:
      - caplog fixture for warnings.

    Outputs:
      - None; asserts default, low-clamp, and high-clamp behaviors.
    """

    caplog.set_level(logging.WARNING, logger=base_logger.name)

    # Valid string value
    assert BasePlugin._parse_priority_value("25", "pre_priority", base_logger) == 25

    # Invalid type falls back to default 50
    assert BasePlugin._parse_priority_value("xx", "pre_priority", base_logger) == 50
    assert any("Invalid pre_priority" in r.message for r in caplog.records)

    # Below range clamps to 1
    assert BasePlugin._parse_priority_value(-10, "pre_priority", base_logger) == 1
    assert any("pre_priority below 1" in r.message for r in caplog.records)

    # Above range clamps to 255
    assert BasePlugin._parse_priority_value(300, "pre_priority", base_logger) == 255
    assert any("pre_priority above 255" in r.message for r in caplog.records)


def test_inheritable_ttl_cache_per_class_and_ttl(monkeypatch):
    """Brief: inheritable_ttl_cache caches per class and recreates on TTL change.

    Inputs:
      - monkeypatch fixture (unused but kept for symmetry).

    Outputs:
      - None; asserts underlying method called once per key until TTL config changes.
    """

    class Dummy:
        cache_ttl = 60
        cache_maxsize = 8

        def __init__(self) -> None:
            self.calls = 0

        @inheritable_ttl_cache(lambda self, x: x)
        def compute(self, x: int) -> int:
            self.calls += 1
            return x * 2

    a = Dummy()
    b = Dummy()

    # First call populates cache.
    assert a.compute(1) == 2
    assert a.calls == 1

    # Same key and class uses cache; no extra calls.
    assert a.compute(1) == 2
    assert a.calls == 1

    # Different instance, same class/key also uses same per-class cache.
    assert b.compute(1) == 2
    assert a.calls == 1
    assert b.calls == 0

    # Change TTL on class; next call should rebuild cache and invoke method again.
    Dummy.cache_ttl = 120
    assert a.compute(1) == 2
    assert a.calls == 2


def test_baseplugin_cache_wrapper_uses_inheritable_ttl_cache():
    """Brief: BasePlugin.cache decorator applies inheritable_ttl_cache to methods.

    Inputs:
      - None; defines a simple plugin class with a cached method.

    Outputs:
      - None; asserts method result is cached across calls with same arguments.
    """

    class CachingPlugin(BasePlugin):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        @BasePlugin.cache(lambda self, x: x)
        def compute(self, x: int) -> int:
            self.calls += 1
            return x * 3

    p = CachingPlugin()
    assert p.compute(2) == 6
    assert p.calls == 1
    # Second call with same arg hits cache
    assert p.compute(2) == 6
    assert p.calls == 1
