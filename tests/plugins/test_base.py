"""
Brief: Tests for foghorn.plugins.base module.

Inputs:
  - None

Outputs:
  - None
"""
import pytest
from foghorn.plugins.base import (
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)


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
