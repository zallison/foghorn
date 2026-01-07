"""
Brief: Tests for plugin hook priority ordering and configuration.

Inputs:
  - None

Outputs:
  - None: Asserts ordering, clamping, and YAML override behavior
"""

import logging

from foghorn.plugins.resolve.base import BasePlugin, PluginContext


def test_default_priorities_are_100():
    """
    Brief: Verify BasePlugin defaults to pre_priority=100 and post_priority=100.

    Inputs:
      - None

    Outputs:
      - None: Asserts class and instance default priorities are 100
    """
    assert BasePlugin.pre_priority == 100
    assert BasePlugin.post_priority == 100

    plugin = BasePlugin()
    assert plugin.pre_priority == 100
    assert plugin.post_priority == 100


def test_class_attribute_defaults_respected():
    """
    Brief: Subclass priority class attributes override base defaults.

    Inputs:
      - PluginA with pre_priority=10, PluginB with pre_priority=100

    Outputs:
      - None: Asserts instances inherit class priorities
    """

    class PluginA(BasePlugin):
        pre_priority = 10

    class PluginB(BasePlugin):
        pre_priority = 100

    a = PluginA()
    b = PluginB()

    assert a.pre_priority == 10
    assert a.post_priority == 100  # default
    assert b.pre_priority == 100
    assert b.post_priority == 100  # default


def test_yaml_config_overrides_class_defaults():
    """
    Brief: Config dict overrides class default priorities.

    Inputs:
      - Plugin with class defaults; config with pre_priority=5, post_priority=200

    Outputs:
      - None: Asserts instance uses config values over class defaults
    """

    class MyPlugin(BasePlugin):
        pre_priority = 30
        post_priority = 40

    plugin = MyPlugin(pre_priority=5, post_priority=200)
    assert plugin.pre_priority == 5
    assert plugin.post_priority == 200


def test_clamping_below_range(caplog):
    """
    Brief: Priority values below 1 are clamped to 1 with warning.

    Inputs:
      - Config: pre_priority=0, post_priority=-5

    Outputs:
      - None: Asserts pre=1, post=1; warnings logged
    """
    with caplog.at_level(logging.WARNING):
        plugin = BasePlugin(pre_priority=0, post_priority=-5)

    assert plugin.pre_priority == 1
    assert plugin.post_priority == 1
    assert any("below 1; clamping to 1" in rec.message for rec in caplog.records)


def test_clamping_above_range(caplog):
    """
    Brief: Priority values above 255 are clamped to 255 with warning.

    Inputs:
      - Config: pre_priority=256, post_priority=1000

    Outputs:
      - None: Asserts pre=255, post=255; warnings logged
    """
    with caplog.at_level(logging.WARNING):
        plugin = BasePlugin(pre_priority=256, post_priority=1000)

    assert plugin.pre_priority == 255
    assert plugin.post_priority == 255
    assert any("above 255; clamping to 255" in rec.message for rec in caplog.records)


def test_invalid_type_uses_default(caplog):
    """
    Brief: Non-integer priority values fall back to default with warning.

    Inputs:
      - Config: pre_priority="abc", post_priority=None

    Outputs:
      - None: Asserts pre=100, post=100 (defaults); warning logged for "abc"
    """
    with caplog.at_level(logging.WARNING):
        plugin = BasePlugin(pre_priority="abc")

    assert plugin.pre_priority == 100  # fallback to class default
    assert any("Invalid pre_priority" in rec.message for rec in caplog.records)


def test_stable_ties_preserve_registration_order():
    """
    Brief: Plugins with equal priorities execute in registration order (stable sort).

    Inputs:
      - Three plugins all with equal default pre_priority.

    Outputs:
      - None: Asserts sorted order equals original order
    """

    class PluginA(BasePlugin):
        pass

    class PluginB(BasePlugin):
        pass

    class PluginC(BasePlugin):
        pass

    plugins = [PluginA(), PluginB(), PluginC()]

    # Sort by pre_priority (all 50)
    sorted_pre = sorted(plugins, key=lambda p: getattr(p, "pre_priority", 50))
    assert [type(p).__name__ for p in sorted_pre] == ["PluginA", "PluginB", "PluginC"]

    # Sort by post_priority (all 50)
    sorted_post = sorted(plugins, key=lambda p: getattr(p, "post_priority", 50))
    assert [type(p).__name__ for p in sorted_post] == ["PluginA", "PluginB", "PluginC"]


def test_integration_ordering_pre_hooks():
    """
    Brief: Pre hooks execute in ascending pre_priority order.

    Inputs:
      - AllowlistPlugin pre=10, BlocklistPlugin pre=20, RedirectPlugin pre=100

    Outputs:
      - None: Asserts pre execution order: Allowlist -> Blocklist -> Redirect
    """
    execution_order = []

    class AllowlistPlugin(BasePlugin):
        pre_priority = 10

        def pre_resolve(self, qname, qtype, req, ctx):
            execution_order.append("Allowlist")
            return None

    class BlocklistPlugin(BasePlugin):
        pre_priority = 20

        def pre_resolve(self, qname, qtype, req, ctx):
            execution_order.append("Blocklist")
            return None

    class RedirectPlugin(BasePlugin):
        pre_priority = 100

        def pre_resolve(self, qname, qtype, req, ctx):
            execution_order.append("Redirect")
            return None

    # Register in arbitrary order
    plugins = [RedirectPlugin(), AllowlistPlugin(), BlocklistPlugin()]

    # Sort and execute
    ctx = PluginContext(client_ip="127.0.0.1")
    for p in sorted(plugins, key=lambda p: getattr(p, "pre_priority", 50)):
        p.pre_resolve("example.com", 1, b"", ctx)

    assert execution_order == ["Allowlist", "Blocklist", "Redirect"]


def test_integration_ordering_post_hooks():
    """
    Brief: Post hooks execute in ascending post_priority order.

    Inputs:
      - LoggerPlugin post=10, Filter post=100, RewritePlugin post=200

    Outputs:
      - None: Asserts post execution order: Logger -> Filter -> Rewrite
    """
    execution_order = []

    class LoggerPlugin(BasePlugin):
        post_priority = 10

        def post_resolve(self, qname, qtype, response_wire, ctx):
            execution_order.append("Logger")
            return None

    class Filter(BasePlugin):
        post_priority = 100

        def post_resolve(self, qname, qtype, response_wire, ctx):
            execution_order.append("Filter")
            return None

    class RewritePlugin(BasePlugin):
        post_priority = 200

        def post_resolve(self, qname, qtype, response_wire, ctx):
            execution_order.append("Rewrite")
            return None

    # Register in arbitrary order
    plugins = [Filter(), RewritePlugin(), LoggerPlugin()]

    # Sort and execute
    ctx = PluginContext(client_ip="127.0.0.1")
    for p in sorted(plugins, key=lambda p: getattr(p, "post_priority", 50)):
        p.post_resolve("example.com", 1, b"response", ctx)

    assert execution_order == ["Logger", "Filter", "Rewrite"]


def test_mixed_priorities_and_defaults():
    """
    Brief: Mix of explicit and default priorities sorts correctly.

    Inputs:
      - PluginA pre=1, PluginB pre=default(100), PluginC pre=200

    Outputs:
      - None: Asserts execution order A -> B -> C
    """

    class PluginA(BasePlugin):
        pre_priority = 1

    class PluginB(BasePlugin):
        pass  # defaults to 100

    class PluginC(BasePlugin):
        pre_priority = 200

    plugins = [PluginC(), PluginB(), PluginA()]
    sorted_plugins = sorted(plugins, key=lambda p: getattr(p, "pre_priority", 50))

    assert [type(p).__name__ for p in sorted_plugins] == [
        "PluginA",
        "PluginB",
        "PluginC",
    ]


def test_config_override_with_string_coercion():
    """
    Brief: String priority values are coerced to int.

    Inputs:
      - Config: pre_priority="25", post_priority="75"

    Outputs:
      - None: Asserts pre=25, post=75 (coerced from strings)
    """
    plugin = BasePlugin(pre_priority="25", post_priority="75")
    assert plugin.pre_priority == 25
    assert plugin.post_priority == 75
