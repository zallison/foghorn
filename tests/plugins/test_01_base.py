"""
Brief: Tests for foghorn.plugins.base module.

Inputs:
  - None

Outputs:
  - None
"""

import logging

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.base import BasePlugin, PluginContext, PluginDecision
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
    assert BasePlugin.pre_priority == 100
    assert BasePlugin.post_priority == 100


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


def test_base_plugin_name_default_and_override() -> None:
    """Brief: BasePlugin assigns a default name and honors explicit overrides.

    Inputs:
      - None.

    Outputs:
      - None; asserts that the default name uses aliases/class name and that an
        explicit "name" argument is stored on the instance.
    """

    # Default BasePlugin with no aliases should fall back to class name.
    p = BasePlugin()
    assert p.name == "BasePlugin"

    # Plugins with aliases prefer the first alias when no explicit name is given.
    @plugin_aliases("alias_one", "alias_two")
    class P(BasePlugin):
        pass

    p2 = P()
    assert p2.name == "alias_one"

    # Explicit name should override any alias-derived default.
    p3 = P(name="custom_name")
    assert p3.name == "custom_name"


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

    # Invalid post_priority is logged and defaults to 100.
    p2 = P(post_priority="not-an-int")
    assert p2.post_priority == 100
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

    # Invalid type falls back to default 100
    assert BasePlugin._parse_priority_value("xx", "pre_priority", base_logger) == 100
    assert any("Invalid pre_priority" in r.message for r in caplog.records)

    # Below range clamps to 1
    assert BasePlugin._parse_priority_value(-10, "pre_priority", base_logger) == 1
    assert any("pre_priority below 1" in r.message for r in caplog.records)

    # Above range clamps to 255
    assert BasePlugin._parse_priority_value(300, "pre_priority", base_logger) == 255
    assert any("pre_priority above 255" in r.message for r in caplog.records)


def test_base_plugin_handle_sigusr2_default_noop():
    """Brief: Default handle_sigusr2 implementation is a no-op that returns None.

    Inputs:
      - None.

    Outputs:
      - None; asserts method returns None and does not raise.
    """
    plugin = BasePlugin()
    assert plugin.handle_sigusr2() is None


def test_base_plugin_setup_default_noop():
    """Brief: Default setup implementation is a no-op that returns None.

    Inputs:
      - None.

    Outputs:
      - None; asserts setup() returns None and does not raise.
    """
    plugin = BasePlugin()
    assert plugin.setup() is None


def test_base_plugin_targets_default_all_clients():
    """Brief: When no targets are configured, all clients are targeted.

    Inputs:
      - None.

    Outputs:
      - None; asserts targets() returns True for arbitrary client IPs.
    """
    plugin = BasePlugin()
    ctx1 = PluginContext(client_ip="192.0.2.1")
    ctx2 = PluginContext(client_ip="10.0.0.1")
    assert plugin.targets(ctx1) is True
    assert plugin.targets(ctx2) is True


def test_base_plugin_targets_cidr_includes_only_matches():
    """Brief: targets() restricts matches to configured CIDR ranges.

    Inputs:
      - targets: ["10.0.0.0/8"]

    Outputs:
      - None; asserts only clients in the CIDR are targeted.
    """
    plugin = BasePlugin(targets=["10.0.0.0/8"])
    ctx_match = PluginContext(client_ip="10.1.2.3")
    ctx_miss = PluginContext(client_ip="192.0.2.1")
    assert plugin.targets(ctx_match) is True
    assert plugin.targets(ctx_miss) is False


def test_base_plugin_targets_ignore_inverts_logic_when_no_targets():
    """Brief: With only targets_ignore configured, all but ignored clients are targeted.

    Inputs:
      - targets_ignore: ["10.0.0.0/8"]

    Outputs:
      - None; asserts ignored client is not targeted while others are.
    """
    plugin = BasePlugin(targets_ignore=["10.0.0.0/8"])
    ctx_ignored = PluginContext(client_ip="10.1.2.3")
    ctx_other = PluginContext(client_ip="192.0.2.1")
    assert plugin.targets(ctx_ignored) is False
    assert plugin.targets(ctx_other) is True


def test_base_plugin_targets_and_ignore_combined():
    """Brief: targets_ignore overrides targets for specific subranges.

    Inputs:
      - targets: ["10.0.0.0/8"]
      - targets_ignore: ["10.0.0.0/16"]

    Outputs:
      - None; asserts clients in ignore range are skipped while others in
        targets are included.
    """
    plugin = BasePlugin(targets=["10.0.0.0/8"], targets_ignore=["10.0.0.0/16"])
    ctx_ignored = PluginContext(client_ip="10.0.1.1")
    ctx_allowed = PluginContext(client_ip="10.1.2.3")
    ctx_outside = PluginContext(client_ip="192.0.2.1")
    assert plugin.targets(ctx_ignored) is False
    assert plugin.targets(ctx_allowed) is True
    assert plugin.targets(ctx_outside) is False


def test_base_plugin_targets_uses_cache_for_repeated_client(monkeypatch):
    """Brief: targets() caches per-client decisions to avoid repeated IP parsing.

    Inputs:
      - monkeypatch: pytest fixture to wrap ipaddress.ip_address.

    Outputs:
      - None; asserts that the underlying ipaddress.ip_address helper is only
        invoked once for repeated targets() calls with the same client_ip.
    """
    # Configure a simple targets-only plugin so explicit CIDRs are in effect.
    plugin = BasePlugin(targets=["10.0.0.0/8"], targets_cache_ttl_seconds=300)
    ctx = PluginContext(client_ip="10.1.2.3")

    # Wrap the module-level ipaddress.ip_address used inside BasePlugin so we
    # can observe how many times it is called for the same client.
    import foghorn.plugins.base as base_mod  # type: ignore[import]

    calls = {"count": 0}
    original_ip_address = base_mod.ipaddress.ip_address

    def _wrapped_ip_address(addr):  # type: ignore[no-untyped-def]
        calls["count"] += 1
        return original_ip_address(addr)

    monkeypatch.setattr(base_mod.ipaddress, "ip_address", _wrapped_ip_address)

    # First call should compute and cache the result.
    first = plugin.targets(ctx)
    # Second call with the same client_ip should hit the TTL cache and not
    # invoke ipaddress.ip_address again.
    second = plugin.targets(ctx)

    assert first is True
    assert second is True
    assert calls["count"] == 1


def _make_raw_query(name: str, qtype: int) -> bytes:
    """Brief: Helper to construct a minimal DNS query wire for BasePlugin tests.

    Inputs:
      - name: Domain name to query.
      - qtype: Numeric QTYPE code.

    Outputs:
      - bytes: Packed DNS query suitable for BasePlugin._make_a_response.
    """
    qtype_name = QTYPE.get(qtype, str(qtype))
    query = DNSRecord.question(name, qtype=qtype_name)
    return query.pack()


def test_make_a_response_parse_failure_returns_none():
    """Brief: _make_a_response returns None when DNSRecord.parse raises.

    Inputs:
      - None; uses deliberately invalid raw request bytes.

    Outputs:
      - None; asserts that a parse error path returns None.
    """
    plugin = BasePlugin()
    # Call setup() to mirror plugin lifecycle expectations.
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    result = plugin._make_a_response(
        qname="example.com",
        query_type=int(QTYPE.A),
        raw_req=b"not-a-valid-dns-packet",
        ctx=ctx,
        ipaddr="1.2.3.4",
    )
    assert result is None


def test_make_a_response_builds_a_record_with_custom_ttl():
    """Brief: _make_a_response builds an A record answer using self._ttl.

    Inputs:
      - None; constructs a valid A query and uses a fake _ttl value.

    Outputs:
      - None; asserts A record IP and TTL match expected values.
    """
    plugin = BasePlugin()
    plugin.setup()
    # Inject a custom TTL so we can assert it.
    plugin._ttl = 123  # type: ignore[assignment]
    ctx = PluginContext(client_ip="127.0.0.1")

    raw_req = _make_raw_query("a.example", int(QTYPE.A))
    wire = plugin._make_a_response(
        qname="a.example",
        query_type=int(QTYPE.A),
        raw_req=raw_req,
        ctx=ctx,
        ipaddr="5.6.7.8",
    )
    assert wire is not None

    response = DNSRecord.parse(wire)
    answers = [rr for rr in response.rr if rr.rtype == QTYPE.A]
    assert len(answers) == 1
    assert str(answers[0].rdata) == "5.6.7.8"
    assert answers[0].ttl == 123


def test_make_a_response_builds_aaaa_record_with_fixed_ttl():
    """Brief: _make_a_response builds an AAAA record answer with fixed TTL 60.

    Inputs:
      - None; constructs a valid AAAA query.

    Outputs:
      - None; asserts AAAA record IP and TTL use the hard-coded value.
    """
    plugin = BasePlugin()
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    raw_req = _make_raw_query("aaaa.example", int(QTYPE.AAAA))
    wire = plugin._make_a_response(
        qname="aaaa.example",
        query_type=int(QTYPE.AAAA),
        raw_req=raw_req,
        ctx=ctx,
        ipaddr="2001:db8::1",
    )
    assert wire is not None

    response = DNSRecord.parse(wire)
    answers = [rr for rr in response.rr if rr.rtype == QTYPE.AAAA]
    assert len(answers) == 1
    assert str(answers[0].rdata) == "2001:db8::1"
    # TTL for AAAA answers is hard-coded to 60 seconds in _make_a_response.
    assert answers[0].ttl == 60
