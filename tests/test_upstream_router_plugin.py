from __future__ import annotations
import pytest

from foghorn.plugins.upstream_router import UpstreamRouterPlugin
from foghorn.plugins.base import PluginContext


def test_exact_domain_match_sets_upstream_override():
    plugin = UpstreamRouterPlugin(routes=[
        {"domain": "corp.example.com", "upstream": {"host": "10.0.0.53", "port": 5353}}
    ])
    ctx = PluginContext(client_ip="1.2.3.4")
    plugin.pre_resolve("corp.example.com", 1, ctx)
    assert ctx.upstream_override == ("10.0.0.53", 5353)


def test_suffix_match_with_and_without_leading_dot():
    plugin = UpstreamRouterPlugin(routes=[
        {"suffix": "internal", "upstream": {"host": "192.168.1.1", "port": 53}},
        {"suffix": ".svc.cluster.local", "upstream": {"host": "127.0.0.1", "port": 1053}},
    ])

    # Match suffix anywhere at end
    ctx1 = PluginContext(client_ip="1.2.3.4")
    plugin.pre_resolve("db.internal", 1, ctx1)
    assert ctx1.upstream_override == ("192.168.1.1", 53)

    # Exact equals suffix (no dot in qname)
    ctx2 = PluginContext(client_ip="1.2.3.4")
    plugin.pre_resolve("internal", 1, ctx2)
    assert ctx2.upstream_override == ("192.168.1.1", 53)

    # Match normalized dotted suffix, and tolerate trailing dot + case-insensitivity
    ctx3 = PluginContext(client_ip="1.2.3.4")
    plugin.pre_resolve("KUBE-DNS.SVC.CLUSTER.LOCAL.", 1, ctx3)
    assert ctx3.upstream_override == ("127.0.0.1", 1053)


def test_no_match_leaves_override_none():
    plugin = UpstreamRouterPlugin(routes=[
        {"domain": "corp.example.com", "upstream": {"host": "10.0.0.53", "port": 53}}
    ])
    ctx = PluginContext(client_ip="1.2.3.4")
    plugin.pre_resolve("example.com", 1, ctx)
    assert ctx.upstream_override is None
