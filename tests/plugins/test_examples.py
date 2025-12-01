"""
Brief: Tests for foghorn.plugins.examples module.

Inputs:
  - None

Outputs:
  - None
"""

from dnslib import QTYPE, A, DNSRecord

from foghorn.plugins.base import PluginContext
from foghorn.plugins.examples import (ExamplesPlugin, _count_subdomains,
                                      _length_without_dots)


def test_count_subdomains_simple():
    """
    Brief: Count subdomains for simple domain.

    Inputs:
      - qname: domain string
      - base_labels: number of base labels (default 2)

    Outputs:
      - None: Asserts correct subdomain count
    """
    assert _count_subdomains("example.com") == 0
    assert _count_subdomains("www.example.com") == 1
    assert _count_subdomains("a.b.example.com") == 2


def test_count_subdomains_with_trailing_dot():
    """
    Brief: Count subdomains with trailing dot.

    Inputs:
      - qname: domain string with trailing dot

    Outputs:
      - None: Asserts trailing dot ignored
    """
    assert _count_subdomains("www.example.com.") == 1


def test_count_subdomains_deep():
    """
    Brief: Count subdomains for deeply nested domain.

    Inputs:
      - qname: domain with many subdomains

    Outputs:
      - None: Asserts correct count
    """
    assert _count_subdomains("a.b.c.d.e.f.example.com") == 6


def test_length_without_dots_simple():
    """
    Brief: Calculate length excluding dots.

    Inputs:
      - qname: domain string

    Outputs:
      - None: Asserts correct length
    """
    assert _length_without_dots("example.com") == 10  # "examplecom"
    assert _length_without_dots("a.b.c") == 3  # "abc"


def test_length_without_dots_trailing_dot():
    """
    Brief: Calculate length with trailing dot removed.

    Inputs:
      - qname: domain with trailing dot

    Outputs:
      - None: Asserts trailing dot excluded
    """
    assert _length_without_dots("example.com.") == 10


def test_examples_plugin_init_defaults():
    """
    Brief: Verify ExamplesPlugin initializes with defaults.

    Inputs:
      - None

    Outputs:
      - None: Asserts default config values
    """
    plugin = ExamplesPlugin()
    plugin.setup()
    assert plugin.max_subdomains == 5
    assert plugin.max_length_no_dots == 50
    assert plugin.base_labels == 2
    assert plugin.apply_to_qtypes == ["*"]


def test_examples_plugin_init_custom_config():
    """
    Brief: Verify ExamplesPlugin initializes with custom config.

    Inputs:
      - **config: custom configuration values

    Outputs:
      - None: Asserts custom values stored
    """
    plugin = ExamplesPlugin(
        max_subdomains=3,
        max_length_no_dots=30,
        base_labels=3,
        apply_to_qtypes=["A", "AAAA"],
    )
    plugin.setup()
    assert plugin.max_subdomains == 3
    assert plugin.max_length_no_dots == 30
    assert plugin.base_labels == 3
    assert plugin.apply_to_qtypes == ["A", "AAAA"]


def test_examples_plugin_pre_resolve_allows_normal():
    """
    Brief: Verify normal domain is allowed.

    Inputs:
      - qname: normal domain within limits

    Outputs:
      - None: Asserts None returned (allow)
    """
    plugin = ExamplesPlugin()
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")
    decision = plugin.pre_resolve("www.example.com", QTYPE.A, b"", ctx)
    assert decision is None


def test_examples_plugin_pre_resolve_denies_too_many_subdomains():
    """
    Brief: Verify domain with too many subdomains is denied.

    Inputs:
      - qname: domain exceeding max_subdomains

    Outputs:
      - None: Asserts deny decision
    """
    plugin = ExamplesPlugin(max_subdomains=3)
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")
    # a.b.c.d.example.com = 4 subdomains
    decision = plugin.pre_resolve("a.b.c.d.example.com", QTYPE.A, b"", ctx)
    assert decision is not None
    assert decision.action == "deny"


def test_examples_plugin_pre_resolve_denies_too_long():
    """
    Brief: Verify domain exceeding length limit is denied.

    Inputs:
      - qname: domain with length > max_length_no_dots

    Outputs:
      - None: Asserts deny decision
    """
    plugin = ExamplesPlugin(max_length_no_dots=10)
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")
    # "verylongdomainname.com" = 21 chars without dots
    decision = plugin.pre_resolve("verylongdomainname.com", QTYPE.A, b"", ctx)
    assert decision is not None
    assert decision.action == "deny"


def test_examples_plugin_applies_qtype_filter():
    """
    Brief: Verify qtype filtering works.

    Inputs:
      - apply_to_qtypes: specific types
      - qtype: matching and non-matching types

    Outputs:
      - None: Asserts filtering applied
    """
    plugin = ExamplesPlugin(max_subdomains=0, apply_to_qtypes=["A"])
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    # Should deny A queries
    decision_a = plugin.pre_resolve("www.example.com", QTYPE.A, b"", ctx)
    assert decision_a is not None
    assert decision_a.action == "deny"

    # Should allow AAAA queries (not in apply_to_qtypes)
    decision_aaaa = plugin.pre_resolve("www.example.com", QTYPE.AAAA, b"", ctx)
    assert decision_aaaa is None


def test_examples_plugin_post_resolve_no_rewrite_rules():
    """
    Brief: Verify no action when rewrite_rules empty.

    Inputs:
      - rewrite_rules: empty list

    Outputs:
      - None: Asserts None returned
    """
    plugin = ExamplesPlugin()
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")
    query = DNSRecord.question("example.com", "A")
    response = query.reply()
    response.add_answer(*DNSRecord.parse(query.send("1.1.1.1", 53)).rr)
    decision = plugin.post_resolve("example.com", QTYPE.A, response.pack(), ctx)
    # Without rewrite rules, should return None
    assert decision is None


def test_examples_plugin_post_resolve_with_rewrite():
    """
    Brief: Verify A record rewrite works.

    Inputs:
      - rewrite_first_ipv4: rewrite rule configuration
      - response: DNS response with A records

    Outputs:
      - None: Asserts override decision with modified response
    """
    rewrite_first_ipv4 = [{"apply_to_qtypes": ["A"], "ip_override": "127.0.0.1"}]
    plugin = ExamplesPlugin(rewrite_first_ipv4=rewrite_first_ipv4)
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    # Create a proper response with A record using RR
    from dnslib import RR, DNSHeader

    query = DNSRecord.question("example.com", "A")
    response = DNSRecord(DNSHeader(id=query.header.id, qr=1, aa=1, ra=1), q=query.q)
    response.add_answer(
        RR(
            rname="example.com",
            rtype=QTYPE.A,
            rclass=1,
            ttl=60,
            rdata=A("93.184.216.34"),
        )
    )
    decision = plugin.post_resolve("example.com", QTYPE.A, response.pack(), ctx)
    assert decision is not None
    assert decision.action == "override"

    # Parse modified response and verify IP changed
    modified = DNSRecord.parse(decision.response)
    assert str(modified.rr[0].rdata) == "127.0.0.1"


def test_examples_plugin_qtype_name_normalization():
    """
    Brief: Verify qtype name normalization.

    Inputs:
      - qtype: int or string qtype

    Outputs:
      - None: Asserts normalized uppercase name
    """
    plugin = ExamplesPlugin()
    assert plugin._qtype_name(1) == "A"
    assert plugin._qtype_name("a") == "A"
    assert plugin._qtype_name("AAAA") == "AAAA"
