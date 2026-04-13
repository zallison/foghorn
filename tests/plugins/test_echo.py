"""
Brief: Tests for foghorn.plugins.resolve.echo module.

Inputs:
  - None

Outputs:
  - None
"""

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.resolve.base import PluginContext
from foghorn.plugins.resolve.echo import Echo


def test_echo_pre_resolve_not_targeted_returns_none():
    """Brief: When ctx does not match plugin targets, Echo should not run.

    Inputs:
      - plugin: Echo configured with explicit targets
      - ctx: PluginContext with a client_ip outside the targeted networks

    Outputs:
      - None: Asserts pre_resolve returns None
    """
    plugin = Echo(targets=["192.0.2.0/24"])
    plugin.setup()

    ctx = PluginContext(client_ip="198.51.100.1")
    req = DNSRecord.question("example.com", qtype="A").pack()

    decision = plugin.pre_resolve("example.com", QTYPE.A, req, ctx)
    assert decision is None


def test_echo_pre_resolve_parse_failure_returns_none():
    """Brief: Invalid DNS wire bytes should be ignored (fall through).

    Inputs:
      - req: invalid/empty wire bytes

    Outputs:
      - None: Asserts pre_resolve returns None
    """
    plugin = Echo()
    plugin.setup()

    ctx = PluginContext(client_ip="1.2.3.4")
    decision = plugin.pre_resolve("example.com", QTYPE.A, b"", ctx)
    assert decision is None


def test_echo_pre_resolve_builds_txt_override_response():
    """Brief: Echo should synthesize a TXT override response on match.

    Inputs:
      - qname: name to echo (trailing dot allowed)
      - qtype: query type integer
      - req: valid DNS query wire bytes

    Outputs:
      - None: Asserts returned PluginDecision contains a TXT RR with the echoed text
    """
    plugin = Echo()
    plugin.setup()

    ctx = PluginContext(client_ip="1.2.3.4")
    request = DNSRecord.question("example.com", qtype="A")
    decision = plugin.pre_resolve("Example.COM.", QTYPE.A, request.pack(), ctx)

    assert decision is not None
    assert decision.action == "override"
    assert isinstance(decision.response, (bytes, bytearray))

    response = DNSRecord.parse(decision.response)
    assert response.header.id == request.header.id
    assert response.header.qr == 1
    assert len(response.rr) == 1

    rr = response.rr[0]
    assert rr.rtype == QTYPE.TXT
    assert rr.ttl == Echo.ttl

    # dnslib TXT stores one or more byte-string chunks.
    txt = b"".join(getattr(rr.rdata, "data", [])).decode("utf-8")
    assert txt == "Example.COM A"


def test_echo_pre_resolve_uses_class_ttl_override():
    """Brief: Echo should use the plugin class's ttl attribute for the answer.

    Inputs:
      - ttl: custom class attribute override

    Outputs:
      - None: Asserts the TXT RR ttl matches the overridden class attribute
    """

    class EchoTTL(Echo):
        ttl = 42

    plugin = EchoTTL()
    plugin.setup()

    ctx = PluginContext(client_ip="1.2.3.4")
    request = DNSRecord.question("example.com", qtype="A")
    decision = plugin.pre_resolve("example.com", QTYPE.A, request.pack(), ctx)

    assert decision is not None
    response = DNSRecord.parse(decision.response)
    assert response.rr[0].ttl == 42
