"""Brief: Tests for dns_rebinding plugin post-resolve filtering behavior.

Inputs:
  - None

Outputs:
  - None
"""

from dnslib import AAAA, QTYPE, RR, A, DNSRecord

from foghorn.plugins.resolve.base import PluginContext, PluginDecision
from foghorn.plugins.resolve.dns_rebinding import DnsRebinding


def _mk_response_with_answers(name: str, answers: list[tuple[str, str, int]]) -> bytes:
    """Brief: Build packed DNS response bytes with mixed A/AAAA answers.

    Inputs:
      - name: DNS owner name for answer records.
      - answers: list of (rtype, ip, ttl) tuples where rtype is 'A' or 'AAAA'.

    Outputs:
      - bytes: Packed DNS response wire.
    """

    query = DNSRecord.question(name, "A")
    response = query.reply()
    for rtype, ip_value, ttl in answers:
        if rtype == "A":
            response.add_answer(RR(name, QTYPE.A, rdata=A(ip_value), ttl=ttl))
        else:
            response.add_answer(RR(name, QTYPE.AAAA, rdata=AAAA(ip_value), ttl=ttl))
    return response.pack()


def test_post_resolve_denies_private_ipv4_for_non_allowlisted_name() -> None:
    """Brief: Private IPv4 answer is denied when queried name is not allowlisted.

    Inputs:
      - qname: www.example.com
      - answer: A 192.168.1.10

    Outputs:
      - None: Asserts deny action and dns_rebinding stat label.
    """

    plugin = DnsRebinding()
    plugin.setup()
    ctx = PluginContext(client_ip="192.0.2.10")
    response_wire = _mk_response_with_answers(
        "www.example.com", [("A", "192.168.1.10", 60)]
    )

    decision = plugin.post_resolve("www.example.com", QTYPE.A, response_wire, ctx)

    assert isinstance(decision, PluginDecision)
    assert decision.action == "deny"
    assert decision.stat == "dns_rebinding"


def test_post_resolve_denies_private_ipv6_for_non_allowlisted_name() -> None:
    """Brief: Private IPv6 answer is denied when queried name is not allowlisted.

    Inputs:
      - qname: www.example.com
      - answer: AAAA fd00::10

    Outputs:
      - None: Asserts deny action.
    """

    plugin = DnsRebinding()
    plugin.setup()
    ctx = PluginContext(client_ip="192.0.2.10")
    response_wire = _mk_response_with_answers(
        "www.example.com", [("AAAA", "fd00::10", 60)]
    )

    decision = plugin.post_resolve("www.example.com", QTYPE.AAAA, response_wire, ctx)

    assert isinstance(decision, PluginDecision)
    assert decision.action == "deny"


def test_post_resolve_allowlist_suffix_and_exact_modes_skip() -> None:
    """Brief: Allowlisted names bypass deny checks in suffix and exact modes.

    Inputs:
      - allowlist suffix mode: example.com
      - allowlist exact mode: login.example.com

    Outputs:
      - None: Asserts skip decisions for matching names.
    """

    suffix_plugin = DnsRebinding(
        allowlist_domains=["example.com"],
        allowlist_mode="suffix",
    )
    suffix_plugin.setup()
    exact_plugin = DnsRebinding(
        allowlist_domains=["login.example.com"],
        allowlist_mode="exact",
    )
    exact_plugin.setup()
    ctx = PluginContext(client_ip="192.0.2.10")
    response_wire = _mk_response_with_answers(
        "login.example.com", [("A", "192.168.1.20", 60)]
    )

    suffix_decision = suffix_plugin.post_resolve(
        "login.example.com", QTYPE.A, response_wire, ctx
    )
    exact_decision = exact_plugin.post_resolve(
        "login.example.com", QTYPE.A, response_wire, ctx
    )

    assert isinstance(suffix_decision, PluginDecision)
    assert suffix_decision.action == "skip"
    assert isinstance(exact_decision, PluginDecision)
    assert exact_decision.action == "skip"


def test_post_resolve_skips_when_no_private_answer_exists() -> None:
    """Brief: Public-only answers are not denied.

    Inputs:
      - answer: A 93.184.216.34

    Outputs:
      - None: Asserts skip action.
    """

    plugin = DnsRebinding()
    plugin.setup()
    ctx = PluginContext(client_ip="192.0.2.10")
    response_wire = _mk_response_with_answers(
        "www.example.com", [("A", "93.184.216.34", 60)]
    )

    decision = plugin.post_resolve("www.example.com", QTYPE.A, response_wire, ctx)

    assert isinstance(decision, PluginDecision)
    assert decision.action == "skip"


def test_post_resolve_respects_baseplugin_targeting_gates() -> None:
    """Brief: Non-targeted requests are ignored by post_resolve.

    Inputs:
      - targets.ips: 10.0.0.0/8
      - targets.qtypes: AAAA
      - ctx.client_ip: 192.0.2.10
      - qtype: A

    Outputs:
      - None: Asserts None when request does not pass targeting.
    """

    plugin = DnsRebinding(
        targets={
            "ips": ["10.0.0.0/8"],
            "qtypes": ["AAAA"],
        }
    )
    plugin.setup()
    ctx = PluginContext(client_ip="192.0.2.10")
    response_wire = _mk_response_with_answers(
        "www.example.com", [("A", "192.168.1.10", 60)]
    )

    decision = plugin.post_resolve("www.example.com", QTYPE.A, response_wire, ctx)

    assert decision is None
