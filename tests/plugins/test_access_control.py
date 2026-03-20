"""
Brief: Tests for foghorn.plugins.resolve.access_control module.

Inputs:
  - None

Outputs:
  - None
"""

import pytest
from dnslib import DNSRecord, QTYPE, RCODE

from foghorn.plugins.resolve.access_control import AccessControl, _parse_client_ip
from foghorn.plugins.resolve.base import PluginContext


def test_access_control_init_default_allow(tmp_path):
    """
    Brief: Verify AccessControl initializes with default allow.

    Inputs:
      - config: empty or minimal configuration

    Outputs:
      - None: Asserts default is 'allow'
    """
    plugin = AccessControl()
    plugin.setup()
    assert plugin.default == "allow"


def test_access_control_init_default_deny(tmp_path):
    """
    Brief: Verify AccessControl initializes with default deny.

    Inputs:
      - config: default set to 'deny'

    Outputs:
      - None: Asserts default is 'deny'
    """
    plugin = AccessControl(default="deny")
    plugin.setup()
    assert plugin.default == "deny"


def test_access_control_allow_list_parsing(tmp_path):
    """
    Brief: Verify allow list parses IP networks correctly.

    Inputs:
      - config: allow list with CIDR notation

    Outputs:
      - None: Asserts networks parsed
    """
    plugin = AccessControl(allow=["192.168.1.0/24", "10.0.0.0/8"])
    plugin.setup()
    assert len(plugin.allow_nets) == 2


def test_access_control_deny_list_parsing(tmp_path):
    """
    Brief: Verify deny list parses IP networks correctly.

    Inputs:
      - config: deny list with CIDR notation

    Outputs:
      - None: Asserts networks parsed
    """
    plugin = AccessControl(deny=["192.168.1.10/32", "172.16.0.0/12"])
    plugin.setup()
    assert len(plugin.deny_nets) == 2


def test_access_control_allows_by_default(tmp_path):
    """
    Brief: Verify queries allowed by default policy.

    Inputs:
      - config: default='allow', no rules
      - client_ip: arbitrary IP

    Outputs:
      - None: Asserts decision to allow (deny action returned)
    """
    plugin = AccessControl(default="allow")
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision.action == "allow"


def test_access_control_denies_by_default(tmp_path):
    """
    Brief: Verify queries denied by default policy.

    Inputs:
      - config: default='deny', no rules
      - client_ip: arbitrary IP

    Outputs:
      - None: Asserts decision to deny
    """
    plugin = AccessControl(default="deny")
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision.action == "override"
    denied = DNSRecord.parse(decision.response)
    assert denied.header.rcode == RCODE.REFUSED


def test_access_control_allow_rule_matches(tmp_path):
    """
    Brief: Verify matching allow rule permits query.

    Inputs:
      - config: default='deny', allow=['192.168.1.0/24']
      - client_ip: IP in allowed range

    Outputs:
      - None: Asserts None returned (allow)
    """
    plugin = AccessControl(default="deny", allow=["192.168.1.0/24"])
    plugin.setup()
    ctx = PluginContext(client_ip="192.168.1.100")
    decision = plugin.pre_resolve("example.com", 1, b"", ctx)
    assert decision is None


def test_access_control_deny_rule_matches(tmp_path):
    """
    Brief: Verify matching deny rule blocks query.

    Inputs:
      - config: default='allow', deny=['192.168.1.10']
      - client_ip: denied IP

    Outputs:
      - None: Asserts decision to deny
    """
    plugin = AccessControl(default="allow", deny=["192.168.1.10"])
    plugin.setup()
    ctx = PluginContext(client_ip="192.168.1.10")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision is not None
    assert decision.action == "override"
    denied = DNSRecord.parse(decision.response)
    assert denied.header.rcode == RCODE.REFUSED


def test_access_control_deny_takes_precedence(tmp_path):
    """
    Brief: Verify deny rules take precedence over allow rules.

    Inputs:
      - config: allow=['192.168.1.0/24'], deny=['192.168.1.10']
      - client_ip: IP in both allow and deny ranges

    Outputs:
      - None: Asserts decision to deny
    """
    plugin = AccessControl(
        default="allow", allow=["192.168.1.0/24"], deny=["192.168.1.10"]
    )
    plugin.setup()
    ctx = PluginContext(client_ip="192.168.1.10")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision is not None
    assert decision.action == "override"
    denied = DNSRecord.parse(decision.response)
    assert denied.header.rcode == RCODE.REFUSED


def test_access_control_ipv6_support(tmp_path):
    """
    Brief: Verify IPv6 addresses work in ACL.

    Inputs:
      - config: allow=['2001:db8::/32']
      - client_ip: IPv6 address

    Outputs:
      - None: Asserts IPv6 processed correctly
    """
    plugin = AccessControl(default="deny", allow=["2001:db8::/32"])
    plugin.setup()

    ctx = PluginContext(client_ip="2001:db8::1")
    decision = plugin.pre_resolve("example.com", 1, b"", ctx)
    assert decision is None


def test_access_control_single_ip_no_mask(tmp_path):
    """
    Brief: Verify single IP without CIDR mask works.

    Inputs:
      - config: deny=['10.0.0.1']
      - client_ip: exact match IP

    Outputs:
      - None: Asserts single IP parsed as /32
    """
    plugin = AccessControl(default="allow", deny=["10.0.0.1"])
    plugin.setup()
    ctx = PluginContext(client_ip="10.0.0.1")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision is not None
    assert decision.action == "override"
    denied = DNSRecord.parse(decision.response)
    assert denied.header.rcode == RCODE.REFUSED


def test_access_control_no_rules_default_allow(tmp_path):
    """
    Brief: Verify default allow with no rules allows all.

    Inputs:
      - config: default='allow', no rules
      - client_ip: any IP

    Outputs:
      - None: Asserts decision to allow
    """
    plugin = AccessControl(default="allow")
    plugin.setup()
    ctx = PluginContext(client_ip="203.0.113.1")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision.action == "allow"


def test_access_control_no_rules_default_deny(tmp_path):
    """
    Brief: Verify default deny with no rules denies all.

    Inputs:
      - config: default='deny', no rules
      - client_ip: any IP

    Outputs:
      - None: Asserts decision to deny
    """
    plugin = AccessControl(default="deny")
    plugin.setup()
    ctx = PluginContext(client_ip="203.0.113.1")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision.action == "override"
    denied = DNSRecord.parse(decision.response)
    assert denied.header.rcode == RCODE.REFUSED


def test_access_control_respects_baseplugin_targets(tmp_path):
    """Brief: AccessControl returns None when client is not targeted.

    Inputs:
      - targets: ["10.0.0.0/8"]
      - default: deny

    Outputs:
      - None; asserts pre_resolve returns None instead of deny when the
        client_ip is outside the targets set.
    """
    plugin = AccessControl(default="deny", targets=["10.0.0.0/8"])
    plugin.setup()
    ctx = PluginContext(client_ip="192.0.2.1")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision is None


def test_access_control_invalid_default_warns_and_defaults_allow(caplog) -> None:
    """Brief: Invalid default policy logs warning and resets to allow.

    Inputs:
      - caplog: pytest fixture for log capture.

    Outputs:
      - None
    """

    plugin = AccessControl(default="nope")
    with caplog.at_level("WARNING"):
        plugin.setup()
    assert plugin.default == "allow"
    assert any("invalid default" in record.getMessage() for record in caplog.records)


def test_access_control_invalid_network_raises() -> None:
    """Brief: Invalid CIDR entries raise during setup.

    Inputs:
      - None

    Outputs:
      - None
    """

    plugin = AccessControl(allow=["bad-cidr"])
    with pytest.raises(ValueError):
        plugin.setup()


def test_access_control_invalid_deny_response_defaults_to_refused(caplog) -> None:
    """Brief: Invalid deny_response logs warning and falls back to refused.

    Inputs:
      - caplog: pytest fixture for log capture.

    Outputs:
      - None
    """

    plugin = AccessControl(default="deny", deny_response="nope")
    with caplog.at_level("WARNING"):
        plugin.setup()
    ctx = PluginContext(client_ip="198.51.100.9")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision.action == "override"
    denied = DNSRecord.parse(decision.response)
    assert denied.header.rcode == RCODE.REFUSED
    assert any(
        "unknown deny_response" in record.getMessage() for record in caplog.records
    )


def test_access_control_deny_response_nxdomain() -> None:
    """Brief: deny_response nxdomain yields deny action without override.

    Inputs:
      - None

    Outputs:
      - None
    """

    plugin = AccessControl(default="deny", deny_response="nxdomain")
    plugin.setup()
    ctx = PluginContext(client_ip="203.0.113.10")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision.action == "deny"


def test_access_control_deny_response_drop() -> None:
    """Brief: deny_response drop yields drop action.

    Inputs:
      - None

    Outputs:
      - None
    """

    plugin = AccessControl(default="deny", deny_response="drop")
    plugin.setup()
    ctx = PluginContext(client_ip="203.0.113.11")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision.action == "drop"


def test_access_control_deny_response_servfail() -> None:
    """Brief: deny_response servfail returns SERVFAIL override.

    Inputs:
      - None

    Outputs:
      - None
    """

    plugin = AccessControl(default="deny", deny_response="servfail")
    plugin.setup()
    ctx = PluginContext(client_ip="203.0.113.12")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision.action == "override"
    denied = DNSRecord.parse(decision.response)
    assert denied.header.rcode == RCODE.SERVFAIL


@pytest.mark.parametrize("mode", ["noerror_empty", "nodata"])
def test_access_control_deny_response_noerror_empty(mode: str) -> None:
    """Brief: deny_response noerror_empty/nodata yields NOERROR with empty answer.

    Inputs:
      - mode: deny_response mode under test.

    Outputs:
      - None
    """

    plugin = AccessControl(default="deny", deny_response=mode)
    plugin.setup()
    ctx = PluginContext(client_ip="203.0.113.13")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision.action == "override"
    denied = DNSRecord.parse(decision.response)
    assert denied.header.rcode == RCODE.NOERROR
    assert denied.rr == []


@pytest.mark.parametrize(
    ("qtype", "ip4", "ip6", "expected_type"),
    [
        (QTYPE.A, "192.0.2.10", None, QTYPE.A),
        (QTYPE.AAAA, None, "2001:db8::10", QTYPE.AAAA),
    ],
)
def test_access_control_deny_response_ip_answers(
    qtype: int, ip4: str | None, ip6: str | None, expected_type: int
) -> None:
    """Brief: deny_response ip synthesizes A/AAAA responses when configured.

    Inputs:
      - qtype: DNS query type under test.
      - ip4: IPv4 response address.
      - ip6: IPv6 response address.
      - expected_type: expected answer type.

    Outputs:
      - None
    """

    plugin = AccessControl(
        default="deny",
        deny_response="ip",
        deny_response_ip4=ip4,
        deny_response_ip6=ip6,
    )
    plugin.setup()
    ctx = PluginContext(client_ip="198.51.100.20")
    decision = plugin.pre_resolve(
        "example.com",
        qtype,
        DNSRecord.question("example.com", QTYPE[qtype]).pack(),
        ctx,
    )
    assert decision.action == "override"
    denied = DNSRecord.parse(decision.response)
    assert denied.rr
    assert denied.rr[0].rtype == expected_type


def test_access_control_deny_response_ip_fallback_without_a_or_aaaa() -> None:
    """Brief: deny_response ip falls back to configured IP for non-A/AAAA types.

    Inputs:
      - None

    Outputs:
      - None
    """

    plugin = AccessControl(
        default="deny",
        deny_response="ip",
        deny_response_ip4="192.0.2.55",
    )
    plugin.setup()
    ctx = PluginContext(client_ip="198.51.100.21")
    decision = plugin.pre_resolve(
        "example.com",
        QTYPE.TXT,
        DNSRecord.question("example.com", "TXT").pack(),
        ctx,
    )
    assert decision.action == "override"
    denied = DNSRecord.parse(decision.response)
    assert denied.header.rcode == RCODE.NOERROR
    assert denied.rr == []


def test_access_control_deny_response_ip_without_config_falls_back_to_deny() -> None:
    """Brief: deny_response ip without IP config falls back to deny.

    Inputs:
      - None

    Outputs:
      - None
    """

    plugin = AccessControl(default="deny", deny_response="ip")
    plugin.setup()
    ctx = PluginContext(client_ip="198.51.100.22")
    decision = plugin.pre_resolve(
        "example.com", QTYPE.A, DNSRecord.question("example.com", "A").pack(), ctx
    )
    assert decision.action == "deny"


def test_access_control_parse_client_ip_invalid_raises() -> None:
    """Brief: _parse_client_ip raises ValueError for invalid IPs.

    Inputs:
      - None

    Outputs:
      - None
    """

    with pytest.raises(ValueError):
        _parse_client_ip("not-an-ip")


def test_access_control_admin_pages_descriptor_snapshot() -> None:
    """Brief: Admin UI descriptors and snapshot include expected keys.

    Inputs:
      - None

    Outputs:
      - None
    """

    plugin = AccessControl(
        default="deny", allow=["192.168.0.0/24"], deny=["10.0.0.0/8"]
    )
    plugin.setup()
    plugin.name = "acl_custom"

    pages = plugin.get_admin_pages()
    assert len(pages) == 1
    assert pages[0].slug == "access-control"
    assert pages[0].kind == "access_control"

    descriptor = plugin.get_admin_ui_descriptor()
    assert descriptor["name"] == "acl_custom"
    assert "snapshot" in descriptor["endpoints"]

    snapshot = plugin.get_http_snapshot()
    assert snapshot["policy"]["default"] == "deny"
    assert snapshot["policy"]["allow_rules"] == 1
    assert snapshot["policy"]["deny_rules"] == 1
