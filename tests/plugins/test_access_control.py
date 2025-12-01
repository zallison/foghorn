"""
Brief: Tests for foghorn.plugins.access_control module.

Inputs:
  - None

Outputs:
  - None
"""

from foghorn.plugins.access_control import AccessControlPlugin
from foghorn.plugins.base import PluginContext


def test_access_control_init_default_allow(tmp_path):
    """
    Brief: Verify AccessControlPlugin initializes with default allow.

    Inputs:
      - config: empty or minimal configuration

    Outputs:
      - None: Asserts default is 'allow'
    """
    plugin = AccessControlPlugin()
    plugin.setup()
    assert plugin.default == "allow"


def test_access_control_init_default_deny(tmp_path):
    """
    Brief: Verify AccessControlPlugin initializes with default deny.

    Inputs:
      - config: default set to 'deny'

    Outputs:
      - None: Asserts default is 'deny'
    """
    plugin = AccessControlPlugin(default="deny")
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
    plugin = AccessControlPlugin(allow=["192.168.1.0/24", "10.0.0.0/8"])
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
    plugin = AccessControlPlugin(deny=["192.168.1.10/32", "172.16.0.0/12"])
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
    plugin = AccessControlPlugin(default="allow")
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")
    decision = plugin.pre_resolve("example.com", 1, b"", ctx)
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
    plugin = AccessControlPlugin(default="deny")
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")
    decision = plugin.pre_resolve("example.com", 1, b"", ctx)
    assert decision.action == "deny"


def test_access_control_allow_rule_matches(tmp_path):
    """
    Brief: Verify matching allow rule permits query.

    Inputs:
      - config: default='deny', allow=['192.168.1.0/24']
      - client_ip: IP in allowed range

    Outputs:
      - None: Asserts None returned (allow)
    """
    plugin = AccessControlPlugin(default="deny", allow=["192.168.1.0/24"])
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
    plugin = AccessControlPlugin(default="allow", deny=["192.168.1.10"])
    plugin.setup()
    ctx = PluginContext(client_ip="192.168.1.10")
    decision = plugin.pre_resolve("example.com", 1, b"", ctx)
    assert decision is not None
    assert decision.action == "deny"


def test_access_control_deny_takes_precedence(tmp_path):
    """
    Brief: Verify deny rules take precedence over allow rules.

    Inputs:
      - config: allow=['192.168.1.0/24'], deny=['192.168.1.10']
      - client_ip: IP in both allow and deny ranges

    Outputs:
      - None: Asserts decision to deny
    """
    plugin = AccessControlPlugin(
        default="allow", allow=["192.168.1.0/24"], deny=["192.168.1.10"]
    )
    plugin.setup()
    ctx = PluginContext(client_ip="192.168.1.10")
    decision = plugin.pre_resolve("example.com", 1, b"", ctx)
    assert decision is not None
    assert decision.action == "deny"


def test_access_control_ipv6_support(tmp_path):
    """
    Brief: Verify IPv6 addresses work in ACL.

    Inputs:
      - config: allow=['2001:db8::/32']
      - client_ip: IPv6 address

    Outputs:
      - None: Asserts IPv6 processed correctly
    """
    plugin = AccessControlPlugin(default="deny", allow=["2001:db8::/32"])
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
    plugin = AccessControlPlugin(default="allow", deny=["10.0.0.1"])
    plugin.setup()
    ctx = PluginContext(client_ip="10.0.0.1")
    decision = plugin.pre_resolve("example.com", 1, b"", ctx)
    assert decision is not None
    assert decision.action == "deny"


def test_access_control_no_rules_default_allow(tmp_path):
    """
    Brief: Verify default allow with no rules allows all.

    Inputs:
      - config: default='allow', no rules
      - client_ip: any IP

    Outputs:
      - None: Asserts decision to allow
    """
    plugin = AccessControlPlugin(default="allow")
    plugin.setup()
    ctx = PluginContext(client_ip="203.0.113.1")
    decision = plugin.pre_resolve("example.com", 1, b"", ctx)
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
    plugin = AccessControlPlugin(default="deny")
    plugin.setup()
    ctx = PluginContext(client_ip="203.0.113.1")
    decision = plugin.pre_resolve("example.com", 1, b"", ctx)
    assert decision.action == "deny"


def test_access_control_respects_baseplugin_targets(tmp_path):
    """Brief: AccessControlPlugin returns None when client is not targeted.

    Inputs:
      - targets: ["10.0.0.0/8"]
      - default: deny

    Outputs:
      - None; asserts pre_resolve returns None instead of deny when the
        client_ip is outside the targets set.
    """
    plugin = AccessControlPlugin(default="deny", targets=["10.0.0.0/8"])
    plugin.setup()
    ctx = PluginContext(client_ip="192.0.2.1")
    decision = plugin.pre_resolve("example.com", 1, b"", ctx)
    assert decision is None
