"""
Brief: IPv4/IPv6 mismatch behavior tests for EtcHosts plugin.

Inputs:
  - None

Outputs:
  - None
"""

import importlib
from dnslib import DNSRecord, QTYPE
from foghorn.plugins.base import PluginContext


def test_etc_hosts_ipv4_entry_does_not_answer_aaaa(tmp_path):
    """
    Brief: When hosts file maps to IPv4, AAAA queries are not overridden.

    Inputs:
      - hosts file with IPv4 only

    Outputs:
      - None: Asserts pre_resolve returns None for AAAA
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("192.0.2.10 v4only.local\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    q = DNSRecord.question("v4only.local", "AAAA")
    decision = plugin.pre_resolve("v4only.local", QTYPE.AAAA, q.pack(), ctx)
    assert decision is None


def test_etc_hosts_ipv6_entry_does_not_answer_a(tmp_path):
    """
    Brief: When hosts file maps to IPv6, A queries are not overridden.

    Inputs:
      - hosts file with IPv6 only

    Outputs:
      - None: Asserts pre_resolve returns None for A
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("2001:db8::1 v6only.local\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    q = DNSRecord.question("v6only.local", "A")
    decision = plugin.pre_resolve("v6only.local", QTYPE.A, q.pack(), ctx)
    assert decision is None
