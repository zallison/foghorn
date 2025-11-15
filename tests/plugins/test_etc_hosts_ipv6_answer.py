"""
Brief: Test EtcHosts returns AAAA answers for IPv6 entries.

Inputs:
  - tmp_path: pytest fixture for temp directory

Outputs:
  - None: asserts override decision with AAAA record matching IPv6 address
"""

import importlib
from dnslib import DNSRecord, QTYPE
from foghorn.plugins.base import PluginContext


def test_etc_hosts_pre_resolve_ipv6_answer(tmp_path):
    """
    Brief: Ensure an IPv6 mapping yields an AAAA override response.

    Inputs:
      - hosts file with IPv6 mapping for a hostname

    Outputs:
      - None: asserts pre_resolve returns override with AAAA RR and correct IPv6

    Example:
      2001:db8::42 v6host.local
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    ipv6 = "2001:db8::42"
    hosts_file.write_text(f"{ipv6} v6host.local\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    q = DNSRecord.question("v6host.local", "AAAA")
    decision = plugin.pre_resolve("v6host.local", QTYPE.AAAA, q.pack(), ctx)

    assert decision is not None and decision.action == "override"
    assert decision.response is not None

    resp = DNSRecord.parse(decision.response)
    # One or more answers; verify first is AAAA with expected address
    assert any(rr.rtype == QTYPE.AAAA for rr in resp.rr)
    assert any(str(rr.rdata) == ipv6 for rr in resp.rr if rr.rtype == QTYPE.AAAA)
