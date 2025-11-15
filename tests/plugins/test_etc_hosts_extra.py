"""
Brief: Extra tests for EtcHosts plugin edge cases and response correctness.

Inputs:
  - None

Outputs:
  - None
"""

import importlib
from dnslib import DNSRecord, QTYPE
from foghorn.plugins.base import PluginContext


def test_pre_resolve_override_response_id_matches(tmp_path):
    """
    Brief: Override response preserves the original query transaction ID.

    Inputs:
      - hosts file with a single mapping; A query

    Outputs:
      - None: asserts response header.id equals request header.id
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("10.0.0.1 example.local\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    q = DNSRecord.question("example.local", "A")
    req_wire = q.pack()
    decision = plugin.pre_resolve("example.local", QTYPE.A, req_wire, ctx)
    assert decision is not None and decision.response is not None

    resp = DNSRecord.parse(decision.response)
    assert resp.header.id == q.header.id


def test_pre_resolve_parse_failure_returns_override_with_none_response(tmp_path):
    """
    Brief: When request wire cannot be parsed, override response is None.

    Inputs:
      - invalid raw request bytes with matching hostname

    Outputs:
      - None: asserts override decision with response is None
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("192.0.2.1 broken.local\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    decision = plugin.pre_resolve("broken.local", QTYPE.A, b"not-a-dns-wire", ctx)
    assert decision is not None
    assert decision.action == "override"
    assert decision.response is None
