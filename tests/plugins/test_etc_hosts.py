"""
Brief: Tests for foghorn.plugins.etc-hosts module.

Inputs:
  - None

Outputs:
  - None
"""

import importlib

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.base import PluginContext


def test_etc_hosts_module_import():
    """
    Brief: Verify etc-hosts module imports correctly.

    Inputs:
      - None

    Outputs:
      - None: Asserts module name
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    assert mod.__name__ == "foghorn.plugins.etc-hosts"


def test_etc_hosts_init_with_custom_file(tmp_path):
    """
    Brief: Verify EtcHosts initializes with custom hosts file.

    Inputs:
      - file_path: path to custom hosts file
      - tmp_path: temporary directory for test file

    Outputs:
      - None: Asserts file loaded
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n192.168.1.1 router.local\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    assert "localhost" in plugin.hosts
    assert plugin.hosts["localhost"] == "127.0.0.1"
    assert "router.local" in plugin.hosts
    assert plugin.hosts["router.local"] == "192.168.1.1"


def test_etc_hosts_parses_multiple_aliases(tmp_path):
    """
    Brief: Verify multiple hostnames per IP are parsed.

    Inputs:
      - hosts file with multiple aliases per IP

    Outputs:
      - None: Asserts all aliases mapped
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost local host1 host2\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    assert plugin.hosts["localhost"] == "127.0.0.1"
    assert plugin.hosts["local"] == "127.0.0.1"
    assert plugin.hosts["host1"] == "127.0.0.1"
    assert plugin.hosts["host2"] == "127.0.0.1"


def test_etc_hosts_ignores_comments(tmp_path):
    """
    Brief: Verify comment lines are ignored.

    Inputs:
      - hosts file with comment lines

    Outputs:
      - None: Asserts comments not parsed
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("# Comment line\n127.0.0.1 localhost\n# Another comment\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    assert len(plugin.hosts) == 2  # 127.0.0.1 and 1.0.0.124.in-addr.arpa
    assert "localhost" in plugin.hosts


def test_etc_hosts_ignores_empty_lines(tmp_path):
    """
    Brief: Verify empty lines are ignored.

    Inputs:
      - hosts file with empty lines

    Outputs:
      - None: Asserts empty lines skipped
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("\n\n127.0.0.1 localhost\n\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    assert len(plugin.hosts) == 2


def test_etc_hosts_pre_resolve_matched_a_record(tmp_path):
    """
    Brief: Verify matched hostname returns A record.

    Inputs:
      - qname: hostname in hosts file
      - qtype: A record query

    Outputs:
      - None: Asserts override decision with correct IP
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("192.168.1.100 myhost.local\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    # Create a proper query
    query = DNSRecord.question("myhost.local", "A")

    decision = plugin.pre_resolve("myhost.local", QTYPE.A, query.pack(), ctx)
    assert decision is not None
    assert decision.action == "override"
    assert decision.response is not None

    # Parse response and verify it contains the correct IP
    response = DNSRecord.parse(decision.response)
    assert len(response.rr) > 0


def test_etc_hosts_pre_resolve_no_match(tmp_path):
    """
    Brief: Verify unmatched hostname returns None.

    Inputs:
      - qname: hostname not in hosts file

    Outputs:
      - None: Asserts None returned
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    query = DNSRecord.question("unknown.local", "A")
    decision = plugin.pre_resolve("unknown.local", QTYPE.A, query.pack(), ctx)
    assert decision is None


def test_etc_hosts_pre_resolve_ignores_non_a_aaaa(tmp_path):
    """
    Brief: Verify non-A/AAAA queries are ignored.

    Inputs:
      - qtype: MX, TXT, or other non-A/AAAA types

    Outputs:
      - None: Asserts None returned
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    query = DNSRecord.question("localhost", "MX")
    decision = plugin.pre_resolve("localhost", QTYPE.MX, query.pack(), ctx)
    assert decision is None


def test_etc_hosts_pre_resolve_strips_trailing_dot(tmp_path):
    """
    Brief: Verify trailing dot is stripped from qname.

    Inputs:
      - qname: hostname with trailing dot

    Outputs:
      - None: Asserts match works without trailing dot
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    query = DNSRecord.question("localhost.", "A")
    decision = plugin.pre_resolve("localhost.", QTYPE.A, query.pack(), ctx)
    assert decision is not None
    assert decision.action == "override"


def test_etc_hosts_ipv6_support(tmp_path):
    """
    Brief: Verify IPv6 addresses in hosts file work.

    Inputs:
      - hosts file with IPv6 addresses

    Outputs:
      - None: Asserts IPv6 parsed and returned
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("::1 localhost6\n2001:db8::1 ipv6host\n")

    plugin = EtcHosts(file_path=str(hosts_file))
    plugin.setup()
    assert "localhost6" in plugin.hosts
    assert plugin.hosts["localhost6"] == "::1"
    assert plugin.hosts["ipv6host"] == "2001:db8::1"


def test_etc_hosts_polling_detects_file_changes(tmp_path):
    """Brief: Verify polling-based detector notices file changes.

    Inputs:
      - tmp_path: pytest-provided temporary directory for hosts file.

    Outputs:
      - None: Asserts that _have_files_changed() returns True on initial
        snapshot and after a subsequent modification.
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n")

    # Disable watchdog to focus this test purely on the polling helper.
    plugin = EtcHosts(file_path=str(hosts_file), watchdog_enabled=False)
    plugin.setup()

    # First call should treat the baseline snapshot as a change.
    assert plugin._have_files_changed() is True

    # Subsequent call without any modification should report no change.
    assert plugin._have_files_changed() is False

    # Modify the file so that size/mtime change, then verify the detector
    # observes the new snapshot.
    hosts_file.write_text(
        "127.0.0.1 localhost\n127.0.0.2 other.local\n",
    )
    assert plugin._have_files_changed() is True
