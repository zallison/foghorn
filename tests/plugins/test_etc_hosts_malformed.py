"""
Brief: Test _load_hosts raises ValueError on malformed hosts line with only IP.

Inputs:
  - tmp_path: pytest fixture for temp directory

Outputs:
  - None: asserts ValueError is raised during plugin initialization
"""

import importlib
import pytest


def test_etc_hosts_load_hosts_malformed_single_entry_with_comment(tmp_path):
    """
    Brief: Ensure _load_hosts raises ValueError when a line has an IP but no hostname.

    Inputs:
      - hosts file where the second line lacks a hostname (only IP then comment)

    Outputs:
      - None: asserts ValueError is raised when initializing EtcHosts

    Example:
      127.0.0.1 home
      192.168.88.3       # <-- invalid
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 home\n192.168.88.3       # <-- invalid\n")

    with pytest.raises(ValueError):
        plugin = EtcHosts(file_path=str(hosts_file))
        plugin.setup()
