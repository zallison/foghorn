"""
Brief: Tests for multiple file support in EtcHosts plugin (file_paths and file_path).

Inputs:
  - tmp_path: pytest fixture to create temporary files

Outputs:
  - None: assertions on merged host mappings
"""

import importlib

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.base import PluginContext


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


def test_init_with_file_paths_only_merges_in_order(tmp_path):
    """
    Brief: file_paths alone loads files in order; later overrides earlier.

    Inputs:
      - file_paths: [f1, f2]
    Outputs:
      - None: asserts that entries from f2 override f1 on conflicts

    Example:
      f1: 1.1.1.1 hostA
      f2: 2.2.2.2 hostA
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    f1 = _write(tmp_path, "f1", "1.1.1.1 hostA\n127.0.0.1 localhost\n1.1.2.2 hostC\n")
    f2 = _write(tmp_path, "f2", "2.2.2.2 hostA\n10.0.0.2 hostB\n")

    plugin = EtcHosts(file_paths=[str(f1), str(f2)])
    plugin.setup()
    assert plugin.hosts["hostA"] == "2.2.2.2"  # overridden by later file
    assert plugin.hosts["hostB"] == "10.0.0.2"
    assert plugin.hosts["hostC"] == "1.1.2.2"
    assert plugin.hosts["localhost"] == "127.0.0.1"


def test_both_params_with_redundant_legacy_deduplicates(tmp_path):
    """
    Brief: When file_path duplicates an entry in file_paths, it is de-duplicated; order preserved.

    Inputs:
      - file_paths: [f1, f2]; file_path: f1 (redundant)
    Outputs:
      - None: f2 still overrides f1 for conflicting hostnames

    Example:
      f1: 1.1.1.1 hostA
      f2: 2.2.2.2 hostA
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    f1 = _write(tmp_path, "f1", "1.1.1.1 hostA\n")
    f2 = _write(tmp_path, "f2", "2.2.2.2 hostA\n")

    plugin = EtcHosts(file_paths=[str(f1), str(f2)], file_path=str(f1))
    plugin.setup()
    # Expect f2 to override since effective order remains [f1, f2]
    assert plugin.hosts["hostA"] == "2.2.2.2"


def test_both_params_with_nonredundant_legacy_appends_last(tmp_path):
    """
    Brief: When both are provided and legacy is distinct, legacy is included last and overrides earlier files.

    Inputs:
      - file_paths: [f1]; file_path: f2 (distinct)
    Outputs:
      - None: legacy f2 overrides entries from f1

    Example:
      f1: 1.1.1.1 hostA
      f2: 3.3.3.3 hostA
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    f1 = _write(tmp_path, "f1", "1.1.1.1 hostA\n10.0.0.2 hostB\n")
    f2 = _write(tmp_path, "f2", "3.3.3.3 hostA\n")

    plugin = EtcHosts(file_paths=[str(f1)], file_path=str(f2))
    plugin.setup()
    # Legacy path appended last should override hostA
    assert plugin.hosts["hostA"] == "3.3.3.3"
    # Non-conflicting entry from f1 remains
    assert plugin.hosts["hostB"] == "10.0.0.2"


def test_no_input_uses_default_via_monkeypatched_normalize(tmp_path, monkeypatch):
    """
    Brief: With no inputs, default path would be /etc/hosts; we monkeypatch normalization to point to a tmp file to test parsing.

    Inputs:
      - None (no file_paths or file_path provided)
    Outputs:
      - None: asserts entries are loaded from the monkeypatched default path

    Example:
      default -> tmp file with 4.4.4.4 defaultHost
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    default_hosts = _write(tmp_path, "default", "4.4.4.4 defaultHost\n")

    def _fake_normalize(self, file_paths, legacy):
        return [str(default_hosts)]

    monkeypatch.setattr(EtcHosts, "_normalize_paths", _fake_normalize)

    plugin = EtcHosts()  # no inputs -> uses monkeypatched default
    plugin.setup()
    assert plugin.hosts["defaultHost"] == "4.4.4.4"


def test_pre_resolve_with_multiple_files_uses_last_override(tmp_path):
    """\
    Brief: pre_resolve honours merged hosts from multiple files, using the last file on conflicts.

    Inputs:
      - tmp_path: pytest-provided temporary directory for constructing two hosts files.

    Outputs:
      - None: asserts that the A record answer resolves to the IP from the later file.

    Example:
      f1: 1.1.1.1 multi.local
      f2: 2.2.2.2 multi.local
    """
    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    f1 = _write(tmp_path, "f1", "1.1.1.1 multi.local\n")
    f2 = _write(tmp_path, "f2", "2.2.2.2 multi.local\n")

    plugin = EtcHosts(file_paths=[str(f1), str(f2)], watchdog_enabled=False)
    plugin.setup()

    # Sanity check: mapping should already reflect the override from f2.
    assert plugin.hosts["multi.local"] == "2.2.2.2"

    ctx = PluginContext(client_ip="127.0.0.1")
    query = DNSRecord.question("multi.local", "A")

    decision = plugin.pre_resolve("multi.local", QTYPE.A, query.pack(), ctx)
    assert decision is not None
    assert decision.action == "override"
    assert decision.response is not None
