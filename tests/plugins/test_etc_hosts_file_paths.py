"""
Brief: Tests for multiple file support in EtcHosts plugin (file_paths and file_path).

Inputs:
  - tmp_path: pytest fixture to create temporary files

Outputs:
  - None: assertions on merged host mappings
"""

import importlib


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

    f1 = _write(tmp_path, "f1", "1.1.1.1 hostA\n127.0.0.1 localhost\n")
    f2 = _write(tmp_path, "f2", "2.2.2.2 hostA\n10.0.0.2 hostB\n")

    plugin = EtcHosts(file_paths=[str(f1), str(f2)])
    assert plugin.hosts["hostA"] == "2.2.2.2"  # overridden by later file
    assert plugin.hosts["hostB"] == "10.0.0.2"
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
    assert plugin.hosts["defaultHost"] == "4.4.4.4"
