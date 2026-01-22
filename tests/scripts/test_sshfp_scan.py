"""Tests for the sshfp_scan CLI wrapper.

Inputs:
  - None directly; uses monkeypatch and capsys fixtures from pytest.

Outputs:
  - Verifies that multiple targets (hostnames, IPs, and CIDRs) are expanded
    correctly and passed to ssh_keyscan.collect_sshfp_records.
"""

from __future__ import annotations

from typing import List

import pytest

import importlib.util
import pathlib
import sys

# Load the sshfp_scan script as a module so we can call main() directly
_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[2] / "scripts"
_SSHFP_SCAN_PATH = _SCRIPTS_DIR / "sshfp_scan.py"

_spec = importlib.util.spec_from_file_location("sshfp_scan", _SSHFP_SCAN_PATH)
assert _spec is not None and _spec.loader is not None
_sshfp_scan = importlib.util.module_from_spec(_spec)
sys.modules["sshfp_scan"] = _sshfp_scan
_spec.loader.exec_module(_sshfp_scan)

sshfp_scan = _sshfp_scan


class DummyResult:
    """Brief: Tiny helper to capture calls for assertions.

    Inputs:
      - hosts: List[str] of hostnames/IPs that were scanned.

    Outputs:
      - Object with ``hosts`` attribute for inspection in tests.
    """

    def __init__(self, hosts: List[str]) -> None:
        self.hosts = hosts


def test_multiple_targets_and_cidrs_are_expanded(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Ensure CLI expands CIDRs and calls collect_sshfp_records per host.

    This test passes multiple targets, including a CIDR, and verifies that
    ``collect_sshfp_records`` is invoked for each expanded host in order.
    """

    called_hosts: List[str] = []

    def fake_collect_sshfp_records(*, hostname: str, port: int, timeout: float):  # type: ignore[override]
        called_hosts.append(hostname)
        # Return a predictable record to prove we printed something.
        return [f"{hostname} IN SSHFP 1 1 deadbeef"]

    # Monkeypatch the util function used by the CLI.
    monkeypatch.setattr(
        sshfp_scan.ssh_keyscan, "collect_sshfp_records", fake_collect_sshfp_records
    )

    # 192.0.2.0/30 yields usable hosts 192.0.2.1 and 192.0.2.2
    argv = [
        "host1.example",  # hostname
        "192.0.2.10",  # single IP
        "192.0.2.0/30",  # CIDR (two usable hosts)
    ]

    exit_code = sshfp_scan.main(argv)
    captured = capsys.readouterr()

    assert exit_code == 0

    # We expect host1.example, 192.0.2.10, 192.0.2.1, 192.0.2.2 in this order.
    assert called_hosts == [
        "host1.example",
        "192.0.2.10",
        "192.0.2.1",
        "192.0.2.2",
    ]

    # And at least one SSHFP line per host was printed.
    for host in called_hosts:
        assert f"{host} IN SSHFP" in captured.out


def test_zone_format_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Brief: --zone-record-format emits pipe-delimited SSHFP records for ZoneRecords.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - capsys: pytest capture fixture.

    Outputs:
      - Asserts that when --zone-record-format is set, output lines follow
        "<domain>|SSHFP|<ttl>|<alg> <fptype> <fingerprint>" for each record.
    """

    def fake_collect_sshfp_records(*, hostname: str, port: int, timeout: float):  # type: ignore[override]
        assert hostname == "host1.example"
        return ["host1.example IN SSHFP 1 1 deadbeef"]

    monkeypatch.setattr(
        sshfp_scan.ssh_keyscan, "collect_sshfp_records", fake_collect_sshfp_records
    )

    argv = [
        "--zone-record-format",
        "--zone-ttl",
        "600",
        "host1.example",
    ]

    exit_code = sshfp_scan.main(argv)
    captured = capsys.readouterr()

    assert exit_code == 0
    # Domain should be normalized to lower-case without trailing dot, TTL from
    # --zone-ttl, and value as "alg fptype fingerprint".
    assert captured.out.strip() == "host1.example|SSHFP|600|1 1 deadbeef"
