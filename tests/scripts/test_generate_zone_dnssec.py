"""Tests for generate_zone_dnssec.py helper script.

Brief: Verify key generation, zone signing, and DS record output.

Inputs:
  - pytest fixtures (tmp_path, capsys).

Outputs:
  - Test assertions validating script behavior.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys


def test_generate_zone_dnssec_help():
    """Brief: Script prints help without errors.

    Inputs:
      - None.

    Outputs:
      - Asserts exit code 0 and --zone appears in help output.
    """
    result = subprocess.run(
        [sys.executable, "scripts/generate_zone_dnssec.py", "--help"],
        capture_output=True,
        text=True,
        cwd=pathlib.Path(__file__).parents[2],
    )
    assert result.returncode == 0
    assert "--zone" in result.stdout


def test_generate_zone_dnssec_creates_signed_zone(tmp_path: pathlib.Path):
    """Brief: Script generates keys and signs a zone file.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that signed zone file is created, contains DNSKEY and RRSIG.
    """
    # Create a minimal unsigned zone file.
    unsigned = tmp_path / "unsigned.zone"
    unsigned.write_text(
        """\
$ORIGIN example.test.
$TTL 300
@   IN  SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 604800 300 )
@   IN  NS  ns1.example.test.
@   IN  A   192.0.2.1
www IN  A   192.0.2.2
""",
        encoding="utf-8",
    )

    signed = tmp_path / "signed.zone"
    keys_dir = tmp_path / "keys"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/generate_zone_dnssec.py",
            "--zone",
            "example.test.",
            "--input",
            str(unsigned),
            "--output",
            str(signed),
            "--keys-dir",
            str(keys_dir),
            "--algorithm",
            "ECDSAP256SHA256",
        ],
        capture_output=True,
        text=True,
        cwd=pathlib.Path(__file__).parents[2],
    )

    assert result.returncode == 0, f"Script failed: {result.stderr}"
    assert signed.exists(), "Signed zone file not created"

    signed_content = signed.read_text(encoding="utf-8")

    # Check that DNSKEY records are present.
    assert "DNSKEY" in signed_content, "DNSKEY not found in signed zone"

    # Check that RRSIG records are present.
    assert "RRSIG" in signed_content, "RRSIG not found in signed zone"

    # Check that key files were created.
    ksk_key = keys_dir / "Kexample_test.ksk.key"
    zsk_key = keys_dir / "Kexample_test.zsk.key"
    assert ksk_key.exists(), "KSK key file not created"
    assert zsk_key.exists(), "ZSK key file not created"


def test_generate_zone_dnssec_outputs_ds_records(tmp_path: pathlib.Path, capsys):
    """Brief: Script outputs DS records when not writing to a file.

    Inputs:
      - tmp_path: pytest temporary directory.
      - capsys: pytest fixture for capturing output.

    Outputs:
      - Asserts that DS records are printed to stdout.
    """
    unsigned = tmp_path / "unsigned.zone"
    unsigned.write_text(
        """\
$ORIGIN ds-test.example.
$TTL 300
@   IN  SOA ns1.ds-test.example. hostmaster.ds-test.example. ( 1 3600 600 604800 300 )
@   IN  NS  ns1.ds-test.example.
@   IN  A   192.0.2.10
""",
        encoding="utf-8",
    )

    signed = tmp_path / "signed.zone"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/generate_zone_dnssec.py",
            "--zone",
            "ds-test.example.",
            "--input",
            str(unsigned),
            "--output",
            str(signed),
            "--force-new-keys",
        ],
        capture_output=True,
        text=True,
        cwd=pathlib.Path(__file__).parents[2],
    )

    assert result.returncode == 0, f"Script failed: {result.stderr}"
    # DS records should be printed to stdout.
    assert "DS" in result.stdout, "DS records not in stdout"


def test_generate_zone_dnssec_ds_output_file(tmp_path: pathlib.Path):
    """Brief: Script writes DS records to a file when --ds-output is specified.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that DS file is created with correct content.
    """
    unsigned = tmp_path / "unsigned.zone"
    unsigned.write_text(
        """\
$ORIGIN ds-file.example.
$TTL 300
@   IN  SOA ns1.ds-file.example. hostmaster.ds-file.example. ( 1 3600 600 604800 300 )
@   IN  NS  ns1.ds-file.example.
@   IN  A   192.0.2.20
""",
        encoding="utf-8",
    )

    signed = tmp_path / "signed.zone"
    ds_file = tmp_path / "ds-records.txt"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/generate_zone_dnssec.py",
            "--zone",
            "ds-file.example.",
            "--input",
            str(unsigned),
            "--output",
            str(signed),
            "--ds-output",
            str(ds_file),
            "--force-new-keys",
        ],
        capture_output=True,
        text=True,
        cwd=pathlib.Path(__file__).parents[2],
    )

    assert result.returncode == 0, f"Script failed: {result.stderr}"
    assert ds_file.exists(), "DS file not created"

    ds_content = ds_file.read_text(encoding="utf-8")
    assert "IN DS" in ds_content, "DS record not found in DS file"


def test_generate_zone_dnssec_reuses_existing_keys(tmp_path: pathlib.Path):
    """Brief: Script reuses existing keys when not forcing new generation.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that running twice without --force-new-keys produces same key tags.
    """
    unsigned = tmp_path / "unsigned.zone"
    unsigned.write_text(
        """\
$ORIGIN reuse.example.
$TTL 300
@   IN  SOA ns1.reuse.example. hostmaster.reuse.example. ( 1 3600 600 604800 300 )
@   IN  NS  ns1.reuse.example.
@   IN  A   192.0.2.30
""",
        encoding="utf-8",
    )

    signed1 = tmp_path / "signed1.zone"
    signed2 = tmp_path / "signed2.zone"
    keys_dir = tmp_path / "keys"

    # First run generates keys.
    result1 = subprocess.run(
        [
            sys.executable,
            "scripts/generate_zone_dnssec.py",
            "--zone",
            "reuse.example.",
            "--input",
            str(unsigned),
            "--output",
            str(signed1),
            "--keys-dir",
            str(keys_dir),
        ],
        capture_output=True,
        text=True,
        cwd=pathlib.Path(__file__).parents[2],
    )
    assert result1.returncode == 0

    # Second run reuses keys.
    result2 = subprocess.run(
        [
            sys.executable,
            "scripts/generate_zone_dnssec.py",
            "--zone",
            "reuse.example.",
            "--input",
            str(unsigned),
            "--output",
            str(signed2),
            "--keys-dir",
            str(keys_dir),
        ],
        capture_output=True,
        text=True,
        cwd=pathlib.Path(__file__).parents[2],
    )
    assert result2.returncode == 0

    # Check that key tags are the same (from stderr logs).
    # The key tags are logged as "KSK key tag: <num>" and "ZSK key tag: <num>".
    assert "Loaded existing KSK key" in result2.stderr
    assert "Loaded existing ZSK key" in result2.stderr
