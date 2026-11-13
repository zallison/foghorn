"""Brief: Tests for scripts/generate_dns_update_keys.py (TSIG-only).

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import base64
import importlib.util
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "generate_dns_update_keys.py"


def _load_script_module():
    """Brief: Load generate_dns_update_keys as a module.

    Inputs:
      - None

    Outputs:
      - Loaded module object.
    """

    spec = importlib.util.spec_from_file_location("generate_dns_update_keys", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_generate_tsig_secret_lengths() -> None:
    """Brief: TSIG secrets match expected raw key lengths per algorithm.

    Inputs:
      - None

    Outputs:
      - None; asserts decoded secret byte lengths.
    """

    mod = _load_script_module()
    assert len(base64.b64decode(mod.generate_tsig_secret("hmac-md5"))) == 16
    assert len(base64.b64decode(mod.generate_tsig_secret("hmac-sha256"))) == 32
    assert len(base64.b64decode(mod.generate_tsig_secret("hmac-sha512"))) == 64


def test_cli_tsig_prints_secret() -> None:
    """Brief: --tsig prints a TSIG secret when --name is provided.

    Inputs:
      - None

    Outputs:
      - None; asserts exit 0 and TSIG Secret line on stdout.
    """

    proc = subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            "--tsig",
            "--name",
            "key.example.com",
            "--algorithm",
            "hmac-sha256",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "TSIG Secret (hmac-sha256):" in proc.stdout
    secret = proc.stdout.split(":", 1)[1].strip()
    assert len(base64.b64decode(secret)) == 32


def test_cli_tsig_config_snippet() -> None:
    """Brief: --tsig --config-snippet emits YAML with tsig keys.

    Inputs:
      - None

    Outputs:
      - None; asserts exit 0 and tsig snippet fields.
    """

    proc = subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            "--tsig",
            "--name",
            "key.example.com",
            "--config-snippet",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "tsig:" in proc.stdout
    assert 'name: "key.example.com"' in proc.stdout
    assert "secret:" in proc.stdout
    assert "psk:" not in proc.stdout


def test_cli_psk_hard_errors_tsig_only() -> None:
    """Brief: --psk exits non-zero with a clear TSIG-only message.

    Inputs:
      - None

    Outputs:
      - None; asserts exit 2 and TSIG-only error on stderr.
    """

    proc = subprocess.run(
        [sys.executable, str(_SCRIPT), "--psk"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "TSIG-only" in proc.stderr
    assert "not supported" in proc.stderr.lower()
    assert proc.stdout == ""


def test_cli_psk_with_config_snippet_still_errors() -> None:
    """Brief: --psk --config-snippet still hard-errors (no PSK output).

    Inputs:
      - None

    Outputs:
      - None; asserts non-zero exit and no PSK token on stdout.
    """

    proc = subprocess.run(
        [sys.executable, str(_SCRIPT), "--psk", "--config-snippet"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "PSK Token" not in proc.stdout
    assert "PSK Token" not in proc.stderr
    assert "TSIG-only" in proc.stderr


def test_make_gen_psk_token_hard_errors() -> None:
    """Brief: make gen-psk-token exits non-zero with TSIG-only guidance.

    Inputs:
      - None

    Outputs:
      - None; asserts make target fails closed.
    """

    proc = subprocess.run(
        ["make", "-C", str(_REPO_ROOT), "gen-psk-token"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    combined = (proc.stdout or "") + (proc.stderr or "")
    assert "TSIG-only" in combined or "gen-tsig-key" in combined
    assert "not supported" in combined.lower()
