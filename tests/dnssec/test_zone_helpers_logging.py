"""Tests for foghorn.dnssec.zone_helpers logging redaction.

Brief: Verify warning logs in zone_helpers do not emit secret-bearing values.

Inputs:
  - pytest fixtures (caplog, monkeypatch, tmp_path).

Outputs:
  - Assertions that sensitive values never appear in warning log messages.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from dnslib import QTYPE

from foghorn.dnssec import zone_helpers, zone_signer


def test_normalize_generate_policy_warning_redacts_raw_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Brief: Invalid generate policy warning logs type metadata, not raw values.

    Inputs:
      - caplog: pytest log capture fixture.

    Outputs:
      - Asserts unsupported raw generate values are not logged verbatim.
    """

    secret_value = "dns-update-secret-abc123"

    with caplog.at_level(logging.WARNING, logger=zone_helpers.logger.name):
        normalized = zone_helpers._normalize_generate_policy(
            secret_value,
            log=zone_helpers.logger,
        )

    assert normalized == "maybe"
    assert any(
        "unsupported dnssec_signing.generate value" in rec.getMessage()
        for rec in caplog.records
    )
    assert all(secret_value not in rec.getMessage() for rec in caplog.records)


def test_auto_sign_skip_warning_redacts_exception_text(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Brief: Auto-sign skip warning omits exception text that may contain secrets.

    Inputs:
      - caplog: pytest log capture fixture.
      - monkeypatch: pytest monkeypatch fixture.
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts auto-sign skip logs do not include secret-bearing exception text.
    """

    secret_value = "tsig-secret-material"

    def _raise_secret_exception(*_args, **_kwargs) -> object:
        raise RuntimeError(f"failed to load keys: secret={secret_value}")

    monkeypatch.setattr(zone_signer, "ensure_zone_keys", _raise_secret_exception)
    monkeypatch.setattr(
        zone_helpers,
        "_add_nsec3_chain_to_zone",
        lambda *_args, **_kwargs: None,
    )

    mapping = {}
    name_index = {
        "example.com": {
            int(QTYPE.A): (
                300,
                ["192.0.2.1"],
                set(),
            )
        }
    }
    zone_soa = {"example.com": (300, ["unused"], set())}
    dnssec_cfg_raw = {
        "keys_dir": str(tmp_path / "keys"),
        "algorithm": "ECDSAP256SHA256",
        "generate": "yes",
        "validity_days": 7,
    }

    with caplog.at_level(logging.WARNING, logger=zone_helpers.logger.name):
        zone_helpers.auto_sign_zones(
            mapping,
            name_index,
            zone_soa,
            dnssec_cfg_raw,
            log=zone_helpers.logger,
        )

    messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "ZoneRecords DNSSEC auto-sign skipped for example.com" in msg
        for msg in messages
    )
    assert all(secret_value not in msg for msg in messages)
