"""Unit tests for foghorn.utils.human_units and config model coercion."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from foghorn.config.models.server import (
    HttpApiRequestAuditConfig,
    ListenerUdp,
    TsigFeatureConfig,
)
from foghorn.utils.human_units import (
    parse_bytes,
    parse_duration_seconds,
    parse_duration_seconds_int,
)


def test_parse_bytes_si_and_iec() -> None:
    """Brief: SI uses 1000; IEC (MiB) uses 1024.

    Inputs:
      - None.

    Outputs:
      - Asserts parse_bytes for bare numbers and unit strings.
    """

    assert parse_bytes(4096) == 4096
    assert parse_bytes("4096") == 4096
    assert parse_bytes("4k") == 4000
    assert parse_bytes("4KB") == 4000
    assert parse_bytes("4M") == 4_000_000
    assert parse_bytes("4MB") == 4_000_000
    assert parse_bytes("256kb") == 256_000
    assert parse_bytes("4MiB") == 4 * 1024 * 1024
    assert parse_bytes("1GiB") == 1024**3
    assert parse_bytes("1.5kB") == 1500


def test_parse_bytes_rejects_bad() -> None:
    """Brief: Invalid byte sizes raise.

    Inputs:
      - None.

    Outputs:
      - Asserts TypeError/ValueError on bad inputs.
    """

    with pytest.raises(ValueError):
        parse_bytes("-1")
    with pytest.raises(ValueError):
        parse_bytes("12XB")
    with pytest.raises(TypeError):
        parse_bytes(True)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        parse_bytes("")


def test_parse_duration_tokens_and_clock() -> None:
    """Brief: Duration tokens and H:MM:SS elapsed forms.

    Inputs:
      - None.

    Outputs:
      - Asserts seconds for mixed human forms.
    """

    assert parse_duration_seconds(15) == 15.0
    assert parse_duration_seconds("90") == 90.0
    assert parse_duration_seconds("500ms") == pytest.approx(0.5)
    assert parse_duration_seconds("1h30m") == 5400.0
    assert parse_duration_seconds("2 days") == 2 * 86400.0
    assert parse_duration_seconds("1 hour and 30 minutes") == 5400.0
    assert parse_duration_seconds("12:00:00") == 12 * 3600.0
    assert parse_duration_seconds("01:30:00") == 5400.0
    assert parse_duration_seconds("90:00") == 90 * 60.0  # MM:SS
    assert parse_duration_seconds_int("1.4s") == 1
    assert parse_duration_seconds_int("1.5s") == 2


def test_parse_duration_rejects_bad() -> None:
    """Brief: Invalid durations raise.

    Inputs:
      - None.

    Outputs:
      - Asserts errors for empty, unknown unit, bad clock.
    """

    with pytest.raises(ValueError):
        parse_duration_seconds("")
    with pytest.raises(ValueError):
        parse_duration_seconds("1 fortnight")
    with pytest.raises(ValueError):
        parse_duration_seconds("1:60:00")
    with pytest.raises(ValueError):
        parse_duration_seconds("-5")


def test_model_fields_accept_human_strings() -> None:
    """Brief: Core model fields coerce size/duration strings.

    Inputs:
      - None.

    Outputs:
      - Asserts ListenerUdp / audit / TSIG fields normalize units.
    """

    udp = ListenerUdp(max_query_bytes="4KiB", max_response_bytes="1M")
    assert udp.max_query_bytes == 4096
    assert udp.max_response_bytes == 1_000_000

    audit = HttpApiRequestAuditConfig(
        retention_max_db_bytes="128MB",
        retention_max_age_seconds="365 days",
    )
    assert audit.retention_max_db_bytes == 128_000_000
    assert audit.retention_max_age_seconds == 365 * 86400.0

    tsig = TsigFeatureConfig(max_fudge_seconds="5m")
    assert tsig.max_fudge_seconds == 300


def test_coerce_config_human_units_tree() -> None:
    """Brief: Tree walker normalizes plugin config leaves by key suffix.

    Inputs:
      - None.

    Outputs:
      - Asserts nested *_bytes/*_seconds/*_ms coercion; vars left alone.
    """

    from foghorn.utils.human_units import coerce_config_human_units

    cfg = {
        "variables": {"HOLD": "2 days"},
        "plugins": [
            {
                "type": "rate",
                "config": {
                    "window_seconds": "1m",
                    "targets_cache_ttl_seconds": "30s",
                    "max_bytes": "2MiB",
                    "timeout_ms": "1.5s",
                    "rate_limit_per_client_per_second": 12.5,
                },
            }
        ],
        "server": {
            "axfr": {"max_transfer_rate_bytes_per_second": "1M"},
        },
    }
    coerce_config_human_units(cfg)
    assert cfg["variables"]["HOLD"] == "2 days"
    plug = cfg["plugins"][0]["config"]
    assert plug["window_seconds"] == 60.0
    assert plug["targets_cache_ttl_seconds"] == 30.0
    assert plug["max_bytes"] == 2 * 1024 * 1024
    assert plug["timeout_ms"] == 1500
    # Not a unit key ending in _seconds/_bytes:
    assert plug["rate_limit_per_client_per_second"] == 12.5
    assert cfg["server"]["axfr"]["max_transfer_rate_bytes_per_second"] == 1_000_000


def test_model_fields_still_reject_constraint_violations() -> None:
    """Brief: Constraints apply after human coercion.

    Inputs:
      - None.

    Outputs:
      - Asserts ValidationError when coerced value is out of range.
    """

    with pytest.raises(ValidationError):
        ListenerUdp(max_query_bytes="1B")  # ge=12
