"""Tests for upstream health profile presets.

Brief:
  Ensure upstreams.health.profile loads knob presets from the built-in
  upstreams_health_profiles.yaml file and that explicit config overrides those
  presets.

Inputs:
  - runtime_config.parse_upstream_health_config()

Outputs:
  - Assertions for profile selection, override precedence, and error handling.
"""

from __future__ import annotations

import pytest

from foghorn.runtime_config import parse_upstream_health_config


def test_parse_upstream_health_config_profile_applies() -> None:
    """Brief: profile presets are applied when upstreams.health.profile is set.

    Inputs:
      - upstream_cfg with health.profile='aggressive'

    Outputs:
      - UpstreamHealthConfig reflects the aggressive preset values.
    """

    cfg = {"health": {"profile": "aggressive"}}
    out = parse_upstream_health_config(cfg)

    assert out.max_serv_fail == 2
    assert out.unknown_after_seconds == 120.0
    assert out.probe_percent == 5.0


def test_parse_upstream_health_config_profile_overrides() -> None:
    """Brief: explicit keys override profile preset values.

    Inputs:
      - upstream_cfg with health.profile='aggressive' and explicit max_serv_fail.

    Outputs:
      - max_serv_fail uses explicit value; other knobs still come from profile.
    """

    cfg = {"health": {"profile": "aggressive", "max_serv_fail": 9}}
    out = parse_upstream_health_config(cfg)

    assert out.max_serv_fail == 9
    assert out.unknown_after_seconds == 120.0


def test_parse_upstream_health_config_unknown_profile_raises() -> None:
    """Brief: unknown upstreams.health.profile raises ValueError.

    Inputs:
      - upstream_cfg with health.profile='nope'

    Outputs:
      - ValueError.
    """

    with pytest.raises(ValueError, match="Unknown upstreams\\.health\\.profile"):
        parse_upstream_health_config({"health": {"profile": "nope"}})
