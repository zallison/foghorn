"""Unit tests for foghorn.security_limits helper functions."""

from __future__ import annotations

import pytest

from foghorn import security_limits


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("", False),
        ("localhost", True),
        (" LOCALHOST ", True),
        ("127.0.0.1", True),
        ("::1", True),
        ("8.8.8.8", False),
        ("not-an-ip", False),
    ],
)
def test_is_loopback_host_branch_coverage(host: str, expected: bool) -> None:
    """Brief: is_loopback_host covers empty, alias, parse-success, and parse-fail paths.

    Inputs:
      - host: Host text to classify.
      - expected: Expected loopback classification.

    Outputs:
      - None; asserts expected loopback outcome.
    """

    assert security_limits.is_loopback_host(host) is expected


def test_clamp_positive_int_valid_value_above_minimum() -> None:
    """Brief: clamp_positive_int returns parsed value when it is already >= minimum.

    Inputs:
      - None.

    Outputs:
      - None; asserts parsed value is returned unchanged.
    """

    assert security_limits.clamp_positive_int("7", default=3, minimum=2) == 7


def test_clamp_positive_int_value_below_minimum_is_clamped() -> None:
    """Brief: clamp_positive_int clamps parsed values below minimum.

    Inputs:
      - None.

    Outputs:
      - None; asserts minimum is returned when value is too small.
    """

    assert security_limits.clamp_positive_int("0", default=9, minimum=2) == 2


def test_clamp_positive_int_parse_error_uses_default() -> None:
    """Brief: clamp_positive_int falls back to default when value parsing fails.

    Inputs:
      - None.

    Outputs:
      - None; asserts default is used on parse errors.
    """

    assert security_limits.clamp_positive_int(object(), default=5, minimum=2) == 5


def test_clamp_positive_int_fallback_default_can_still_be_clamped() -> None:
    """Brief: clamp_positive_int clamps fallback default when it is below minimum.

    Inputs:
      - None.

    Outputs:
      - None; asserts minimum is returned after default fallback.
    """

    assert security_limits.clamp_positive_int("bad", default=1, minimum=3) == 3


def test_clamp_positive_int_raises_when_default_is_not_int_castable() -> None:
    """Brief: clamp_positive_int propagates conversion errors for non-castable default.

    Inputs:
      - None.

    Outputs:
      - None; asserts ValueError is raised for invalid default fallback.
    """

    with pytest.raises(ValueError):
        security_limits.clamp_positive_int("bad", default="nan", minimum=1)  # type: ignore[arg-type]


def test_clamp_positive_int_raises_when_minimum_is_not_int_castable() -> None:
    """Brief: clamp_positive_int propagates conversion errors for non-castable minimum.

    Inputs:
      - None.

    Outputs:
      - None; asserts ValueError is raised for invalid minimum conversion.
    """

    with pytest.raises(ValueError):
        security_limits.clamp_positive_int("2", default=1, minimum="nan")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, 0),
        ("", 0),
        ("abc", 0),
        ("-1", 0),
        ("0", 0),
        (" 42 ", 42),
    ],
)
def test_maybe_parse_content_length_branch_coverage(
    value: str | None, expected: int
) -> None:
    """Brief: maybe_parse_content_length covers none/invalid/non-positive/positive paths.

    Inputs:
      - value: Content-Length header candidate string.
      - expected: Expected normalized integer length.

    Outputs:
      - None; asserts normalized content length result.
    """

    assert security_limits.maybe_parse_content_length(value) == expected
