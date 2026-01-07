"""
Brief: Tests for BaseStatsStore helper functions and config model.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

import pytest

from foghorn.plugins.querylog.base import (
    BaseStatsStore,
    StatsStoreBackendConfig,
)


def test_stats_store_backend_config_normalization() -> None:
    """Brief: StatsStoreBackendConfig normalizes name, backend, and config.

    Inputs:
      - None.

    Outputs:
      - None; asserts defaults and extra config fields are preserved.
    """

    cfg = StatsStoreBackendConfig(backend="sqlite", config={"db_path": ":memory:"})
    assert cfg.backend == "sqlite"
    assert cfg.name is None
    assert cfg.config["db_path"] == ":memory:"

    # Extra top-level fields are allowed and preserved.
    cfg2 = StatsStoreBackendConfig(backend="mysql", config={}, extra_field="x")
    assert getattr(cfg2, "extra_field") == "x"


@pytest.mark.parametrize(
    "page,page_size,expected_page,expected_size",
    [
        (1, 10, 1, 10),
        ("2", "5", 2, 5),
        ("bad", "also-bad", 1, 100),
        (0, 0, 1, 100),
    ],
)
def test_normalize_page_args_basic(
    page: object, page_size: object, expected_page: int, expected_size: int
) -> None:
    """Brief: _normalize_page_args clamps invalid values and enforces bounds.

    Inputs:
      - page: Raw page value under test.
      - page_size: Raw page_size value under test.

    Outputs:
      - None; asserts the normalized (page, page_size) pair.
    """

    page_i, size_i = BaseStatsStore._normalize_page_args(page, page_size)
    assert page_i == expected_page
    assert size_i == expected_size


def test_normalize_page_args_custom_defaults_and_max() -> None:
    """Brief: _normalize_page_args honors custom defaults and max_page_size.

    Inputs:
      - None.

    Outputs:
      - None; asserts fallback defaults and max_page_size clamping.
    """

    # Parsing failure falls back to provided defaults.
    page_i, size_i = BaseStatsStore._normalize_page_args(
        page="bad",
        page_size="also-bad",
        default_page=3,
        default_page_size=50,
        max_page_size=200,
    )
    assert page_i == 3
    assert size_i == 50

    # Oversized page_size is clamped to max_page_size.
    _, size_i2 = BaseStatsStore._normalize_page_args(
        page=1,
        page_size=10000,
        default_page=1,
        default_page_size=100,
        max_page_size=500,
    )
    assert size_i2 == 500


@pytest.mark.parametrize(
    "start_ts,end_ts,interval,exp_start,exp_end,exp_interval",
    [
        (0.0, 10.0, 5, 0.0, 10.0, 5),
        ("1.5", "3.5", "4", 1.5, 3.5, 4),
        ("x", "y", "z", 0.0, 0.0, 0),
    ],
)
def test_normalize_interval_args_variants(
    start_ts: object,
    end_ts: object,
    interval: object,
    exp_start: float,
    exp_end: float,
    exp_interval: int,
) -> None:
    """Brief: _normalize_interval_args parses floats/ints and handles failures.

    Inputs:
      - start_ts: Raw start timestamp.
      - end_ts: Raw end timestamp.
      - interval: Raw interval value.

    Outputs:
      - None; asserts the normalized (start_f, end_f, interval_i) triple.
    """

    start_f, end_f, interval_i = BaseStatsStore._normalize_interval_args(
        start_ts, end_ts, interval
    )
    assert start_f == pytest.approx(exp_start)
    assert end_f == pytest.approx(exp_end)
    assert interval_i == exp_interval
