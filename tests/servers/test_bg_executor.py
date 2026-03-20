"""Brief: Tests for foghorn.servers.bg_executor branch coverage.

Inputs:
  - pytest fixtures (monkeypatch)

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

import pytest

from foghorn.servers import bg_executor as be


@pytest.fixture(autouse=True)
def _reset_bg_executor_state() -> None:
    """Brief: Reset shared executor globals for isolated tests.

    Inputs:
      - None

    Outputs:
      - None
    """

    be._BG_EXECUTOR = None
    be._BG_EXECUTOR_MAX_WORKERS = 4
    yield
    if be._BG_EXECUTOR is not None:
        be._BG_EXECUTOR.shutdown(wait=True, cancel_futures=True)
    be._BG_EXECUTOR = None
    be._BG_EXECUTOR_MAX_WORKERS = 4


@pytest.mark.parametrize("max_workers", [None, "nope", 0, -1])
def test_configure_ignores_invalid_max_workers(max_workers) -> None:
    """Brief: configure_bg_executor ignores None/invalid/too-small values.

    Inputs:
      - max_workers: parameterized invalid values

    Outputs:
      - None
    """

    be.configure_bg_executor(max_workers=max_workers)
    assert be._BG_EXECUTOR is None
    assert be._BG_EXECUTOR_MAX_WORKERS == 4


def test_configure_sets_max_workers_before_creation() -> None:
    """Brief: configure_bg_executor sets max workers before lazy creation.

    Inputs:
      - None

    Outputs:
      - None
    """

    be.configure_bg_executor(max_workers=2)
    assert be._BG_EXECUTOR is None
    assert be._BG_EXECUTOR_MAX_WORKERS == 2

    executor = be.get_bg_executor()
    assert executor._max_workers == 2


def test_configure_no_effect_after_creation() -> None:
    """Brief: configure_bg_executor is ignored after executor creation.

    Inputs:
      - None

    Outputs:
      - None
    """

    executor = be.get_bg_executor()
    be.configure_bg_executor(max_workers=8)
    assert be._BG_EXECUTOR is executor
    assert executor._max_workers == 4


def test_get_bg_executor_returns_singleton() -> None:
    """Brief: get_bg_executor returns the same instance after creation.

    Inputs:
      - None

    Outputs:
      - None
    """

    first = be.get_bg_executor()
    second = be.get_bg_executor()
    assert first is second


def test_get_bg_executor_default_when_none() -> None:
    """Brief: get_bg_executor falls back to default when configured None.

    Inputs:
      - None

    Outputs:
      - None
    """

    be._BG_EXECUTOR_MAX_WORKERS = None
    executor = be.get_bg_executor()
    assert executor._max_workers == 4
