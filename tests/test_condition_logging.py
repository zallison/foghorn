"""Brief: Tests for foghorn.utils.condition_logging.

Inputs:
  - None.

Outputs:
  - None.
"""

from __future__ import annotations

import logging
import types

import foghorn.utils.condition_logging as condition_log


def test_condition_logging_module_functions_throttle_and_recover(
    monkeypatch, caplog
) -> None:
    """Brief: Module helpers warn once, re-warn hourly, recover once.

    Inputs:
      - monkeypatch/caplog: pytest fixtures.

    Outputs:
      - None; asserts WARNING/DEBUG/INFO transitions on a plain owner object.
    """

    owner = types.SimpleNamespace(logger=logging.getLogger("foghorn.test.condition"))
    timeline = iter([100.0, 101.0, 102.0, 3700.0, 3701.0])
    monkeypatch.setattr(condition_log.time, "monotonic", lambda: next(timeline))
    caplog.set_level(logging.DEBUG, logger=owner.logger.name)

    condition_log.note_condition_failure(owner, "k", "down %s", "x")
    condition_log.note_condition_failure(owner, "k", "down %s", "x")
    condition_log.note_condition_failure(owner, "k", "down %s", "x")

    warnings = [
        r
        for r in caplog.records
        if r.levelno >= logging.WARNING and "down x" in r.getMessage()
    ]
    assert len(warnings) == 1
    assert any(
        "suppressed repeated condition" in r.getMessage() for r in caplog.records
    )

    caplog.clear()
    condition_log.note_condition_failure(owner, "k", "down %s", "x")
    warnings = [
        r
        for r in caplog.records
        if r.levelno >= logging.WARNING and "down x" in r.getMessage()
    ]
    assert len(warnings) == 1
    assert any("still failing" in r.getMessage() for r in warnings)
    assert any("suppressed 2 repeated warning(s)" in r.getMessage() for r in warnings)

    caplog.clear()
    condition_log.note_condition_ok(owner, "k", "up %s", "x")
    assert any("up x" in r.getMessage() for r in caplog.records)

    caplog.clear()
    condition_log.note_condition_ok(owner, "k", "up %s", "x")
    assert not any("up x" in r.getMessage() for r in caplog.records)


def test_init_condition_logging_resets_maps() -> None:
    """Brief: init_condition_logging creates empty maps and applies rewarn override.

    Inputs:
      - None.

    Outputs:
      - None; asserts lock/maps/interval on owner.
    """

    owner = types.SimpleNamespace()
    condition_log.init_condition_logging(owner, rewarn_interval_seconds=120.0)
    assert owner._condition_failed_by_key == {}
    assert owner._condition_suppressed_by_key == {}
    assert owner._condition_last_warned_by_key == {}
    assert owner._condition_rewarn_interval_seconds == 120.0
    assert owner._condition_log_lock is not None
