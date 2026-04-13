"""Brief: Unit tests for foghorn.plugins.resolve.zone_records.axfr_polling.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import threading
from typing import Any, Optional

import pytest

from foghorn.plugins.resolve.zone_records import axfr_polling


class _FakeEvent:
    """Brief: Minimal Event stand-in for deterministic polling loop tests.

    Inputs:
      - waits: Sequence of boolean return values for successive wait() calls.

    Outputs:
      - Event-like object with wait() and set().

    Example:
      >>> ev = _FakeEvent([False, True])
      >>> ev.wait(1.0)
      False
      >>> ev.wait(1.0)
      True
    """

    def __init__(self, waits: list[bool]) -> None:
        self.waits = list(waits)
        self.wait_calls: list[float] = []
        self.set_called = False

    def wait(self, timeout: float) -> bool:
        self.wait_calls.append(float(timeout))
        if self.waits:
            return bool(self.waits.pop(0))
        return True

    def set(self) -> None:
        self.set_called = True


class _FakeThread:
    """Brief: Minimal Thread stand-in capturing the loop callback.

    Inputs:
      - target: callable invoked by the thread.
      - name: thread name.

    Outputs:
      - Thread-like object with .start() and .daemon.
    """

    def __init__(self, *, target: Any, name: str) -> None:
        self.target = target
        self.name = name
        self.daemon: bool = False
        self.started = False

    def start(self) -> None:
        self.started = True


class _Plugin:
    """Brief: Minimal plugin stand-in for axfr_polling.

    Inputs:
      - zones: value assigned to _axfr_zones.

    Outputs:
      - Object exposing _axfr_zones, _load_records, and poll state attributes.
    """

    def __init__(
        self,
        zones: Optional[list[dict[str, object]]] = None,
        *,
        min_interval_seconds: Optional[float] = None,
    ) -> None:
        self._axfr_zones = list(zones or [])
        self._axfr_loaded_once = True
        self.load_calls = 0
        self._reload_records_lock = threading.RLock()
        if min_interval_seconds is not None:
            self._axfr_poll_min_interval = float(min_interval_seconds)

    def _load_records(self) -> None:
        self.load_calls += 1


def test_start_axfr_polling_no_zones_noop(monkeypatch) -> None:
    """Brief: No axfr_zones configured -> no polling thread.

    Inputs:
      - plugin: plugin with empty _axfr_zones.

    Outputs:
      - None: Asserts _axfr_poll_thread is not created.
    """
    monkeypatch.setattr(axfr_polling.threading, "Thread", _FakeThread, raising=True)
    monkeypatch.setattr(
        axfr_polling.threading, "Event", lambda: _FakeEvent([]), raising=True
    )

    plugin = _Plugin([])
    axfr_polling.start_axfr_polling(plugin)

    assert getattr(plugin, "_axfr_poll_thread", None) is None


def test_start_axfr_polling_no_intervals_noop(monkeypatch) -> None:
    """Brief: axfr_zones with non-positive intervals -> no polling thread.

    Inputs:
      - plugin: zones present but poll_interval_seconds <= 0.

    Outputs:
      - None: Asserts _axfr_poll_thread is not created.
    """
    monkeypatch.setattr(axfr_polling.threading, "Thread", _FakeThread, raising=True)
    monkeypatch.setattr(
        axfr_polling.threading, "Event", lambda: _FakeEvent([]), raising=True
    )

    plugin = _Plugin(
        [
            {"zone": "example.com", "poll_interval_seconds": 0},
            {"zone": "example.net", "poll_interval_seconds": None},
        ]
    )
    axfr_polling.start_axfr_polling(plugin)

    assert getattr(plugin, "_axfr_poll_thread", None) is None


def test_start_axfr_polling_uses_min_interval_and_starts_thread(monkeypatch) -> None:
    """Brief: Polling uses the minimum configured poll_interval_seconds.

    Inputs:
      - plugin: zones with multiple positive poll intervals.

    Outputs:
      - None: Asserts interval and thread attributes are set.
    """
    monkeypatch.setattr(axfr_polling.threading, "Thread", _FakeThread, raising=True)

    ev = _FakeEvent([True])
    monkeypatch.setattr(axfr_polling.threading, "Event", lambda: ev, raising=True)

    plugin = _Plugin(
        [
            {"zone": "example.com", "poll_interval_seconds": 15},
            {"zone": "example.net", "poll_interval_seconds": 20},
        ],
        min_interval_seconds=10,
    )

    axfr_polling.start_axfr_polling(plugin)

    assert plugin._axfr_poll_interval == 15.0
    assert plugin._axfr_poll_stop is ev

    thread = plugin._axfr_poll_thread
    assert isinstance(thread, _FakeThread)
    assert thread.name == "ZoneRecordsAxfrPoller"
    assert thread.daemon is True
    assert thread.started is True


def test_start_axfr_polling_clamps_interval_below_minimum(monkeypatch) -> None:
    """Brief: poll_interval_seconds below minimum is clamped.

    Inputs:
      - plugin: zones with poll_interval_seconds lower than minimum.

    Outputs:
      - None: Asserts minimum interval is enforced.
    """
    monkeypatch.setattr(axfr_polling.threading, "Thread", _FakeThread, raising=True)

    ev = _FakeEvent([True])
    monkeypatch.setattr(axfr_polling.threading, "Event", lambda: ev, raising=True)

    plugin = _Plugin(
        [
            {"zone": "example.com", "poll_interval_seconds": 5},
        ],
        min_interval_seconds=60,
    )

    axfr_polling.start_axfr_polling(plugin)

    assert plugin._axfr_poll_interval == 60.0


def test_axfr_polling_loop_calls_load_records_and_resets_flag(monkeypatch) -> None:
    """Brief: One polling tick should reset _axfr_loaded_once and call _load_records.

    Inputs:
      - FakeEvent.wait returns False then True to run exactly one iteration.

    Outputs:
      - None: Asserts load_records called once and _axfr_loaded_once is cleared.
    """
    monkeypatch.setattr(axfr_polling.threading, "Thread", _FakeThread, raising=True)

    ev = _FakeEvent([False, True])
    monkeypatch.setattr(axfr_polling.threading, "Event", lambda: ev, raising=True)

    plugin = _Plugin(
        [
            {"zone": "example.com", "poll_interval_seconds": 12},
        ],
        min_interval_seconds=10,
    )

    axfr_polling.start_axfr_polling(plugin)

    thread = plugin._axfr_poll_thread
    assert isinstance(thread, _FakeThread)

    # Execute the captured loop callback synchronously.
    thread.target()

    assert ev.wait_calls == [12.0, 12.0]
    assert plugin._axfr_loaded_once is False
    assert plugin.load_calls == 1


def test_axfr_polling_loop_skips_when_reload_inflight(monkeypatch) -> None:
    """Brief: Skip poll cycle when a reload is already in progress.

    Inputs:
      - plugin: reload lock pre-acquired to simulate in-flight reload.

    Outputs:
      - None: Asserts no load occurs.
    """
    monkeypatch.setattr(axfr_polling.threading, "Thread", _FakeThread, raising=True)

    ev = _FakeEvent([False, True])
    monkeypatch.setattr(axfr_polling.threading, "Event", lambda: ev, raising=True)

    class _BusyLock:
        def acquire(self, blocking: bool = False) -> bool:
            return False

        def release(self) -> None:
            raise AssertionError("release should not be called when acquire fails")

    plugin = _Plugin([{"zone": "example.com", "poll_interval_seconds": 2}])
    plugin._reload_records_lock = _BusyLock()
    axfr_polling.start_axfr_polling(plugin)

    plugin._axfr_poll_thread.target()

    assert plugin.load_calls == 0


def test_axfr_polling_loop_bails_when_interval_non_positive(monkeypatch) -> None:
    """Brief: Loop returns immediately when _axfr_poll_interval <= 0.

    Inputs:
      - plugin._axfr_poll_interval forced to 0 before running the loop.

    Outputs:
      - None: Asserts no waits or loads occur.
    """
    monkeypatch.setattr(axfr_polling.threading, "Thread", _FakeThread, raising=True)

    ev = _FakeEvent([False])
    monkeypatch.setattr(axfr_polling.threading, "Event", lambda: ev, raising=True)

    plugin = _Plugin([{"zone": "example.com", "poll_interval_seconds": 1}])
    axfr_polling.start_axfr_polling(plugin)

    plugin._axfr_poll_interval = 0.0
    plugin._axfr_poll_thread.target()

    assert ev.wait_calls == []
    assert plugin.load_calls == 0


def test_axfr_polling_loop_bails_when_stop_event_missing(monkeypatch) -> None:
    """Brief: Loop returns immediately when _axfr_poll_stop is None.

    Inputs:
      - plugin._axfr_poll_stop forced to None before running the loop.

    Outputs:
      - None: Asserts no waits or loads occur.
    """
    monkeypatch.setattr(axfr_polling.threading, "Thread", _FakeThread, raising=True)

    ev = _FakeEvent([False])
    monkeypatch.setattr(axfr_polling.threading, "Event", lambda: ev, raising=True)

    plugin = _Plugin([{"zone": "example.com", "poll_interval_seconds": 1}])
    axfr_polling.start_axfr_polling(plugin)

    plugin._axfr_poll_stop = None
    plugin._axfr_poll_thread.target()

    assert plugin.load_calls == 0


def test_start_axfr_polling_requires_load_records(monkeypatch) -> None:
    """Brief: Missing _load_records should raise a clear error.

    Inputs:
      - plugin: object without _load_records.

    Outputs:
      - None: Asserts ValueError is raised.
    """

    class _NoLoader:
        def __init__(self) -> None:
            self._axfr_zones = [{"zone": "example.com", "poll_interval_seconds": 2}]

    monkeypatch.setattr(axfr_polling.threading, "Thread", _FakeThread, raising=True)
    monkeypatch.setattr(
        axfr_polling.threading, "Event", lambda: _FakeEvent([]), raising=True
    )

    with pytest.raises(ValueError, match="plugin._load_records"):
        axfr_polling.start_axfr_polling(_NoLoader())
