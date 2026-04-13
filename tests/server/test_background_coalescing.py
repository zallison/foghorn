"""Regression tests for bounded background work scheduling.

Brief:
  Ensure best-effort background work (cache refresh and NOTIFY AXFR refresh)
  is coalesced so repeated triggers do not submit unbounded tasks.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import foghorn.servers.server as srv


class _AxfrBackedPlugin:
    """Minimal plugin stub with AXFR-backed zone config for NOTIFY refresh tests."""

    def __init__(self, zones: list[str]):
        self._axfr_zones = [{"zone": z} for z in zones]
        self._axfr_loaded_once = True
        self.load_calls = 0

    def _load_records(self) -> None:
        self.load_calls += 1


def test_schedule_cache_refresh_coalesces(monkeypatch) -> None:
    """Brief: _schedule_cache_refresh submits at most one task per (wire, ip).

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts only one submit occurs for repeated calls.
    """

    submitted: list[object] = []

    monkeypatch.setattr(srv, "_bg_submit", lambda key, fn: submitted.append(key))

    q = b"\x12\x34wire"
    srv._schedule_cache_refresh(q, "127.0.0.1")
    srv._schedule_cache_refresh(q, "127.0.0.1")

    assert len(submitted) == 1


def test_schedule_cache_refresh_clears_inflight_when_submit_rejected(
    monkeypatch,
) -> None:
    """Brief: Rejected submissions clear coalescing state so refresh can retry.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts inflight key cleanup on rejection and later resubmission.
    """

    q = b"\xaa\xbbrefresh"
    key = bytes(q)

    with srv._BG_LOCK:
        srv._BG_CACHE_INFLIGHT.discard(key)

    monkeypatch.setattr(srv, "_bg_submit", lambda _key, _fn: False)
    srv._schedule_cache_refresh(q, "127.0.0.1")

    with srv._BG_LOCK:
        assert key not in srv._BG_CACHE_INFLIGHT

    submitted: list[object] = []
    monkeypatch.setattr(
        srv,
        "_bg_submit",
        lambda task_key, _fn: submitted.append(task_key) or True,
    )
    srv._schedule_cache_refresh(q, "127.0.0.1")

    assert submitted == [key]

    with srv._BG_LOCK:
        srv._BG_CACHE_INFLIGHT.discard(key)


def test_schedule_notify_axfr_refresh_coalesces(
    monkeypatch, set_runtime_snapshot
) -> None:
    """Brief: _schedule_notify_axfr_refresh submits at most one task per zone.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts only one submit occurs for repeated NOTIFY events.
    """

    plugin = _AxfrBackedPlugin(["example.com"])
    set_runtime_snapshot(plugins=[plugin])

    submitted: list[object] = []

    monkeypatch.setattr(srv, "_bg_submit", lambda key, fn: submitted.append(key))

    upstream = {"host": "198.51.100.5", "port": 53}
    srv._schedule_notify_axfr_refresh("example.com.", upstream)
    srv._schedule_notify_axfr_refresh("example.com.", upstream)

    assert len(submitted) == 1
    # The submit key may be plain "<zone>" or namespaced "<plugin-id>:<zone>".
    # Coalescing behavior is what matters here.
    assert str(submitted[0]).split(":")[-1] == "example.com"


def test_schedule_notify_axfr_refresh_clears_inflight_when_submit_rejected(
    monkeypatch, set_runtime_snapshot
) -> None:
    """Brief: Rejected NOTIFY refresh submissions clear in-flight state for retries.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts in-flight cleanup on rejection and later resubmission.
    """

    import foghorn.plugins.resolve.zone_records as zone_records_mod

    plugin = _AxfrBackedPlugin(["example.com"])
    set_runtime_snapshot(plugins=[plugin])

    zone_key = f"{id(plugin)}:example.com"
    upstream = {"host": "198.51.100.5", "port": 53}

    with zone_records_mod._NOTIFY_BG_LOCK:
        zone_records_mod._NOTIFY_REFRESH_INFLIGHT.discard(zone_key)
        zone_records_mod._NOTIFY_REFRESH_STATE.pop(zone_key, None)

    monkeypatch.setattr(srv, "_bg_submit", lambda _key, _fn: False)
    srv._schedule_notify_axfr_refresh("example.com.", upstream)

    with zone_records_mod._NOTIFY_BG_LOCK:
        assert zone_key not in zone_records_mod._NOTIFY_REFRESH_INFLIGHT

    submitted: list[object] = []
    monkeypatch.setattr(
        srv,
        "_bg_submit",
        lambda task_key, _fn: submitted.append(task_key) or True,
    )
    srv._schedule_notify_axfr_refresh("example.com.", upstream)

    assert submitted == [zone_key]

    with zone_records_mod._NOTIFY_BG_LOCK:
        zone_records_mod._NOTIFY_REFRESH_INFLIGHT.discard(zone_key)
        zone_records_mod._NOTIFY_REFRESH_STATE.pop(zone_key, None)
