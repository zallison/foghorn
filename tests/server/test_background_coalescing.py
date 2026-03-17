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
