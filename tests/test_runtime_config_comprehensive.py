"""Comprehensive tests for runtime_config module.

Brief:
  Test all non-trivial branches and edge cases in runtime_config.py.
  Focus on ensure reload/restart logic, plugin lifecycle, and configuration
  validation work correctly.

Inputs:
  - runtime_config module functions

Outputs:
  - Assertions covering branches, corner cases, and error conditions
"""

from __future__ import annotations
from dataclasses import replace

import threading
import time

import pytest
import foghorn.runtime_config as runtime_config_mod

from foghorn.runtime_config import (
    _build_snapshot,
    _default_snapshot,
    _effective_cfg_for_reload_only,
    _restart_required_reasons,
    _swap_snapshot,
    analyze_config_change,
    clear_runtime,
    get_runtime_snapshot,
    initialize_runtime,
    load_config_from_disk,
    parse_upstream_health_config,
    reload_from_config,
    reload_from_disk,
)


def test_parse_upstream_health_config_empty_inputs() -> None:
    """Empty or non-dict inputs return defaults."""
    result = parse_upstream_health_config(None)
    assert result.max_serv_fail == 3
    assert result.unknown_after_seconds == 300.0


def test_parse_upstream_health_config_health_not_dict() -> None:
    """health key that is not a dict falls back to defaults."""
    result = parse_upstream_health_config({"health": "not a dict"})
    assert result.max_serv_fail == 3


def test_parse_upstream_health_config_unknown_profile() -> None:
    """Unknown profile name raises ValueError."""
    with pytest.raises(ValueError, match="Unknown upstreams\\.health\\.profile"):
        parse_upstream_health_config({"health": {"profile": "unknown_profile"}})


def test_parse_upstream_health_config_explicit_keys_override_profile() -> None:
    """Explicit config keys override profile presets."""
    cfg = {"health": {"profile": "aggressive", "max_serv_fail": 10}}
    result = parse_upstream_health_config(cfg)
    assert result.max_serv_fail == 10


def test_parse_upstream_health_config_probe_floor_enforced() -> None:
    """probe_min_percent never goes below 0.5."""
    cfg = {"health": {"probe_min_percent": 0.1, "probe_max_percent": 1.0}}
    result = parse_upstream_health_config(cfg)
    assert result.probe_min_percent == 0.5


def test_parse_upstream_health_config_min_gt_max_swapped() -> None:
    """When probe_min > probe_max, values are swapped."""
    cfg = {"health": {"probe_min_percent": 10.0, "probe_max_percent": 5.0}}
    result = parse_upstream_health_config(cfg)
    assert result.probe_min_percent == 5.0
    assert result.probe_max_percent == 10.0


def test_parse_upstream_health_config_clamp_invalid_floats() -> None:
    """Invalid numeric values fall back to defaults."""
    cfg = {"health": {"probe_percent": "invalid", "max_serv_fail": "not a number"}}
    result = parse_upstream_health_config(cfg)
    assert result.probe_percent == 1.0
    assert result.max_serv_fail == 3


def test_parse_upstream_health_config_clamp_bounds() -> None:
    """Extreme values are clamped to configured bounds."""
    cfg = {"health": {"probe_percent": 150.0, "unknown_after_seconds": 100000.0}}
    result = parse_upstream_health_config(cfg)
    assert 0.0 <= result.probe_percent <= 100.0
    assert 0.0 <= result.unknown_after_seconds <= 86400.0


def test_initialize_runtime_basic() -> None:
    """Initialize runtime with snapshot and config path."""
    clear_runtime()
    snap = _default_snapshot()
    initialize_runtime(
        snapshot=snap,
        config_path="/tmp/test.yaml",
        cli_vars=[],
        unknown_keys_policy="warn",
    )
    result = get_runtime_snapshot()
    assert result.generation == snap.generation


def test_initialize_runtime_default_unknown_keys_policy_is_error() -> None:
    """Default initialize_runtime unknown-keys policy is strict (error).

    Inputs:
      - None.

    Outputs:
      - None; asserts _UNKNOWN_KEYS_POLICY defaults to 'error'.
    """
    clear_runtime()
    snap = _default_snapshot()
    initialize_runtime(snapshot=snap, config_path="/tmp/test.yaml")
    assert runtime_config_mod._UNKNOWN_KEYS_POLICY == "error"


def test_clear_runtime() -> None:
    """clear_runtime resets module state."""
    clear_runtime()
    snap = _default_snapshot()
    initialize_runtime(snapshot=snap, config_path="/tmp/test.yaml")
    assert get_runtime_snapshot().generation == 0
    clear_runtime()
    assert get_runtime_snapshot().generation == 0


def test_get_runtime_snapshot_uninitialized() -> None:
    """Return default snapshot when not initialized."""
    clear_runtime()
    result = get_runtime_snapshot()
    assert result.generation == 0
    assert result.cfg == {}


def test_load_config_from_disk_config_path_not_configured() -> None:
    """Raise error when config_path not set."""
    clear_runtime()
    with pytest.raises(ValueError, match="config_path not configured"):
        load_config_from_disk()


def test_analyze_config_change_identical() -> None:
    """No change when configs are identical."""
    cfg = {"server": {"resolver": {"mode": "forward"}}}
    result = analyze_config_change(cfg, current_cfg=cfg)
    assert result["changed"] is False
    assert result["restart_required"] is False


def test_analyze_config_change_different_no_restart() -> None:
    """Different config without listener/http changes."""
    current = {"server": {"resolver": {"mode": "forward"}}}
    desired = {"server": {"resolver": {"mode": "recursive"}}}
    result = analyze_config_change(desired, current_cfg=current)
    assert result["changed"] is True
    assert result["restart_required"] is False


def test_analyze_config_change_listen_changed() -> None:
    """server.listen changes require restart."""
    current = {"server": {"listen": {"udp": {"port": 53}}}}
    desired = {"server": {"listen": {"udp": {"port": 5353}}}}
    result = analyze_config_change(desired, current_cfg=current)
    assert result["restart_required"] is True


def test_reload_from_disk_config_path_not_set() -> None:
    """Return error when config_path not configured."""
    clear_runtime()
    result = reload_from_disk()
    assert result.ok is False
    assert "config_path not configured" in result.error


def test_reload_from_config_building_snapshot_fails() -> None:
    """Return error when _build_snapshot fails."""
    clear_runtime()
    snap = _default_snapshot()
    initialize_runtime(snapshot=snap, config_path="/tmp/test.yaml")
    bad_cfg = {"server": "not a dict"}
    result = reload_from_config(bad_cfg)
    assert result.ok is False


def test_reload_from_config_no_restart_needed() -> None:
    """Apply changes when no restart required."""
    clear_runtime()
    snap = _default_snapshot()
    initialize_runtime(snapshot=snap, config_path="/tmp/test.yaml")
    cfg = {"server": {"resolver": {"mode": "recursive"}}}
    result = reload_from_config(cfg)
    assert result.ok is True
    assert result.restart_required is False


class _ShutdownSpyPlugin:
    """Record shutdown invocations for runtime reaper tests."""

    def __init__(self) -> None:
        self.shutdown_calls = 0
        self.shutdown_event = threading.Event()

    def shutdown(self) -> None:
        self.shutdown_calls += 1
        self.shutdown_event.set()


def test_swap_snapshot_reaps_old_plugins_after_grace_without_extra_reload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Single reload eventually reaps queued old plugins after grace."""
    clear_runtime()
    monkeypatch.setattr(runtime_config_mod, "_PLUGIN_SHUTDOWN_GRACE_SECONDS", 0.05)

    old_plugin = _ShutdownSpyPlugin()
    old_snapshot = replace(_default_snapshot(), plugins=[old_plugin], generation=1)
    initialize_runtime(snapshot=old_snapshot, config_path="/tmp/test.yaml")

    _swap_snapshot(replace(_default_snapshot(), generation=2))

    assert old_plugin.shutdown_event.wait(timeout=1.5)
    assert old_plugin.shutdown_calls == 1
    with runtime_config_mod._OLD_PLUGINS_LOCK:
        assert runtime_config_mod._OLD_PLUGINS == []
    clear_runtime()


def test_swap_snapshot_reaps_multiple_old_plugin_generations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple queued generations are drained and each plugin is shut down once."""
    clear_runtime()
    monkeypatch.setattr(runtime_config_mod, "_PLUGIN_SHUTDOWN_GRACE_SECONDS", 0.05)

    plugin_gen1 = _ShutdownSpyPlugin()
    plugin_gen2 = _ShutdownSpyPlugin()

    initialize_runtime(
        snapshot=replace(_default_snapshot(), plugins=[plugin_gen1], generation=1),
        config_path="/tmp/test.yaml",
    )
    _swap_snapshot(replace(_default_snapshot(), plugins=[plugin_gen2], generation=2))
    _swap_snapshot(replace(_default_snapshot(), generation=3))

    assert plugin_gen1.shutdown_event.wait(timeout=1.5)
    assert plugin_gen2.shutdown_event.wait(timeout=1.5)
    assert plugin_gen1.shutdown_calls == 1
    assert plugin_gen2.shutdown_calls == 1
    with runtime_config_mod._OLD_PLUGINS_LOCK:
        assert runtime_config_mod._OLD_PLUGINS == []
    clear_runtime()


def test_swap_snapshot_atomic() -> None:
    """Snapshot swap is atomic under lock."""
    clear_runtime()
    snap = _default_snapshot()
    initialize_runtime(snapshot=snap, config_path="/tmp/test.yaml")

    snap2 = _default_snapshot()
    _swap_snapshot(snap2)

    results = []

    def read_and_check():
        for _ in range(100):
            r = get_runtime_snapshot()
            results.append(r.generation)

    for _ in range(5):
        threading.Thread(target=read_and_check).start()

    time.sleep(0.1)
    for gen in results:
        assert gen in (0, snap2.generation)


def test_build_snapshot_server_not_dict() -> None:
    """Non-dict server config raises ValueError."""
    with pytest.raises(ValueError, match="server.*must be a mapping"):
        _build_snapshot({"server": "not a dict"}, stats_collector=None, generation=0)


def test_build_snapshot_resolver_not_dict() -> None:
    """Non-dict resolver config raises ValueError."""
    with pytest.raises(ValueError, match="resolver.*must be a mapping"):
        _build_snapshot(
            {"server": {"resolver": "not a dict"}},
            stats_collector=None,
            generation=0,
        )


def test_build_snapshot_resolver_mode_defaults() -> None:
    """Apply default values for resolver config."""
    cfg = {"server": {"resolver": {"mode": "recursive"}, "upstreams": []}}
    snap = _build_snapshot(cfg, stats_collector=None, generation=0)
    assert snap.resolver_mode == "recursive"
    assert snap.recursive_max_depth == 16


def test_build_snapshot_invalid_numeric_values() -> None:
    """Invalid numeric config values fall back to defaults."""
    cfg = {
        "server": {
            "resolver": {
                "mode": "recursive",
                "timeout_ms": "not a number",
                "max_depth": "not a number",
            },
            "upstreams": [],
        }
    }
    snap = _build_snapshot(cfg, stats_collector=None, generation=0)
    assert snap.recursive_timeout_ms == 2000
    assert snap.recursive_max_depth == 16


def test_build_snapshot_recursive_mode_no_upstreams() -> None:
    """In recursive mode, no upstreams needed."""
    cfg = {"server": {"resolver": {"mode": "recursive"}}}
    snap = _build_snapshot(cfg, stats_collector=None, generation=0)
    assert len(snap.upstream_addrs) == 0


def test_build_snapshot_max_concurrent_clamp() -> None:
    """max_concurrent is clamped to at least 1."""
    cfg = {
        "server": {
            "resolver": {"mode": "recursive"},
            "upstreams": {"endpoints": [], "max_concurrent": 0},
        }
    }
    snap = _build_snapshot(cfg, stats_collector=None, generation=0)
    assert snap.upstream_max_concurrent == 1


def test_build_snapshot_edns_udp_payload_clamp() -> None:
    """edns_udp_payload clamped to at least 512."""
    cfg = {
        "server": {
            "resolver": {"mode": "recursive"},
            "upstreams": {"endpoints": []},
            "dnssec": {"udp_payload_size": 100},
        }
    }
    snap = _build_snapshot(cfg, stats_collector=None, generation=0)
    assert snap.edns_udp_payload == 512


def test_build_snapshot_udp_max_response_bytes_clamp() -> None:
    """udp_max_response_bytes clamped to non-negative."""
    cfg = {
        "server": {
            "resolver": {"mode": "recursive"},
            "upstreams": {"endpoints": []},
            "listen": {"udp": {"max_response_bytes": -100}},
        }
    }
    snap = _build_snapshot(cfg, stats_collector=None, generation=0)
    assert snap.udp_max_response_bytes is not None
    assert snap.udp_max_response_bytes >= 0


def test_build_snapshot_axfr_allow_clients_strings() -> None:
    """allow_clients converted to strings, falsy values filtered."""
    cfg = {
        "server": {
            "resolver": {"mode": "recursive"},
            "upstreams": {"endpoints": []},
            "axfr": {"allow_clients": ["1.2.3.4", "", None, 5]},
        }
    }
    snap = _build_snapshot(cfg, stats_collector=None, generation=0)
    assert snap.axfr_allow_clients == ["1.2.3.4", "5"]


def test_restart_required_reasons_listen_change() -> None:
    """Detect server.listen changes."""
    old = {"server": {"listen": {"udp": {"port": 53}}}}
    new = {"server": {"listen": {"udp": {"port": 5353}}}}
    reasons = _restart_required_reasons(old, new)
    assert len(reasons) == 1


def test_restart_required_reasons_http_change() -> None:
    """Detect server.http changes."""
    old = {"server": {"http": {"enabled": False}}}
    new = {"server": {"http": {"enabled": True}}}
    reasons = _restart_required_reasons(old, new)
    assert len(reasons) == 1


def test_restart_required_reasons_server_not_dict() -> None:
    """Non-dict server values treated as empty dict."""
    old = {"server": "not a dict"}
    new = {"server": "also not a dict"}
    reasons = _restart_required_reasons(old, new)
    assert len(reasons) == 0


def test_effective_cfg_for_reload_only_listen_preserved() -> None:
    """Preserve old server.listen in reload_only mode."""
    old = {"server": {"listen": {"udp": {"port": 53}}}}
    new = {"server": {"listen": {"udp": {"port": 5353}}}}
    eff = _effective_cfg_for_reload_only(old, new)
    assert eff["server"]["listen"] == old["server"]["listen"]


def test_effective_cfg_for_reload_only_other_values_from_new() -> None:
    """Non-listener/http values come from new config."""
    old = {"server": {"listen": {"udp": {"port": 53}}}, "other": "old"}
    new = {"server": {"listen": {"udp": {"port": 5353}}}, "other": "new"}
    eff = _effective_cfg_for_reload_only(old, new)
    assert eff["other"] == "new"


def test_default_snapshot_safe_defaults() -> None:
    """Default snapshot has conservative defaults."""
    snap = _default_snapshot()
    assert snap.resolver_mode == "forward"
    assert snap.timeout_ms == 2000


def test_empty_config_snapshot() -> None:
    """Handle completely empty config."""
    cfg = {
        "server": {"resolver": {"mode": "recursive"}, "upstreams": {"endpoints": []}}
    }
    snap = _build_snapshot(cfg, stats_collector=None, generation=0)
    assert snap.resolver_mode == "recursive"


def test_build_snapshot_passes_context_to_setup_runner(monkeypatch) -> None:
    """_build_snapshot forwards resolver/upstream context to run_setup_plugins."""

    captured: dict[str, object] = {}

    def _record_setup(plugins, **kwargs):  # type: ignore[no-untyped-def]
        captured["plugins"] = list(plugins)
        captured.update(kwargs)

    monkeypatch.setattr(runtime_config_mod, "run_setup_plugins", _record_setup)
    monkeypatch.setattr(runtime_config_mod, "load_plugins", lambda _specs: [])

    cfg = {
        "server": {
            "resolver": {"mode": "forward", "timeout_ms": 2450},
        },
        "upstreams": {
            "strategy": "failover",
            "max_concurrent": 5,
            "endpoints": [{"host": "8.8.8.8", "port": 53}],
        },
    }

    snap = _build_snapshot(cfg, stats_collector=None, generation=3)

    assert captured["plugins"] == []
    assert captured["upstreams"] == snap.upstream_addrs
    assert captured["upstream_backups"] == snap.upstream_backup_addrs
    assert captured["timeout_ms"] == snap.timeout_ms
    assert captured["resolver_mode"] == snap.resolver_mode
    assert captured["upstream_max_concurrent"] == snap.upstream_max_concurrent
