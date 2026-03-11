from __future__ import annotations

import json

import pytest
import yaml

from foghorn.config import config_dump


def test_build_effective_config_for_display_non_mapping_returns_empty() -> None:
    out = config_dump.build_effective_config_for_display(["not-a-dict"])
    assert out == {}


def test_build_effective_config_for_display_deepcopies_and_fills_top_level_defaults() -> (
    None
):
    cfg = {
        "server": {
            "resolver": {"mode": "forward"},
        },
        "plugins": {},
    }

    out = config_dump.build_effective_config_for_display(cfg)

    # Deep-copy: input must remain unchanged.
    assert cfg["plugins"] == {}
    assert cfg["server"] == {"resolver": {"mode": "forward"}}

    # Top-level defaults.
    assert out["plugins"] == []
    assert isinstance(out["server"], dict)

    # Listen defaults should exist and be explicit.
    listen = out["server"]["listen"]
    assert "host" not in listen
    assert "port" not in listen
    assert listen["udp"]["enabled"] is True
    assert listen["tcp"]["enabled"] is False

    # Logging defaults should exist.
    assert out["logging"]["python"]["level"] == "info"


def test_build_effective_config_for_display_coerces_non_mapping_server_block() -> None:
    cfg = {
        "server": "not-a-dict",
        "plugins": [],
    }

    out = config_dump.build_effective_config_for_display(cfg)

    assert isinstance(out["server"], dict)
    assert "listen" in out["server"]


def test_dump_config_text_json_and_yaml_roundtrip() -> None:
    cfg = {"a": 1, "b": {"c": True}}

    text_json = config_dump.dump_config_text(cfg, fmt=" JSON ")
    assert text_json.endswith("\n")
    assert json.loads(text_json) == cfg

    text_yaml = config_dump.dump_config_text(cfg, fmt="yaml")
    assert yaml.safe_load(text_yaml) == cfg


def test_expand_server_listen_defaults_legacy_dns_and_invalid_subblocks() -> None:
    server_cfg = {
        "listen": {
            "dns": {
                "host": "0.0.0.0",
                "port": "not-an-int",
            },
            # Invalid types to force the best-effort fallback path in _sub().
            "udp": True,
            "tcp": "nope",
            # Empty dict means "configured" => enabled by default.
            "dot": {},
            "doh": {},
        }
    }

    config_dump._expand_server_listen_defaults(server_cfg)

    listen = server_cfg["listen"]
    assert "host" not in listen
    assert "port" not in listen
    assert listen["udp"]["host"] == "0.0.0.0"
    assert listen["udp"]["port"] == 5335

    # When listener blocks are not mappings, defaults are applied directly.
    assert listen["udp"]["enabled"] is True
    assert listen["tcp"]["enabled"] is False

    # DoT/DoH defaults become enabled when their sections are mappings.
    assert listen["dot"]["enabled"] is True
    assert listen["doh"]["enabled"] is True


def test_expand_server_listen_defaults_dict_sections_use_enabled_values() -> None:
    server_cfg = {
        "listen": {
            "udp": {"enabled": 0},
            "tcp": {"enabled": 1},
        }
    }

    config_dump._expand_server_listen_defaults(server_cfg)

    listen = server_cfg["listen"]
    assert bool(listen["udp"]["enabled"]) is False
    assert bool(listen["tcp"]["enabled"]) is True


def test_expand_server_resolver_defaults_handles_invalid_ints_and_preserves_mode() -> (
    None
):
    server_cfg = {
        "resolver": {
            "mode": "NONE",
            "timeout_ms": "bad",
            "per_try_timeout_ms": None,
            "max_depth": "bad",
            "use_asyncio": False,
        }
    }

    config_dump._expand_server_resolver_defaults(server_cfg)

    r = server_cfg["resolver"]
    assert r["mode"] in ["none", "master"]
    assert r["timeout_ms"] == 2000
    assert r["per_try_timeout_ms"] == 2000
    assert r["max_depth"] == 12
    assert r["use_asyncio"] is False


def test_expand_server_resolver_defaults_coerces_non_mapping_resolver_block() -> None:
    server_cfg = {"resolver": "not-a-dict"}

    config_dump._expand_server_resolver_defaults(server_cfg)

    r = server_cfg["resolver"]
    assert r["mode"] == "forward"
    assert r["timeout_ms"] == 2000


def test_expand_server_dnssec_defaults_handles_invalid_payload_size() -> None:
    server_cfg = {"dnssec": {"mode": None, "validation": None, "udp_payload_size": "x"}}

    config_dump._expand_server_dnssec_defaults(server_cfg)

    d = server_cfg["dnssec"]
    assert d["mode"] == "ignore"
    assert d["validation"] == "upstream_ad"
    assert d["udp_payload_size"] == 1232


def test_expand_server_http_defaults_enabled_logic_and_nested_mappings() -> None:
    # Empty mapping => disabled (mirrors foghorn.main/start_webserver semantics).
    server_cfg = {"http": {}}
    config_dump._expand_server_http_defaults(server_cfg)
    assert server_cfg["http"]["enabled"] is False

    # Non-empty mapping => enabled by default.
    server_cfg2 = {"http": {"host": "0.0.0.0"}}
    config_dump._expand_server_http_defaults(server_cfg2)
    assert server_cfg2["http"]["enabled"] is True

    # Explicit enabled flag overrides "presence".
    server_cfg3 = {
        "http": {
            "host": "0.0.0.0",
            "enabled": 0,
            "logs": "nope",
            "cors": "nope",
            "auth": "nope",
        }
    }
    config_dump._expand_server_http_defaults(server_cfg3)
    http = server_cfg3["http"]
    assert http["enabled"] is False
    assert isinstance(http["logs"], dict)
    assert isinstance(http["cors"], dict)
    assert http["cors"]["allowlist"] == []
    assert isinstance(http["auth"], dict)


def test_expand_server_feature_flags_and_axfr_allow_clients_type_coercion() -> None:
    server_cfg = {"axfr": {"allow_clients": "not-a-list"}}

    config_dump._expand_server_feature_flags(server_cfg)

    assert server_cfg["enable_ede"] is False
    assert server_cfg["forward_local"] is False
    assert server_cfg["axfr"]["enabled"] is False
    assert server_cfg["axfr"]["allow_clients"] == []


def test_expand_upstreams_defaults_normalizes_endpoints_and_backup_when_forward() -> (
    None
):
    out = {
        "server": {"resolver": {"mode": "forward"}},
        "upstreams": {
            "endpoints": [{"host": "1.1.1.1"}],
            "backup": {"endpoints": [{"host": "8.8.8.8"}]},
        },
    }

    config_dump._expand_upstreams_defaults(out)

    upstreams = out["upstreams"]
    assert upstreams["strategy"] == "failover"
    assert upstreams["max_concurrent"] == 1
    assert upstreams["endpoints"][0]["port"] == 53
    assert upstreams["backup"]["endpoints"][0]["port"] == 53


def test_expand_upstreams_defaults_leaves_legacy_list_form_unmodified() -> None:
    out = {
        "server": {"resolver": {"mode": "forward"}},
        "upstreams": [{"host": "1.1.1.1"}],
    }

    config_dump._expand_upstreams_defaults(out)

    assert isinstance(out["upstreams"], list)
    assert out["upstreams"][0] == {"host": "1.1.1.1"}


def test_expand_upstreams_defaults_skips_normalization_when_non_forward_mode() -> None:
    out = {
        "server": {"resolver": {"mode": "recursive"}},
        "upstreams": {"endpoints": [{"host": "1.1.1.1"}]},
    }

    config_dump._expand_upstreams_defaults(out)

    # Defaults are still filled, but endpoints stay un-normalized.
    assert out["upstreams"]["endpoints"] == [{"host": "1.1.1.1"}]


def test_expand_upstreams_defaults_resolver_mode_none_is_alias_for_master() -> None:
    out = {
        "server": {"resolver": {"mode": "none"}},
        "upstreams": {"endpoints": [{"host": "1.1.1.1"}]},
    }

    config_dump._expand_upstreams_defaults(out)

    # master != forward => endpoint normalization is skipped.
    assert out["upstreams"]["endpoints"] == [{"host": "1.1.1.1"}]


def test_expand_upstreams_defaults_backup_invalid_type_is_preserved() -> None:
    out = {
        "server": {"resolver": {"mode": "forward"}},
        "upstreams": {"endpoints": [{"host": "1.1.1.1"}], "backup": "nope"},
    }

    config_dump._expand_upstreams_defaults(out)

    assert out["upstreams"]["backup"] == "nope"
    assert out["upstreams"]["endpoints"][0]["port"] == 53


def test_expand_upstreams_defaults_handles_normalization_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(_cfg):
        raise RuntimeError("boom")

    monkeypatch.setattr(config_dump, "normalize_upstream_config", _boom)

    out = {
        "server": {"resolver": {"mode": "forward"}},
        "upstreams": {"endpoints": [{"host": "1.1.1.1"}]},
    }

    config_dump._expand_upstreams_defaults(out)

    # Best-effort: keep endpoints in their original form.
    assert out["upstreams"]["endpoints"] == [{"host": "1.1.1.1"}]


def test_expand_upstreams_defaults_backup_normalization_exception_preserves_backup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _backup_boom(_cfg):
        raise RuntimeError("boom")

    monkeypatch.setattr(config_dump, "normalize_upstream_backup_config", _backup_boom)

    out = {
        "server": {"resolver": {"mode": "forward"}},
        "upstreams": {
            "endpoints": [{"host": "1.1.1.1"}],
            "backup": {"endpoints": [{"host": "8.8.8.8"}]},
        },
    }

    config_dump._expand_upstreams_defaults(out)

    # Primary endpoints normalize successfully before backup normalization fails.
    assert out["upstreams"]["endpoints"][0]["port"] == 53
    # Backup endpoints should remain as originally provided.
    assert out["upstreams"]["backup"]["endpoints"] == [{"host": "8.8.8.8"}]


def test_expand_upstreams_defaults_max_concurrent_parsing_and_clamping() -> None:
    out_bad = {
        "server": {"resolver": {"mode": "forward"}},
        "upstreams": {"endpoints": [{"host": "1.1.1.1"}], "max_concurrent": "bad"},
    }
    config_dump._expand_upstreams_defaults(out_bad)
    assert out_bad["upstreams"]["max_concurrent"] == 1

    # 0 is treated as "unset" by the runtime (main.py uses `or 1`), so it
    # normalizes to 1 without hitting the <1 clamp.
    out_zero = {
        "server": {"resolver": {"mode": "forward"}},
        "upstreams": {"endpoints": [{"host": "1.1.1.1"}], "max_concurrent": 0},
    }
    config_dump._expand_upstreams_defaults(out_zero)
    assert out_zero["upstreams"]["max_concurrent"] == 1

    # Negative values are truthy, so they reach the <1 clamp.
    out_negative = {
        "server": {"resolver": {"mode": "forward"}},
        "upstreams": {"endpoints": [{"host": "1.1.1.1"}], "max_concurrent": -1},
    }
    config_dump._expand_upstreams_defaults(out_negative)
    assert out_negative["upstreams"]["max_concurrent"] == 1


def test_expand_upstreams_defaults_non_mapping_is_left_untouched() -> None:
    out = {"upstreams": "not-a-dict"}
    config_dump._expand_upstreams_defaults(out)
    assert out["upstreams"] == "not-a-dict"
