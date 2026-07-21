"""Brief: Branch-focused tests for foghorn.servers.webserver.admin_logic.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from foghorn.servers.webserver import admin_logic
from foghorn.servers.webserver.admin_logic import (
    AdminLogicHttpError,
    _parse_sort_expression,
    build_admin_capabilities_payload,
    build_admin_status_payload,
    build_config_verify_payload,
    build_plugin_access_control_rules_payload,
    build_plugin_docker_container_payload,
    build_plugin_etc_hosts_lookup_payload,
    build_plugin_mdns_services_payload,
    build_plugin_rate_limit_profiles_payload,
    build_plugin_upstream_evaluate_payload,
    build_plugin_zone_records_lookup_payload,
    build_table_page_payload,
    execute_query_log_clear,
    execute_rate_limit_clear,
    execute_rate_limit_keys_list,
    execute_records_apply,
    execute_records_delete,
    execute_records_validate,
    find_plugin_instance_by_name,
)


class _Lock:
    """Brief: Minimal context-manager lock stub for plugin state access."""

    def __enter__(self) -> "_Lock":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class RateLimit:
    """Brief: Test-only class named to match admin_logic class-name filters."""


class EtcHosts:
    """Brief: Test-only class named to match admin_logic class-name filters."""


class ZoneRecords:
    """Brief: Test-only class named to match admin_logic class-name filters."""


class TestBuildTablePagePayload:
    """Branch coverage for search/sort/paging behavior."""

    def test_normalizes_invalid_paging_and_direction(self) -> None:
        rows = [{"name": "c"}, {"name": "a"}, {"name": "b"}]
        payload = build_table_page_payload(
            rows,
            page=0,
            page_size=9999,
            sort_key="name",
            sort_dir="bad",
        )
        assert payload["page"] == 1
        assert payload["page_size"] == 500
        assert payload["sort_dir"] == "asc"
        assert [r["name"] for r in payload["items"]] == ["a", "b", "c"]

    def test_search_filter_and_nested_key_sort_desc(self) -> None:
        rows = [
            {"meta": {"score": "2"}, "name": "alpha"},
            {"meta": {"score": "10"}, "name": "beta"},
            {"meta": {"score": "1"}, "name": "gamma"},
        ]
        payload = build_table_page_payload(
            rows,
            sort_key="meta.score",
            sort_dir="desc",
            search="a",
        )
        assert [r["name"] for r in payload["items"]] == ["beta", "alpha", "gamma"]


class TestPluginPayloadBuilders:
    """Branch coverage for plugin-* payload builders."""

    def test_access_control_rules_not_found_and_normalized(self) -> None:
        with pytest.raises(AdminLogicHttpError) as exc:
            build_plugin_access_control_rules_payload([], "missing")
        assert exc.value.status_code == 404

        plugin = SimpleNamespace(
            name="acl",
            allow_nets=["10.0.0.0/8", None, "10.0.0.0/8"],
            deny_nets=["192.0.2.0/24", None],
            default="deny",
            deny_response="nxdomain",
        )
        out = build_plugin_access_control_rules_payload([plugin], "acl")
        assert out["rules"]["allow_cidrs"] == ["10.0.0.0/8"]
        assert out["rules"]["deny_cidrs"] == ["192.0.2.0/24"]
        assert out["rules"]["default"] == "deny"

    def test_etc_hosts_lookup_requires_name_and_finds_locked_entry(self) -> None:
        plugin = EtcHosts()
        plugin.name = "etc"
        plugin._hosts_lock = _Lock()
        plugin.hosts = {"example.com": "192.0.2.4"}
        plugin._entry_sources = {"example.com": "/tmp/hosts"}

        with pytest.raises(AdminLogicHttpError) as exc:
            build_plugin_etc_hosts_lookup_payload([plugin], "etc", name=" ")
        assert exc.value.status_code == 400

        out = build_plugin_etc_hosts_lookup_payload([plugin], "etc", name="example.com.")
        assert out["entry"]["name"] == "example.com"
        assert out["entry"]["value"] == "192.0.2.4"
        assert out["entry"]["source"] == "/tmp/hosts"

    def test_etc_hosts_lookup_missing_entry(self) -> None:
        plugin = EtcHosts()
        plugin.name = "etc"
        plugin.hosts = {}
        plugin._entry_sources = {}
        plugin._hosts_lock = None

        with pytest.raises(AdminLogicHttpError) as exc:
            build_plugin_etc_hosts_lookup_payload([plugin], "etc", name="missing.com")
        assert exc.value.status_code == 404

    def test_docker_payload_validates_name_and_matches_case_insensitive(self) -> None:
        plugin = SimpleNamespace(
            name="docker",
            get_http_snapshot=lambda: {
                "containers": [{"name": "Api"}, {"name": "db"}],
            },
        )
        with pytest.raises(AdminLogicHttpError) as exc:
            build_plugin_docker_container_payload([plugin], "docker", name="")
        assert exc.value.status_code == 400

        out = build_plugin_docker_container_payload([plugin], "docker", name="api")
        assert len(out["containers"]) == 1
        assert out["containers"][0]["name"] == "Api"

        with pytest.raises(AdminLogicHttpError) as missing:
            build_plugin_docker_container_payload([plugin], "docker", name="cache")
        assert missing.value.status_code == 404

    def test_mdns_services_status_and_type_filters(self) -> None:
        plugin = SimpleNamespace(
            name="mdns",
            get_http_snapshot=lambda: {
                "services": [{"type": "_http._tcp", "status": "up"}],
                "down_services": [{"type": "_ssh._tcp", "status": "down"}],
            },
        )
        with pytest.raises(AdminLogicHttpError) as exc:
            build_plugin_mdns_services_payload([plugin], "mdns", status="sideways", service_type=None)
        assert exc.value.status_code == 400

        out_all = build_plugin_mdns_services_payload(
            [plugin], "mdns", status=None, service_type=None
        )
        assert len(out_all["services"]) == 2

        out_down = build_plugin_mdns_services_payload(
            [plugin], "mdns", status="down", service_type="_ssh._tcp"
        )
        assert len(out_down["services"]) == 1
        assert out_down["services"][0]["status"] == "down"

    def test_zone_records_lookup_branches(self) -> None:
        plugin = ZoneRecords()
        plugin.name = "zr"
        plugin._records_lock = _Lock()
        plugin._name_index = {
            "example.com": {
                1: (300, ["192.0.2.9"], ["seed"]),
                28: (300, ["2001:db8::1"], ["seed"]),
                15: ("not", "a", "tuple"),
            }
        }

        with pytest.raises(AdminLogicHttpError) as owner_err:
            build_plugin_zone_records_lookup_payload(
                [plugin], "zr", owner=" ", qtype=None
            )
        assert owner_err.value.status_code == 400

        with pytest.raises(AdminLogicHttpError) as qtype_err:
            build_plugin_zone_records_lookup_payload(
                [plugin], "zr", owner="example.com", qtype="INVALID"
            )
        assert qtype_err.value.status_code == 400

        with pytest.raises(AdminLogicHttpError) as missing:
            build_plugin_zone_records_lookup_payload(
                [plugin], "zr", owner="missing.com", qtype=None
            )
        assert missing.value.status_code == 404

        out = build_plugin_zone_records_lookup_payload(
            [plugin], "zr", owner="example.com.", qtype="A"
        )
        assert out["owner"] == "example.com"
        assert out["qtype"] == 1
        assert len(out["records"]) == 1
        assert out["records"][0]["qtype_name"] == "A"

    def test_upstream_evaluate_branches(self) -> None:
        plugin = SimpleNamespace(name="router")

        with pytest.raises(AdminLogicHttpError):
            build_plugin_upstream_evaluate_payload([], "router", qname="example.com")

        with pytest.raises(AdminLogicHttpError) as qname_err:
            build_plugin_upstream_evaluate_payload([plugin], "router", qname=" ")
        assert qname_err.value.status_code == 400

        with pytest.raises(AdminLogicHttpError) as missing_matcher:
            build_plugin_upstream_evaluate_payload([plugin], "router", qname="a.com")
        assert missing_matcher.value.status_code == 404

        plugin._match_upstream_candidates = lambda _qname: [{"id": "a"}]
        out = build_plugin_upstream_evaluate_payload([plugin], "router", qname="a.com.")
        assert out["matched"] is True
        assert out["qname"] == "a.com"

        plugin._match_upstream_candidates = lambda _qname: "not-a-list"
        out_empty = build_plugin_upstream_evaluate_payload([plugin], "router", qname="a.com")
        assert out_empty["matched"] is False
        assert out_empty["candidates"] == []


class TestRateLimitProfilesPayload:
    """Branch coverage for profile-listing and sorting helpers."""

    def _make_plugin(self) -> RateLimit:
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE rate_profiles (key TEXT, avg_rps REAL, max_rps REAL, samples INTEGER, last_update INTEGER)"
        )
        conn.executemany(
            "INSERT INTO rate_profiles VALUES (?, ?, ?, ?, ?)",
            [
                ("global", 2.5, 9.0, 3, 100),
                ("192.0.2.1", 1.0, 4.0, 2, 50),
            ],
        )
        conn.commit()

        plugin = RateLimit()
        plugin.name = "rl"
        plugin._db_lock = _Lock()
        plugin._conn = conn
        plugin._get_current_window_rps_snapshot = lambda limit=0: {"global": 7.5}
        return plugin

    def test_parse_sort_expression(self) -> None:
        assert _parse_sort_expression(None) == ("avg_rps", True)
        assert _parse_sort_expression("-samples") == ("samples", True)
        assert _parse_sort_expression("samples:desc") == ("samples", True)
        assert _parse_sort_expression("samples") == ("samples", False)

    def test_rate_limit_profile_payload_sort_limit_and_errors(self) -> None:
        with pytest.raises(AdminLogicHttpError):
            build_plugin_rate_limit_profiles_payload([], "rl", limit=10, sort="avg_rps")

        plugin = self._make_plugin()
        out = build_plugin_rate_limit_profiles_payload(
            [plugin], "rl", limit=1, sort="-avg_rps"
        )
        assert out["total"] == 2
        assert out["limit"] == 1
        assert out["sort"]["direction"] == "desc"
        assert len(out["profiles"]) == 1
        assert out["profiles"][0]["key"] == "global"
        assert out["profiles"][0]["current_rps"] == 7.5

        with pytest.raises(AdminLogicHttpError) as bad_sort:
            build_plugin_rate_limit_profiles_payload([plugin], "rl", limit=1, sort="bogus")
        assert bad_sort.value.status_code == 400

    def test_rate_limit_profile_unavailable_storage_and_query_failure(self) -> None:
        plugin = RateLimit()
        plugin.name = "rl"
        plugin._db_lock = None
        plugin._conn = None
        with pytest.raises(AdminLogicHttpError) as unavailable:
            build_plugin_rate_limit_profiles_payload([plugin], "rl", limit=10, sort=None)
        assert unavailable.value.status_code == 404

        class _BrokenConn:
            def cursor(self):
                raise RuntimeError("db broken")

        plugin2 = RateLimit()
        plugin2.name = "rl2"
        plugin2._db_lock = _Lock()
        plugin2._conn = _BrokenConn()
        with pytest.raises(AdminLogicHttpError) as broken:
            build_plugin_rate_limit_profiles_payload([plugin2], "rl2", limit=10, sort=None)
        assert broken.value.status_code == 500


class TestAdminRuntimeAndConfigHelpers:
    """Branch coverage for runtime-status and config verification helpers."""

    def test_build_admin_status_payload_with_metrics_and_restart(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = SimpleNamespace(get_async_queue_metrics=lambda: {"queued": 2})
        stats = SimpleNamespace(_store=store)
        runtime = SimpleNamespace(get_restart_pending=lambda: {"reason": "config"})
        monkeypatch.setattr(
            admin_logic,
            "time",
            SimpleNamespace(time=lambda: 123.4),
        )
        from foghorn import runtime_config

        monkeypatch.setattr(
            runtime_config,
            "get_runtime_snapshot",
            lambda: SimpleNamespace(generation=9),
        )
        out = build_admin_status_payload(
            cfg={},
            config_path="/tmp/foghorn.yaml",
            stats_collector=stats,
            plugins=[object(), object()],
            admin_runtime_state=runtime,
        )
        assert out["status"] == "ok"
        assert out["runtime_generation"] == 9
        assert out["plugin_count"] == 2
        assert out["query_log_enabled"] is False
        assert out["query_log_queue"]["queued"] == 2
        assert out["restart_pending"]["reason"] == "config"
        assert out["timestamp_ts"] == 123.4

    def test_build_admin_capabilities_payload(self) -> None:
        stats = SimpleNamespace(
            _store=SimpleNamespace(supports_query_log_clear=lambda: True)
        )
        rl = RateLimit()
        rl.name = "rl"
        etc = EtcHosts()
        etc.name = "etc"
        zr = ZoneRecords()
        zr.name = "zr"
        out = build_admin_capabilities_payload(
            stats_collector=stats,
            plugins=[rl, etc, zr],
        )
        assert out["query_log"]["clear_supported"] is True
        assert out["rate_limit"]["plugin_count"] == 1
        assert out["records"]["validate_supported"] is True

    def test_build_config_verify_payload_branches(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        with pytest.raises(AdminLogicHttpError) as no_path:
            build_config_verify_payload(raw_yaml=None, config_path=None, current_cfg={})
        assert no_path.value.status_code == 500

        from foghorn import runtime_config

        seen = {"loaded": []}

        def _load_config_from_disk(config_path: str):
            seen["loaded"].append(config_path)
            if config_path.endswith(".yaml"):
                return {"a": 1}
            raise ValueError("bad file")

        monkeypatch.setattr(runtime_config, "load_config_from_disk", _load_config_from_disk)
        monkeypatch.setattr(
            runtime_config,
            "analyze_config_change",
            lambda desired_cfg, current_cfg: {"restart_required": desired_cfg != current_cfg},
        )
        cfg_path = tmp_path / "foghorn.yaml"
        cfg_path.write_text("a: 1\n", encoding="utf-8")

        out = build_config_verify_payload(
            raw_yaml="a: 1\n",
            config_path=str(cfg_path),
            current_cfg={},
        )
        assert out["status"] == "ok"
        assert out["analysis"]["restart_required"] is True
        assert any("foghorn-admin-verify-" in p for p in seen["loaded"])

        def _raise_load(_config_path: str):
            raise ValueError("parse failed")

        monkeypatch.setattr(runtime_config, "load_config_from_disk", _raise_load)
        with pytest.raises(AdminLogicHttpError) as bad_parse:
            build_config_verify_payload(raw_yaml=None, config_path=str(cfg_path), current_cfg={})
        assert bad_parse.value.status_code == 400


class TestExecuteHelpers:
    """Branch coverage for execute_* helper functions."""

    def test_execute_query_log_clear_paths(self) -> None:
        with pytest.raises(AdminLogicHttpError):
            execute_query_log_clear(store=None, filters={}, dry_run=False)

        store = SimpleNamespace(supports_query_log_clear=lambda: False)
        with pytest.raises(AdminLogicHttpError) as unsupported:
            execute_query_log_clear(store=store, filters={}, dry_run=False)
        assert unsupported.value.status_code == 400

        class _Store:
            def supports_query_log_clear(self):
                return True

            def clear_query_log(self, filters, dry_run):
                if filters.get("explode"):
                    raise RuntimeError("boom")
                if filters.get("non_dict"):
                    return 7
                return {
                    "matched": 3,
                    "deleted": 2,
                    "dry_run": dry_run,
                    "filters": filters,
                }

        out = execute_query_log_clear(store=_Store(), filters={"a": 1}, dry_run=True)
        assert out["matched"] == 3
        assert out["deleted"] == 2
        fallback = execute_query_log_clear(store=_Store(), filters={"non_dict": True}, dry_run=False)
        assert fallback["matched"] == 0
        with pytest.raises(AdminLogicHttpError) as err:
            execute_query_log_clear(store=_Store(), filters={"explode": True}, dry_run=False)
        assert err.value.status_code == 500

    def test_execute_rate_limit_keys_list_and_clear(self) -> None:
        rl = RateLimit()
        rl.name = "rl"
        rl.admin_list_profile_keys = lambda **kwargs: {"keys": ["a"], "kwargs": kwargs}
        rl.admin_clear_profiles = lambda **kwargs: {"ok": True, "kwargs": kwargs}

        listed = execute_rate_limit_keys_list(
            plugins=[rl],
            plugin_name="rl",
            page=2,
            page_size=5,
            search="a",
        )
        assert listed["status"] == "ok"
        assert listed["items"][0]["plugin"] == "rl"

        cleared = execute_rate_limit_clear(
            plugins=[rl],
            plugin_name=None,
            key="a",
            include_global=False,
        )
        assert cleared["status"] == "ok"
        assert cleared["items"][0]["data"]["ok"] is True

    def test_execute_rate_limit_errors(self) -> None:
        with pytest.raises(AdminLogicHttpError) as missing:
            execute_rate_limit_keys_list(
                plugins=[],
                plugin_name=None,
                page=1,
                page_size=10,
                search=None,
            )
        assert missing.value.status_code == 404

        rl = RateLimit()
        rl.name = "rl"
        with pytest.raises(AdminLogicHttpError) as unsupported:
            execute_rate_limit_clear(
                plugins=[rl],
                plugin_name="rl",
                key=None,
                include_global=True,
            )
        assert unsupported.value.status_code == 400

    def test_execute_records_validate_apply_delete(self) -> None:
        plugin = EtcHosts()
        plugin.name = "etc"
        plugin.admin_validate_record_mutation = lambda **kwargs: {"validated": kwargs}
        plugin.admin_apply_record_mutation = lambda **kwargs: {"applied": kwargs}
        plugin.admin_delete_record_mutation = lambda **kwargs: {"deleted": kwargs}

        validated = execute_records_validate(
            plugins=[plugin],
            target="etc_hosts",
            plugin_name="etc",
            payload={"name": "example.com", "value": "192.0.2.7"},
        )
        assert validated["status"] == "ok"

        applied = execute_records_apply(
            plugins=[plugin],
            target="etc_hosts",
            plugin_name="etc",
            payload={"name": "example.com", "value": "192.0.2.7", "persist": True},
        )
        assert applied["status"] == "ok"
        assert applied["result"]["applied"]["persist"] is True

        deleted = execute_records_delete(
            plugins=[plugin],
            target="etc_hosts",
            plugin_name="etc",
            payload={"name": "example.com", "persist": False},
        )
        assert deleted["status"] == "ok"

        with pytest.raises(AdminLogicHttpError):
            execute_records_validate(
                plugins=[plugin],
                target="unknown",
                plugin_name="etc",
                payload={},
            )

    def test_execute_records_zone_records_paths(self) -> None:
        plugin = ZoneRecords()
        plugin.name = "zr"
        plugin.admin_validate_record_mutation = lambda **kwargs: {"validated": kwargs}
        plugin.admin_apply_record_mutation = lambda **kwargs: {"applied": kwargs}
        plugin.admin_delete_record_mutation = lambda **kwargs: {"deleted": kwargs}

        validated = execute_records_validate(
            plugins=[plugin],
            target="zone_records",
            plugin_name="zr",
            payload={"owner": "example.com", "qtype": "A", "value": "192.0.2.5", "ttl": 60},
        )
        assert validated["result"]["validated"]["ttl"] == 60

        applied = execute_records_apply(
            plugins=[plugin],
            target="zone_records",
            plugin_name="zr",
            payload={"owner": "example.com", "qtype": "A", "value": "192.0.2.5", "ttl": 60},
        )
        assert applied["status"] == "ok"

        deleted = execute_records_delete(
            plugins=[plugin],
            target="zone_records",
            plugin_name="zr",
            payload={"owner": "example.com", "qtype": "A", "value": "192.0.2.5"},
        )
        assert deleted["status"] == "ok"
    def test_execute_records_list_uses_default_limit_and_include_expired(self) -> None:
        """Brief: records-list helper applies default include_expired and limit values.

        Inputs:
          - Runtime-state stub exposing list_temporary_records.

        Outputs:
          - list_temporary_records receives include_expired=True and limit=500.
        """

        calls: list[dict[str, Any]] = []

        class _Runtime:
            def list_temporary_records(self, **kwargs: Any) -> list[dict[str, Any]]:
                calls.append(dict(kwargs))
                return [{"key": "etc_hosts:eh:a.example"}]

        payload = admin_logic.execute_records_list(
            runtime_state=_Runtime(),
            target="etc_hosts",
            plugin_name="eh",
        )
        assert payload["status"] == "ok"
        assert payload["count"] == 1
        assert calls
        assert calls[0]["include_expired"] is True
        assert calls[0]["limit"] == 500

    def test_find_plugin_instance_by_name_still_works_with_new_branches(self) -> None:
        plugin = SimpleNamespace(name="target")
        assert find_plugin_instance_by_name([plugin], "target") is plugin
