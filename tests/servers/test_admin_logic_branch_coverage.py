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
    build_admin_version_compat_payload,
    build_config_diff_payload,
    build_config_lint_payload,
    build_config_verify_payload,
    build_plugin_access_control_rules_payload,
    build_plugin_docker_container_payload,
    build_plugin_etc_hosts_lookup_payload,
    build_plugin_mdns_services_payload,
    build_plugin_rate_limit_profiles_payload,
    build_plugin_upstream_evaluate_payload,
    build_plugin_zone_records_lookup_payload,
    build_table_page_payload,
    build_upstream_status_payload,
    execute_query_log_compact,
    execute_query_log_clear,
    execute_query_log_export,
    execute_rate_limit_clear,
    execute_rate_limit_hot_keys,
    execute_rate_limit_keys_list,
    execute_rate_limit_reset_counters,
    execute_records_apply,
    execute_records_delete,
    execute_records_purge_expired,
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

    def test_execute_query_log_export_branches_and_csv_escaping(self) -> None:
        """Brief: query-log export handles mixed payloads, paging, and CSV quoting.

        Inputs:
          - Store stubs returning non-dict, non-list, and mixed items payloads.

        Outputs:
          - Export payloads are stable and quote/escape CSV fields correctly.
        """

        class _StoreNonDict:
            def select_query_log(self, **kwargs: Any) -> int:
                _ = kwargs
                return 7

        out_non_dict = execute_query_log_export(
            store=_StoreNonDict(),
            filters={},
            export_format="jsonl",
            limit=5,
        )
        assert out_non_dict["status"] == "ok"
        assert out_non_dict["count"] == 0
        assert out_non_dict["data"] == ""

        class _StoreNonListItems:
            def select_query_log(self, **kwargs: Any) -> dict[str, Any]:
                _ = kwargs
                return {"items": "bad"}

        out_non_list = execute_query_log_export(
            store=_StoreNonListItems(),
            filters={},
            export_format="jsonl",
            limit=5,
        )
        assert out_non_list["status"] == "ok"
        assert out_non_list["count"] == 0

        class _StorePaged:
            def __init__(self) -> None:
                self.calls: list[dict[str, Any]] = []

            def select_query_log(self, **kwargs: Any) -> dict[str, Any]:
                self.calls.append(dict(kwargs))
                page = int(kwargs.get("page", 1))
                if page == 1:
                    return {
                        "items": [
                            {
                                "id": 1,
                                "qname": "a.example",
                                "error": 'has,comma "quote"\nand newline',
                                "status": "ok",
                            },
                            "skip-me",
                        ]
                    }
                return {"items": []}

        paged = _StorePaged()
        out_csv = execute_query_log_export(
            store=paged,
            filters={"qname": "a.example"},
            export_format="csv",
            limit=2,
        )
        assert out_csv["status"] == "ok"
        assert out_csv["format"] == "csv"
        assert out_csv["count"] == 1
        assert out_csv["truncated"] is False
        assert "id,ts,timestamp,client_ip,qname" in out_csv["data"]
        assert '"has,comma ""quote""\nand newline"' in out_csv["data"]
        assert len(paged.calls) == 2
        assert paged.calls[0]["qname"] == "a.example"

        with pytest.raises(AdminLogicHttpError) as bad_format:
            execute_query_log_export(
                store=paged,
                filters={},
                export_format="yaml",
                limit=10,
            )
        assert bad_format.value.status_code == 400

        class _StoreError:
            def select_query_log(self, **kwargs: Any) -> dict[str, Any]:
                _ = kwargs
                raise RuntimeError("boom")

        with pytest.raises(AdminLogicHttpError) as export_error:
            execute_query_log_export(
                store=_StoreError(),
                filters={},
                export_format="jsonl",
                limit=10,
            )
        assert export_error.value.status_code == 500

    def test_execute_query_log_export_jsonl_with_rows(self) -> None:
        """Brief: JSONL export serializes non-empty rows.

        Inputs:
          - Store stub returning one dict query-log row.

        Outputs:
          - JSONL payload contains a serialized line with stable content.
        """

        class _StoreOneRow:
            def select_query_log(self, **kwargs: Any) -> dict[str, Any]:
                _ = kwargs
                return {"items": [{"id": 1, "qname": "example.com"}]}

        out = execute_query_log_export(
            store=_StoreOneRow(),
            filters={},
            export_format="jsonl",
            limit=1,
        )
        assert out["status"] == "ok"
        assert out["format"] == "jsonl"
        assert out["count"] == 1
        assert '"id": 1' in out["data"]
        assert '"qname": "example.com"' in out["data"]

    def test_execute_query_log_compact_branches(self) -> None:
        """Brief: query-log compact handles backend guards, modes, and failures.

        Inputs:
          - Backend stubs for non-sqlite and sqlite-like execution paths.

        Outputs:
          - Expected status payloads or AdminLogicHttpError with stable codes.
        """

        with pytest.raises(AdminLogicHttpError) as missing_store:
            execute_query_log_compact(store=None, mode="vacuum", dry_run=True)
        assert missing_store.value.status_code == 404

        class _NonSqlStore:
            pass

        with pytest.raises(AdminLogicHttpError) as wrong_backend:
            execute_query_log_compact(
                store=_NonSqlStore(),
                mode="vacuum",
                dry_run=True,
            )
        assert wrong_backend.value.status_code == 400

        class StatsSQLiteStore:
            def __init__(self) -> None:
                self._conn = None
                self._lock = _Lock()

        with pytest.raises(AdminLogicHttpError) as no_conn:
            execute_query_log_compact(
                store=StatsSQLiteStore(),
                mode="vacuum",
                dry_run=True,
            )
        assert no_conn.value.status_code == 500

        class _FetchOne:
            def __init__(self, n: int) -> None:
                self._n = n

            def fetchone(self) -> tuple[int]:
                return (self._n,)

        class _Conn:
            def __init__(self) -> None:
                self.ops: list[str] = []
                self.count = 5

            def execute(self, sql: str) -> _FetchOne:
                self.ops.append(sql)
                if "SELECT COUNT(1)" in sql:
                    return _FetchOne(self.count)
                return _FetchOne(0)

        class StatsSQLiteStore:
            def __init__(self, *, batch: bool, conn: _Conn) -> None:
                self._conn = conn
                self._lock = _Lock()
                self._batch_writes = batch
                self.flush_calls = 0

            def _flush_locked(self) -> None:
                self.flush_calls += 1

        conn_a = _Conn()
        store_a = StatsSQLiteStore(batch=True, conn=conn_a)
        dry = execute_query_log_compact(store=store_a, mode="vacuum", dry_run=True)
        assert dry["status"] == "ok"
        assert dry["dry_run"] is True
        assert store_a.flush_calls == 1

        conn_b = _Conn()
        store_b = StatsSQLiteStore(batch=False, conn=conn_b)
        out_opt = execute_query_log_compact(store=store_b, mode="optimize", dry_run=False)
        assert out_opt["status"] == "ok"
        assert out_opt["mode"] == "optimize"
        assert "PRAGMA optimize" in conn_b.ops
        assert "PRAGMA wal_checkpoint(TRUNCATE)" in conn_b.ops

        conn_c = _Conn()
        store_c = StatsSQLiteStore(batch=False, conn=conn_c)
        out_prune = execute_query_log_compact(
            store=store_c, mode="prune_only", dry_run=False
        )
        assert out_prune["status"] == "ok"
        assert out_prune["mode"] == "prune_only"
        assert all(op != "VACUUM" for op in conn_c.ops)

        class _BoomConn(_Conn):
            def execute(self, sql: str) -> _FetchOne:
                if "PRAGMA wal_checkpoint" in sql:
                    raise RuntimeError("checkpoint failed")
                return super().execute(sql)

        boom_store = StatsSQLiteStore(batch=False, conn=_BoomConn())
        with pytest.raises(AdminLogicHttpError) as compact_error:
            execute_query_log_compact(
                store=boom_store, mode="vacuum", dry_run=False
            )
        assert compact_error.value.status_code == 500

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

    def test_execute_records_apply_tracks_temporary_records(self) -> None:
        """Brief: execute_records_apply updates temporary-record tracking state.

        Inputs:
          - EtcHosts plugin stub with apply mutation support.
          - Runtime-state stub with upsert/remove methods.

        Outputs:
          - Non-persistent apply upserts tracking record, persistent apply removes it.
        """

        plugin = EtcHosts()
        plugin.name = "etc"
        plugin.admin_apply_record_mutation = lambda **kwargs: {"applied": kwargs}

        upsert_calls: list[dict[str, Any]] = []
        remove_calls: list[dict[str, Any]] = []

        class _Runtime:
            def upsert_temporary_record(self, **kwargs: Any) -> None:
                upsert_calls.append(dict(kwargs))

            def remove_temporary_record(self, **kwargs: Any) -> None:
                remove_calls.append(dict(kwargs))

        runtime = _Runtime()
        out_temp = execute_records_apply(
            plugins=[plugin],
            target="etc_hosts",
            plugin_name="etc",
            payload={"name": "a.example", "value": "192.0.2.7", "persist": False, "ttl": 45},
            runtime_state=runtime,
        )
        assert out_temp["status"] == "ok"
        assert len(upsert_calls) == 1
        assert upsert_calls[0]["target"] == "etc_hosts"
        assert upsert_calls[0]["plugin"] == "etc"
        assert upsert_calls[0]["ttl_seconds"] == 45

        out_persist = execute_records_apply(
            plugins=[plugin],
            target="etc_hosts",
            plugin_name="etc",
            payload={"name": "a.example", "value": "192.0.2.7", "persist": True},
            runtime_state=runtime,
        )
        assert out_persist["status"] == "ok"
        assert len(remove_calls) == 1
        assert remove_calls[0]["key"].startswith("etc_hosts:etc:")

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

    def test_execute_records_delete_zone_owner_wildcard_runtime_cleanup(self) -> None:
        """Brief: owner-only zone delete removes all tracked temporary records for that owner.

        Inputs:
          - ZoneRecords plugin with delete support.
          - Runtime-state stub exposing list_temporary_records/remove_temporary_record.

        Outputs:
          - Matching keys for the owner are removed; non-matching entries are ignored.
        """

        plugin = ZoneRecords()
        plugin.name = "zr"
        plugin.admin_delete_record_mutation = lambda **kwargs: {"deleted": kwargs}

        removed_keys: list[str] = []

        class _Runtime:
            def remove_temporary_record(self, **kwargs: Any) -> None:
                key = str(kwargs.get("key", ""))
                removed_keys.append(key)

            def list_temporary_records(self, **kwargs: Any) -> list[dict[str, Any]]:
                _ = kwargs
                return [
                    {"key": "k1", "payload": {"owner": "example.com", "qtype": "A", "value": "192.0.2.1"}},
                    {"key": "k2", "payload": {"owner": "example.com.", "qtype": "AAAA", "value": "2001:db8::1"}},
                    {"key": "k3", "payload": {"owner": "other.example", "qtype": "A", "value": "192.0.2.9"}},
                    {"key": "", "payload": {"owner": "example.com", "qtype": "TXT", "value": "x"}},
                    {"key": "k4", "payload": "bad"},
                    {"key": "k5", "payload": {"owner": "example.com", "qtype": "MX", "value": "mail.example"}},
                ]

        out = execute_records_delete(
            plugins=[plugin],
            target="zone_records",
            plugin_name="zr",
            payload={"owner": "example.com", "qtype": "", "value": ""},
            runtime_state=_Runtime(),
        )
        assert out["status"] == "ok"
        assert set(removed_keys) == {"k1", "k2", "k5"}
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


class TestAdditionalBranchCoverage:
    """Additional branch coverage for remaining high-value admin_logic paths."""

    def test_build_config_diff_and_lint_payload_branches(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Brief: exercise config diff/lint success and error branches."""

        with pytest.raises(AdminLogicHttpError) as missing:
            build_config_diff_payload(raw_yaml=None, config_path=None, current_cfg={})
        assert missing.value.status_code == 500

        from foghorn import runtime_config

        def _load_config_from_disk(config_path: str) -> dict[str, Any]:
            if "foghorn-admin-diff-" in config_path:
                return {"root": {"a": 1, "list": [1, 2]}, "empty": {}}
            if config_path.endswith("foghorn.yaml"):
                return {"root": {"a": 2, "b": "x"}, "old": True}
            raise ValueError("bad path")

        monkeypatch.setattr(runtime_config, "load_config_from_disk", _load_config_from_disk)
        monkeypatch.setattr(
            runtime_config,
            "analyze_config_change",
            lambda desired_cfg, current_cfg: {
                "changed": desired_cfg != current_cfg,
                "restart_required": True,
                "reload_required": False,
            },
        )

        cfg_path = tmp_path / "foghorn.yaml"
        cfg_path.write_text("root:\n  a: 2\n", encoding="utf-8")

        diff_out = build_config_diff_payload(
            raw_yaml="root:\n  a: 1\n",
            config_path=str(cfg_path),
            current_cfg={"root": {"a": 2, "b": "x"}, "old": True},
        )
        assert diff_out["status"] == "ok"
        assert diff_out["changed"] is True
        assert diff_out["diff"]["added_count"] >= 1
        assert diff_out["diff"]["removed_count"] >= 1
        assert diff_out["diff"]["modified_count"] >= 1

        lint_out = build_config_lint_payload(
            raw_yaml="root:\n  a: 1\n",
            config_path=str(cfg_path),
            current_cfg={"root": {"a": 2, "b": "x"}, "old": True},
        )
        assert lint_out["status"] == "ok"
        rule_ids = {issue["rule_id"] for issue in lint_out["issues"]}
        assert "restart_required" in rule_ids

        monkeypatch.setattr(
            runtime_config,
            "load_config_from_disk",
            lambda _config_path: (_ for _ in ()).throw(ValueError("parse failed")),
        )
        with pytest.raises(AdminLogicHttpError) as bad_parse:
            build_config_diff_payload(
                raw_yaml=None,
                config_path=str(cfg_path),
                current_cfg={},
            )
        assert bad_parse.value.status_code == 400

    def test_build_admin_version_compat_payload_branches(self) -> None:
        """Brief: exercise version-compat payload plugin/store fallback behavior."""

        class _Plugin:
            name = "p1"

            def admin_validate_record_mutation(self, **kwargs: Any) -> dict[str, Any]:
                return dict(kwargs)

        class _Store:
            def supports_query_log_clear(self) -> bool:
                raise RuntimeError("boom")

        out = build_admin_version_compat_payload(
            plugins=[_Plugin()],
            stats_collector=SimpleNamespace(_store=_Store()),
        )
        assert out["status"] == "ok"
        assert out["query_log"]["enabled"] is True
        assert out["query_log"]["clear_supported"] is False
        assert out["plugins"][0]["capabilities"]["records_validate"] is True

    def test_execute_rate_limit_hot_keys_and_reset_counters(self) -> None:
        """Brief: cover hot-key aggregation and in-memory counter reset branches."""

        rl = RateLimit()
        rl.name = "rl"
        rl._db_lock = _Lock()
        rl._conn = sqlite3.connect(":memory:")
        rl._conn.execute(
            "CREATE TABLE rate_profiles (key TEXT, avg_rps REAL, max_rps REAL, samples INTEGER, last_update INTEGER)"
        )
        rl._conn.executemany(
            "INSERT INTO rate_profiles VALUES (?, ?, ?, ?, ?)",
            [
                ("global", 9.0, 10.0, 3, 1),
                ("k1", 2.0, 5.0, 7, 100),
                ("k2", 0.5, 1.0, 2, 0),
            ],
        )
        rl._conn.commit()
        rl._get_current_window_rps_snapshot = lambda limit=0: {"k1": 4.2, "k3": 9.9}
        rl._active_window_lock = _Lock()
        rl._active_window_counts = {"k1": 1, "k2": 2}
        rl._active_window_id = "win"
        rl._deny_episode_count = {"k1": 1}
        rl._burst_exceeded_count = {"k1": 2}
        rl._below_threshold_count = {"k2": 3}

        hot = execute_rate_limit_hot_keys(plugins=[rl], plugin_name="rl", limit=2)
        assert hot["status"] == "ok"
        assert hot["items"][0]["plugin"] == "rl"
        assert len(hot["items"][0]["items"]) == 2

        reset = execute_rate_limit_reset_counters(plugins=[rl], plugin_name="rl")
        assert reset["status"] == "ok"
        assert reset["items"][0]["active_window_keys_cleared"] == 2
        assert rl._active_window_counts == {}
        assert rl._active_window_id is None
        assert rl._deny_episode_count == {}
        assert rl._burst_exceeded_count == {}
        assert rl._below_threshold_count == {}
        rl._conn.close()

    def test_execute_rate_limit_hot_keys_error_and_fallback_paths(self) -> None:
        """Brief: cover missing-plugin and snapshot/db exception fallbacks."""

        with pytest.raises(AdminLogicHttpError) as missing:
            execute_rate_limit_hot_keys(plugins=[], plugin_name=None, limit=5)
        assert missing.value.status_code == 404

        class _BrokenConn:
            def cursor(self) -> Any:
                raise RuntimeError("db down")

        rl = RateLimit()
        rl.name = "rl"
        rl._db_lock = _Lock()
        rl._conn = _BrokenConn()
        rl._get_current_window_rps_snapshot = lambda limit=0: (_ for _ in ()).throw(RuntimeError("snap down"))

        out = execute_rate_limit_hot_keys(plugins=[rl], plugin_name="rl", limit=5)
        assert out["status"] == "ok"
        assert out["items"][0]["items"] == []

        with pytest.raises(AdminLogicHttpError) as missing_reset:
            execute_rate_limit_reset_counters(plugins=[rl], plugin_name="other")
        assert missing_reset.value.status_code == 404

    def test_execute_records_purge_expired_paths(self) -> None:
        """Brief: cover purge-expired success, filtering, and failure branches."""

        assert execute_records_purge_expired(
            runtime_state=None,
            plugins=[],
            target="etc_hosts",
            plugin_name="etc",
        )["removed"] == 0

        class _RuntimeNoFn:
            pass

        assert execute_records_purge_expired(
            runtime_state=_RuntimeNoFn(),
            plugins=[],
            target="etc_hosts",
            plugin_name="etc",
        )["failed"] == 0

        class _Runtime:
            def purge_expired_temporary_records(self) -> list[dict[str, Any]]:
                return [
                    {"key": "a", "target": "etc_hosts", "plugin": "etc", "payload": {"name": "x.example"}},
                    {"key": "b", "target": "etc_hosts", "plugin": "etc", "payload": {"name": "boom.example"}},
                    {"key": "c", "target": "zone_records", "plugin": "zr", "payload": {"owner": "a", "qtype": "A", "value": "1.1.1.1"}},
                    {"key": "d", "target": "etc_hosts", "plugin": "other", "payload": {"name": "skip.example"}},
                ]

        plugin = EtcHosts()
        plugin.name = "etc"

        def _delete(**kwargs: Any) -> dict[str, Any]:
            if kwargs.get("name") == "boom.example":
                raise RuntimeError("delete failed")
            return {"deleted": kwargs}

        plugin.admin_delete_record_mutation = _delete

        out = execute_records_purge_expired(
            runtime_state=_Runtime(),
            plugins=[plugin],
            target="etc_hosts",
            plugin_name="etc",
        )
        assert out["status"] == "ok"
        assert out["removed"] == 1
        assert out["failed"] == 1
        statuses = {item["status"] for item in out["items"]}
        assert statuses == {"removed", "failed"}

        with pytest.raises(AdminLogicHttpError) as not_found:
            execute_records_purge_expired(
                runtime_state=_Runtime(),
                plugins=[],
                target="etc_hosts",
                plugin_name="etc",
            )
        assert not_found.value.status_code == 404

    def test_build_upstream_status_payload_typeerror_snapshot_fallback(
        self, set_runtime_snapshot
    ) -> None:
        """Brief: snapshot(reset=False) TypeError falls back to snapshot()."""

        upstreams = [{"host": "8.8.8.8", "port": 53}]
        snap_obj = SimpleNamespace(
            upstreams={
                "8.8.8.8:53": {"success": 4, "timeout": 2, "ok": 3, "bad": -4}
            }
        )

        class _Collector:
            def __init__(self) -> None:
                self.calls: list[tuple[Any, ...]] = []

            def snapshot(self, *args: Any, **kwargs: Any) -> Any:
                self.calls.append((args, kwargs))
                if "reset" in kwargs:
                    raise TypeError("no reset kw")
                return snap_obj

        set_runtime_snapshot(
            upstream_addrs=upstreams,
            upstream_backup_addrs=[],
            upstream_strategy="failover",
            upstream_max_concurrent="not-int",
            stats_collector=_Collector(),
        )
        payload = build_upstream_status_payload({}, now_ts=1707752400.0)
        assert payload["max_concurrent"] == 1
        item = payload["items"][0]
        assert item["run_query_count"] == 9
        assert item["run_failed_count"] == 2

    def test_build_upstream_status_payload_snapshot_and_items_edge_paths(
        self, set_runtime_snapshot
    ) -> None:
        """Brief: upstream status handles malformed collector snapshot and backup rows."""

        upstreams = [{"host": "1.1.1.1", "port": 53}, "bad-upstream"]
        backup = [{"host": "9.9.9.9", "port": 53}, {"endpoint": "https://dns.example/dns-query"}]

        class _CollectorNoSnapshot:
            snapshot = None

        set_runtime_snapshot(
            upstream_addrs=upstreams,
            upstream_backup_addrs=backup,
            upstream_max_concurrent=0,
            stats_collector=_CollectorNoSnapshot(),
        )
        payload = build_upstream_status_payload({}, now_ts=1707752400.0)
        assert payload["max_concurrent"] == 1
        # Only dict upstream entries should produce items.
        assert len(payload["items"]) == 3
        assert {it["role"] for it in payload["items"]} == {"primary", "backup"}
        for item in payload["items"]:
            assert item["run_query_count"] == 0
            assert item["run_failed_count"] == 0

    def test_execute_records_apply_delete_error_and_unknown_target_paths(self) -> None:
        """Brief: cover plugin-missing/unsupported/unknown-target and plugin error branches."""

        with pytest.raises(AdminLogicHttpError) as missing_apply:
            execute_records_apply(
                plugins=[],
                target="etc_hosts",
                plugin_name="missing",
                payload={},
            )
        assert missing_apply.value.status_code == 404

        plugin = EtcHosts()
        plugin.name = "etc"

        with pytest.raises(AdminLogicHttpError) as unsupported_apply:
            execute_records_apply(
                plugins=[plugin],
                target="etc_hosts",
                plugin_name="etc",
                payload={"name": "a.example", "value": "192.0.2.1"},
            )
        assert unsupported_apply.value.status_code == 400

        plugin.admin_apply_record_mutation = (
            lambda **kwargs: (_ for _ in ()).throw(ValueError("apply failed"))
        )
        with pytest.raises(AdminLogicHttpError) as apply_failed:
            execute_records_apply(
                plugins=[plugin],
                target="etc_hosts",
                plugin_name="etc",
                payload={"name": "a.example", "value": "192.0.2.1"},
            )
        assert apply_failed.value.status_code == 400

        plugin.admin_delete_record_mutation = (
            lambda **kwargs: (_ for _ in ()).throw(ValueError("delete failed"))
        )
        with pytest.raises(AdminLogicHttpError) as delete_failed:
            execute_records_delete(
                plugins=[plugin],
                target="etc_hosts",
                plugin_name="etc",
                payload={"name": "a.example"},
            )
        assert delete_failed.value.status_code == 400

        with pytest.raises(AdminLogicHttpError) as unknown_apply:
            execute_records_apply(
                plugins=[plugin],
                target="unknown",
                plugin_name="etc",
                payload={},
            )
        assert unknown_apply.value.status_code == 400

        with pytest.raises(AdminLogicHttpError) as unknown_delete:
            execute_records_delete(
                plugins=[plugin],
                target="unknown",
                plugin_name="etc",
                payload={},
            )
        assert unknown_delete.value.status_code == 400
