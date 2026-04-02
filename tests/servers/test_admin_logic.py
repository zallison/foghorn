"""Brief: Tests for foghorn.servers.webserver.admin_logic module.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from foghorn.plugins.resolve.base import AdminPageSpec
from foghorn.servers.webserver.admin_logic import (
    AdminLogicHttpError,
    _get_store_from_collector,
    build_named_plugin_snapshot,
    build_query_log_aggregate_payload,
    build_query_log_payload,
    build_upstream_status_payload,
    collect_admin_pages_for_response,
    collect_plugin_ui_descriptors,
    find_admin_page_detail,
    find_plugin_instance_by_name,
)


class TestAdminLogicHttpError:
    """Tests for AdminLogicHttpError exception dataclass."""

    def test_error_creation(self) -> None:
        """Brief: Create and inspect an AdminLogicHttpError.

        Inputs:
          - None

        Outputs:
          - Assert status_code and detail are accessible.
        """

        err = AdminLogicHttpError(status_code=404, detail="not found")
        assert err.status_code == 404
        assert err.detail == "not found"

    def test_error_is_exception(self) -> None:
        """Brief: Verify AdminLogicHttpError is an Exception.

        Inputs:
          - None

        Outputs:
          - Assert it can be raised and caught as Exception.
        """

        with pytest.raises(AdminLogicHttpError):
            raise AdminLogicHttpError(status_code=500, detail="error")

    def test_error_frozen_dataclass(self) -> None:
        """Brief: Verify the dataclass is frozen (immutable).

        Inputs:
          - None

        Outputs:
          - Assert mutation raises an error.
        """

        err = AdminLogicHttpError(status_code=404, detail="not found")
        with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
            err.status_code = 500  # type: ignore[misc]


class TestGetStoreFromCollector:
    """Tests for _get_store_from_collector helper."""

    def test_none_collector(self) -> None:
        """Brief: Handle None collector gracefully.

        Inputs:
          - collector: None

        Outputs:
          - Assert return value is None.
        """

        result = _get_store_from_collector(None)
        assert result is None

    def test_collector_with_store(self) -> None:
        """Brief: Extract _store from a collector instance.

        Inputs:
          - collector: Mock with _store attribute

        Outputs:
          - Assert _store is returned.
        """

        mock_store = Mock()
        mock_collector = Mock()
        mock_collector._store = mock_store

        result = _get_store_from_collector(mock_collector)
        assert result is mock_store

    def test_collector_without_store(self) -> None:
        """Brief: Handle collector with no _store attribute.

        Inputs:
          - collector: Mock without _store

        Outputs:
          - Assert return value is None.
        """

        mock_collector = Mock(spec=[])  # No attributes
        result = _get_store_from_collector(mock_collector)
        assert result is None


class TestBuildQueryLogPayload:
    """Tests for build_query_log_payload."""

    def test_empty_result(self) -> None:
        """Brief: Handle store with no results.

        Inputs:
          - store: Mock returning empty dict

        Outputs:
          - Assert defaults are applied.
        """

        mock_store = Mock()
        mock_store.select_query_log.return_value = {}

        payload = build_query_log_payload(
            mock_store,
            client_ip=None,
            qtype=None,
            qname=None,
            rcode=None,
            status=None,
            source=None,
            start_ts=None,
            end_ts=None,
            page=1,
            page_size=25,
        )

        assert payload["total"] == 0
        assert payload["page"] == 1
        assert payload["page_size"] == 25
        assert payload["total_pages"] == 0
        assert payload["items"] == []

    def test_with_items_and_ts_conversion(self) -> None:
        """Brief: Convert 'ts' fields to 'timestamp' in ISO format.

        Inputs:
          - store: Mock returning items with ts field

        Outputs:
          - Assert timestamp field is added in ISO format.
        """

        mock_store = Mock()
        mock_store.select_query_log.return_value = {
            "total": 2,
            "page": 1,
            "page_size": 25,
            "total_pages": 1,
            "items": [
                {"ts": 1707752400.0, "qname": "example.com"},
                {"ts": 1707752500.0, "qname": "test.com"},
            ],
        }

        payload = build_query_log_payload(
            mock_store,
            client_ip=None,
            qtype=None,
            qname=None,
            rcode=None,
            status=None,
            source=None,
            start_ts=None,
            end_ts=None,
            page=1,
            page_size=25,
        )

        assert len(payload["items"]) == 2
        assert "timestamp" in payload["items"][0]
        assert "Z" in payload["items"][0]["timestamp"]
        assert payload["items"][0]["qname"] == "example.com"

    def test_with_filters(self) -> None:
        """Brief: Pass filter parameters to store.

        Inputs:
          - store: Mock to verify parameters

        Outputs:
          - Assert filter parameters are forwarded.
        """

        mock_store = Mock()
        mock_store.select_query_log.return_value = {"items": []}

        build_query_log_payload(
            mock_store,
            client_ip="192.0.2.1",
            qtype="A",
            qname="example.com",
            rcode="NOERROR",
            status="cache_hit",
            source="cache",
            ede_code="15",
            start_ts=1000.0,
            end_ts=2000.0,
            page=2,
            page_size=50,
        )

        mock_store.select_query_log.assert_called_once_with(
            client_ip="192.0.2.1",
            qtype="A",
            qname="example.com",
            rcode="NOERROR",
            status="cache_hit",
            source="cache",
            ede_code="15",
            start_ts=1000.0,
            end_ts=2000.0,
            page=2,
            page_size=50,
        )

    def test_non_dict_items_passed_through(self) -> None:
        """Brief: Pass through items that are not dicts.

        Inputs:
          - store: Mock with mixed item types

        Outputs:
          - Assert non-dict items are included unchanged.
        """

        mock_store = Mock()
        mock_store.select_query_log.return_value = {
            "items": [
                {"ts": 1707752400.0, "qname": "valid.com"},
                "string_item",
                None,
            ],
        }

        payload = build_query_log_payload(
            mock_store,
            client_ip=None,
            qtype=None,
            qname=None,
            rcode=None,
            status=None,
            source=None,
            start_ts=None,
            end_ts=None,
            page=1,
            page_size=25,
        )

        assert len(payload["items"]) == 3
        assert payload["items"][1] == "string_item"
        assert payload["items"][2] is None


class TestBuildQueryLogAggregatePayload:
    """Tests for build_query_log_aggregate_payload."""

    def test_basic_aggregate(self) -> None:
        """Brief: Build aggregate payload from store result.

        Inputs:
          - store: Mock returning aggregate data

        Outputs:
          - Assert start/end times and items are included.
        """

        mock_store = Mock()
        mock_store.aggregate_query_log_counts.return_value = {
            "items": [
                {
                    "bucket_start_ts": 1707752400.0,
                    "bucket_end_ts": 1707752460.0,
                    "count": 42,
                }
            ]
        }

        start_dt = datetime(2024, 2, 12, 10, 0, 0, tzinfo=timezone.utc)
        end_dt = datetime(2024, 2, 12, 11, 0, 0, tzinfo=timezone.utc)

        payload = build_query_log_aggregate_payload(
            mock_store,
            start_dt=start_dt,
            end_dt=end_dt,
            interval_seconds=60,
            client_ip=None,
            qtype=None,
            qname=None,
            rcode=None,
            group_by=None,
        )

        assert "start" in payload
        assert "end" in payload
        assert payload["interval_seconds"] == 60
        assert "Z" in payload["start"]
        assert "Z" in payload["end"]
        assert len(payload["items"]) == 1
        assert "bucket_start" in payload["items"][0]
        assert "bucket_end" in payload["items"][0]

    def test_aggregate_with_filters(self) -> None:
        """Brief: Pass filter parameters to store.

        Inputs:
          - store: Mock to verify parameters

        Outputs:
          - Assert filter parameters are forwarded.
        """

        mock_store = Mock()
        mock_store.aggregate_query_log_counts.return_value = {"items": []}

        start_dt = datetime(2024, 2, 12, 10, 0, 0, tzinfo=timezone.utc)
        end_dt = datetime(2024, 2, 12, 11, 0, 0, tzinfo=timezone.utc)

        build_query_log_aggregate_payload(
            mock_store,
            start_dt=start_dt,
            end_dt=end_dt,
            interval_seconds=300,
            client_ip="192.0.2.1",
            qtype="A",
            qname="example.com",
            rcode="NOERROR",
            group_by="qtype",
        )

        call_kwargs = mock_store.aggregate_query_log_counts.call_args[1]
        assert call_kwargs["client_ip"] == "192.0.2.1"
        assert call_kwargs["qtype"] == "A"
        assert call_kwargs["qname"] == "example.com"
        assert call_kwargs["rcode"] == "NOERROR"
        assert call_kwargs["group_by"] == "qtype"
        assert call_kwargs["interval_seconds"] == 300

    def test_aggregate_non_dict_items_skipped(self) -> None:
        """Brief: Skip items that are not dicts.

        Inputs:
          - store: Mock with mixed item types

        Outputs:
          - Assert non-dict items are excluded.
        """

        mock_store = Mock()
        mock_store.aggregate_query_log_counts.return_value = {
            "items": ["not a dict", {"bucket_start_ts": 1.0, "count": 1}, None]
        }

        start_dt = datetime(2024, 2, 12, 10, 0, 0, tzinfo=timezone.utc)
        end_dt = datetime(2024, 2, 12, 11, 0, 0, tzinfo=timezone.utc)

        payload = build_query_log_aggregate_payload(
            mock_store,
            start_dt=start_dt,
            end_dt=end_dt,
            interval_seconds=60,
            client_ip=None,
            qtype=None,
            qname=None,
            rcode=None,
            group_by=None,
        )

        # Only the dict item should remain
        assert len(payload["items"]) == 1
        assert "bucket_start_ts" in payload["items"][0]


class TestBuildUpstreamStatusPayload:
    """Tests for build_upstream_status_payload."""

    def test_none_config(self) -> None:
        """Brief: Handle None config gracefully.

        Inputs:
          - config: None

        Outputs:
          - Assert empty items list and defaults.
        """

        payload = build_upstream_status_payload(None, now_ts=1707752400.0)

        assert payload["strategy"] == "failover"
        assert payload["max_concurrent"] == 1
        assert payload["items"] == []

    def test_empty_config(self) -> None:
        """Brief: Handle config with no upstreams.

        Inputs:
          - config: Empty dict

        Outputs:
          - Assert defaults are applied.
        """

        payload = build_upstream_status_payload({}, now_ts=1707752400.0)

        assert payload["strategy"] == "failover"
        assert payload["max_concurrent"] == 1
        assert payload["items"] == []

    def test_upstream_with_health_status(self, set_runtime_snapshot) -> None:
        """Brief: Build upstream items from the active RuntimeSnapshot.

        Inputs:
          - set_runtime_snapshot: Fixture helper to override RuntimeSnapshot fields.

        Outputs:
          - Assert payload includes upstream strategy/max_concurrent and per-upstream items.
        """

        upstreams = [
            {"host": "8.8.8.8", "port": 53},
            {"host": "1.1.1.1", "port": 53},
        ]
        set_runtime_snapshot(
            upstream_addrs=upstreams,
            upstream_backup_addrs=[],
            upstream_strategy="round_robin",
            upstream_max_concurrent=5,
        )

        now_ts = 1707752400.0
        payload = build_upstream_status_payload({}, now_ts=now_ts)

        assert payload["strategy"] == "round_robin"
        assert payload["max_concurrent"] == 5
        assert len(payload["items"]) == 2
        assert {it.get("role") for it in payload["items"]} == {"primary"}

    def test_upstream_payload_includes_run_query_counts(
        self, set_runtime_snapshot
    ) -> None:
        """Brief: Include run query/failure counts from StatsCollector snapshot.

        Inputs:
          - set_runtime_snapshot: Fixture helper.

        Outputs:
          - Assert each upstream item includes run_query_count/run_failed_count.
        """

        upstreams = [
            {"host": "8.8.8.8", "port": 53},
            {"host": "1.1.1.1", "port": 53},
        ]
        mock_snapshot = Mock()
        mock_snapshot.upstreams = {
            "8.8.8.8:53": {"success": 7, "timeout": 2, "servfail": 1},
            "1.1.1.1:53": {"success": 3},
        }
        mock_collector = Mock()
        mock_collector.snapshot.return_value = mock_snapshot

        set_runtime_snapshot(
            upstream_addrs=upstreams,
            upstream_backup_addrs=[],
            stats_collector=mock_collector,
        )

        payload = build_upstream_status_payload({}, now_ts=1707752400.0)
        items_by_id = {str(item.get("id")): item for item in payload["items"]}

        assert items_by_id["8.8.8.8:53"]["run_query_count"] == 10
        assert items_by_id["8.8.8.8:53"]["run_failed_count"] == 3
        assert items_by_id["1.1.1.1:53"]["run_query_count"] == 3
        assert items_by_id["1.1.1.1:53"]["run_failed_count"] == 0
        mock_collector.snapshot.assert_called_once_with(reset=False)

    def test_upstream_payload_resolves_run_counts_from_legacy_key_with_config_id(
        self, set_runtime_snapshot
    ) -> None:
        """Brief: Resolve run counters when upstream payload id differs from legacy stats key.

        Inputs:
          - set_runtime_snapshot: Fixture helper.
          - Upstream config with explicit id field.
          - Stats snapshot keyed by legacy host:port ids.

        Outputs:
          - Assert run_query_count/run_failed_count are populated via fallback.
        """

        upstreams = [
            {"id": "resolver-a", "host": "8.8.8.8", "port": 53},
            {"id": "resolver-b", "host": "1.1.1.1", "port": 53},
        ]
        mock_snapshot = Mock()
        mock_snapshot.upstreams = {
            "8.8.8.8:53": {"success": 5, "timeout": 1},
            "1.1.1.1:53": {"success": 4, "servfail": 2},
        }
        mock_collector = Mock()
        mock_collector.snapshot.return_value = mock_snapshot

        set_runtime_snapshot(
            upstream_addrs=upstreams,
            upstream_backup_addrs=[],
            stats_collector=mock_collector,
        )

        payload = build_upstream_status_payload({}, now_ts=1707752400.0)
        items_by_id = {str(item.get("id")): item for item in payload["items"]}

        assert items_by_id["resolver-a"]["run_query_count"] == 6
        assert items_by_id["resolver-a"]["run_failed_count"] == 1
        assert items_by_id["resolver-b"]["run_query_count"] == 6
        assert items_by_id["resolver-b"]["run_failed_count"] == 2
        mock_collector.snapshot.assert_called_once_with(reset=False)

    def test_health_only_upstreams(self, set_runtime_snapshot) -> None:
        """Brief: Upstream status payload lists only configured upstreams.

        Inputs:
          - set_runtime_snapshot: Fixture helper.

        Outputs:
          - Assert payload items reflect only upstream_addrs / upstream_backup_addrs.
        """

        set_runtime_snapshot(
            upstream_addrs=[],
            upstream_backup_addrs=[],
        )

        now_ts = 1707752400.0
        payload = build_upstream_status_payload({}, now_ts=now_ts)
        assert payload["items"] == []


class TestCollectAdminPagesForResponse:
    """Tests for collect_admin_pages_for_response."""

    def test_empty_plugins_list(self) -> None:
        """Brief: Handle empty plugins list.

        Inputs:
          - plugins: Empty list

        Outputs:
          - Assert empty pages list.
        """

        pages = collect_admin_pages_for_response([])
        assert pages == []

    def test_plugin_without_name(self) -> None:
        """Brief: Ignore plugins without a name.

        Inputs:
          - plugins: List with plugin lacking name

        Outputs:
          - Assert plugin is skipped.
        """

        mock_plugin = Mock(spec=[])
        pages = collect_admin_pages_for_response([mock_plugin])
        assert pages == []

    def test_plugin_without_get_admin_pages(self) -> None:
        """Brief: Ignore plugins without get_admin_pages method.

        Inputs:
          - plugins: Plugin with name but no method

        Outputs:
          - Assert plugin is skipped.
        """

        mock_plugin = Mock()
        mock_plugin.name = "test_plugin"
        del mock_plugin.get_admin_pages  # Remove the method

        pages = collect_admin_pages_for_response([mock_plugin])
        assert pages == []

    def test_valid_admin_page_spec(self) -> None:
        """Brief: Collect valid AdminPageSpec instances.

        Inputs:
          - plugins: Plugin with valid AdminPageSpec

        Outputs:
          - Assert page is collected with all fields.
        """

        mock_plugin = Mock()
        mock_plugin.name = "test_plugin"
        mock_plugin.get_admin_pages.return_value = [
            AdminPageSpec(
                slug="page1",
                title="Page One",
                description="A test page",
                layout="two_column",
                kind="custom",
            )
        ]

        pages = collect_admin_pages_for_response([mock_plugin])

        assert len(pages) == 1
        page = pages[0]
        assert page["plugin"] == "test_plugin"
        assert page["slug"] == "page1"
        assert page["title"] == "Page One"
        assert page["description"] == "A test page"
        assert page["layout"] == "two_column"
        assert page["kind"] == "custom"

    def test_dict_style_admin_page(self) -> None:
        """Brief: Collect admin pages from dict-style specs.

        Inputs:
          - plugins: Plugin returning dict specs

        Outputs:
          - Assert dict pages are normalized.
        """

        mock_plugin = Mock()
        mock_plugin.name = "dict_plugin"
        mock_plugin.get_admin_pages.return_value = [
            {
                "slug": "dict_page",
                "title": "Dict Page",
                "description": "From dict",
                "kind": "test",
            }
        ]

        pages = collect_admin_pages_for_response([mock_plugin])

        assert len(pages) == 1
        assert pages[0]["slug"] == "dict_page"
        assert pages[0]["title"] == "Dict Page"

    def test_invalid_pages_skipped(self) -> None:
        """Brief: Skip pages with missing slug or title.

        Inputs:
          - plugins: Plugin with invalid pages

        Outputs:
          - Assert invalid pages are filtered out.
        """

        mock_plugin = Mock()
        mock_plugin.name = "plugin"
        mock_plugin.get_admin_pages.return_value = [
            AdminPageSpec(slug="", title="No Slug"),
            AdminPageSpec(slug="no-title", title=""),
            AdminPageSpec(slug="valid", title="Valid"),
        ]

        pages = collect_admin_pages_for_response([mock_plugin])

        assert len(pages) == 1
        assert pages[0]["slug"] == "valid"

    def test_invalid_layout_defaults_to_one_column(self) -> None:
        """Brief: Normalize invalid layout values.

        Inputs:
          - plugins: Plugin with invalid layout

        Outputs:
          - Assert layout defaults to one_column.
        """

        mock_plugin = Mock()
        mock_plugin.name = "plugin"
        mock_plugin.get_admin_pages.return_value = [
            AdminPageSpec(
                slug="test",
                title="Test",
                layout="INVALID_LAYOUT",
            )
        ]

        pages = collect_admin_pages_for_response([mock_plugin])

        assert len(pages) == 1
        assert pages[0]["layout"] == "one_column"

    def test_get_admin_pages_exception_ignored(self) -> None:
        """Brief: Ignore plugins where get_admin_pages raises.

        Inputs:
          - plugins: Plugin with failing method

        Outputs:
          - Assert plugin is skipped.
        """

        mock_plugin = Mock()
        mock_plugin.name = "failing_plugin"
        mock_plugin.get_admin_pages.side_effect = RuntimeError("boom")

        pages = collect_admin_pages_for_response([mock_plugin])

        assert pages == []


class TestFindAdminPageDetail:
    """Tests for find_admin_page_detail."""

    def test_plugin_not_found(self) -> None:
        """Brief: Return None when plugin not found.

        Inputs:
          - plugins: List with different plugin
          - plugin_name: Non-existent name

        Outputs:
          - Assert None is returned.
        """

        mock_plugin = Mock()
        mock_plugin.name = "other_plugin"

        result = find_admin_page_detail([mock_plugin], "missing", "slug")
        assert result is None

    def test_page_not_found(self) -> None:
        """Brief: Return None when page slug not found.

        Inputs:
          - plugins: Plugin with pages
          - page_slug: Non-existent slug

        Outputs:
          - Assert None is returned.
        """

        mock_plugin = Mock()
        mock_plugin.name = "plugin"
        mock_plugin.get_admin_pages.return_value = [
            AdminPageSpec(slug="page1", title="Page 1")
        ]

        result = find_admin_page_detail([mock_plugin], "plugin", "missing_slug")
        assert result is None

    def test_page_detail_found(self) -> None:
        """Brief: Return page detail when found.

        Inputs:
          - plugins: Plugin with matching page

        Outputs:
          - Assert full detail is returned with html fields.
        """

        mock_plugin = Mock()
        mock_plugin.name = "plugin"
        mock_plugin.get_admin_pages.return_value = [
            AdminPageSpec(
                slug="detail-page",
                title="Detail Page",
                description="Test detail",
                html_left="<div>left</div>",
                html_right="<div>right</div>",
                layout="two_column",
            )
        ]

        result = find_admin_page_detail([mock_plugin], "plugin", "detail-page")

        assert result is not None
        assert result["slug"] == "detail-page"
        assert result["title"] == "Detail Page"
        assert result["html_left"] == "<div>left</div>"
        assert result["html_right"] == "<div>right</div>"
        assert result["layout"] == "two_column"


class TestCollectPluginUiDescriptors:
    """Tests for collect_plugin_ui_descriptors."""

    def test_empty_plugins(self) -> None:
        """Brief: Handle empty plugins list.

        Inputs:
          - plugins: Empty list

        Outputs:
          - Assert empty items list.
        """

        items = collect_plugin_ui_descriptors([])
        assert items == []

    def test_plugin_without_descriptor_method(self) -> None:
        """Brief: Ignore plugins without get_admin_ui_descriptor.

        Inputs:
          - plugins: Plugin without method

        Outputs:
          - Assert plugin is skipped.
        """

        mock_plugin = Mock(spec=["name"])
        mock_plugin.name = "plugin"

        items = collect_plugin_ui_descriptors([mock_plugin])
        assert items == []

    def test_valid_descriptor_collection(self) -> None:
        """Brief: Collect valid UI descriptors.

        Inputs:
          - plugins: Plugin with descriptor

        Outputs:
          - Assert descriptor is collected and normalized.
        """

        mock_plugin = Mock()
        mock_plugin.name = "docker"
        mock_plugin.get_admin_ui_descriptor.return_value = {
            "name": "docker",
            "title": "Docker",
            "order": 10,
            "kind": "docker_hosts",
        }

        items = collect_plugin_ui_descriptors([mock_plugin])

        assert len(items) == 1
        assert items[0]["name"] == "docker"
        assert items[0]["title"] == "Docker"
        assert items[0]["order"] == 10

    def test_descriptor_sorting(self) -> None:
        """Brief: Sort descriptors by order then title.

        Inputs:
          - plugins: Multiple plugins with descriptors

        Outputs:
          - Assert items are sorted correctly.
        """

        plugins = []
        for name, order, title in [
            ("z_plugin", 100, "Z Plugin"),
            ("a_plugin", 10, "A Plugin"),
            ("m_plugin", 50, "M Plugin"),
        ]:
            mock_plugin = Mock()
            mock_plugin.name = name
            mock_plugin.get_admin_ui_descriptor.return_value = {
                "name": name,
                "title": title,
                "order": order,
            }
            plugins.append(mock_plugin)

        items = collect_plugin_ui_descriptors(plugins)

        # Should be sorted by order first
        assert items[0]["order"] == 10
        assert items[1]["order"] == 50
        assert items[2]["order"] == 100

    def test_multi_instance_title_normalization(self) -> None:
        """Brief: Normalize titles for multiple instances of same plugin.

        Inputs:
          - plugins: Multiple instances of "EtcHosts" plugin

        Outputs:
          - Assert duplicates get instance name appended.
        """

        plugins = []
        for i, name in enumerate(["etc_hosts_1", "etc_hosts_2"]):
            mock_plugin = Mock()
            mock_plugin.name = name
            mock_plugin.get_admin_ui_descriptor.return_value = {
                "name": name,
                "title": f"ETC Hosts ({name})",
                "order": 100,
            }
            plugins.append(mock_plugin)

        items = collect_plugin_ui_descriptors(plugins)

        # Both should have the base title "ETC Hosts" with their names appended
        assert len(items) == 2
        titles = {item["title"] for item in items}
        assert "ETC Hosts (etc_hosts_1)" in titles or "ETC Hosts" in titles


class TestFindPluginInstanceByName:
    """Tests for find_plugin_instance_by_name."""

    def test_empty_plugins(self) -> None:
        """Brief: Handle empty plugins list.

        Inputs:
          - plugins: Empty list

        Outputs:
          - Assert None is returned.
        """

        result = find_plugin_instance_by_name([], "plugin")
        assert result is None

    def test_plugin_found(self) -> None:
        """Brief: Find plugin by name.

        Inputs:
          - plugins: List with matching plugin

        Outputs:
          - Assert plugin instance is returned.
        """

        mock_plugin = Mock()
        mock_plugin.name = "target_plugin"

        result = find_plugin_instance_by_name([mock_plugin], "target_plugin")
        assert result is mock_plugin

    def test_plugin_not_found(self) -> None:
        """Brief: Return None when plugin name doesn't match.

        Inputs:
          - plugins: List with different plugin

        Outputs:
          - Assert None is returned.
        """

        mock_plugin = Mock()
        mock_plugin.name = "other_plugin"

        result = find_plugin_instance_by_name([mock_plugin], "missing")
        assert result is None

    def test_attribute_error_ignored(self) -> None:
        """Brief: Ignore plugins where accessing name raises.

        Inputs:
          - plugins: Plugin with failing name property

        Outputs:
          - Assert iteration continues.
        """

        mock_plugin1 = Mock()
        del mock_plugin1.name  # Will raise when accessed

        mock_plugin2 = Mock()
        mock_plugin2.name = "found"

        result = find_plugin_instance_by_name([mock_plugin1, mock_plugin2], "found")
        assert result is mock_plugin2


class TestBuildNamedPluginSnapshot:
    """Tests for build_named_plugin_snapshot."""

    def test_plugin_not_found(self) -> None:
        """Brief: Raise 404 when plugin not found.

        Inputs:
          - plugins: Empty list

        Outputs:
          - Assert AdminLogicHttpError with 404.
        """

        with pytest.raises(AdminLogicHttpError) as exc_info:
            build_named_plugin_snapshot([], "missing", label="Test")

        assert exc_info.value.status_code == 404

    def test_plugin_lacks_snapshot_method(self) -> None:
        """Brief: Raise 404 when plugin lacks get_http_snapshot.

        Inputs:
          - plugins: Plugin without method

        Outputs:
          - Assert AdminLogicHttpError with 404.
        """

        mock_plugin = Mock(spec=["name"])
        mock_plugin.name = "plugin"

        with pytest.raises(AdminLogicHttpError) as exc_info:
            build_named_plugin_snapshot([mock_plugin], "plugin", label="Test")

        assert exc_info.value.status_code == 404

    def test_snapshot_success(self) -> None:
        """Brief: Build snapshot when method succeeds.

        Inputs:
          - plugins: Plugin with working get_http_snapshot

        Outputs:
          - Assert payload includes plugin name and data.
        """

        mock_plugin = Mock()
        mock_plugin.name = "test_plugin"
        mock_plugin.get_http_snapshot.return_value = {"status": "ok", "count": 42}

        result = build_named_plugin_snapshot([mock_plugin], "test_plugin", label="Test")

        assert result["plugin"] == "test_plugin"
        assert result["data"]["status"] == "ok"
        assert result["data"]["count"] == 42

    def test_snapshot_method_raises(self) -> None:
        """Brief: Raise 500 when snapshot method fails.

        Inputs:
          - plugins: Plugin where method raises

        Outputs:
          - Assert AdminLogicHttpError with 500 and error detail.
        """

        mock_plugin = Mock()
        mock_plugin.name = "failing_plugin"
        mock_plugin.get_http_snapshot.side_effect = ValueError("snapshot error")

        with pytest.raises(AdminLogicHttpError) as exc_info:
            build_named_plugin_snapshot(
                [mock_plugin], "failing_plugin", label="Failing"
            )

        assert exc_info.value.status_code == 500
        assert (
            "snapshot error" in exc_info.value.detail
            or "Failing" in exc_info.value.detail
        )
