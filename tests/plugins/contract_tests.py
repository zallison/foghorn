from foghorn.plugins.querylog.base import (
    BaseStatsStore,
    QueryLogAggregateResult,
    QueryLogSelectResult,
)
from foghorn.plugins.resolve.base import BasePlugin, PluginContext, PluginDecision


class ResolvePluginContract:
    """Contract tests for plugins inheriting from BasePlugin."""

    def __init__(self, plugin: BasePlugin):
        self.plugin = plugin

    def test_basic_interface(self):
        """Ensure all expected hooks are present."""
        assert hasattr(self.plugin, "pre_resolve"), "Plugin must implement pre_resolve"
        assert hasattr(
            self.plugin, "post_resolve"
        ), "Plugin must implement post_resolve"
        assert hasattr(self.plugin, "targets"), "Plugin must implement targets"

    def test_priority_bounds(self):
        """Ensure priorities are within the expected 1-255 range."""
        assert (
            1 <= self.plugin.pre_priority <= 255
        ), f"pre_priority {self.plugin.pre_priority} out of bounds"
        assert (
            1 <= self.plugin.post_priority <= 255
        ), f"post_priority {self.plugin.post_priority} out of bounds"
        assert (
            1 <= self.plugin.setup_priority <= 255
        ), f"setup_priority {self.plugin.setup_priority} out of bounds"

    def test_targets_returns_bool(self):
        """Ensure targets() always returns a boolean."""
        ctx = PluginContext(client_ip="1.1.1.1")
        result = self.plugin.targets(ctx)
        assert isinstance(
            result, bool
        ), f"targets() should return bool, got {type(result)}"

    def test_pre_resolve_return_type(self):
        """Ensure pre_resolve returns Optional[PluginDecision]."""
        ctx = PluginContext(client_ip="1.1.1.1")
        # We don't care about the value, just the type
        result = self.plugin.pre_resolve("example.com", 1, b"", ctx)
        if result is not None:
            assert isinstance(result, PluginDecision)

    def test_post_resolve_return_type(self):
        """Ensure post_resolve returns Optional[PluginDecision]."""
        ctx = PluginContext(client_ip="1.1.1.1")
        # We don't care about the value, just the type
        result = self.plugin.post_resolve("example.com", 1, b"response", ctx)
        if result is not None:
            assert isinstance(result, PluginDecision)

    def test_name_is_set(self):
        """Ensure the plugin has a non-empty name."""
        assert hasattr(self.plugin, "name"), "Plugin must have a 'name' attribute"
        assert len(str(self.plugin.name)) > 0, "Plugin name should not be empty"


class StatsStoreContract:
    """Contract tests for backends inheriting from BaseStatsStore."""

    def __init__(self, store: BaseStatsStore):
        self.store = store

    def test_lifecycle_methods(self):
        """Ensure required lifecycle methods are implemented."""
        assert hasattr(self.store, "health_check")
        assert hasattr(self.store, "close")

    def test_count_methods(self):
        """Ensure required counter methods are implemented."""
        assert hasattr(self.store, "increment_count")
        assert hasattr(self.store, "set_count")
        assert hasattr(self.store, "has_counts")
        assert hasattr(self.store, "export_counts")

    def test_query_log_methods(self):
        """Ensure required query-log methods are implemented."""
        assert hasattr(self.store, "insert_query_log")
        assert hasattr(self.store, "select_query_log")
        assert hasattr(self.store, "aggregate_query_log_counts")

    def test_select_query_log_return_type(self):
        """Ensure select_query_log returns QueryLogSelectResult."""
        # We don't care about the value, just the type
        result = self.store.select_query_log(
            qname="example.com",
            page=1,
            page_size=100,
            filters={},
            sort_by="timestamp",
            sort_order="desc",
        )
        assert isinstance(result, QueryLogSelectResult)

    def test_aggregate_query_log_counts_return_type(self):
        """Ensure aggregate_query_log_counts returns QueryLogAggregateResult."""
        # We don't care about the value, just the type
        result = self.store.aggregate_query_log_counts(
            qname="example.com", interval_seconds=60, group_by="rcode"
        )
        assert isinstance(result, QueryLogAggregateResult)

    def test_metrics_keys(self):
        """Ensure get_async_queue_metrics returns expected keys."""
        metrics = self.store.get_async_queue_metrics()
        expected_keys = {
            "capacity",
            "size",
            "pct_full",
            "drops_total",
            "drops_by_op",
            "drops_by_reason",
        }
        assert expected_keys.issubset(
            metrics.keys()
        ), f"Missing metrics keys: {expected_keys - metrics.keys()}"
