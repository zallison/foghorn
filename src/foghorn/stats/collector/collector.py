from __future__ import annotations

from .init import _StatsCollectorInitUtils
from .plugin_upstream import _StatsCollectorPluginUpstreamUtils
from .record import _StatsCollectorRecordUtils
from .snapshot import _StatsCollectorSnapshotUtils
from .warm_load import _StatsCollectorWarmLoadUtils


class StatsCollector(
    _StatsCollectorInitUtils,
    _StatsCollectorRecordUtils,
    _StatsCollectorPluginUpstreamUtils,
    _StatsCollectorSnapshotUtils,
    _StatsCollectorWarmLoadUtils,
):
    """
    Thread-safe statistics aggregator for DNS server metrics.

    Inputs (constructor):
        track_uniques: Enable unique client/domain tracking (default True)
        include_qtype_breakdown: Track query type distribution (default True)
        include_top_clients: Track top clients by request count (default False)
        include_top_domains: Track top domains by request count (default False)
        top_n: Number of top items to track (default 10)
        track_latency: Enable latency histogram (default False)
        max_unique_clients: Maximum unique clients retained in-memory when
            track_uniques is enabled (default 50000).
        max_unique_domains: Maximum unique domains retained in-memory when
            track_uniques is enabled (default 50000).
        ignore_top_clients: Optional list of client IPs/CIDRs to hide from top_clients
        ignore_top_domains: Optional list of base domains to hide from top_domains
        ignore_top_subdomains: Optional list of full qnames to hide from top_subdomains

    Outputs:
        StatsCollector instance for recording events and taking snapshots

    All public methods are thread-safe via a single RLock. Critical sections
    are kept minimal (O(1) operations only). The snapshot() method creates a
    deep copy for safe logging without holding the lock.

    Example:
        >>> collector = StatsCollector(track_uniques=True, track_latency=True)
        >>> collector.record_query('192.0.2.1', 'example.com', 'A')
        >>> collector.record_cache_hit('example.com')
        >>> collector.record_response_rcode('NOERROR')
        >>> snapshot = collector.snapshot(reset=False)
        >>> snapshot.totals['total_queries']
        1
    """

    pass
