from __future__ import annotations

from .core import _StatsSQLiteStoreCore
from .query_log import _QueryLogMixin
from .rebuild import _RebuildMixin


class StatsSQLiteStore(_StatsSQLiteStoreCore, _QueryLogMixin, _RebuildMixin):
    """SQLite-backed persistent statistics store.

    Inputs (constructor):
        db_path: Filesystem path to the SQLite database file.
        batch_writes: Enable batched writes instead of per-call commits (default False).
        batch_time_sec: Maximum age (in seconds) of a batch before it is flushed.
        batch_max_size: Maximum number of queued operations before forced flush.

    Outputs:
        StatsSQLiteStore instance used to maintain aggregate counters (``counts``
        table) and an append-only DNS query log (``query_log`` table).

    The previous implementation stored :class:`StatsSnapshot` objects as JSON
    blobs in a ``stats_snapshots`` table. That approach has been replaced with
    a more normalized schema that is suitable for analytics and reconstruction
    of statistics across restarts.

    Example:
        >>> store = StatsSQLiteStore('./config/var/stats.db')
        >>> store.increment_count('totals', 'total_queries')
        >>> store.increment_count('domains', 'example.com')
    """

    pass
