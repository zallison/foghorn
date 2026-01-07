from __future__ import annotations

import logging
import threading
from typing import Dict, List, Optional, Tuple

from dnslib import QTYPE, DNSRecord
from pydantic import BaseModel, Field

from foghorn.servers.server import resolve_query_bytes
from foghorn.servers.udp_server import DNSUDPHandler
from foghorn.stats import StatsCollector, StatsSnapshot

from .base import BasePlugin, PluginContext, PluginDecision, plugin_aliases

logger = logging.getLogger(__name__)


_PREFETCH_LOCAL = threading.local()


class DnsPrefetchConfig(BaseModel):
    """Brief: Typed configuration model for DnsPrefetch.

    Inputs:
      - interval_seconds: How often to sample statistics and perform prefetch cycles.
      - prefetch_top_n: Maximum number of domains considered per cycle based on
        cache_hit_domains/top_domains statistics.
      - max_consecutive_misses: Per-domain cap on consecutive prefetch cycles
        without any observed cache hit; once exceeded, prefetching for that
        domain is paused until a new cache hit is seen.
      - qtypes: List of DNS qtype names to prefetch (e.g. ["A", "AAAA"]).

    Outputs:
      - DnsPrefetchConfig instance with normalized field types.
    """

    interval_seconds: float = Field(default=60.0, ge=1.0)
    prefetch_top_n: int = Field(default=100, ge=1)
    max_consecutive_misses: int = Field(default=5, ge=1)
    qtypes: List[str] = Field(default_factory=lambda: ["A", "AAAA"])

    class Config:
        extra = "allow"


@plugin_aliases("dns_prefetch", "prefetch")
class DnsPrefetch(BasePlugin):
    """Prefetch DNS records for frequently requested domains using statistics.

    Brief:
      - Periodically inspects StatsCollector snapshots to identify hot domains
        (primarily cache_hit_domains and, as a fallback, top_domains).
      - Issues background DNS queries via resolve_query_bytes() for a bounded
        number of those domains and qtypes so that cache entries stay warm.
      - Applies a per-domain max_consecutive_misses cap so domains that never
        see cache hits after prefetching are automatically deprioritized.

    Example use in YAML config:

        plugins:
          - module: dns_prefetch
            config:
              interval_seconds: 60
              prefetch_top_n: 100
              max_consecutive_misses: 5
              qtypes: ["A", "AAAA"]
    """

    def __init__(self, **config: object) -> None:
        """Brief: Initialize DnsPrefetch from raw configuration.

        Inputs:
          - **config: Arbitrary keyword configuration, validated by
            DnsPrefetchConfig when available.

        Outputs:
          - None; initializes runtime attributes but does not start background
            threads until setup() is called.
        """

        super().__init__(**config)
        self._config_model = DnsPrefetchConfig(**(self.config or {}))
        self.interval_seconds: float = float(self._config_model.interval_seconds)
        self.prefetch_top_n: int = int(self._config_model.prefetch_top_n)
        self.max_consecutive_misses: int = int(
            self._config_model.max_consecutive_misses
        )
        self.qtypes: List[str] = list(self._config_model.qtypes or ["A", "AAAA"])

        # Per-domain tracking of observed cache hit counts and consecutive
        # prefetch cycles without any new hit.
        self._hit_counts: Dict[str, int] = {}
        self._miss_streaks: Dict[str, int] = {}

        self._stop_event: threading.Event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - DnsPrefetchConfig class for use by the core config loader.
        """

        return DnsPrefetchConfig

    def setup(self) -> None:
        """Brief: Start background thread that performs periodic prefetch cycles.

        Inputs:
          - None (uses configuration stored on self._config_model).

        Outputs:
          - None; spawns a daemon thread which runs until process exit or
            handle_sigusr2() requests stop.
        """

        if self.interval_seconds <= 0:
            # Disabled via configuration; no background prefetching.
            return

        if self._thread is not None and self._thread.is_alive():
            return

        self._thread = threading.Thread(
            target=self._run_loop,
            name="DnsPrefetch",
            daemon=True,
        )
        self._thread.start()

    def handle_sigusr2(self) -> None:
        """Brief: Stop the background prefetch loop on SIGUSR2 notifications.

        Inputs:
          - None.

        Outputs:
          - None; best-effort signal to stop the worker thread.
        """

        try:
            self._stop_event.set()
        except Exception:
            # Defensive: never let signal handling raise.
            logger.info("DnsPrefetch: failed to set stop event", exc_info=True)

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Pre-resolve hook (no-op for dns_prefetch).

        Inputs:
          - qname: Query domain name.
          - qtype: Query type integer.
          - req: Raw DNS request bytes.
          - ctx: PluginContext for the request.

        Outputs:
          - Always None; dns_prefetch does not alter individual queries.
        """

        # Avoid reacting to our own synthetic prefetch queries.
        if getattr(_PREFETCH_LOCAL, "in_prefetch", False):
            return None
        return None

    def post_resolve(
        self, qname: str, qtype: int, response_wire: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Post-resolve hook (currently a no-op for dns_prefetch).

        Inputs:
          - qname: Query domain name.
          - qtype: Query type integer.
          - response_wire: DNS response wire bytes.
          - ctx: PluginContext.

        Outputs:
          - Always None; dns_prefetch relies on background cycles instead of
            per-request behaviour.
        """

        if getattr(_PREFETCH_LOCAL, "in_prefetch", False):
            return None
        return None

    # ---------------- Internal helpers -----------------

    def _run_loop(self) -> None:
        """Brief: Worker loop that periodically performs one prefetch cycle.

        Inputs:
          - None (reads configuration and StatsCollector from DNSUDPHandler).

        Outputs:
          - None; runs until _stop_event is set.
        """

        while not self._stop_event.wait(self.interval_seconds):
            try:
                self._run_single_cycle()
            except Exception:
                logger.info("DnsPrefetch: prefetch cycle failed", exc_info=True)

    def _get_stats_collector(self) -> Optional[StatsCollector]:
        """Brief: Return the active StatsCollector if available.

        Inputs:
          - None.

        Outputs:
          - StatsCollector instance or None when statistics are disabled.
        """

        collector = getattr(DNSUDPHandler, "stats_collector", None)
        if isinstance(collector, StatsCollector):
            return collector
        return None

    def _run_single_cycle(self) -> None:
        """Brief: Execute a single prefetch cycle based on current statistics.

        Inputs:
          - None (uses DNSUDPHandler.stats_collector).

        Outputs:
          - None; issues at most prefetch_top_n background queries.
        """

        collector = self._get_stats_collector()
        if collector is None:
            return

        snap: StatsSnapshot = collector.snapshot(reset=False)

        # Prefer cache_hit_domains so we keep entries warm that are actually
        # being served from cache. Fall back to top_domains when no cache hits
        # have been observed yet.
        candidates: List[Tuple[str, int]] = []
        if snap.cache_hit_domains:
            candidates = list(snap.cache_hit_domains)
        elif snap.top_domains:
            candidates = list(snap.top_domains)

        if not candidates:
            return

        # Sort by descending count and take configured prefix.
        candidates.sort(key=lambda item: int(item[1]), reverse=True)
        limited = candidates[: self.prefetch_top_n]

        # Build a quick lookup for current hit counts so we can track whether
        # prefetching for a domain ever results in cache hits.
        current_hits: Dict[str, int] = {str(d): int(c) for d, c in limited}

        for domain, _count in limited:
            name = str(domain)
            prev_hits = int(self._hit_counts.get(name, 0))
            new_hits = int(current_hits.get(name, 0))

            if new_hits > prev_hits:
                # A real cache hit occurred since the last cycle; reset streak.
                self._hit_counts[name] = new_hits
                self._miss_streaks[name] = 0
            else:
                # No new cache hits observed for this domain since last cycle.
                streak = self._miss_streaks.get(name, 0) + 1
                self._miss_streaks[name] = streak
                if streak >= self.max_consecutive_misses:
                    # Stop prefetching this domain until a future cycle sees
                    # additional cache hits.
                    if streak >= self.max_consecutive_misses:
                        logger.info(
                            "DnsPrefetch: skipping %s (streak=%d, max=%d)",
                            name,
                            streak,
                            self.max_consecutive_misses,
                        )
                    continue

            self._prefetch_domain(name)

    def _prefetch_domain(self, domain: str) -> None:
        """Brief: Issue prefetch queries for a single domain across configured qtypes.

        Inputs:
          - domain: Domain name string to prefetch.

        Outputs:
          - None; best-effort, errors are logged at debug level.
        """

        if not domain:
            return

        for qtype_name in self.qtypes:
            try:
                self._prefetch_single(domain, qtype_name)
            except Exception:
                logger.info(
                    "DnsPrefetch: prefetch failed for %s %s",
                    domain,
                    qtype_name,
                    exc_info=True,
                )

    def _prefetch_single(self, domain: str, qtype_name: str) -> None:
        """Brief: Perform a single synthetic DNS query for domain/qtype pair.

        Inputs:
          - domain: Domain name string.
          - qtype_name: DNS qtype name (e.g., "A" or "AAAA").

        Outputs:
          - None; cache and upstream statistics are updated via the normal
            resolve_query_bytes pipeline, but no response is sent to any
            external client.
        """

        try:
            qtype_num = QTYPE.get(qtype_name, None)
        except Exception:
            qtype_num = None
        if qtype_num is None:
            return

        # Construct a standard DNS question. dnslib allows qtype as string.
        q = DNSRecord.question(domain, qtype_name)
        wire = q.pack()

        # Mark this thread as performing prefetch so plugin hooks can ignore
        # synthetic traffic.
        setattr(_PREFETCH_LOCAL, "in_prefetch", True)
        try:
            # Use a loopback-style client IP so operators can optionally hide
            # these internal queries from top_clients via statistics.ignore.
            resolve_query_bytes(wire, "127.0.0.1")
        finally:
            setattr(_PREFETCH_LOCAL, "in_prefetch", False)
