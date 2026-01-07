from __future__ import annotations

import logging
import sqlite3
import threading
import time
from typing import Optional

from pydantic import BaseModel, Field

from foghorn.utils.current_cache import get_current_namespaced_cache, module_namespace
from foghorn.utils.register_caches import registered_lru_cached
from foghorn.plugins.resolve.base import BasePlugin, PluginContext, PluginDecision

log = logging.getLogger(__name__)


class GreylistConfig(BaseModel):
    """Brief: Typed configuration model for GreylistExample.

    Inputs:
      - duration_seconds: Greylist window in seconds.
      - duration_hours: Legacy hours-based window.
      - db_path: Path to sqlite DB.
      - cache_ttl_seconds: TTL for in-memory cache.
      - cache_max_entries: Max entries in cache.

    Outputs:
      - GreylistConfig instance with normalized field types.
    """

    duration_seconds: Optional[int] = Field(default=None, ge=0)
    duration_hours: int = Field(default=24, ge=0)
    db_path: str = Field(default="./config/var/greylist.db")
    cache_ttl_seconds: int = Field(default=300, ge=0)
    cache_max_entries: int = Field(default=100000, ge=0)

    class Config:
        extra = "allow"


class GreylistExample(BasePlugin):
    """
    A greylisting plugin that uses a persistent sqlite3 database and a fast
    in-memory cache.

    Brief: Implements DNS greylisting with permanent allow after initial window.

    This plugin checks the last two segments of a domain name to see if it has
    been requested before. If not, it stores the domain and the time it was
    seen, and denies the request. If it has been seen before, it checks if it
    is older than a configurable amount of time. If it is, the request is
    permanently allowed (first_seen is never updated after the initial deny).

    Key behavior:
    - Base domain key: last two labels of qname (e.g., "sub.example.com" -> "example.com")
    - Greylist window: configurable duration_seconds after first_seen
    - Once allowed after window: permanently allowed (until data is purged externally)
    - No schema changes: uses existing first_seen timestamp without updates
    """

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - GreylistConfig class for use by the core config loader.
        """

        return GreylistConfig

    def start(self, **config):
        """
        Initializes the GreylistExample.

        Args:
            **config: Plugin-specific configuration.
        """
        self.duration_seconds = self.config.get(
            "duration_seconds", self.config.get("duration_hours", 24) * 3600
        )
        self.db_path = self.config.get("db_path", "./config/var/greylist.db")
        self.cache_ttl_seconds = self.config.get("cache_ttl_seconds", 300)
        self.cache_max_entries = self.config.get("cache_max_entries", 100000)

        self._lock = threading.Lock()
        self._db_init()
        self._cache = get_current_namespaced_cache(
            namespace=module_namespace(__file__),
            cache_plugin=self.config.get("cache"),
        )

    def _db_init(self):
        """
        Initializes the sqlite3 database.
        """
        with self._lock:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS greylist ("
                "domain TEXT PRIMARY KEY, "
                "first_seen INTEGER NOT NULL"
                ")"
            )

    @registered_lru_cached(maxsize=1024)
    def _to_base_domain(self, qname: str) -> str:
        """
        Extracts the last two labels of a domain name.

        Args:
            qname: The domain name to process.

        Returns:
            The last two labels of the domain name.
        """
        s = str(qname).rstrip(".").lower()
        labels = [p for p in s.split(".") if p]
        if len(labels) >= 2:
            return ".".join(labels[-2:])
        else:
            return s

    def _db_get_first_seen(self, domain: str) -> Optional[int]:
        """
        Retrieves the first seen timestamp for a domain from the database.

        Args:
            domain: The domain to look up.

        Returns:
            The first seen timestamp, or None if the domain is not found.
        """
        cur = self.conn.cursor()
        cur.execute("SELECT first_seen FROM greylist WHERE domain=?", (domain,))
        row = cur.fetchone()
        return row[0] if row else None

    def _db_upsert_first_seen(self, domain: str, now: int):
        """
        Inserts the first seen timestamp for a domain in the database.

        Args:
            domain: The domain to update.
            now: The current timestamp.
        """
        with self._lock:
            self.conn.execute(
                "INSERT or IGNORE INTO greylist (domain, first_seen) VALUES (?, ?) ",
                (domain, now),
            )
            self.conn.commit()

    def _cache_get_or_db_load(self, domain: str) -> Optional[int]:
        """
        Retrieves the first seen timestamp from the cache, or loads it from the
        database if it is not in the cache.

        Args:
            domain: The domain to look up.

        Returns:
            The first seen timestamp, or None if the domain is not found.
        """
        cached = self._cache.get((domain, 0))
        if cached is not None:
            return int(cached.decode())

        first_seen = self._db_get_first_seen(domain)
        if first_seen is not None:
            self._cache.set(
                (domain, 0), self.cache_ttl_seconds, str(first_seen).encode()
            )
        return first_seen

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        A hook that runs before the DNS query is resolved.

        Args:
            qname: The queried domain name.
            qtype: The query type.
            req: The raw DNS request.
            ctx: The plugin context.

        Returns:
            A PluginDecision, or None to allow the query to proceed.
        """
        if not self.targets(ctx):
            return None

        now = int(time.time())
        base_domain = self._to_base_domain(qname)
        first_seen = self._cache_get_or_db_load(base_domain)

        if first_seen is None:
            log.debug(f"Greylist first-seen deny for {base_domain}")
            self._db_upsert_first_seen(base_domain, now)
            self._cache.set((base_domain, 0), self.cache_ttl_seconds, str(now).encode())
            return PluginDecision(action="deny")

        if now - first_seen >= self.duration_seconds:
            log.debug(f"Greylist allow for {base_domain}")
            # Do not update first_seen to preserve permanent allow after window
            return None
        else:
            time_left = self.duration_seconds - (now - first_seen)
            log.debug(f"Greylist deny ({time_left} seconds left) for {base_domain}")
            return PluginDecision(action="deny")
