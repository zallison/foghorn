from __future__ import annotations
import time
import sqlite3
import threading
import logging
from typing import Optional

from foghorn.plugins.base import BasePlugin, PluginDecision, PluginContext
from foghorn.cache import TTLCache

log = logging.getLogger(__name__)

class GreylistPlugin(BasePlugin):
    """
    A greylisting plugin that uses a persistent sqlite3 database and a fast
    in-memory cache.

    This plugin checks the last two segments of a domain name to see if it has
    been requested before. If not, it stores the domain and the time it was
    seen, and denies the request. If it has been seen before, it checks if it
    is older than a configurable amount of time. If it is, the request is
    allowed, otherwise it is denied.
    """

    def __init__(self, **config):
        """
        Initializes the GreylistPlugin.

        Args:
            **config: Plugin-specific configuration.
        """
        super().__init__(**config)
        self.duration_seconds = self.config.get('duration_seconds', self.config.get('duration_hours', 24) * 3600)
        self.db_path = self.config.get('db_path', './greylist.db')
        self.cache_ttl_seconds = self.config.get('cache_ttl_seconds', 300)
        self.cache_max_entries = self.config.get('cache_max_entries', 100000)

        self._lock = threading.Lock()
        self._db_init()
        self._cache = TTLCache()

    def _db_init(self):
        """
        Initializes the sqlite3 database.
        """
        with self._lock:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.execute('PRAGMA journal_mode=WAL')
            self.conn.execute(
                'CREATE TABLE IF NOT EXISTS greylist ('
                'domain TEXT PRIMARY KEY, '
                'last_seen INTEGER NOT NULL'
                ')'
            )

    def _to_base_domain(self, qname: str) -> str:
        """
        Extracts the last two labels of a domain name.

        Args:
            qname: The domain name to process.

        Returns:
            The last two labels of the domain name.
        """
        s = str(qname).rstrip('.').lower()
        labels = [p for p in s.split('.') if p]
        if len(labels) >= 2:
            return '.'.join(labels[-2:])
        else:
            return s

    def _db_get_last_seen(self, domain: str) -> Optional[int]:
        """
        Retrieves the last seen timestamp for a domain from the database.

        Args:
            domain: The domain to look up.

        Returns:
            The last seen timestamp, or None if the domain is not found.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT last_seen FROM greylist WHERE domain=?', (domain,))
        row = cur.fetchone()
        return row[0] if row else None

    def _db_upsert_last_seen(self, domain: str, now: int):
        """
        Inserts or updates the last seen timestamp for a domain in the database.

        Args:
            domain: The domain to update.
            now: The current timestamp.
        """
        with self._lock:
            self.conn.execute(
                'INSERT INTO greylist (domain, last_seen) VALUES (?, ?) '
                'ON CONFLICT(domain) DO UPDATE SET last_seen=excluded.last_seen',
                (domain, now),
            )
            self.conn.commit()

    def _cache_get_or_db_load(self, domain: str) -> Optional[int]:
        """
        Retrieves the last seen timestamp from the cache, or loads it from the
        database if it is not in the cache.

        Args:
            domain: The domain to look up.

        Returns:
            The last seen timestamp, or None if the domain is not found.
        """
        cached = self._cache.get((domain, 0))
        if cached is not None:
            return int(cached.decode())
        
        last_seen = self._db_get_last_seen(domain)
        if last_seen is not None:
            self._cache.set((domain, 0), self.cache_ttl_seconds, str(last_seen).encode())
        return last_seen

    def pre_resolve(self, qname: str, qtype: int, req: bytes, ctx: PluginContext) -> Optional[PluginDecision]:
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
        now = int(time.time())
        base_domain = self._to_base_domain(qname)
        last_seen = self._cache_get_or_db_load(base_domain)

        if last_seen is None:
            log.debug(f'Greylist first-seen deny for {base_domain}')
            self._db_upsert_last_seen(base_domain, now)
            self._cache.set((base_domain, 0), self.cache_ttl_seconds, str(now).encode())
            return PluginDecision(action='deny')

        if now - last_seen >= self.duration_seconds:
            log.debug(f'Greylist allow for {base_domain}')
            self._db_upsert_last_seen(base_domain, now)
            self._cache.set((base_domain, 0), self.cache_ttl_seconds, str(now).encode())
            return None
        else:
            log.debug(f'Greylist deny (cooldown) for {base_domain}')
            return PluginDecision(action='deny')

