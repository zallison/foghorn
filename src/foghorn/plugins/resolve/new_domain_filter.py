from __future__ import annotations

import datetime as dt
import logging
import sqlite3
import threading
import time
from typing import Any, Optional

from pydantic import BaseModel, Field

from foghorn.utils.current_cache import get_current_namespaced_cache, module_namespace

# Try to import popular whois libraries in a robust way
try:
    import whois as _whois_mod  # python-whois typically exposes whois(domain)
except Exception:  # pragma: no cover - import best effort
    _whois_mod = None

try:  # optional fallback library
    import pythonwhois as _pythonwhois_mod  # exposes get_whois(domain)
except Exception:  # pragma: no cover - import best effort
    _pythonwhois_mod = None

from .base import BasePlugin, PluginContext, PluginDecision, plugin_aliases

logger = logging.getLogger(__name__)


class NewDomainFilterExampleConfig(BaseModel):
    """Brief: Typed configuration model for NewDomainFilterExample.

    Inputs:
      - threshold_days: Minimum allowed domain age in days.
      - whois_db_path: Path to WHOIS cache DB.
      - whois_cache_ttl_seconds: In-memory cache TTL.
      - whois_refresh_seconds: Max age of DB entries before refresh.

    Outputs:
      - NewDomainFilterExampleConfig instance with normalized field types.
    """

    threshold_days: int = Field(default=7, ge=0)
    whois_db_path: str = Field(default="./config/var/whois_cache.db")
    whois_cache_ttl_seconds: int = Field(default=3600, ge=0)
    whois_refresh_seconds: int = Field(default=86400, ge=0)

    class Config:
        extra = "allow"


@plugin_aliases("new_domain", "new_domain_filter", "ndf")
class NewDomainFilterExample(BasePlugin):
    """Plugin that filters out domains registered too recently.

    Brief:
      - Uses WHOIS data (with in-memory and sqlite caches) to compute domain age
        in days and denies queries for domains younger than a configurable
        threshold.

    Example use in YAML config:

        plugins:
          - module: foghorn.plugins.new_domain_filter.NewDomainFilterExample
            config:
              threshold_days: 30
    """

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - NewDomainFilterExampleConfig class for use by the core config loader.
        """

        return NewDomainFilterExampleConfig

    def setup(self):
        """
        Initializes the NewDomainFilterExample.

        Inputs:
          - None (configuration is taken from ``self.config`` set by BasePlugin).

        Outputs:
          - None (sets threshold_days, WHOIS cache/DB configuration and opens DB).

        Example:
          >>> from foghorn.plugins.new_domain_filter import NewDomainFilterExample
          >>> plugin = NewDomainFilterExample(threshold_days=10)
          >>> plugin.setup()
          >>> plugin.threshold_days
          10
        """
        # BasePlugin.__init__ has already stored configuration in self.config;
        # setup() is responsible only for deriving runtime attributes.
        self.threshold_days: int = int(self.config.get("threshold_days", 7))

        # Caching configuration
        self.whois_db_path: str = self.config.get(
            "whois_db_path", "./config/var/whois_cache.db"
        )
        self.whois_cache_ttl_seconds: int = int(
            self.config.get("whois_cache_ttl_seconds", 3600)
        )
        self.whois_refresh_seconds: int = int(
            self.config.get("whois_refresh_seconds", 86400)
        )

        # In-memory cache and persistent DB for WHOIS results
        self._whois_cache = get_current_namespaced_cache(
            namespace=module_namespace(__file__),
            cache_plugin=self.config.get("cache"),
        )
        self._db_lock = threading.Lock()
        self._db_init()

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Checks the age of the domain and denies the request if it's too new.
        Args:
            qname: The queried domain name.
            qtype: The query type.
            req: The raw DNS request.
            ctx: The plugin context.
        Returns:
            A PluginDecision to deny the request if the domain is too new, otherwise None.
        """
        if not self.targets(ctx):
            return None

        """

        Example use:
            (Note: This is a simplified example that doesn't actually make a network request)
            >>> from foghorn.plugins.new_domain_filter import NewDomainFilterExample
            >>> from foghorn.plugins.resolve.base import PluginContext
            >>> from unittest.mock import patch
            >>> plugin = NewDomainFilterExample(threshold_days=30)
            >>> with patch.object(plugin, '_domain_age_days', return_value=10):
            ...     decision = plugin.pre_resolve("new.com", 1, b'', PluginContext("1.2.3.4"))
            ...     decision.action
            'deny'
        """
        age_days = self._domain_age_days(qname)
        if age_days is None:
            logger.debug("Domain age unknown for %s, allowing", qname)
            return None  # unknown; allow
        if age_days < self.threshold_days:
            logger.warning(
                "Domain %s blocked (age: %d days, threshold: %d)",
                qname,
                age_days,
                self.threshold_days,
            )
            return PluginDecision(action="deny")

        logger.debug("Domain %s allowed (age: %d days)", qname, age_days)
        return None

    def _domain_age_days(self, domain: str) -> Optional[int]:
        """
        Determines the age of a domain in days by querying WHOIS data.

        Inputs:
            domain: str - The domain name to check.

        Outputs:
            Optional[int] - The age of the domain in days, or None if it cannot be determined.

        Example use:
            (Note: This example is for illustration and won't make a real network request)
            >>> from unittest.mock import patch
            >>> from foghorn.plugins.new_domain_filter import NewDomainFilterExample
            >>> plugin = NewDomainFilterExample()
            >>> with patch.object(plugin, '_fetch_creation_date', return_value=dt.datetime(2023, 1, 1, tzinfo=dt.timezone.utc)):
            ...     isinstance(plugin._domain_age_days("example.com"), int)
            True
        """
        try:
            creation_date = self._fetch_creation_date(domain)
            if (
                not creation_date
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                return None

            now = dt.datetime.now(dt.timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=dt.timezone.utc)

            delta = now - creation_date
            return max(0, delta.days)
        except Exception as e:
            logger.warning("Failed to get domain age for %s: %s", domain, str(e))
            return None

    def _fetch_creation_date(self, domain: str) -> Optional[dt.datetime]:
        """
        Fetches the domain creation date with caching.
        Uses an in-memory TTL cache (foghorn.cache.FoghornTTLCache) and a persistent
        sqlite3 database for long-term cache.

        Inputs:
            domain: str - The domain name.

        Outputs:
            Optional[datetime] - A timezone-aware creation datetime if available; otherwise None.
        """
        # 1) Fast in-memory cache
        cached = self._whois_cache.get((domain, 1))
        if cached is not None:
            try:
                ts = int(cached.decode())
                return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc)
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably

        # 2) Persistent DB cache
        rec = self._db_get_creation_record(domain)
        now_ts = int(time.time())
        if rec is not None:
            creation_ts, fetched_at = rec
            if now_ts - fetched_at < self.whois_refresh_seconds:
                # Fresh enough; populate memory cache and return
                self._whois_cache.set(
                    (domain, 1), self.whois_cache_ttl_seconds, str(creation_ts).encode()
                )
                return dt.datetime.fromtimestamp(int(creation_ts), tz=dt.timezone.utc)

        # 3) Network lookup as last resort
        creation_date = self._whois_lookup_creation_date(domain)
        if (
            creation_date is None
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            return None

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=dt.timezone.utc)
        creation_ts = int(creation_date.timestamp())

        # Persist and cache
        self._db_upsert_creation_record(domain, creation_ts, now_ts)
        self._whois_cache.set(
            (domain, 1), self.whois_cache_ttl_seconds, str(creation_ts).encode()
        )
        return creation_date

    def _whois_lookup_creation_date(self, domain: str) -> Optional[dt.datetime]:
        """
        Performs the actual WHOIS lookups using available libraries.
        Tries multiple libraries to be robust against environment differences.

        Inputs:
            domain: str - The domain name.

        Outputs:
            Optional[datetime] - A creation datetime if available; otherwise None.
        """
        # Attempt python-whois API: whois.whois(domain)
        if _whois_mod is not None:
            try:
                whois_fn: Any = getattr(_whois_mod, "whois", None)
                if callable(whois_fn):
                    w = whois_fn(domain)
                    creation_date = getattr(w, "creation_date", None)
                    if creation_date:
                        if isinstance(creation_date, list):
                            creation_date = min(creation_date)
                        return creation_date
                # Some other whois packages expose query(domain)
                query_fn: Any = getattr(_whois_mod, "query", None)
                if callable(query_fn):
                    q = query_fn(domain)
                    creation_date = getattr(q, "creation_date", None)
                    if creation_date:
                        return creation_date
            except Exception as e:  # pragma: no cover - best effort
                logger.debug("python-whois lookup failed for %s: %s", domain, e)

        # Attempt pythonwhois API: pythonwhois.get_whois(domain)
        if _pythonwhois_mod is not None:
            try:
                data = _pythonwhois_mod.get_whois(domain)
                creation_date = (
                    data.get("creation_date") if isinstance(data, dict) else None
                )
                if creation_date:
                    if isinstance(creation_date, list):
                        creation_date = min(creation_date)
                    return creation_date
            except Exception as e:  # pragma: no cover - best effort
                logger.debug("pythonwhois lookup failed for %s: %s", domain, e)

        return None

    def _db_init(self) -> None:
        """
        Initializes the sqlite3 database for WHOIS caching.

        Inputs:
            None

        Outputs:
            None
        """
        with self._db_lock:
            self._conn = sqlite3.connect(self.whois_db_path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS domain_whois ("
                "domain TEXT PRIMARY KEY, "
                "creation_ts INTEGER NOT NULL, "
                "fetched_at INTEGER NOT NULL"
                ")"
            )
            self._conn.commit()

    def _db_get_creation_record(self, domain: str) -> Optional[tuple[int, int]]:
        """
        Loads (creation_ts, fetched_at) from the DB for a domain.

        Inputs:
            domain: str

        Outputs:
            Optional[tuple[int,int]] - (creation_ts, fetched_at) or None.
        """
        cur = self._conn.cursor()
        cur.execute(
            "SELECT creation_ts, fetched_at FROM domain_whois WHERE domain=?", (domain,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return int(row[0]), int(row[1])

    def _db_upsert_creation_record(
        self, domain: str, creation_ts: int, now_ts: int
    ) -> None:
        """
        Inserts or updates WHOIS record for domain.

        Inputs:
            domain: str
            creation_ts: int - epoch seconds UTC
            now_ts: int - fetch time epoch seconds

        Outputs:
            None
        """
        with self._db_lock:
            self._conn.execute(
                "INSERT INTO domain_whois (domain, creation_ts, fetched_at) VALUES (?, ?, ?) "
                "ON CONFLICT(domain) DO UPDATE SET creation_ts=excluded.creation_ts, fetched_at=excluded.fetched_at",
                (domain, int(creation_ts), int(now_ts)),
            )
            self._conn.commit()
