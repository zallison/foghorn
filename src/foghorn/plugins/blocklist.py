from __future__ import annotations
import time
import os
import sqlite3
import logging
from typing import Optional

from foghorn.plugins.base import PluginDecision, PluginContext
from foghorn.plugins.base import BasePlugin, plugin_aliases
from foghorn.cache import TTLCache

logger = logging.getLogger(__name__)


@plugin_aliases("blocklist", "block", "allow")
class BlocklistPlugin(BasePlugin):
    """
    DNS allow/deny plugin backed by SQLite.

    Brief: Loads allowlists and blocklists from config and files into a SQLite DB,
    denying queries for domains marked as "deny" while allowing others.
    """

    def __init__(self, **config) -> None:
        """
        Initialize plugin configuration and database.

        Inputs:
            **config: Supported keys
              - db_path (str): Path to the SQLite DB file. Default: ./blocklist.db
              - allowlist (list[str]): Domains to explicitly allow.
              - allowlist_files (list[str]): Files with newline-separated allow domains.
              - blocklist (list[str]): Domains to explicitly deny.
              - blocklist_files (list[str]): Files with newline-separated deny domains.
              - cache_ttl_seconds (int): In-memory cache TTL for is_allowed results. Default: 300.
        Outputs:
            None
        """
        super().__init__(**config)

        # Configuration
        self.db_path: str = self.config.get("db_path", "./blocklist.db")
        self.cache_ttl_seconds: int = int(self.config.get("cache_ttl_seconds", 300))

        self.blocklist = self.config.get("blocklist", [])
        self.blocklist_files = self.config.get("blocklist_files", [])

        self.allowlist = self.config.get("allowlist", [])
        self.allowlist_files = self.config.get("allowlist_files", [])

        # In-memory decision cache for is_allowed(domain)
        self._allow_cache = TTLCache()

        # Database setup
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db_init()

        # Preload configured domains/files
        for domain in self.allowlist:
            self._db_insert_domain(domain, "config", "allow")
        for file in self.allowlist_files:
            self.load_list_from_file(file, "allow")

        for domain in self.blocklist:
            self._db_insert_domain(domain, "config", "deny")
        for file in self.blocklist_files:
            self.load_list_from_file(file, "deny")

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Decide whether to deny the query based on stored mode.

        Inputs:
            qname: Queried domain name.
            qtype: DNS record type (unused).
            req: Raw DNS request bytes (unused).
            ctx: Plugin context.
        Outputs:
            PluginDecision("deny") when domain is denied; otherwise None to proceed.

        Example:
            >>> from foghorn.plugins.base import PluginContext
            >>> p = BlocklistPlugin(blocklist=["bad.com"])  # doctest: +ELLIPSIS
            >>> p.pre_resolve("bad.com", 1, b"", PluginContext("127.0.0.1")).action
            'deny'
        """
        if self.is_allowed(qname):
            return None
        return PluginDecision(action="deny")

    def _connect_to_db(self) -> sqlite3.Connection:
        """
        Create and return a SQLite connection.

        Inputs:
            None
        Outputs:
            sqlite3.Connection to the configured DB path.
        """
        return sqlite3.connect(self.db_path)

    def _db_init(self) -> None:
        """
        Create the blocked_domains table if it does not exist.

        Inputs:
            None
        Outputs:
            None
        """
        self.conn.execute(
            (
                "CREATE TABLE IF NOT EXISTS blocked_domains ("
                "domain TEXT PRIMARY KEY, "
                "filename TEXT, "
                "mode TEXT CHECK (mode IN ('allow','deny')) NOT NULL, "
                "added_at INTEGER NOT NULL"
                ")"
            )
        )
        # Clear blocklist.
        self.conn.execute(("TRUNCATE TABLE blocked_domains"))

        self.conn.commit()

    def _db_insert_domain(self, domain: str, filename: str, mode: str) -> None:
        """
        Insert or update a domain record.

        Inputs:
            domain: Domain name.
            filename: Source identifier (e.g., filepath or "config").
            mode: Either "allow" or "deny".
        Outputs:
            None
        """
        added_at = int(time.time())
        self.conn.execute(
            "INSERT OR REPLACE INTO blocked_domains (domain, filename, mode, added_at) "
            "VALUES (?, ?, ?, ?)",
            (domain, filename, mode, added_at),
        )
        self.conn.commit()

    def load_list_from_file(self, filename: str, mode: str = "deny") -> None:
        """
        Load domains from a newline-separated file into the database.

        Inputs:
            filename: Path to file containing domains.
            mode: Either "allow" or "deny". Default: "deny".
        Outputs:
            None

        Example:
            >>> import tempfile, os
            >>> fp = tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8")
            >>> _ = fp.write("example.com\n#comment\n\n")
            >>> _ = fp.flush(); fp.close()
            >>> p = BlocklistPlugin()
            >>> p.load_list_from_file(fp.name, mode="allow")
            >>> p.is_allowed("example.com")
            True
            >>> os.unlink(fp.name)
        """
        mode = mode.lower()
        if mode not in {"deny", "allow"}:
            raise ValueError("mode must be 'allow' or 'deny'")
        if not os.path.isfile(filename):
            logger.warning("List file %s not found", filename)
            return

        with open(filename, "r", encoding="utf-8") as fh:
            for line in fh:
                domain = line.strip()
                if not domain or domain.startswith("#"):
                    continue
                self._db_insert_domain(domain, filename, mode)
        # Invalidate decision cache after bulk updates
        self._allow_cache.purge_expired()  # opportunistic cleanup

    def is_allowed(self, domain: str) -> bool:
        """
        Return True if the domain is allowed. Results are cached.

        Inputs:
            domain: Domain name to check.
        Outputs:
            True when mode is "allow" or the domain is absent; False when "deny".

        Example:
            >>> p = BlocklistPlugin(blocklist=["bad.com"])  # doctest: +ELLIPSIS
            >>> p.is_allowed("good.com")
            True
            >>> p.is_allowed("bad.com")
            False
        """
        key = (str(domain).rstrip(".").lower(), 0)

        cached = self._allow_cache.get(key)
        if cached is not None:
            try:
                return cached == b"1"
            except Exception:
                pass

        cur = self.conn.execute(
            "SELECT mode FROM blocked_domains WHERE domain = ?",
            (key[0],),
        )
        row = cur.fetchone()
        allowed = True if not row else (row[0] == "allow")

        # Cache decision as '1' for True and '0' for False
        try:
            self._allow_cache.set(
                key, int(self.cache_ttl_seconds), b"1" if allowed else b"0"
            )
        except Exception:
            pass

        return allowed
