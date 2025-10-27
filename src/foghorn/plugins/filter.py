from __future__ import annotations
import ipaddress
import logging
import re
import sqlite3
import os
import time
from typing import Optional, List, Set, Union, Dict
from dnslib import DNSRecord, QTYPE, RCODE
from foghorn.cache import TTLCache

from .base import BasePlugin, PluginDecision, PluginContext, plugin_aliases

logger = logging.getLogger(__name__)


@plugin_aliases("filter")
class FilterPlugin(BasePlugin):
    """
    A comprehensive filtering plugin that filters both domains and IP addresses.

    Pre-resolve filtering blocks domains based on:
    - Exact domain matches
    - Domain patterns (regex or substring matching)
    - Keyword filtering (e.g., blocking domains containing certain words)

    Post-resolve filtering blocks or modifies responses based on:
    - Specific IP addresses with per-IP actions
    - IP ranges/subnets with per-range actions
    - Actions: "remove" (remove from response), "deny" (return NXDOMAIN), or "replace" (substitute with another IP)

    Example use:
        In config.yaml:
        plugins:
          - module: foghorn.plugins.filter.FilterPlugin
            config:
              # Pre-resolve (domain) filterings (exact match)
              allowed_domains:
                - www.example.com
              blocked_domains:
                - "malware.com"
                - "example-bad.org"
              blocked_patterns:
                - ".*\\.porn\\..*"
                - "casino.*"
              blocked_keywords:
                - "porn"
                - "gambling"
                - "malware"
              # Post-resolve (IP) filtering with per-IP actions
              blocked_ips:
                - ip: "192.0.2.1"
                  action: "deny"
                - ip: "198.51.100.0/24"
                  action: "remove"
                - ip: "203.0.113.5"
                  action: "replace"
                  replace_with: "127.0.0.1"
                - ip: "2001:db8::/32"
                  action: "deny"
              # Alternative simple format (defaults to deny)
              # blocked_ips:
              #   - "192.0.2.1"
              #   - "198.51.100.0/24"
    """

    def __init__(self, **config):
        """
        Initializes the FilterPlugin.

        Args:
            **config: Configuration for the plugin containing domain and IP filters.
        """
        super().__init__(**config)
        self._domain_cache = TTLCache()

        self.cache_ttl_seconds = self.config.get("cache_ttl_seconds", 600) # 10 minutes
        self.db_path: str = self.config.get("db_path", "./var/blocklist.db")
        self.default = self.config.get("default", "deny")
        self.blocklist_files = self.config.get("blocklist_files", [])
        self.allowlist_files = self.config.get("allowlist_files", [])
        self.blocklist = self.config.get("blocked_domains", [])
        self.allowlist = self.config.get("allow_domainss", [])

        self._connect_to_db()
        self._db_init()

        # Preload configured domains/files
        for file in self.allowlist_files:
            self.load_list_from_file(file, "allow")
        for file in self.blocklist_files:
            self.load_list_from_file(file, "deny")

        for domain in self.blocklist:
            self._db_insert_domain(domain, "config", "deny")
        for domain in self.allowlist:
            self._db_insert_domain(domain, "config", "allow")


        # Pre-resolve (domain) filtering configuration
        self.blocked_domains: Set[str] = set(self.config.get("blocked_domains", []))
        self.blocked_patterns: List[re.Pattern] = []
        self.blocked_keywords: Set[str] = set(self.config.get("blocked_keywords", []))

        # Compile regex patterns for domain filtering
        for pattern in self.config.get("blocked_patterns", []):
            try:
                self.blocked_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                logger.error("Invalid regex pattern '%s': %s", pattern, e)

        # Post-resolve (IP) filtering configuration
        # Maps IP networks/addresses to their actions ("remove" or "deny")
        self.blocked_networks: Dict[
            Union[ipaddress.IPv4Network, ipaddress.IPv6Network], Dict
        ] = {}
        self.blocked_ips: Dict[
            Union[ipaddress.IPv4Address, ipaddress.IPv6Address], Dict
        ] = {}

        # Parse IP addresses and networks with actions
        for ip_config in self.config.get("blocked_ips", []):
            try:
                # Handle both simple string format and dict format
                if isinstance(ip_config, str):
                    ip_spec = ip_config
                    action = "deny"  # default action
                elif isinstance(ip_config, dict):
                    ip_spec = ip_config.get("ip", "")
                    action = ip_config.get("action", "deny").lower()
                else:
                    logger.error("Invalid blocked_ips entry format: %s", ip_config)
                    continue

                if action not in ("remove", "deny", "replace"):
                    logger.warning(
                        "Invalid action '%s' for IP '%s', defaulting to 'deny'",
                        action,
                        ip_spec,
                    )
                    action = "deny"

                if action == "replace":
                    replace_with = ip_config.get("replace_with")
                    if not replace_with:
                        logger.error(
                            "Action 'replace' for IP '%s' requires 'replace_with' field.",
                            ip_spec,
                        )
                        continue
                    try:
                        # Validate the replacement IP
                        ipaddress.ip_address(replace_with)
                    except ValueError as e:
                        logger.error(
                            "Invalid 'replace_with' IP address '%s' for rule '%s': %s",
                            replace_with,
                            ip_spec,
                            e,
                        )
                        continue

                if "/" in ip_spec:
                    # It's a network/subnet
                    network = ipaddress.ip_network(ip_spec, strict=False)
                    if action == "replace":
                        self.blocked_networks[network] = {
                            "action": action,
                            "replace_with": replace_with,
                        }
                    else:
                        self.blocked_networks[network] = {"action": action}
                else:
                    # It's a single IP address
                    ip_addr = ipaddress.ip_address(ip_spec)
                    if action == "replace":
                        self.blocked_ips[ip_addr] = {
                            "action": action,
                            "replace_with": replace_with,
                        }
                    else:
                        self.blocked_ips[ip_addr] = {"action": action}

            except ValueError as e:
                logger.error("Invalid IP address/network '%s': %s", ip_spec, e)

    def add_to_cache(self, key: any, allowed: bool):
        try:
            self._domain_cache.set(
                key, int(self.cache_ttl_seconds), b"1" if allowed else b"0"
            )
        except Exception as e:
            logging.warn(f"exception adding to cache {e}")
            pass

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Filters domains before DNS resolution based on blocked lists and patterns.

        Args:
            qname: The queried domain name.
            qtype: The query type.
            req: The raw DNS request.
            ctx: The plugin context.

        Returns:
            A PluginDecision to deny blocked domains, otherwise None.
        """
        domain = qname.lower()
        key = (str(domain).rstrip(".").lower(), 0)

        cached = self._domain_cache.get(key)
        if cached is not None:
            try:
                return cached == b"1"
            except Exception:
                pass

        if not self.is_allowed(domain):
            logger.debug("Domain '%s' blocked (exact match)", qname)
            self.add_to_cache(domain, b"0")
            return PluginDecision(action="deny")

        # Check keyword filtering
        for keyword in self.blocked_keywords:
            if keyword.lower() in domain:
                logger.debug(
                    "Domain '%s' blocked (contains keyword '%s')", qname, keyword
                )
                self.add_to_cache(domain, b"0")
                return PluginDecision(action="deny")

        # Check regex patterns
        for pattern in self.blocked_patterns:
            if pattern.search(domain):
                logger.debug(
                    "Domain '%s' blocked (matches pattern '%s')", qname, pattern.pattern
                )
                self.add_to_cache(domain, b"0")
                return PluginDecision(action="deny")

        logger.debug("Domain '%s' allowed", qname)
        self.add_to_cache(domain, b"1")

        return None

    def post_resolve(
        self, qname: str, qtype: int, response_wire: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Filters IP addresses in DNS responses after resolution.

        Args:
            qname: The queried domain name.
            qtype: The query type.
            response_wire: The response from the upstream server.
            ctx: The plugin context.

        Returns:
            A PluginDecision to modify or deny responses containing blocked IPs, otherwise None.
        """
        # Only process A and AAAA records
        if qtype not in (QTYPE.A, QTYPE.AAAA):
            return None

        if not self.blocked_ips and not self.blocked_networks:
            return None

        try:
            response = DNSRecord.parse(response_wire)
        except Exception as e:
            logger.debug("Failed to parse DNS response: %s", e)
            return None

        blocked_ips_deny = []  # IPs that should cause NXDOMAIN
        blocked_ips_remove = []  # IPs that should be removed
        modified_records = []
        original_records = list(response.rr)
        records_changed = False

        # Check each answer record
        for rr in original_records:
            if rr.rtype in (QTYPE.A, QTYPE.AAAA):
                try:
                    ip_addr = ipaddress.ip_address(str(rr.rdata))
                    action_config = self._get_ip_action(ip_addr)

                    if action_config:
                        action = action_config.get("action")
                        if action == "deny":
                            blocked_ips_deny.append(str(ip_addr))
                            logger.debug(
                                "Blocked IP %s for domain %s (action: deny)",
                                ip_addr,
                                qname,
                            )
                            records_changed = True
                        elif action == "remove":
                            blocked_ips_remove.append(str(ip_addr))
                            logger.debug(
                                "Blocked IP %s for domain %s (action: remove)",
                                ip_addr,
                                qname,
                            )
                            records_changed = True
                        elif action == "replace":
                            replace_ip_str = action_config.get("replace_with")
                            try:
                                replacement_ip = ipaddress.ip_address(replace_ip_str)
                                # Ensure IP versions are compatible
                                if ip_addr.version == replacement_ip.version:
                                    rr.rdata = replacement_ip
                                    modified_records.append(rr)
                                    logger.info(
                                        "Replaced IP %s with %s for domain %s",
                                        ip_addr,
                                        replacement_ip,
                                        qname,
                                    )
                                else:
                                    logger.warning(
                                        "Cannot replace IP %s with %s due to version mismatch.",
                                        ip_addr,
                                        replacement_ip,
                                    )
                                    modified_records.append(rr)
                                records_changed = True
                            except ValueError:
                                logger.error(
                                    "Invalid replacement IP: %s", replace_ip_str
                                )
                                modified_records.append(rr)
                        else:
                            modified_records.append(rr)
                    else:
                        modified_records.append(rr)
                except ValueError:
                    modified_records.append(rr)  # Keep non-IP records
            else:
                modified_records.append(rr)  # Keep non-A/AAAA records

        # If any IP has "deny" action, return NXDOMAIN for entire response
        if blocked_ips_deny:
            logger.debugg(
                "Denying %s due to blocked IPs with deny action: %s",
                qname,
                ", ".join(blocked_ips_deny),
            )
            return PluginDecision(action="deny")

        # If records were changed (removed or replaced), create a new response
        if records_changed:
            if not modified_records:
                # If all IPs were removed or failed to be replaced, return NXDOMAIN
                logger.warning(
                    "All IPs removed or failed to replace for %s, returning NXDOMAIN",
                    qname,
                )
                return PluginDecision(action="deny")

            # Create modified response with the updated records
            modified_response = response
            modified_response.rr = modified_records

            try:
                modified_wire = modified_response.pack()
                logger.info("Modified DNS response for %s", qname)
                return PluginDecision(action="override", response=modified_wire)
            except Exception as e:
                logger.error("Failed to create modified response: %s", e)
                return PluginDecision(action="deny")

        return None

    def _get_ip_action(
        self, ip_addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    ) -> Optional[Dict]:
        """
        Gets the action configuration for a blocked IP address.

        Args:
            ip_addr: The IP address to check.

        Returns:
            The action configuration dictionary (e.g., {"action": "replace", "replace_with": "1.2.3.4"})
            if blocked, None if not blocked.
        """
        # Check exact IP matches first (more specific)
        if ip_addr in self.blocked_ips:
            return self.blocked_ips[ip_addr]

        # Check network ranges
        for network, action in self.blocked_networks.items():
            if ip_addr in network:
                return action

        return None

    def _connect_to_db(self) -> sqlite3.Connection:
        """Create and return a SQLite connection."""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)

    def _db_init(self) -> None:
        """Create the blocked_domains table if it does not exist."""

        # Clear blocklist, maybe
        if self.config.get("clear", 1):
            logger.debug("clearing allow/deny databases")
            self.conn.execute("DROP TABLE IF EXISTS blocked_domains")

        logger.debug("Creating blocked_domains database")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS blocked_domains ("
            "domain TEXT PRIMARY KEY, "
            "filename TEXT, "
            "mode TEXT CHECK (mode IN ('allow','deny')) NOT NULL, "
            "added_at INTEGER NOT NULL"
            ")"
        )

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
        """
        mode = mode.lower()
        if mode not in {"deny", "allow"}:
            raise ValueError("mode must be 'allow' or 'deny'")

        if not os.path.isfile(filename):
            raise FileNotFoundError("No file %s", filename)

        logger.debug("Opening %s for %s", filename, mode)
        with open(filename, "r", encoding="utf-8") as fh:
            for line in fh:
                domain = line.strip()
                if not domain or domain.startswith("#"):
                    continue
                self._db_insert_domain(domain, filename, mode)

    def is_allowed(self, domain: str) -> bool:
        """
        Return True if the domain is allowed by exact match.

        Inputs:
            domain: Domain name to check.
        Outputs:
            True when mode is "allow" or not blocked and the default is allow
        """
        cur = self.conn.execute(
            "SELECT mode FROM blocked_domains WHERE domain = ?",
            (domain,),
        )
        row = cur.fetchone()
        allowed: bool = self.default == "allow"
        if row:
            allowed = row[0] == "allow"

        return allowed
