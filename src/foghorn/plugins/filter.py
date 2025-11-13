from __future__ import annotations
import csv
import glob
import ipaddress
import json
import logging
import re
import sqlite3
import os
import time
from typing import Optional, List, Set, Union, Dict, Iterator, Tuple
from dnslib import DNSRecord, QTYPE, RCODE, A as RDATA_A, AAAA as RDATA_AAAA
from foghorn.cache import TTLCache

from .base import BasePlugin, PluginDecision, PluginContext, plugin_aliases

logger = logging.getLogger(__name__)


@plugin_aliases("filter", "block", "allow")
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
                Supported keys (in addition to existing ones):
                  - allowed_domains_files: list[str] of files or globs with one domain per line (comments with '#')
                  - blocked_domains_files: list[str] of files or globs with one domain per line
                  - blocked_patterns_files: list[str] of files or globs with one regex per line (IGNORECASE)
                  - blocked_keywords_files: list[str] of files or globs with one keyword per line
                  - blocked_ips_files: list[str] of files or globs; each line either
                        "IP_OR_CIDR" (defaults to deny),
                        "IP_OR_CIDR,action[,replace_with]" (CSV), or
                        JSON line: {"ip": "IP_OR_CIDR", "action": "deny|remove|replace", "replace_with": "IP"}
                Glob patterns are expanded. Missing files raise FileNotFoundError.
        """
        super().__init__(**config)
        self._domain_cache = TTLCache()

        self.cache_ttl_seconds = self.config.get("cache_ttl_seconds", 600)  # 10 minutes
        self.db_path: str = self.config.get("db_path", "./var/blocklist.db")
        self.default = self.config.get("default", "deny")

        # Back-compat keep existing keys, add new *_domains_files keys
        self.blocklist_files: List[str] = self._expand_globs(
            list(self.config.get("blocklist_files", []))
            + list(self.config.get("blocked_domains_files", []))
        )
        self.allowlist_files: List[str] = self._expand_globs(
            list(self.config.get("allowlist_files", []))
            + list(self.config.get("allowed_domains_files", []))
        )

        self.blocklist = self.config.get("blocked_domains", [])
        self.allowlist = self.config.get("allowed_domains", [])

        # Pre-resolve (domain) filtering configuration (inline first)
        self.blocked_domains: Set[str] = set(self.config.get("blocked_domains", []))
        self.blocked_patterns: List[re.Pattern] = []
        self.blocked_keywords: Set[str] = set(self.config.get("blocked_keywords", []))

        # Compile regex patterns for domain filtering from inline config
        for pattern in self.config.get("blocked_patterns", []):
            try:
                self.blocked_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:  # pragma: no cover
                logger.error("Invalid regex pattern '%s': %s", pattern, e)

        # Post-resolve (IP) filtering configuration
        # Maps IP networks/addresses to their actions
        self.blocked_networks: Dict[
            Union[ipaddress.IPv4Network, ipaddress.IPv6Network], Dict
        ] = {}
        self.blocked_ips: Dict[
            Union[ipaddress.IPv4Address, ipaddress.IPv6Address], Dict
        ] = {}

        # Parse IP addresses and networks with actions from inline config
        for ip_config in self.config.get("blocked_ips", []):
            try:
                # Handle both simple string format and dict format
                if isinstance(ip_config, str):
                    ip_spec = ip_config
                    action = "deny"  # default action
                    replace_with = None
                elif isinstance(ip_config, dict):
                    ip_spec = ip_config.get("ip", "")
                    action = ip_config.get("action", "deny").lower()
                    replace_with = ip_config.get("replace_with")
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
                    if not replace_with:
                        logger.error(
                            "Action 'replace' for IP '%s' requires 'replace_with' field.",
                            ip_spec,
                        )
                        continue
                    try:
                        # Validate the replacement IP
                        ipaddress.ip_address(replace_with)
                    except ValueError as e:  # pragma: no cover
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

            except ValueError as e:  # pragma: no cover
                logger.error("Invalid IP address/network '%s': %s", ip_spec, e)

        # Connect DB and initialize table
        self._connect_to_db()
        self._db_init()

        # Load domains from files and inline with defined precedence (last write wins):
        # 1) allowlist files, 2) blocklist files, 3) inline allowed_domains, 4) inline blocked_domains
        for file in self.allowlist_files:
            self.load_list_from_file(file, "allow")
        for file in self.blocklist_files:
            self.load_list_from_file(file, "deny")
        for domain in self.allowlist:
            self._db_insert_domain(domain, "config", "allow")
        for domain in self.blocklist:
            self._db_insert_domain(domain, "config", "deny")

        # Load patterns/keywords/IPs from files (additive to inline config)
        for patfile in self._expand_globs(
            list(self.config.get("blocked_patterns_files", []))
        ):
            for pat in self._load_patterns_from_file(patfile):
                self.blocked_patterns.append(pat)
        for kwfile in self._expand_globs(
            list(self.config.get("blocked_keywords_files", []))
        ):
            self.blocked_keywords.update(self._load_keywords_from_file(kwfile))
        for ipfile in self._expand_globs(
            list(self.config.get("blocked_ips_files", []))
        ):
            self._load_blocked_ips_from_file(ipfile)

    def add_to_cache(self, key: any, allowed: bool):
        """
        Add a domain decision to the TTL cache.

        Inputs:
            key: Domain cache key. Accepts a domain string or (domain, 0) tuple.
            allowed: True if allowed, False if denied.
        Outputs:
            None
        """
        try:
            # Normalize to (domain, 0) cache key
            if not isinstance(key, tuple):
                norm_key = (str(key).rstrip(".").lower(), 0)
            else:
                norm_key = key
            self._domain_cache.set(
                norm_key, int(self.cache_ttl_seconds), b"1" if allowed else b"0"
            )
        except Exception as e:  # pragma: no cover
            logger.warning(f"exception adding to cache {e}")

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
                if cached == b"1":
                    return None
                else:
                    return PluginDecision(action="deny")
            except Exception:  # pragma: no cover
                pass  # pragma: no cover

        if not self.is_allowed(str(domain).rstrip(".")):
            logger.debug("Domain '%s' blocked (exact match)", qname)
            self.add_to_cache(key, False)
            return PluginDecision(action="deny")

        # Check keyword filtering
        for keyword in self.blocked_keywords:
            if keyword.lower() in domain:
                logger.debug(
                    "Domain '%s' blocked (contains keyword '%s')", qname, keyword
                )
                self.add_to_cache(key, False)
                return PluginDecision(action="deny")

        # Check regex patterns
        for pattern in self.blocked_patterns:
            if pattern.search(domain):
                logger.debug(
                    "Domain '%s' blocked (matches pattern '%s')", qname, pattern.pattern
                )
                self.add_to_cache(key, False)
                return PluginDecision(action="deny")

        logger.debug("Domain '%s' allowed", qname)
        self.add_to_cache(key, True)

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
            raise TypeError("bad qtype")

        if not self.blocked_ips and not self.blocked_networks:
            return None

        try:
            response = DNSRecord.parse(response_wire)
        except Exception as e:
            logger.error("Failed to parse DNS response: %s", e)
            return PluginDecision(action=self.default)

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
                                    # Replace rdata with correct RDATA type
                                    if rr.rtype == QTYPE.A:
                                        rr.rdata = RDATA_A(str(replacement_ip))
                                    elif rr.rtype == QTYPE.AAAA:
                                        rr.rdata = RDATA_AAAA(str(replacement_ip))
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
                            except ValueError:  # pragma: no cover
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
            logger.debug(
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
        """
        Create and return a SQLite connection.

        Inputs:
            None
        Outputs:
            sqlite3.Connection instance connected to the blocklist database.
        """
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        return self.conn

    @staticmethod
    def _expand_globs(paths: List[str]) -> List[str]:
        """
        Expand a list of file paths and globs into concrete file paths.

        Args:
            paths: A list of file paths or glob patterns.

        Returns:
            A list of resolved file paths.

        Raises:
            FileNotFoundError: If a provided path does not exist and matches no files.

        Example:
            >>> # doctest: +SKIP
            >>> FilterPlugin._expand_globs(['config/*.txt', 'config/static.txt'])
            ['config/a.txt', 'config/b.txt', 'config/static.txt']
        """
        resolved: List[str] = []
        for p in paths:
            matches = glob.glob(p)
            if matches:
                resolved.extend(matches)
            else:
                if os.path.exists(p):
                    resolved.append(p)
                else:
                    raise FileNotFoundError(f"No file(s) match pattern or path: {p}")
        return resolved

    @staticmethod
    def _iter_noncomment_lines(path: str) -> Iterator[Tuple[int, str]]:
        """
        Yield non-empty, non-comment lines from a file with line numbers.

        Args:
            path: File path to read.

        Returns:
            Iterator of (line_number, text) for each meaningful line.

        Example:
            >>> # doctest: +SKIP
            >>> for ln, text in FilterPlugin._iter_noncomment_lines('file.txt'):
            ...     print(ln, text)
        """
        with open(path, "r", encoding="utf-8") as fh:
            for idx, raw in enumerate(fh, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                yield idx, line

    def _load_patterns_from_file(self, path: str) -> List[re.Pattern]:
        """
        Load regex patterns from a file, compiling with IGNORECASE.

        Args:
            path: Path to a file with one regex per line; '#' starts a comment.

        Returns:
            A list of compiled regex patterns.

        Example:
            >>> # doctest: +SKIP
            >>> self._load_patterns_from_file('patterns.txt')
            [re.compile('^ads\\.', re.IGNORECASE)]
        """
        patterns: List[re.Pattern] = []
        for ln, text in self._iter_noncomment_lines(path):
            try:
                if text.lstrip().startswith("{"):
                    try:
                        obj = json.loads(text)
                    except json.JSONDecodeError as e:
                        logger.error("Invalid JSON in %s:%d: %s", path, ln, e)
                        continue
                    if not isinstance(obj, dict) or "pattern" not in obj:
                        logger.error(
                            "JSON pattern missing 'pattern' in %s:%d", path, ln
                        )
                        continue
                    patt = str(obj["pattern"])
                    flags = 0
                    for f in obj.get("flags") or []:
                        fs = str(f).upper()
                        if fs == "IGNORECASE":
                            flags |= re.IGNORECASE
                    if flags == 0:
                        flags = re.IGNORECASE
                    patterns.append(re.compile(patt, flags))
                else:
                    patterns.append(re.compile(text, re.IGNORECASE))
            except re.error as e:
                logger.error(
                    "Invalid regex pattern in %s:%d: %s (%s)", path, ln, text, e
                )
        return patterns

    def _load_keywords_from_file(self, path: str) -> Set[str]:
        """
        Load case-insensitive keywords from a file.

        Args:
            path: Path to a file with one keyword per line.

        Returns:
            A set of lowercased keywords.

        Example:
            >>> # doctest: +SKIP
            >>> self._load_keywords_from_file('keywords.txt')
            {'ads', 'tracker'}
        """
        kws: Set[str] = set()
        for ln, text in self._iter_noncomment_lines(path):
            if text.lstrip().startswith("{"):
                try:
                    obj = json.loads(text)
                except json.JSONDecodeError as e:
                    logger.error("Invalid JSON in %s:%d: %s", path, ln, e)
                    continue
                if not isinstance(obj, dict) or "keyword" not in obj:
                    logger.error("JSON keyword missing 'keyword' in %s:%d", path, ln)
                    continue
                kws.add(str(obj["keyword"]).lower())
            else:
                kws.add(text.lower())
        return kws

    def _load_blocked_ips_from_file(self, path: str) -> None:
        """
        Load blocked IP rules from a file supporting simple, CSV, and JSON Lines formats.

        Line formats:
          - Simple: "IP_OR_CIDR" => action=deny
          - CSV:    "IP_OR_CIDR,action[,replace_with]" where action in {deny, remove, replace}
          - JSONL:  {"ip": "IP_OR_CIDR", "action": "deny|remove|replace", "replace_with": "IP"}

        Args:
            path: Path to the IP rules file.

        Returns:
            None

        Example:
            >>> # doctest: +SKIP
            >>> self._load_blocked_ips_from_file('ips.txt')
        """
        for ln, text in self._iter_noncomment_lines(path):
            ip_spec: str
            action: str = "deny"
            replace_with: Optional[str] = None
            try:
                stripped = text.lstrip()
                if stripped.startswith("{"):
                    # JSON line
                    try:
                        obj = json.loads(text)
                    except json.JSONDecodeError as e:
                        logger.error("Invalid JSON in %s:%d: %s", path, ln, e)
                        continue
                    if not isinstance(obj, dict):
                        logger.error("JSON line is not an object in %s:%d", path, ln)
                        continue
                    ip_spec = str(obj.get("ip", "")).strip()
                    action = str(obj.get("action", "deny")).strip().lower() or "deny"
                    replace_with = obj.get("replace_with")
                    if replace_with is not None:
                        replace_with = str(replace_with).strip()
                elif "," in text:
                    # Use csv to parse robustly
                    row = next(csv.reader([text]))
                    if len(row) < 2 or len(row) > 3:
                        logger.error(
                            "Invalid blocked_ips CSV in %s:%d: %r", path, ln, text
                        )
                        continue
                    ip_spec = row[0].strip()
                    action = (row[1] or "").strip().lower() or "deny"
                    replace_with = row[2].strip() if len(row) == 3 else None
                else:
                    ip_spec = text

                if not ip_spec:
                    logger.error("Missing ip in %s:%d", path, ln)
                    continue

                if action not in ("deny", "remove", "replace"):
                    logger.warning(
                        "Invalid action '%s' in %s:%d for '%s'; defaulting to 'deny'",
                        action,
                        path,
                        ln,
                        ip_spec,
                    )
                    action = "deny"

                if "/" in ip_spec:
                    network = ipaddress.ip_network(ip_spec, strict=False)
                    if action == "replace":
                        if not replace_with:
                            logger.error(
                                "Missing replace_with in %s:%d for network '%s'",
                                path,
                                ln,
                                ip_spec,
                            )
                            continue
                        try:
                            ipaddress.ip_address(replace_with)
                        except ValueError:
                            logger.error(
                                "Invalid replace_with '%s' in %s:%d",
                                replace_with,
                                path,
                                ln,
                            )
                            continue
                        self.blocked_networks[network] = {
                            "action": action,
                            "replace_with": replace_with,
                        }
                    else:
                        self.blocked_networks[network] = {"action": action}
                else:
                    ip_addr = ipaddress.ip_address(ip_spec)
                    if action == "replace":
                        if not replace_with:
                            logger.error(
                                "Missing replace_with in %s:%d for ip '%s'",
                                path,
                                ln,
                                ip_spec,
                            )
                            continue
                        try:
                            ipaddress.ip_address(replace_with)
                        except ValueError:
                            logger.error(
                                "Invalid replace_with '%s' in %s:%d",
                                replace_with,
                                path,
                                ln,
                            )
                            continue
                        self.blocked_ips[ip_addr] = {
                            "action": action,
                            "replace_with": replace_with,
                        }
                    else:
                        self.blocked_ips[ip_addr] = {"action": action}
            except ValueError as e:
                logger.error(
                    "Invalid IP/network spec in %s:%d: %s (%s)", path, ln, text, e
                )

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
        Load domains from a file into the database.

        Inputs:
            filename: Path to file containing domains.
            mode: Either "allow" or "deny". Default: "deny".
        Outputs:
            None

        Supported line formats:
          - Plain text: domain per line; blank lines and lines starting with '#' are ignored
          - JSON Lines: {"domain": "example.com"} (optional "mode" in {"allow","deny"} overrides the function arg)
        """
        mode = mode.lower()
        if mode not in {"deny", "allow"}:
            raise ValueError("mode must be 'allow' or 'deny'")

        if not os.path.isfile(filename):
            raise FileNotFoundError(f"No file {filename}")

        def _normalize_token(token: str) -> str:
            """
            Brief: Normalize a domain token from list files.

            Inputs:
              - token: raw domain token
            Outputs:
              - normalized token with Adblock-style wrappers removed

            If the token starts with '||' and ends with '^', those wrappers are stripped.
            """
            t = token.strip()
            if t.startswith("||") and t.endswith("^"):
                t = t[2:-1]
            return t

        logger.debug("Opening %s for %s", filename, mode)
        with open(filename, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                eff_mode = mode
                domain_val = None
                if line.lstrip().startswith("{"):
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.error("Invalid JSON domain line in %s: %s", filename, e)
                        continue
                    if not isinstance(obj, dict):
                        logger.error("JSON domain line not an object in %s", filename)
                        continue
                    domain_val = _normalize_token(str(obj.get("domain", "")).strip())
                    line_mode = obj.get("mode")
                    if isinstance(line_mode, str) and line_mode.lower() in {
                        "allow",
                        "deny",
                    }:
                        eff_mode = line_mode.lower()
                else:
                    domain_val = _normalize_token(line)
                if not domain_val:
                    logger.error("Missing domain entry in %s", filename)
                    continue
                self._db_insert_domain(domain_val, filename, eff_mode)

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
