from __future__ import annotations

import csv
import glob
import hashlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import threading
import time
from typing import Dict, Iterator, List, Optional, Set, Tuple, Union

from dnslib import AAAA as RDATA_AAAA
from dnslib import QTYPE, RCODE, RR
from dnslib import A as RDATA_A
from dnslib import DNSHeader, DNSRecord
from pydantic import BaseModel, Field, ConfigDict

from foghorn.utils.current_cache import get_current_namespaced_cache, module_namespace
from foghorn.utils import ip_networks

from .base import BasePlugin, PluginContext, PluginDecision, plugin_aliases

logger = logging.getLogger(__name__)


class FilterConfig(BaseModel):
    """Brief: Typed configuration model for Filter.

    Inputs:
      - cache_ttl_seconds: TTL for domain cache.
      - db_path: Optional path to blocklist SQLite DB. When omitted or empty,
        the plugin uses a per-instance in-memory database so that multiple
        Filter instances do not share state by default.
      - default: Default policy ("allow" or "deny").
      - ttl: TTL for synthesized responses.
      - deny_response: Policy for deny responses ('nxdomain', 'refused', 'servfail',
        'noerror_empty'/'nodata', 'ip', or 'drop').
      - deny_response_ip4 / deny_response_ip6: Optional IPs for IP-mode denies.
      - allow_qtypes / deny_qtypes: Optional lists of DNS qtype names to allow or deny.
      - *_domains_files: List paths for loading allow/block lists from files.
      - blocked_domains / allowed_domains: Inline domain lists.
      - blocked_patterns / blocked_patterns_files: Regexes.
      - blocked_keywords / blocked_keywords_files: Keywords.
      - blocked_ips / blocked_ips_files: IP rules.

    Outputs:
      - FilterConfig instance with normalized field types.
    """

    cache_ttl_seconds: int = Field(default=600, ge=0)
    db_path: Optional[str] = Field(default=None)
    default: str = Field(default="deny")
    ttl: int = Field(default=300, ge=0)
    deny_response: str = Field(default="nxdomain")
    deny_response_ip4: Optional[str] = None
    deny_response_ip6: Optional[str] = None

    blocked_domains_files: List[str] = Field(default_factory=list)
    allowed_domains_files: List[str] = Field(default_factory=list)

    blocked_domains: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)

    blocked_patterns: List[str] = Field(default_factory=list)
    blocked_patterns_files: List[str] = Field(default_factory=list)

    blocked_keywords: List[str] = Field(default_factory=list)
    blocked_keywords_files: List[str] = Field(default_factory=list)

    blocked_ips: List[Union[str, Dict[str, object]]] = Field(default_factory=list)
    blocked_ips_files: List[str] = Field(default_factory=list)

    clear: int = Field(default=0, ge=0)
    strict_file_loading: bool = Field(default=False)
    max_domain_labels: int = Field(default=32, ge=1)
    max_pattern_match_domain_length: int = Field(default=253, ge=1)
    deny_response_ip_fallback: str = Field(default="nxdomain")

    model_config = ConfigDict(extra="allow")


@plugin_aliases("filter", "block", "allow")
class Filter(BasePlugin):
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
          - module: foghorn.plugins.resolve.filter.Filter
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

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - FilterConfig class for use by the core config loader.
        """

        return FilterConfig

    def setup(self):
        """
        Initializes the Filter.  Config has been read.

        Notes:
            - When ``db_path`` is omitted or empty, this plugin uses an
              in-memory SQLite database so each Filter instance has its
              own isolated allow/deny state by default.
            - When multiple instances explicitly share the same non-empty
              ``db_path``, they also share the same underlying table and
              last-writer-wins semantics apply.
            - Pre-resolve domain decision cache entries are namespaced per
              plugin instance name, so multiple Filter instances do not
              leak allow/deny cache decisions across each other.
        """
        # super().__init__(**config)
        instance_name = str(getattr(self, "name", "") or self.__class__.__name__)
        cache_label = re.sub(r"[^0-9A-Za-z_]", "_", instance_name).strip("_")
        if not cache_label:
            cache_label = "plugin"
        if cache_label[0].isdigit():
            cache_label = f"p_{cache_label}"
        cache_digest = hashlib.sha1(instance_name.encode("utf-8")).hexdigest()[:8]
        cache_namespace = f"{module_namespace(__file__)}_{cache_label}_{cache_digest}"
        self._domain_cache = get_current_namespaced_cache(
            namespace=cache_namespace,
            cache_plugin=self.config.get("cache"),
        )
        # Serialize SQLite access across ThreadingUDPServer handler threads to
        # avoid "InterfaceError: bad parameter or other API misuse" from
        # concurrent use of a single connection.
        self._db_lock = threading.Lock()
        self._loaded_list_file_fingerprints: Dict[
            Tuple[str, str],
            Dict[str, Union[str, int, float]],
        ] = {}
        self._parse_warn_lock = threading.Lock()
        self._last_parse_warn_ts = 0.0

        self.cache_ttl_seconds = self.config.get("cache_ttl_seconds", 600)  # 10 minutes
        raw_db_path = self.config.get("db_path")
        # None/empty db_path => per-instance in-memory database.
        self.db_path: str = raw_db_path or ":memory:"
        self.strict_file_loading = bool(self.config.get("strict_file_loading", False))
        self.max_domain_labels = max(1, int(self.config.get("max_domain_labels", 32)))
        self.max_pattern_match_domain_length = max(
            1, int(self.config.get("max_pattern_match_domain_length", 253))
        )

        raw_default = self.config.get("default", "deny")

        self.default = str(raw_default).lower()
        if self.default not in {"allow", "deny"}:
            logger.warning("unknown default policy; defaulting to 'deny'")
            self.default = "deny"

        # TTL used when synthesizing A/AAAA responses (e.g., when deny_response="ip")
        self._ttl = int(self.config.get("ttl", 300))

        # Policy for what DNS response to send when this plugin "denies" a query.
        # Supported values (case-insensitive):
        #   - "nxdomain" (default): core server synthesizes NXDOMAIN
        #   - "refused": override with REFUSED
        #   - "servfail": override with SERVFAIL
        #   - "noerror_empty"/"nodata": NOERROR with no answer records
        #   - "ip": synthesize an A/AAAA answer using deny_response_ip4/deny_response_ip6
        #   - "drop": send no response (client observes a timeout)
        self.deny_response: str = str(
            self.config.get("deny_response", "nxdomain")
        ).lower()
        self.deny_response_ip4: Optional[str] = self.config.get("deny_response_ip4")
        self.deny_response_ip6: Optional[str] = self.config.get("deny_response_ip6")
        self.deny_response_ip_fallback: str = str(
            self.config.get("deny_response_ip_fallback", "nxdomain")
        ).lower()

        # Optional per-query-type allow/deny controls.
        #
        # Inputs:
        #   - allow_qtypes: list[str] of qtype names (e.g. ["A", "AAAA"]). When set,
        #     qtypes not in the set are denied.
        #   - deny_qtypes: list[str] of qtype names to deny.
        #
        # Outputs:
        #   - self._allow_qtypes / self._deny_qtypes: set[int] of dnslib QTYPE values.
        def _qtype_names_to_ints(values: object) -> Set[int]:
            """Brief: Convert qtype name list (e.g. ["A"]) into dnslib QTYPE ints.

            Inputs:
              - values: object expected to be list/tuple/set[str] of qtype names.

            Outputs:
              - set[int]: Set of QTYPE integer codes.
            """

            if not isinstance(values, (list, tuple, set)):
                return set()
            out: Set[int] = set()
            for v in values:
                if not isinstance(v, str):
                    continue
                name = v.strip().upper()
                if not name:
                    continue
                # dnslib exposes QTYPE.<NAME> integer attributes.
                val = getattr(QTYPE, name, None)
                if val is None:
                    # Allow numeric qtype strings as a fallback.
                    try:
                        val = int(name)
                    except Exception:
                        val = None
                if isinstance(val, int):
                    out.add(int(val))
            return out

        self._allow_qtypes: Set[int] = _qtype_names_to_ints(
            self.config.get("allow_qtypes")
        )
        self._deny_qtypes: Set[int] = _qtype_names_to_ints(
            self.config.get("deny_qtypes")
        )

        valid_deny_responses = {
            "nxdomain",
            "refused",
            "servfail",
            "noerror_empty",
            "nodata",
            "ip",
            "drop",
        }
        if self.deny_response not in valid_deny_responses:
            logger.warning(
                "unknown deny_response %r; defaulting to 'nxdomain'",
                self.deny_response,
            )
            self.deny_response = "nxdomain"
        if self.deny_response_ip_fallback not in valid_deny_responses:
            logger.warning(
                "unknown deny_response_ip_fallback %r; defaulting to 'nxdomain'",
                self.deny_response_ip_fallback,
            )
            self.deny_response_ip_fallback = "nxdomain"
        elif self.deny_response_ip_fallback == "ip":
            logger.warning(
                "deny_response_ip_fallback cannot be 'ip'; defaulting to 'nxdomain'"
            )
            self.deny_response_ip_fallback = "nxdomain"

        self.blocklist_files: List[str] = self._expand_globs(
            list(self.config.get("blocked_domains_files", [])),
            strict=self.strict_file_loading,
        )
        self.allowlist_files: List[str] = self._expand_globs(
            list(self.config.get("allowed_domains_files", [])),
            strict=self.strict_file_loading,
        )

        self.blocklist = self.config.get("blocked_domains", [])
        self.allowlist = self.config.get("allowed_domains", [])
        if self.db_path == ":memory:" and (
            self.blocklist_files
            or self.allowlist_files
            or self.blocklist
            or self.allowlist
        ):
            logger.warning(
                "Filter: db_path is ':memory:'; data and list cache will reset each startup"
            )

        # Pre-resolve (domain) filtering configuration (inline first)
        self.blocked_patterns: List[re.Pattern] = []
        self.blocked_keywords: Set[str] = set(self.config.get("blocked_keywords", []))

        # Compile regex patterns for domain filtering from inline config
        for pattern in self.config.get("blocked_patterns", []):
            compiled = self._compile_block_pattern(str(pattern))
            if compiled is not None:
                self.blocked_patterns.append(compiled)

        # Post-resolve (IP) filtering configuration
        # Maps IP networks/addresses to their actions
        self.blocked_networks: Dict[
            Union[ipaddress.IPv4Network, ipaddress.IPv6Network], Dict
        ] = {}
        self._blocked_networks_by_prefix: Dict[
            int,
            Dict[
                int,
                List[Tuple[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], Dict]],
            ],
        ] = {4: {}, 6: {}}
        self._blocked_network_prefixes: Dict[int, Tuple[int, ...]] = {
            4: tuple(),
            6: tuple(),
        }
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
                    # Validate the replacement IP
                    if (
                        ip_networks.parse_ip(replace_with) is None
                    ):  # pragma: no cover - defensive
                        logger.error(
                            "Invalid 'replace_with' IP address '%s' for rule '%s'",
                            replace_with,
                            ip_spec,
                        )
                        continue

                if "/" in ip_spec:
                    # It's a network/subnet
                    network = ip_networks.parse_network(ip_spec, strict=False)
                    if network is None:
                        raise ValueError(f"invalid network {ip_spec!r}")
                    if action == "replace":
                        self.blocked_networks[network] = {
                            "action": action,
                            "replace_with": replace_with,
                        }
                    else:
                        self.blocked_networks[network] = {"action": action}
                else:
                    # It's a single IP address
                    ip_addr = ip_networks.parse_ip(ip_spec)
                    if ip_addr is None:
                        raise ValueError(f"invalid ip {ip_spec!r}")
                    if action == "replace":
                        self.blocked_ips[ip_addr] = {
                            "action": action,
                            "replace_with": replace_with,
                        }
                    else:
                        self.blocked_ips[ip_addr] = {"action": action}

            except (
                ValueError
            ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                logger.error("Invalid IP address/network '%s': %s", ip_spec, e)

        # Connect DB and initialize table
        self._connect_to_db()
        self._db_init()

        # Load domains from files and inline with defined precedence (last write wins):
        # 1) allowlist files, 2) blocklist files, 3) inline allowed_domains, 4) inline blocked_domains
        allow_changed = self._any_list_file_changed(self.allowlist_files, "allow")
        if allow_changed:
            for file in self.allowlist_files:
                self.load_list_from_file(file, "allow")
        block_changed = self._any_list_file_changed(self.blocklist_files, "deny")
        if block_changed:
            for file in self.blocklist_files:
                self.load_list_from_file(file, "deny")

        # Inline allow/deny domains from config: batch into a single transaction
        if self.allowlist or self.blocklist:
            with self.conn:
                for domain in self.allowlist:
                    self._db_insert_domain(domain, "config", "allow")
                for domain in self.blocklist:
                    self._db_insert_domain(domain, "config", "deny")

        # Load patterns/keywords/IPs from files (additive to inline config)
        for patfile in self._expand_globs(
            list(self.config.get("blocked_patterns_files", [])),
            strict=self.strict_file_loading,
        ):
            for pat in self._load_patterns_from_file(patfile):
                self.blocked_patterns.append(pat)
        for kwfile in self._expand_globs(
            list(self.config.get("blocked_keywords_files", [])),
            strict=self.strict_file_loading,
        ):
            self.blocked_keywords.update(self._load_keywords_from_file(kwfile))
        for ipfile in self._expand_globs(
            list(self.config.get("blocked_ips_files", [])),
            strict=self.strict_file_loading,
        ):
            self._load_blocked_ips_from_file(ipfile)
        self._rebuild_blocked_network_index()

    @staticmethod
    def _is_pattern_safe(pattern: str) -> bool:
        """Brief: Heuristically reject regexes with common catastrophic-backtracking shapes.

        Inputs:
            pattern: Regex pattern text.
        Outputs:
            bool indicating whether the pattern is accepted for runtime matching.
        """
        text = str(pattern or "")
        if not text or len(text) > 512:
            return False
        suspicious = (
            r"\([^)]*[+*][^)]*\)[+*{]",
            r"\(\?:[^)]*[+*][^)]*\)[+*{]",
            r"\(\.\*\)\+",
            r"\(\.\+\)\+",
            r"\.\*.*\.\*",
            r"\\[1-9]",
        )
        return not any(re.search(token, text) for token in suspicious)

    def _compile_block_pattern(
        self,
        pattern: str,
        *,
        path: Optional[str] = None,
        line_number: Optional[int] = None,
        flags: int = re.IGNORECASE,
    ) -> Optional[re.Pattern]:
        """Brief: Compile a block pattern after safety checks.

        Inputs:
            pattern: Regex text.
            path: Optional source file path.
            line_number: Optional source line number.
            flags: Regex compile flags.
        Outputs:
            Compiled pattern or None when rejected/invalid.
        """
        source = (
            f"{path}:{line_number}"
            if path is not None and line_number is not None
            else "config"
        )
        if not self._is_pattern_safe(pattern):
            logger.warning(
                "Rejected potentially unsafe regex pattern from %s: %r",
                source,
                pattern,
            )
            return None
        try:
            return re.compile(pattern, flags)
        except re.error as e:
            logger.error("Invalid regex pattern from %s: %r (%s)", source, pattern, e)
            return None

    def _rebuild_blocked_network_index(self) -> None:
        """Brief: Build per-version/prefix indexes for faster network rule lookup.

        Inputs:
            None.
        Outputs:
            None.
        """
        by_prefix: Dict[
            int,
            Dict[
                int,
                List[Tuple[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], Dict]],
            ],
        ] = {4: {}, 6: {}}
        for network, action in self.blocked_networks.items():
            version = int(network.version)
            prefixlen = int(network.prefixlen)
            by_prefix.setdefault(version, {}).setdefault(prefixlen, []).append(
                (network, action)
            )
        self._blocked_networks_by_prefix = by_prefix
        self._blocked_network_prefixes = {
            version: tuple(sorted(prefixes.keys(), reverse=True))
            for version, prefixes in by_prefix.items()
        }

    def _should_log_parse_warning(self) -> bool:
        """Brief: Rate-limit parse-failure warnings.

        Inputs:
            None.
        Outputs:
            bool indicating whether warning-level logging should be emitted.
        """
        now = time.time()
        with self._parse_warn_lock:
            if now - float(self._last_parse_warn_ts) >= 30.0:
                self._last_parse_warn_ts = now
                return True
        return False

    @staticmethod
    def _normalize_domain(domain: object) -> str:
        """Brief: Canonicalize a domain name for DB lookups and cache keys.

        Inputs:
          - domain: Domain-like object (str, dnslib label, etc.).

        Outputs:
          - str: Lowercased domain with any trailing dot removed.

        Notes:
          - DNS names are case-insensitive.
          - Many sources include a trailing '.' for absolute names; the plugin
            stores and queries domains without the trailing dot.
        """
        from foghorn.utils import dns_names

        return dns_names.normalize_name(domain)

    def add_to_cache(self, key: any, allowed: bool):
        """Brief: Add a pre-resolve decision to the TTL cache.

        Inputs:
          - key: Cache key. Accepts a domain string or (domain, qtype) tuple.
          - allowed: True if allowed, False if denied.

        Outputs:
          - None
        """
        try:
            # Normalize to (domain, qtype) cache key. qtype=0 is a legacy default
            # for callers that only pass a domain.
            if not isinstance(key, tuple):
                norm_key = (self._normalize_domain(key), 0)
            else:
                # Support callers that pass (domain, qtype) tuples.
                if len(key) >= 2:
                    norm_key = (self._normalize_domain(key[0]), int(key[1]))
                else:  # pragma: no cover - defensive
                    norm_key = (self._normalize_domain(key[0]) if key else "", 0)

            self._domain_cache.set(
                norm_key, int(self.cache_ttl_seconds), b"1" if allowed else b"0"
            )
        except (
            Exception
        ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.warning("exception adding to cache for key %r: %s", key, e)

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
            A PluginDecision signalling a deny for blocked domains (mapped to
            NXDOMAIN, REFUSED, SERVFAIL, NOERROR, or a synthetic IP answer
            depending on configuration) or a PluginDecision with action "skip"
            when no pre-resolve filtering applies.
        """
        if not self.targets(ctx):
            return None

        domain = self._normalize_domain(qname)
        # Cache keys:
        #  - (domain, 0): legacy "domain-wide" decision (applies to all qtypes)
        #  - (domain, qtype): qtype-specific decision (used for allow_qtypes/deny_qtypes)
        domain_key = (domain, 0)
        qtype_key = (domain, int(qtype))

        # Enforce query-type allow/deny before any domain-based checks.
        if self._allow_qtypes and int(qtype) not in self._allow_qtypes:
            self.add_to_cache(qtype_key, False)
            return self._build_deny_decision_pre(qname, qtype, req, ctx)
        if self._deny_qtypes and int(qtype) in self._deny_qtypes:
            self.add_to_cache(qtype_key, False)
            return self._build_deny_decision_pre(qname, qtype, req, ctx)

        cached = self._domain_cache.get(qtype_key)
        if cached is None:
            cached = self._domain_cache.get(domain_key)
        if cached is not None:
            try:
                if cached == b"1":
                    return PluginDecision(action="skip")
                else:
                    return self._build_deny_decision_pre(qname, qtype, req, ctx)
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably

        if not self.is_allowed(domain):
            logger.debug("Domain '%s' blocked by allow/deny list", qname)
            self.add_to_cache(domain_key, False)
            return self._build_deny_decision_pre(qname, qtype, req, ctx)

        # Check keyword filtering
        for keyword in self.blocked_keywords:
            if keyword.lower() in domain:
                logger.debug(
                    "Domain '%s' blocked (contains keyword '%s')", qname, keyword
                )
                self.add_to_cache(domain_key, False)
                return self._build_deny_decision_pre(qname, qtype, req, ctx)

        # Check regex patterns
        if len(domain) > int(self.max_pattern_match_domain_length):
            logger.warning(
                "Domain '%s' exceeds max_pattern_match_domain_length=%d; denying request",
                qname,
                int(self.max_pattern_match_domain_length),
            )
            self.add_to_cache(domain_key, False)
            return self._build_deny_decision_pre(qname, qtype, req, ctx)
        for pattern in self.blocked_patterns:
            if pattern.search(domain):
                logger.debug(
                    "Domain '%s' blocked (matches pattern '%s')", qname, pattern.pattern
                )
                self.add_to_cache(domain_key, False)
                return self._build_deny_decision_pre(qname, qtype, req, ctx)

        logger.debug("Domain '%s' allowed", qname)
        self.add_to_cache(domain_key, True)

        return PluginDecision(action="skip")

    def post_resolve(
        self, qname: str, qtype: int, response_wire: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Filter IP addresses in DNS responses after resolution.

        Inputs:
            qname: Queried domain name.
            qtype: Query type.
            response_wire: DNS response bytes from the upstream server.
            ctx: PluginContext with request metadata.

        Outputs:
            PluginDecision to modify or deny responses containing blocked IPs.
            Deny decisions are mapped to NXDOMAIN, REFUSED, SERVFAIL, or other
            policy responses depending on configuration, or a PluginDecision
            with action "skip" when no changes are required.
            Returns None for qtypes other than A/AAAA.

        Example:
            >>> # Only A/AAAA queries are handled; other qtypes return None
            >>> # plugin.post_resolve("ex.com", QTYPE.MX, b"", ctx)  # doctest: +SKIP
        """
        if not self.targets(ctx):
            return None

        # Only process A and AAAA records.
        if qtype not in (QTYPE.A, QTYPE.AAAA):
            return None

        if not self.blocked_ips and not self.blocked_networks:
            return PluginDecision(action="skip")

        try:
            response = DNSRecord.parse(response_wire)
        except Exception as e:
            if self._should_log_parse_warning():
                logger.warning(
                    "failed to parse DNS response for qname=%s client=%s: %s",
                    qname,
                    getattr(ctx, "client_ip", "unknown"),
                    e,
                )
            else:
                logger.debug(
                    "failed to parse DNS response for qname=%s",
                    qname,
                    exc_info=True,
                )
            return PluginDecision(action="deny")

        blocked_ips_deny = []  # IPs that should cause NXDOMAIN
        blocked_ips_remove = []  # IPs that should be removed
        modified_records = []
        original_records = list(response.rr)
        records_changed = False

        # Check each answer record
        for rr in original_records:
            record, changed, denied_ip, removed_ip = self._resolve_post_record_action(
                rr, qname
            )
            if record is not None:
                modified_records.append(record)
            if denied_ip is not None:
                blocked_ips_deny.append(denied_ip)
            if removed_ip is not None:
                blocked_ips_remove.append(removed_ip)
            if changed:
                records_changed = True

        # If any IP has "deny" action, return a policy deny for the entire response
        if blocked_ips_deny:
            logger.debug(
                "Denying %s due to blocked IPs with deny action: %s",
                qname,
                ", ".join(blocked_ips_deny),
            )
            return self._build_deny_decision_post(qname, qtype, response)

        # If records were changed (removed or replaced), create a new response
        if records_changed:
            if not modified_records:
                # If all IPs were removed or failed to be replaced, return a
                # policy deny for the entire response.
                logger.warning(
                    "All IPs removed or failed to replace for %s, returning deny response",
                    qname,
                )
                return self._build_deny_decision_post(qname, qtype, response)

            # Create modified response with the updated records
            modified_response = response
            modified_response.rr = modified_records

            try:
                modified_wire = modified_response.pack()
                logger.info("Modified DNS response for %s", qname)
                return PluginDecision(action="override", response=modified_wire)
            except Exception as e:
                logger.error("Failed to create modified response: %s", e)
                return self._build_deny_decision_post(qname, qtype, response)

        return PluginDecision(action="skip")

    def _resolve_post_record_action(
        self, rr: RR, qname: str
    ) -> Tuple[Optional[RR], bool, Optional[str], Optional[str]]:
        """Brief: Apply post-resolve IP action rules to a single DNS answer record.

        Inputs:
            rr: DNS resource record from upstream response.
            qname: Queried domain name (for logging context).

        Outputs:
            Tuple of:
              - Optional[RR]: record to keep in response (None when removed/denied),
              - bool: whether a rule changed the response handling,
              - Optional[str]: denied IP string (for aggregated logging),
              - Optional[str]: removed IP string (for aggregated tracking).
        """
        if rr.rtype not in (QTYPE.A, QTYPE.AAAA):
            return rr, False, None, None

        try:
            ip_addr = ip_networks.parse_ip(str(rr.rdata))
            if ip_addr is None:
                return rr, False, None, None

            action_config = self._get_ip_action(ip_addr)
            if not action_config:
                return rr, False, None, None

            action = action_config.get("action")
            if action == "deny":
                logger.debug(
                    "Blocked IP %s for domain %s (action: deny)",
                    ip_addr,
                    qname,
                )
                return None, True, str(ip_addr), None

            if action == "remove":
                logger.debug(
                    "Blocked IP %s for domain %s (action: remove)",
                    ip_addr,
                    qname,
                )
                return None, True, None, str(ip_addr)

            if action == "replace":
                replace_ip_str = action_config.get("replace_with")
                replacement_ip = ip_networks.parse_ip(replace_ip_str)
                if replacement_ip is None:  # pragma: no cover - defensive
                    logger.error("Invalid replacement IP: %s", replace_ip_str)
                    return rr, False, None, None

                # Ensure IP versions are compatible
                if ip_addr.version == replacement_ip.version:
                    # Replace rdata with correct RDATA type
                    if rr.rtype == QTYPE.A:
                        rr.rdata = RDATA_A(str(replacement_ip))
                    elif rr.rtype == QTYPE.AAAA:
                        rr.rdata = RDATA_AAAA(str(replacement_ip))
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
                return rr, True, None, None

            return rr, False, None, None
        except ValueError:
            return rr, False, None, None

    def _build_override_decision_from_raw_request(
        self,
        raw_req: bytes,
        mode: str,
        *,
        log_parse_failure: bool,
    ) -> Optional[PluginDecision]:
        """Brief: Build an override PluginDecision from raw DNS request bytes.

        Inputs:
            raw_req: Original DNS request wire bytes.
            mode: Deny response mode ('refused', 'servfail', or NODATA style).
            log_parse_failure: Whether parse failures should be logged as warnings.

        Outputs:
            PluginDecision(action='override', ...) on success, else None if request
            parsing fails.
        """
        try:
            request = DNSRecord.parse(raw_req)
        except Exception as e:
            if log_parse_failure:
                logger.warning(
                    "failed to parse request while building deny response: %s",
                    e,
                )
            return None

        reply = request.reply()
        if mode == "refused":
            reply.header.rcode = RCODE.REFUSED
        elif mode == "servfail":
            reply.header.rcode = RCODE.SERVFAIL
        else:
            reply.header.rcode = RCODE.NOERROR
            # Produce NOERROR with no answers (NODATA-style response)
            reply.rr = []
        return PluginDecision(action="override", response=reply.pack())

    def _build_deny_decision_pre(
        self,
        qname: str,
        qtype: int,
        raw_req: bytes,
        ctx: PluginContext,
    ) -> PluginDecision:
        """
        Brief: Build a PluginDecision for a pre-resolve deny using configured policy.

        Inputs:
            qname: Queried domain name.
            qtype: DNS query type integer.
            raw_req: Original DNS request wire bytes.
            ctx: PluginContext for the current request.

        Outputs:
            PluginDecision whose action is either "deny" (for NXDOMAIN) or
            "override" when a synthetic DNS reply is built (REFUSED, SERVFAIL,
            NOERROR/NODATA, or an A/AAAA answer pointed at a configured IP).

        Example:
            >>> # path=null start=null
            >>> # plugin = Filter(deny_response='refused')  # doctest: +SKIP
        """
        mode = (getattr(self, "deny_response", "nxdomain") or "nxdomain").lower()
        if mode == "nxdomain":
            return PluginDecision(action="deny")
        if mode == "drop":
            return PluginDecision(action="drop")

        if mode in {"refused", "servfail", "noerror_empty", "nodata"}:
            decision = self._build_override_decision_from_raw_request(
                raw_req,
                mode,
                log_parse_failure=True,
            )
            if decision is None:
                return PluginDecision(action="deny")
            return decision

        if mode == "ip":
            if qtype not in (QTYPE.A, QTYPE.AAAA):
                fallback_mode = (
                    getattr(self, "deny_response_ip_fallback", "nxdomain") or "nxdomain"
                ).lower()
                logger.debug(
                    "deny_response='ip' unsupported qtype=%s; fallback=%s",
                    qtype,
                    fallback_mode,
                )
                if fallback_mode == "drop":
                    return PluginDecision(action="drop")
                if fallback_mode == "nxdomain":
                    return PluginDecision(action="deny")
                if fallback_mode in {"refused", "servfail", "noerror_empty", "nodata"}:
                    decision = self._build_override_decision_from_raw_request(
                        raw_req,
                        fallback_mode,
                        log_parse_failure=False,
                    )
                    if decision is None:
                        return PluginDecision(action="deny")
                    return decision
                return PluginDecision(action="deny")
            ipaddr: Optional[str] = None
            if qtype == QTYPE.A and self.deny_response_ip4:
                ipaddr = str(self.deny_response_ip4)
            elif qtype == QTYPE.AAAA and self.deny_response_ip6:
                ipaddr = str(self.deny_response_ip6)
            elif self.deny_response_ip4 or self.deny_response_ip6:
                ipaddr = str(self.deny_response_ip4 or self.deny_response_ip6)

            if ipaddr:
                if ip_networks.parse_ip(ipaddr) is None:  # pragma: no cover - defensive
                    logger.error(
                        "invalid deny_response IP %r for %s",
                        ipaddr,
                        qname,
                    )
                else:
                    response_wire = self._make_a_response(
                        qname=qname,
                        query_type=qtype,
                        raw_req=raw_req,
                        ctx=ctx,
                        ipaddr=ipaddr,
                    )
                    if response_wire is not None:
                        return PluginDecision(action="override", response=response_wire)

        if mode not in {
            "nxdomain",
            "refused",
            "servfail",
            "noerror_empty",
            "nodata",
            "ip",
        }:
            logger.warning("unknown deny_response %r; defaulting to NXDOMAIN", mode)
        else:
            logger.debug(
                "falling back to NXDOMAIN deny for %s (mode=%s)",
                qname,
                mode,
            )
        return PluginDecision(action="deny")

    def _build_deny_decision_post(
        self,
        qname: str,
        qtype: int,
        response: DNSRecord,
    ) -> PluginDecision:
        """
        Brief: Build a PluginDecision for a post-resolve deny using configured policy.

        Inputs:
            qname: Queried domain name.
            qtype: DNS query type integer.
            response: Parsed DNSRecord from the upstream response.

        Outputs:
            PluginDecision mirroring _build_deny_decision_pre but using the
            already-parsed response as the response template.
        """
        mode = (getattr(self, "deny_response", "nxdomain") or "nxdomain").lower()

        if mode == "drop":
            return PluginDecision(action="drop")

        # For NXDOMAIN and IP modes in the post-resolve path, preserve the
        # historical behaviour by signalling a generic deny and letting the
        # core server synthesize the NXDOMAIN reply from the original query.
        if mode in {"nxdomain", "ip"}:
            return PluginDecision(action="deny")

        try:
            if mode == "refused":
                response.header.rcode = RCODE.REFUSED
            elif mode == "servfail":
                response.header.rcode = RCODE.SERVFAIL
            elif mode in {"noerror_empty", "nodata"}:
                response.header.rcode = RCODE.NOERROR
                response.rr = []
            else:
                logger.warning(
                    "unknown deny_response %r in post path; defaulting to NXDOMAIN",
                    mode,
                )
                return PluginDecision(action="deny")

            return PluginDecision(action="override", response=response.pack())
        except (
            Exception
        ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.warning(
                "failed to pack deny response for %s (%s): %s",
                qname,
                mode,
                e,
            )
            return PluginDecision(action="deny")

    def _make_a_response(
        self,
        qname: str,
        query_type: int,
        raw_req: bytes,
        ctx: PluginContext,
        ipaddr: str,
    ) -> Optional[bytes]:
        """Brief: Build a minimal DNS response for A/AAAA queries.

        Inputs:
          - qname: Queried name (currently unused; the parsed request QNAME is
            used instead).
          - query_type: QTYPE integer for the query.
          - raw_req: Raw DNS request wire bytes.
          - ctx: PluginContext for this request (currently unused).
          - ipaddr: IP address string used as the A/AAAA rdata.

        Outputs:
          - Optional[bytes]: Packed DNS response bytes, or None when raw_req
            cannot be parsed.

        Notes:
          - Unlike BasePlugin._make_a_response, this implementation honors
            self._ttl for both A and AAAA answers.
          - For other query types, a response is still packed, but no answers are
            added.
        """
        try:
            request = DNSRecord.parse(raw_req)
        except Exception as e:
            logger.warning("parse failure while building A/AAAA response: %s", e)
            return None

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        if query_type == QTYPE.A:
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.A,
                    rclass=1,
                    ttl=self._ttl,
                    rdata=RDATA_A(ipaddr),
                )
            )
        elif query_type == QTYPE.AAAA:
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.AAAA,
                    rclass=1,
                    ttl=self._ttl,
                    rdata=RDATA_AAAA(ipaddr),
                )
            )

        return reply.pack()

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

        # Check network ranges (most-specific prefixes first).
        version = int(ip_addr.version)
        prefixes = self._blocked_network_prefixes.get(version, tuple())
        buckets = self._blocked_networks_by_prefix.get(version, {})
        for prefixlen in prefixes:
            for network, action in buckets.get(prefixlen, []):
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
    def _expand_globs(paths: List[str], strict: bool = True) -> List[str]:
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
            >>> Filter._expand_globs(['config/*.txt', 'config/static.txt'])
            ['config/a.txt', 'config/b.txt', 'config/static.txt']
        """
        resolved: List[str] = []
        for p in paths:
            matches = sorted(glob.glob(p))
            if matches:
                resolved.extend(matches)
            else:
                if os.path.exists(p):
                    resolved.append(p)
                else:
                    if strict:
                        raise FileNotFoundError(
                            f"No file(s) match pattern or path: {p}"
                        )
                    logger.warning(
                        "skipping missing list/pattern path %s (strict_file_loading=false)",
                        p,
                    )
        return resolved

    @staticmethod
    def _iter_noncomment_lines(path: str) -> Iterator[Tuple[int, str]]:
        """
        Yield non-empty, non-comment lines from a file with line numbers.

        Args:
            path: File path to read.

        Returns:
            Iterator of (line_number, text) for each meaningful line.

        Notes:
            Lines starting with either '#' or '!' are treated as comments so
            that AdGuard/Adblock-style list files are parsed correctly.

        Example:
            >>> # doctest: +SKIP
            >>> for ln, text in Filter._iter_noncomment_lines('file.txt'):
            ...     print(ln, text)
        """
        with open(path, "r", encoding="utf-8") as fh:
            for idx, raw in enumerate(fh, start=1):
                line = raw.strip()
                if (
                    not line
                    or line.startswith("#")
                    or line.startswith("!")
                    or line.startswith("[")
                ):
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
        logger.info("adding %s to the database", path)
        patterns: List[re.Pattern] = []
        for ln, text in self._iter_noncomment_lines(path):
            if text.lstrip().startswith("{"):
                try:
                    obj = json.loads(text)
                except json.JSONDecodeError as e:
                    logger.error("Invalid JSON in %s:%d: %s", path, ln, e)
                    continue
                if not isinstance(obj, dict) or "pattern" not in obj:
                    logger.error("JSON pattern missing 'pattern' in %s:%d", path, ln)
                    continue
                patt = str(obj["pattern"])
                flags = 0
                for f in obj.get("flags") or []:
                    fs = str(f).upper()
                    if fs == "IGNORECASE":
                        flags |= re.IGNORECASE
                if flags == 0:
                    flags = re.IGNORECASE
                compiled = self._compile_block_pattern(
                    patt, path=path, line_number=ln, flags=flags
                )
                if compiled is not None:
                    patterns.append(compiled)
            else:
                compiled = self._compile_block_pattern(
                    text, path=path, line_number=ln, flags=re.IGNORECASE
                )
                if compiled is not None:
                    patterns.append(compiled)
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
                    network = ip_networks.parse_network(ip_spec, strict=False)
                    if network is None:
                        raise ValueError(f"invalid network {ip_spec!r}")
                    if action == "replace":
                        if not replace_with:
                            logger.error(
                                "Missing replace_with in %s:%d for network '%s'",
                                path,
                                ln,
                                ip_spec,
                            )
                            continue
                        if ip_networks.parse_ip(replace_with) is None:
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
                    ip_addr = ip_networks.parse_ip(ip_spec)
                    if ip_addr is None:
                        raise ValueError(f"invalid ip {ip_spec!r}")
                    if action == "replace":
                        if not replace_with:
                            logger.error(
                                "Missing replace_with in %s:%d for ip '%s'",
                                path,
                                ln,
                                ip_spec,
                            )
                            continue
                        if ip_networks.parse_ip(replace_with) is None:
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
        logger.debug("Creating blocked_domains database")

        # Clear blocklist, maybe
        clear_db = bool(self.config.get("clear", 0))
        if clear_db and self.db_path != ":memory:":
            logger.warning(
                "clear=1 with persistent db_path=%s will drop blocked_domains on startup",
                self.db_path,
            )
        if clear_db:
            logger.debug("clearing allow/deny databases")
            self.conn.execute("DROP TABLE IF EXISTS blocked_domains")

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS blocked_domains ("
            "domain TEXT PRIMARY KEY, "
            "filename TEXT, "
            "mode TEXT CHECK (mode IN ('allow','deny')) NOT NULL, "
            "added_at INTEGER NOT NULL"
            ")"
        )
        self._ensure_list_file_cache_schema()

        self.conn.commit()

    def _any_list_file_changed(self, files: List[str], mode: str) -> bool:
        """
        Brief: Determine whether any list file has changed vs cached metadata.

        Inputs:
            files: List of file paths to check.
            mode: Either "allow" or "deny".
        Outputs:
            True when any file is missing from cache or has changed stats.
        """
        if not files:
            return False
        for path in files:
            source_filename = os.path.abspath(path)
            if not os.path.isfile(source_filename):
                return True
            stat_snapshot = self._file_stat_snapshot(source_filename)
            cached_meta = self._get_list_file_cache(source_filename, mode)
            if not cached_meta:
                return True
            cached_size = int(cached_meta.get("size", -1))
            cached_mtime = int(cached_meta.get("mtime", -1))
            cached_ctime = int(cached_meta.get("ctime", -1))
            if (
                int(stat_snapshot["size"]) != cached_size
                or int(stat_snapshot["mtime"]) != cached_mtime
                or int(stat_snapshot["ctime"]) != cached_ctime
            ):
                return True
        return False

    def _ensure_list_file_cache_schema(self) -> None:
        """
        Brief: Ensure list_file_cache schema uses INTEGER timestamps.

        Inputs:
            None.
        Outputs:
            None.
        """
        row = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='list_file_cache'"
        ).fetchone()
        if not row:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS list_file_cache ("
                "filename TEXT NOT NULL, "
                "mode TEXT CHECK (mode IN ('allow','deny')) NOT NULL, "
                "size INTEGER NOT NULL, "
                "mtime INTEGER NOT NULL, "
                "ctime INTEGER NOT NULL, "
                "fingerprint TEXT NOT NULL, "
                "updated_at INTEGER NOT NULL, "
                "PRIMARY KEY (filename, mode)"
                ")"
            )
            return

        cols = self.conn.execute("PRAGMA table_info(list_file_cache)").fetchall()
        col_types = {str(c[1]).lower(): str(c[2]).lower() for c in cols}
        if col_types.get("mtime") == "integer" and col_types.get("ctime") == "integer":
            return

        with self.conn:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS list_file_cache_v2 ("
                "filename TEXT NOT NULL, "
                "mode TEXT CHECK (mode IN ('allow','deny')) NOT NULL, "
                "size INTEGER NOT NULL, "
                "mtime INTEGER NOT NULL, "
                "ctime INTEGER NOT NULL, "
                "fingerprint TEXT NOT NULL, "
                "updated_at INTEGER NOT NULL, "
                "PRIMARY KEY (filename, mode)"
                ")"
            )
            self.conn.execute(
                "INSERT OR REPLACE INTO list_file_cache_v2 "
                "(filename, mode, size, mtime, ctime, fingerprint, updated_at) "
                "SELECT filename, mode, size, "
                "CAST(mtime AS INTEGER), CAST(ctime AS INTEGER), "
                "fingerprint, updated_at "
                "FROM list_file_cache"
            )
            self.conn.execute("DROP TABLE list_file_cache")
            self.conn.execute(
                "ALTER TABLE list_file_cache_v2 RENAME TO list_file_cache"
            )

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
        normalized_domain = self._normalize_domain(domain)
        added_at = int(time.time())
        self.conn.execute(
            "INSERT OR REPLACE INTO blocked_domains (domain, filename, mode, added_at) "
            "VALUES (?, ?, ?, ?)",
            (normalized_domain, filename, mode, added_at),
        )

    @staticmethod
    def _file_content_fingerprint(path: str) -> str:
        """
        Brief: Compute a stable SHA-256 fingerprint for a list file.

        Inputs:
            path: Absolute or relative path to a list file.
        Outputs:
            Hex SHA-256 digest string of the current file bytes.
        """
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _file_stat_snapshot(path: str) -> Dict[str, Union[int, float]]:
        """
        Brief: Capture file size and timestamps for change detection.

        Inputs:
            path: Absolute or relative path to a list file.
        Outputs:
            Dict with 'size', 'mtime', and 'ctime' values (seconds).
        """
        st = os.stat(path)
        return {
            "size": int(st.st_size),
            "mtime": int(round(st.st_mtime)),
            "ctime": int(round(st.st_ctime)),
        }

    @staticmethod
    def _normalize_time_ns(value: object) -> int:
        """
        Brief: Normalize a cached time value to seconds.

        Inputs:
            value: Cached time value (seconds or nanoseconds).
        Outputs:
            Integer seconds since epoch.
        """
        try:
            raw = float(value)
        except (TypeError, ValueError):
            return 0
        # Heuristic: values >=1e12 are ns; convert to seconds.
        if raw >= 1_000_000_000_000:
            return int(round(raw / 1_000_000_000))
        return int(round(raw))

    def _get_list_file_cache(
        self,
        filename: str,
        mode: str,
    ) -> Optional[Dict[str, Union[str, int, float]]]:
        """
        Brief: Retrieve cached list file metadata from memory or SQLite.

        Inputs:
            filename: Absolute path to the list file.
            mode: Either "allow" or "deny".
        Outputs:
            Cached metadata dict or None when no cache exists.
        """
        cache_key = (filename, mode)
        cached = self._loaded_list_file_fingerprints.get(cache_key)
        if cached is not None:
            return cached
        with self._db_lock:
            row = self.conn.execute(
                "SELECT size, mtime, ctime, fingerprint FROM list_file_cache "
                "WHERE filename = ? AND mode = ?",
                (filename, mode),
            ).fetchone()
        if row:
            normalized_mtime = self._normalize_time_ns(row[1])
            normalized_ctime = self._normalize_time_ns(row[2])
            cached = {
                "size": int(row[0]),
                "mtime": normalized_mtime,
                "ctime": normalized_ctime,
                "fingerprint": str(row[3]),
            }
            self._loaded_list_file_fingerprints[cache_key] = cached
            if normalized_mtime != int(round(float(row[1]))) or normalized_ctime != int(
                round(float(row[2]))
            ):
                self._set_list_file_cache(filename, mode, cached)
            return cached
        return None

    def _set_list_file_cache(
        self,
        filename: str,
        mode: str,
        meta: Dict[str, Union[str, int, float]],
    ) -> None:
        """
        Brief: Persist list file metadata to memory and SQLite.

        Inputs:
            filename: Absolute path to the list file.
            mode: Either "allow" or "deny".
            meta: Metadata dict with size, mtime, ctime, and fingerprint.
        Outputs:
            None.
        """
        cache_key = (filename, mode)
        self._loaded_list_file_fingerprints[cache_key] = meta
        with self._db_lock:
            with self.conn:
                self.conn.execute(
                    "INSERT OR REPLACE INTO list_file_cache "
                    "(filename, mode, size, mtime, ctime, fingerprint, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        filename,
                        mode,
                        int(meta.get("size", 0)),
                        int(meta.get("mtime", 0)),
                        int(meta.get("ctime", 0)),
                        str(meta.get("fingerprint", "")),
                        int(time.time()),
                    ),
                )

    @staticmethod
    def _extract_adguard_domain(
        line: str,
    ) -> Tuple[str, Optional[str], bool]:
        """
        Brief: Parse a single AdGuard/Adblock-style line into a domain token.

        Inputs:
            line: Raw non-comment line.
        Outputs:
            Tuple of (domain, mode_override, matched):
              - domain: Parsed domain token (empty when no domain token is present).
              - mode_override: Optional mode override (\"allow\" for '@@' exception rules).
              - matched: True when the input resembles an AdGuard-style rule.
        """
        text = str(line).strip()
        if not text:
            return "", None, False

        mode_override: Optional[str] = None
        if text.startswith("@@"):
            mode_override = "allow"
            text = text[2:].lstrip()

        # Cosmetic rules should be treated as recognized AdGuard syntax but do
        # not contain DNS domain tokens for this plugin.
        if any(marker in text for marker in ("##", "#@#", "#?#", "#$#")):
            return "", mode_override, True

        if not text.startswith("||"):
            return "", None, False

        token = text[2:].strip()
        if "^" in token:
            token = token.split("^", 1)[0]
        if "$" in token:
            token = token.split("$", 1)[0]
        if "/" in token:
            token = token.split("/", 1)[0]

        return token.strip().strip("."), mode_override, True

    @staticmethod
    def _extract_hosts_domains(line: str) -> Tuple[List[str], bool]:
        """
        Brief: Parse a hosts-style line into one or more domain tokens.

        Inputs:
            line: Raw non-comment line.
        Outputs:
            Tuple of (domains, matched):
              - domains: Domain tokens found after the leading IP column.
              - matched: True when the line is recognized as hosts syntax.
        """
        parts = str(line).split()
        if len(parts) < 2:
            return [], False
        if ip_networks.parse_ip(parts[0]) is None:
            return [], False
        domains = [str(token).strip().strip(".") for token in parts[1:]]
        return [d for d in domains if d], True

    @staticmethod
    def _normalize_list_token(token: str) -> str:
        """
        Brief: Normalize a domain token from list files.

        Inputs:
          - token: Raw domain token.
        Outputs:
          - Normalized token with AdGuard/Adblock-style wrappers removed.

        Behaviour:
          - Trims surrounding whitespace and trailing dots.
          - Removes a leading '||' wrapper used by AdGuard/Adblock syntax.
        """
        normalized = token.strip()
        if normalized.startswith("||"):
            normalized = normalized[2:]
        return normalized.strip().strip(".")

    @staticmethod
    def _is_plain_domain_token(token: str) -> bool:
        """
        Brief: Heuristically validate a plain domain token.

        Inputs:
            token: Candidate token.
        Outputs:
            bool indicating whether the token looks like a supported domain entry.
        """
        from foghorn.utils import dns_names

        return dns_names.is_plain_domain_token(token)

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

        source_filename = os.path.abspath(filename)
        stat_snapshot = self._file_stat_snapshot(source_filename)
        logger.debug(
            "Filter: list file stats %s size=%d mtime_ns=%d ctime_ns=%d",
            source_filename,
            int(stat_snapshot["size"]),
            int(stat_snapshot["mtime"]),
            int(stat_snapshot["ctime"]),
        )
        cached_meta = self._get_list_file_cache(source_filename, mode)
        if cached_meta:
            cached_size = int(cached_meta.get("size", -1))
            cached_mtime = int(cached_meta.get("mtime", -1))
            cached_ctime = int(cached_meta.get("ctime", -1))
            logger.debug(
                "Filter: cached list stats %s size=%d mtime_ns=%d ctime_ns=%d",
                source_filename,
                cached_size,
                cached_mtime,
                cached_ctime,
            )
            if (
                int(stat_snapshot["size"]) == cached_size
                and int(stat_snapshot["mtime"]) == cached_mtime
                and int(stat_snapshot["ctime"]) == cached_ctime
            ):
                logger.debug(
                    "skipping unchanged %s list file %s",
                    mode,
                    source_filename,
                )
                return
            logger.debug(
                "Filter: list file changed %s size_match=%s mtime_match=%s ctime_match=%s",
                source_filename,
                int(stat_snapshot["size"]) == cached_size,
                int(stat_snapshot["mtime"]) == cached_mtime,
                int(stat_snapshot["ctime"]) == cached_ctime,
            )
            if int(stat_snapshot["size"]) == cached_size:
                logger.info("hashing list file %s", source_filename)
                content_fingerprint = self._file_content_fingerprint(source_filename)
                cached_fingerprint = cached_meta.get("fingerprint")
                if cached_fingerprint == content_fingerprint:
                    cached_meta.update(stat_snapshot)
                    self._set_list_file_cache(source_filename, mode, cached_meta)
                    logger.debug(
                        "skipping unchanged %s list file %s",
                        mode,
                        source_filename,
                    )
                    return
        logger.info("hashing list file %s", source_filename)
        content_fingerprint = self._file_content_fingerprint(source_filename)

        logger.debug("Opening %s for %s", filename, mode)
        matched_supported_format = False
        inserted_domains = 0
        unsupported_lines = 0
        # Use a single transaction per file for performance on very large lists.
        with self.conn:
            # Replace previous entries from this source/mode when file content
            # changes so removed domains do not remain stale in the DB.
            self.conn.execute(
                "DELETE FROM blocked_domains WHERE filename = ? AND mode = ?",
                (source_filename, mode),
            )
            with open(filename, "r", encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    # Treat both '#' and '!' as comment prefixes so that
                    # AdGuard-style list comments are ignored.
                    if (
                        not line
                        or line.startswith("#")
                        or line.startswith("!")
                        or line.startswith("[")
                    ):
                        continue
                    line = line.split("#", 1)[0].split("!", 1)[0].strip()
                    if not line:
                        continue
                    eff_mode = mode
                    domain_val = None
                    domains_to_insert: List[str] = []
                    if line.lstrip().startswith("{"):
                        matched_supported_format = True
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError as e:
                            logger.error(
                                "Invalid JSON domain line in %s: %s", filename, e
                            )
                            continue
                        if not isinstance(obj, dict):
                            logger.error(
                                "JSON domain line not an object in %s", filename
                            )
                            continue
                        domain_val = self._normalize_list_token(
                            str(obj.get("domain", "")).strip()
                        )
                        line_mode = obj.get("mode")
                        if isinstance(line_mode, str) and line_mode.lower() in {
                            "allow",
                            "deny",
                        }:
                            eff_mode = line_mode.lower()
                    else:
                        adguard_domain, adguard_mode, adguard_matched = (
                            self._extract_adguard_domain(line)
                        )
                        if adguard_matched:
                            matched_supported_format = True
                            if adguard_mode in {"allow", "deny"}:
                                eff_mode = adguard_mode
                            if adguard_domain:
                                domains_to_insert.append(
                                    self._normalize_list_token(adguard_domain)
                                )
                        else:
                            host_domains, hosts_matched = self._extract_hosts_domains(
                                line
                            )
                            if hosts_matched:
                                matched_supported_format = True
                                domains_to_insert.extend(
                                    self._normalize_list_token(domain)
                                    for domain in host_domains
                                )
                            elif self._is_plain_domain_token(line):
                                matched_supported_format = True
                                domains_to_insert.append(
                                    self._normalize_list_token(line)
                                )
                            else:
                                unsupported_lines += 1
                                continue
                    if domain_val is not None:
                        domains_to_insert.append(domain_val)
                    domains_to_insert = [d for d in domains_to_insert if d]
                    if not domains_to_insert:
                        continue
                    for token in domains_to_insert:
                        self._db_insert_domain(
                            self._normalize_domain(token), source_filename, eff_mode
                        )
                        inserted_domains += 1
        self._set_list_file_cache(
            source_filename,
            mode,
            {
                "fingerprint": content_fingerprint,
                **stat_snapshot,
            },
        )
        if inserted_domains > 0:
            logger.info(
                "added %d %s domains from %s",
                inserted_domains,
                mode,
                source_filename,
            )
        if (
            not matched_supported_format
            and unsupported_lines > 0
            and inserted_domains == 0
        ):
            logger.warning(
                "unsupported list format in %s (no entries loaded)",
                filename,
            )

    def is_allowed(self, domain: str) -> bool:
        """
        Return True if the domain is allowed by exact or suffix match.

        Inputs:
            domain: Domain name to check.
        Outputs:
            True when mode is "allow" or not blocked and the default is allow.

        Behaviour:
            - Looks up the exact domain first.
            - If no exact match is found, progressively checks parent-domain
              suffixes (e.g., 'sub.example.com' -> 'example.com' -> 'com').
            - The most specific matching suffix determines allow/deny, enabling
              list entries like 'example.com' to apply to all subdomains while
              still allowing overrides such as 'allow.example.com'.
        """
        # Normalize to a plain string to avoid sqlite InterfaceError when callers
        # pass dnslib labels or other non-str objects.
        normalized = self._normalize_domain(domain)

        # Prepare candidate suffixes from most specific to least specific.
        labels = normalized.split(".") if normalized else []
        if len(labels) > int(self.max_domain_labels):
            labels = labels[-int(self.max_domain_labels) :]
        candidates = (
            [".".join(labels[i:]) for i in range(len(labels))]
            if labels
            else [normalized]
        )
        mode_by_domain: Dict[str, str] = {}
        with self._db_lock:
            placeholders = ",".join("?" for _ in candidates)
            cur = self.conn.execute(
                f"SELECT domain, mode FROM blocked_domains WHERE domain IN ({placeholders})",
                tuple(candidates),
            )
            for domain_value, mode in cur.fetchall():
                mode_by_domain[str(domain_value)] = str(mode)

        allowed: bool = self.default == "allow"
        for candidate in candidates:
            mode = mode_by_domain.get(candidate)
            if mode is not None:
                allowed = mode == "allow"
                break

        return allowed
