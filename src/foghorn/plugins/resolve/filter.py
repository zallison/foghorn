from __future__ import annotations

import csv
import glob
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
from dnslib import QTYPE, RCODE
from dnslib import A as RDATA_A
from dnslib import DNSRecord
from pydantic import BaseModel, Field

from foghorn.utils.current_cache import get_current_namespaced_cache, module_namespace

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
      - deny_response: Policy for deny responses.
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

    clear: int = Field(default=1, ge=0)

    class Config:
        extra = "allow"


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
          - module: foghorn.plugins.filter.Filter
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
        """
        # super().__init__(**config)
        self._domain_cache = get_current_namespaced_cache(
            namespace=module_namespace(__file__),
            cache_plugin=self.config.get("cache"),
        )
        # Serialize SQLite access across ThreadingUDPServer handler threads to
        # avoid "InterfaceError: bad parameter or other API misuse" from
        # concurrent use of a single connection.
        self._db_lock = threading.Lock()

        self.cache_ttl_seconds = self.config.get("cache_ttl_seconds", 600)  # 10 minutes
        raw_db_path = self.config.get("db_path")
        # None/empty db_path => per-instance in-memory database.
        self.db_path: str = raw_db_path or ":memory:"

        raw_default = self.config.get("default", "deny")

        self.default = str(raw_default).lower()

        # TTL used when synthesizing A/AAAA responses (e.g., when deny_response="ip")
        self._ttl = int(self.config.get("ttl", 300))

        # Policy for what DNS response to send when this plugin "denies" a query.
        # Supported values (case-insensitive):
        #   - "nxdomain" (default): core server synthesizes NXDOMAIN
        #   - "refused": override with REFUSED
        #   - "servfail": override with SERVFAIL
        #   - "noerror_empty"/"nodata": NOERROR with no answer records
        #   - "ip": synthesize an A/AAAA answer using deny_response_ip4/deny_response_ip6
        self.deny_response: str = str(
            self.config.get("deny_response", "nxdomain")
        ).lower()
        self.deny_response_ip4: Optional[str] = self.config.get("deny_response_ip4")
        self.deny_response_ip6: Optional[str] = self.config.get("deny_response_ip6")

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
        }
        if self.deny_response not in valid_deny_responses:
            logger.warning(
                "Filter: unknown deny_response %r; defaulting to 'nxdomain'",
                self.deny_response,
            )
            self.deny_response = "nxdomain"

        self.blocklist_files: List[str] = self._expand_globs(
            list(self.config.get("blocked_domains_files", []))
        )
        self.allowlist_files: List[str] = self._expand_globs(
            list(self.config.get("allowed_domains_files", []))
        )

        self.blocklist = self.config.get("blocked_domains", [])
        self.allowlist = self.config.get("allowed_domains", [])

        # Pre-resolve (domain) filtering configuration (inline first)
        self.blocked_patterns: List[re.Pattern] = []
        self.blocked_keywords: Set[str] = set(self.config.get("blocked_keywords", []))

        # Compile regex patterns for domain filtering from inline config
        for pattern in self.config.get("blocked_patterns", []):
            try:
                self.blocked_patterns.append(re.compile(pattern, re.IGNORECASE))
            except (
                re.error
            ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
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
                    except (
                        ValueError
                    ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
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

            except (
                ValueError
            ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
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

        # Inline allow/deny domains from config: batch into a single transaction
        if self.allowlist or self.blocklist:
            with self.conn:
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
                norm_key = (str(key).rstrip(".").lower(), 0)
            else:
                norm_key = key
            self._domain_cache.set(
                norm_key, int(self.cache_ttl_seconds), b"1" if allowed else b"0"
            )
        except (
            Exception
        ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
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
            A PluginDecision signalling a deny for blocked domains (mapped to
            NXDOMAIN, REFUSED, SERVFAIL, NOERROR, or a synthetic IP answer
            depending on configuration) or a PluginDecision with action "skip"
            when no pre-resolve filtering applies.
        """
        if not self.targets(ctx):
            return None

        domain = qname.lower()
        # Cache keys:
        #  - (domain, 0): legacy "domain-wide" decision (applies to all qtypes)
        #  - (domain, qtype): qtype-specific decision (used for allow_qtypes/deny_qtypes)
        domain_key = (str(domain).rstrip(".").lower(), 0)
        qtype_key = (str(domain).rstrip(".").lower(), int(qtype))

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

        if not self.is_allowed(str(domain).rstrip(".")):
            logger.debug("Domain '%s' blocked (exact match)", qname)
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
            qtype: Query type (only A and AAAA are supported).
            response_wire: DNS response bytes from the upstream server.
            ctx: PluginContext with request metadata.

        Outputs:
            PluginDecision to modify or deny responses containing blocked IPs.
            Deny decisions are mapped to NXDOMAIN, REFUSED, SERVFAIL, or other
            policy responses depending on configuration, or a PluginDecision
            with action "skip" when no changes are required.

        Example:
            >>> # Only A/AAAA queries are supported; others raise TypeError
            >>> # plugin.post_resolve("ex.com", QTYPE.MX, b"", ctx)  # doctest: +SKIP
        """
        if not self.targets(ctx):
            return None

        # Only process A and AAAA records; other qtypes are considered a
        # programming error for this plugin and raise TypeError so callers can
        # handle them explicitly.
        if qtype not in (QTYPE.A, QTYPE.AAAA):
            return

        if not self.blocked_ips and not self.blocked_networks:
            return PluginDecision(action="skip")

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
                            except (
                                ValueError
                            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
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

        if mode in {"refused", "servfail", "noerror_empty", "nodata"}:
            try:
                request = DNSRecord.parse(raw_req)
            except (
                Exception
            ) as e:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                logger.warning(
                    "Filter: failed to parse request while building deny response: %s",
                    e,
                )
                return PluginDecision(action="deny")

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

        if mode == "ip":
            ipaddr: Optional[str] = None
            if qtype == QTYPE.A and self.deny_response_ip4:
                ipaddr = str(self.deny_response_ip4)
            elif qtype == QTYPE.AAAA and self.deny_response_ip6:
                ipaddr = str(self.deny_response_ip6)
            elif self.deny_response_ip4 or self.deny_response_ip6:
                ipaddr = str(self.deny_response_ip4 or self.deny_response_ip6)

            if ipaddr:
                try:
                    ipaddress.ip_address(ipaddr)
                except (
                    ValueError
                ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    logger.error(
                        "Filter: invalid deny_response IP %r for %s",
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
            logger.warning(
                "Filter: unknown deny_response %r; defaulting to NXDOMAIN", mode
            )
        else:
            logger.debug(
                "Filter: falling back to NXDOMAIN deny for %s (mode=%s)",
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
                    "Filter: unknown deny_response %r in post path; defaulting to NXDOMAIN",
                    mode,
                )
                return PluginDecision(action="deny")

            return PluginDecision(action="override", response=response.pack())
        except (
            Exception
        ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.warning(
                "Filter: failed to pack deny response for %s (%s): %s",
                qname,
                mode,
                e,
            )
            return PluginDecision(action="deny")

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
            >>> Filter._expand_globs(['config/*.txt', 'config/static.txt'])
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
        logger.info(f"Filter: adding {path} to the database")
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
        logger.debug("Creating blocked_domains database")

        # Clear blocklist, maybe
        if self.config.get("clear", 1):
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
              - normalized token with AdGuard/Adblock-style wrappers removed.

            Behaviour:
              - If the token starts with '||', the prefix is removed.
              - If a caret ('^') is present, the caret must be the last
                non-whitespace character on the line; otherwise the token is
                ignored. For a valid AdGuard-style token like '||domain.com^',
                the resulting domain is 'domain.com'.
            """
            t = token.strip()
            if t.startswith("||"):
                # Drop the leading '||'.
                t = t[2:]
                caret_idx = t.find("^")
                if caret_idx != -1:
                    # Anything non-whitespace after the caret means we ignore
                    # this token entirely (e.g. '||domain.com^$third-party').
                    rest = t[caret_idx + 1 :]
                    if rest.strip():
                        return ""
                    t = t[:caret_idx]
            return t

        logger.debug("Opening %s for %s", filename, mode)
        # Use a single transaction per file for performance on very large lists.
        with self.conn:
            with open(filename, "r", encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    # Treat both '#' and '!' as comment prefixes so that
                    # AdGuard-style list comments are ignored.
                    if not line or line.startswith("#") or line.startswith("!"):
                        continue
                    eff_mode = mode
                    domain_val = None
                    if line.lstrip().startswith("{"):
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
                        domain_val = _normalize_token(
                            str(obj.get("domain", "")).strip()
                        )
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
        normalized = str(domain).rstrip(".")

        # Prepare candidate suffixes from most specific to least specific.
        labels = normalized.split(".") if normalized else []
        candidates = (
            [".".join(labels[i:]) for i in range(len(labels))]
            if labels
            else [normalized]
        )

        row = None
        with self._db_lock:
            for cand in candidates:
                cur = self.conn.execute(
                    "SELECT mode FROM blocked_domains WHERE domain = ?",
                    (cand,),
                )
                row = cur.fetchone()
                if row is not None:
                    break

        allowed: bool = self.default == "allow"
        if row:
            allowed = row[0] == "allow"

        return allowed
