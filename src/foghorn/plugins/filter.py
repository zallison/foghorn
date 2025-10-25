from __future__ import annotations
import ipaddress
import logging
import re
from typing import Optional, List, Set, Union, Dict
from dnslib import DNSRecord, QTYPE, RCODE

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
    - Actions: "remove" (remove from response) or "deny" (return NXDOMAIN)
    
    Example use:
        In config.yaml:
        plugins:
          - module: foghorn.plugins.filter.FilterPlugin
            config:
              # Pre-resolve (domain) filtering
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

        Example use:
            >>> from foghorn.plugins.filter import FilterPlugin
            >>> config = {
            ...     "blocked_domains": ["bad.com"],
            ...     "blocked_keywords": ["porn"],
            ...     "blocked_ips": [
            ...         {"ip": "192.0.2.1", "action": "deny"},
            ...         {"ip": "198.51.100.0/24", "action": "remove"}
            ...     ]
            ... }
            >>> plugin = FilterPlugin(**config)
            >>> len(plugin.blocked_domains)
            1
        """
        super().__init__(**config)
        
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
        self.blocked_networks: Dict[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], str] = {}
        self.blocked_ips: Dict[Union[ipaddress.IPv4Address, ipaddress.IPv6Address], str] = {}
        
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
                
                if action not in ("remove", "deny"):
                    logger.warning("Invalid action '%s' for IP '%s', defaulting to 'deny'", 
                                 action, ip_spec)
                    action = "deny"
                
                if "/" in ip_spec:
                    # It's a network/subnet
                    network = ipaddress.ip_network(ip_spec, strict=False)
                    self.blocked_networks[network] = action
                else:
                    # It's a single IP address
                    ip_addr = ipaddress.ip_address(ip_spec)
                    self.blocked_ips[ip_addr] = action
                    
            except ValueError as e:
                logger.error("Invalid IP address/network '%s': %s", ip_spec, e)

def pre_resolve(self, qname: str, qtype: int, req: bytes, ctx: PluginContext) -> Optional[PluginDecision]:
        """
        Filters domains before DNS resolution based on blocked lists and patterns.

        Args:
            qname: The queried domain name.
            qtype: The query type.
            ctx: The plugin context.

        Returns:
            A PluginDecision to deny blocked domains, otherwise None.

        Example use:
            >>> from foghorn.plugins.filter import FilterPlugin
            >>> from foghorn.plugins.base import PluginContext
            >>> plugin = FilterPlugin(blocked_domains=["bad.com"], blocked_keywords=["porn"])
            >>> ctx = PluginContext("1.2.3.4")
            >>> decision = plugin.pre_resolve("bad.com", 1, ctx)
            >>> decision.action
            'deny'
            >>> decision = plugin.pre_resolve("porn-site.org", 1, ctx)
            >>> decision.action
            'deny'
            >>> plugin.pre_resolve("good.com", 1, ctx) is None
            True
        """
        domain = qname.lower()
        
        # Check exact domain matches
        if domain in self.blocked_domains:
            logger.warning("Domain '%s' blocked (exact match)", qname)
            return PluginDecision(action="deny")
        
        # Check keyword filtering
        for keyword in self.blocked_keywords:
            if keyword.lower() in domain:
                logger.warning("Domain '%s' blocked (contains keyword '%s')", qname, keyword)
                return PluginDecision(action="deny")
        
        # Check regex patterns
        for pattern in self.blocked_patterns:
            if pattern.search(domain):
                logger.warning("Domain '%s' blocked (matches pattern '%s')", qname, pattern.pattern)
                return PluginDecision(action="deny")
        
        logger.debug("Domain '%s' allowed", qname)
        return None

    def post_resolve(self, qname: str, qtype: int, response_wire: bytes, ctx: PluginContext) -> Optional[PluginDecision]:
        """
        Filters IP addresses in DNS responses after resolution.

        Args:
            qname: The queried domain name.
            qtype: The query type.
            response_wire: The response from the upstream server.
            ctx: The plugin context.

        Returns:
            A PluginDecision to modify or deny responses containing blocked IPs, otherwise None.

        Example use:
            (This example shows the concept, but actual usage requires valid DNS wire format)
            >>> from foghorn.plugins.filter import FilterPlugin
            >>> from foghorn.plugins.base import PluginContext
            >>> plugin = FilterPlugin(blocked_ips=[{"ip": "192.0.2.1", "action": "deny"}])
            >>> ctx = PluginContext("1.2.3.4")
            >>> # In practice, this would be called with actual DNS wire format response
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
        clean_records = []
        
        # Check each answer record
        for rr in response.rr:
            if rr.rtype == QTYPE.A:
                try:
                    ip_addr = ipaddress.IPv4Address(str(rr.rdata))
                    action = self._get_ip_action(ip_addr)
                    if action == "deny":
                        blocked_ips_deny.append(str(ip_addr))
                        logger.warning("Blocked IP %s for domain %s (action: deny)", ip_addr, qname)
                    elif action == "remove":
                        blocked_ips_remove.append(str(ip_addr))
                        logger.warning("Blocked IP %s for domain %s (action: remove)", ip_addr, qname)
                    else:
                        clean_records.append(rr)
                except ValueError:
                    clean_records.append(rr)  # Keep non-IP records
            elif rr.rtype == QTYPE.AAAA:
                try:
                    ip_addr = ipaddress.IPv6Address(str(rr.rdata))
                    action = self._get_ip_action(ip_addr)
                    if action == "deny":
                        blocked_ips_deny.append(str(ip_addr))
                        logger.warning("Blocked IPv6 %s for domain %s (action: deny)", ip_addr, qname)
                    elif action == "remove":
                        blocked_ips_remove.append(str(ip_addr))
                        logger.warning("Blocked IPv6 %s for domain %s (action: remove)", ip_addr, qname)
                    else:
                        clean_records.append(rr)
                except ValueError:
                    clean_records.append(rr)  # Keep non-IP records
            else:
                clean_records.append(rr)  # Keep non-A/AAAA records
        
        # If any IP has "deny" action, return NXDOMAIN for entire response
        if blocked_ips_deny:
            logger.warning("Denying %s due to blocked IPs with deny action: %s", 
                         qname, ", ".join(blocked_ips_deny))
            return PluginDecision(action="deny")
        
        # If only "remove" action IPs were found, create modified response
        if blocked_ips_remove:
            if not clean_records:
                # If all IPs were removed, return NXDOMAIN
                logger.warning("All IPs removed for %s, returning NXDOMAIN", qname)
                return PluginDecision(action="deny")
            
            # Create modified response with only clean records
            modified_response = response
            modified_response.rr = clean_records
            
            try:
                modified_wire = modified_response.pack()
                logger.info("Removed %d blocked IPs from %s response", 
                           len(blocked_ips_remove), qname)
                return PluginDecision(action="override", response=modified_wire)
            except Exception as e:
                logger.error("Failed to create modified response: %s", e)
                # Fall back to denying the entire response
                return PluginDecision(action="deny")
        
        return None

    def _get_ip_action(self, ip_addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Optional[str]:
        """
        Gets the action for a blocked IP address.

        Args:
            ip_addr: The IP address to check.

        Returns:
            The action ("deny", "remove") if blocked, None if not blocked.

        Example use:
            >>> from foghorn.plugins.filter import FilterPlugin
            >>> import ipaddress
            >>> plugin = FilterPlugin(blocked_ips=[{"ip": "192.0.2.0/24", "action": "remove"}])
            >>> plugin._get_ip_action(ipaddress.IPv4Address("192.0.2.1"))
            'remove'
            >>> plugin._get_ip_action(ipaddress.IPv4Address("203.0.113.1")) is None
            True
        """
        # Check exact IP matches first (more specific)
        if ip_addr in self.blocked_ips:
            return self.blocked_ips[ip_addr]
        
        # Check network ranges
        for network, action in self.blocked_networks.items():
            if ip_addr in network:
                return action
        
        return None