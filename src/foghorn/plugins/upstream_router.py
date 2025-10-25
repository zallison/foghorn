from __future__ import annotations
import logging
from typing import Dict, List, Optional, Tuple

from .base import BasePlugin, PluginContext, PluginDecision, plugin_aliases

logger = logging.getLogger(__name__)


@plugin_aliases("upstream_router", "router", "upsream")
class UpstreamRouterPlugin(BasePlugin):
    """Route queries to different upstream DNS servers based on the queried domain."""

    def __init__(self, **config):
        """
        Initializes the UpstreamRouterPlugin.

        Args:
            **config: Configuration for the plugin.

        Example use:
            >>> from foghorn.plugins.upstream_router import UpstreamRouterPlugin
            >>> config = {
            ...     "routes": [
            ...         {"domain": "example.com", "upstream": {"host": "1.1.1.1", "port": 53}}
            ...     ]
            ... }
            >>> plugin = UpstreamRouterPlugin(**config)
            >>> plugin.routes[0]["domain"]
            'example.com'
        """
        super().__init__(**config)
        self.routes: List[Dict] = self._normalize_routes(self.config.get("routes", []))

    def pre_resolve(self, qname: str, qtype: int, ctx: PluginContext) -> Optional[PluginDecision]:
        """
        Route queries to specific upstream(s) based on match rules.

        Inputs:
          - qname: queried domain name
          - qtype: DNS query type
          - ctx: PluginContext with client_ip etc.

        Outputs:
          - PluginDecision or None:
              * Typically returns None after setting ctx.upstream_candidates to a list
                of {'host', 'port} if a route matches; server will honor it.
              * Return an override or deny decision only if explicitly configured.

        Example:
          # For qname ending with '.corp', route to two internal resolvers
          if qname.endswith('.corp'):
              ctx.upstream_candidates = [{'host': '10.0.0.2', 'port': 53}, {'host': '10.0.0.3', 'port': 53}]
              return None
        """
        q = qname.rstrip('.').lower()
        upstream_candidates = self._match_upstream_candidates(q)
        if upstream_candidates:
            upstream_info = ", ".join([f"{u['host']}:{u['port']}" for u in upstream_candidates])
            logger.debug("Route matched for %s: upstreams [%s]", qname, upstream_info)
            ctx.upstream_candidates = upstream_candidates
            
            # For backward compatibility, also set upstream_override if there's exactly one upstream
            if len(upstream_candidates) == 1:
                u = upstream_candidates[0]
                ctx.upstream_override = (u["host"], u["port"])
        
        # Do not alter decision flow; just annotate context
        return None

    def _normalize_routes(self, routes: List[Dict]) -> List[Dict]:
        """
        Normalizes and validates the routing rules.

        Args:
            routes: A list of routing rules.
        Returns:
            A list of normalized routing rules.

        Example use:
            >>> from foghorn.plugins.upstream_router import UpstreamRouterPlugin
            >>> plugin = UpstreamRouterPlugin()
            >>> routes = [
            ...     {"domain": "EXAMPLE.COM", "upstream": {"host": "1.1.1.1", "port": "53"}},
            ...     {"suffix": "corp", "upstreams": [{"host": "10.0.0.1", "port": 53}]}
            ... ]
            >>> norm_routes = plugin._normalize_routes(routes)
            >>> norm_routes[0]["domain"]
            'example.com'
            >>> norm_routes[0]["upstream_candidates"]
            [{'host': '1.1.1.1', 'port': 53}]
        """
        norm: List[Dict] = []
        for r in routes or []:
            route = {}
            domain = r.get("domain")
            suffix = r.get("suffix")
            if domain:
                route["domain"] = str(domain).rstrip('.').lower()
            if suffix:
                s = str(suffix).lower()
                # Normalize suffix by removing a leading dot for simpler checks
                if s.startswith('.'):
                    s = s[1:]
                route["suffix"] = s
            
            # Handle both single upstream and multiple upstreams
            upstream_candidates = []
            
            # Check for legacy single upstream format
            single_upstream = r.get("upstream")
            if single_upstream and isinstance(single_upstream, dict):
                host = single_upstream.get("host")
                port = single_upstream.get("port")
                if host and port is not None:
                    try:
                        upstream_candidates.append({"host": str(host), "port": int(port)})
                    except (ValueError, TypeError):
                        continue
            
            # Check for new multiple upstreams format
            multiple_upstreams = r.get("upstreams")
            if multiple_upstreams and isinstance(multiple_upstreams, list):
                for up in multiple_upstreams:
                    if isinstance(up, dict):
                        host = up.get("host")
                        port = up.get("port")
                        if host and port is not None:
                            try:
                                upstream_candidates.append({"host": str(host), "port": int(port)})
                            except (ValueError, TypeError):
                                continue
            
            # Only add route if we have valid matching criteria and at least one upstream
            if upstream_candidates and ("domain" in route or "suffix" in route):
                route["upstream_candidates"] = upstream_candidates
                norm.append(route)
                
        return norm

    def _match_upstream_candidates(self, q: str) -> Optional[List[Dict[str, str | int]]]:
        """
        Finds upstream candidates for a given query name.
        Args:
            q: The query name.
        Returns:
            A list of upstream candidates, or None if no match is found.

        Example use:
            >>> from foghorn.plugins.upstream_router import UpstreamRouterPlugin
            >>> config = {
            ...     "routes": [
            ...         {"domain": "example.com", "upstream": {"host": "1.1.1.1", "port": 53}},
            ...         {"suffix": "corp", "upstreams": [{"host": "10.0.0.1", "port": 53}, {"host": "10.0.0.2", "port": 53}]}
            ...     ]
            ... }
            >>> plugin = UpstreamRouterPlugin(**config)
            >>> plugin._match_upstream_candidates("example.com")
            [{'host': '1.1.1.1', 'port': 53}]
            >>> plugin._match_upstream_candidates("server.corp")
            [{'host': '10.0.0.1', 'port': 53}, {'host': '10.0.0.2', 'port': 53}]
        """
        for r in self.routes:
            if "domain" in r and q == r["domain"]:
                return r["upstream_candidates"]
            if "suffix" in r:
                s = r["suffix"]
                if q == s or q.endswith("." + s):
                    return r["upstream_candidates"]
        return None
