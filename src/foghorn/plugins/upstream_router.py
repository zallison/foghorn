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
        Matches the query against the configured routes and sets an upstream override if a match is found.
        Args:
            qname: The queried domain name.
            qtype: The query type.
            ctx: The plugin context.
        Returns:
            None, as this plugin only annotates the context.

        Example use:
            >>> from foghorn.plugins.upstream_router import UpstreamRouterPlugin
            >>> from foghorn.plugins.base import PluginContext
            >>> config = {
            ...     "routes": [
            ...         {"suffix": "corp.com", "upstream": {"host": "10.0.0.1", "port": 53}}
            ...     ]
            ... }
            >>> plugin = UpstreamRouterPlugin(**config)
            >>> ctx = PluginContext("1.2.3.4")
            >>> plugin.pre_resolve("server.corp.com", 1, ctx)
            >>> ctx.upstream_override
            ('10.0.0.1', 53)
        """
        q = qname.rstrip('.').lower()
        upstream = self._match_upstream(q)
        if upstream is not None:
            logger.debug("Route matched for %s: upstream %s:%d", qname, upstream[0], upstream[1])
            ctx.upstream_override = upstream
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
            ...     {"domain": "EXAMPLE.COM", "upstream": {"host": "1.1.1.1", "port": "53"}}
            ... ]
            >>> norm_routes = plugin._normalize_routes(routes)
            >>> norm_routes[0]["domain"]
            'example.com'
            >>> norm_routes[0]["upstream"]
            ('1.1.1.1', 53)
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
            up = r.get("upstream") or {}
            host = up.get("host")
            port = up.get("port")
            if not host or port is None:
                # Skip invalid route
                continue
            try:
                port = int(port)
            except Exception:
                continue
            route["upstream"] = (str(host), port)
            # Only keep routes that have a matching key and an upstream
            if ("domain" in route or "suffix" in route) and "upstream" in route:
                norm.append(route)
        return norm

    def _match_upstream(self, q: str) -> Optional[Tuple[str, int]]:
        """
        Finds an upstream server for a given query name.
        Args:
            q: The query name.
        Returns:
            The address of the upstream server, or None if no match is found.

        Example use:
            >>> from foghorn.plugins.upstream_router import UpstreamRouterPlugin
            >>> config = {
            ...     "routes": [
            ...         {"domain": "example.com", "upstream": {"host": "1.1.1.1", "port": 53}},
            ...         {"suffix": "corp", "upstream": {"host": "10.0.0.1", "port": 53}}
            ...     ]
            ... }
            >>> plugin = UpstreamRouterPlugin(**config)
            >>> plugin._match_upstream("example.com")
            ('1.1.1.1', 53)
            >>> plugin._match_upstream("server.corp")
            ('10.0.0.1', 53)
        """
        for r in self.routes:
            if "domain" in r and q == r["domain"]:
                return r["upstream"]
            if "suffix" in r:
                s = r["suffix"]
                if q == s or q.endswith("." + s):
                    return r["upstream"]
        return None
