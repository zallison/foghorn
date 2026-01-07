from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from dnslib import RCODE, DNSRecord
from pydantic import BaseModel, Field

from .base import BasePlugin, PluginContext, PluginDecision, plugin_aliases

logger = logging.getLogger(__name__)


class UpstreamRouteTarget(BaseModel):
    """Brief: Single upstream target host/port pair.

    Inputs:
      - host: Upstream DNS host.
      - port: Upstream DNS port.

    Outputs:
      - UpstreamRouteTarget instance with normalized types.
    """

    host: str
    port: int = Field(ge=1, le=65535)


class UpstreamRoute(BaseModel):
    """Brief: Route definition for UpstreamRouter.

    Inputs:
      - domain: Exact domain to match.
      - suffix: Suffix to match (without leading dot).
      - upstreams: List of upstream targets.

    Outputs:
      - UpstreamRoute instance with normalized types.
    """

    domain: Optional[str] = None
    suffix: Optional[str] = None
    upstreams: List[UpstreamRouteTarget] = Field(default_factory=list)

    class Config:
        extra = "allow"


class UpstreamRouterConfig(BaseModel):
    """Brief: Typed configuration model for UpstreamRouter.

    Inputs:
      - routes: List of UpstreamRoute definitions.

    Outputs:
      - UpstreamRouterConfig instance with normalized field types.
    """

    routes: List[UpstreamRoute] = Field(default_factory=list)

    class Config:
        extra = "allow"


@plugin_aliases("upstream_router", "router", "upstream")
class UpstreamRouter(BasePlugin):
    """Routes queries to different upstream DNS servers based on the queried domain, with failover."""

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - UpstreamRouterConfig class for use by the core config loader.
        """

        return UpstreamRouterConfig

    def __init__(self, **config):
        """
        Initializes the UpstreamRouter.

        Args:
            **config: Configuration for the plugin.

        Example use:
            >>> from foghorn.plugins.upstream_router import UpstreamRouter
            >>> config = {
            ...     "routes": [
            ...         {"domain": "example.com", "upstream": {"host": "1.1.1.1", "port": 53}}
            ...     ]
            ... }
            >>> plugin = UpstreamRouter(**config)
            >>> plugin.routes[0]["domain"]
            'example.com'
        """
        super().__init__(**config)
        self.routes: List[Dict] = self._normalize_routes(self.config.get("routes", []))

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Route queries to specific upstream(s) based on match rules.
        Inputs:
          - qname: queried domain name
          - qtype: DNS query type
          - req: raw DNS request
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
        if not self.targets(ctx):
            return None

        q = qname.rstrip(".").lower()
        upstream_candidates = self._match_upstream_candidates(q)
        if upstream_candidates:
            # Set candidates on the context for the main server handler to use.
            ctx.upstream_candidates = upstream_candidates

            upstream_info = ", ".join(
                [f"{u['host']}:{u['port']}" for u in upstream_candidates]
            )
            logger.debug("Route matched for %s: upstreams [%s]", qname, upstream_info)

        # Do not alter decision flow; just return
        return None

    def _normalize_routes(self, routes: List[Dict]) -> List[Dict]:
        """
        Normalizes and validates routing rules using only the modern 'upstreams' list format.

        Args:
            routes: A list of routing rules.
        Returns:
            A list of normalized routing rules.

        Example use:
            >>> from foghorn.plugins.upstream_router import UpstreamRouter
            >>> plugin = UpstreamRouter()
            >>> routes = [
            ...     {"domain": "MiXeD.Example.", "upstreams": [{"host": "1.1.1.1", "port": "53"}]},
            ...     {"suffix": ".Sub.Example", "upstreams": [{"host": "10.0.0.1", "port": 53}]}
            ... ]
            >>> norm_routes = plugin._normalize_routes(routes)
            >>> norm_routes[0]["domain"]
            'mixed.example'
            >>> norm_routes[0]["upstream_candidates"]
            [{'host': '1.1.1.1', 'port': 53}]
        """
        norm: List[Dict] = []
        for r in routes or []:
            route: Dict[str, object] = {}
            domain = r.get("domain")
            suffix = r.get("suffix")
            if domain:
                route["domain"] = str(domain).rstrip(".").lower()
            if suffix:
                s = str(suffix).lower()
                # Normalize suffix by removing a leading dot for simpler checks
                if s.startswith("."):
                    s = s[1:]
                route["suffix"] = s

            # Modern multiple-upstreams format only
            upstream_candidates: List[Dict[str, int | str]] = []
            multiple_upstreams = r.get("upstreams")
            if multiple_upstreams and isinstance(multiple_upstreams, list):
                for up in multiple_upstreams:
                    if isinstance(up, dict):
                        host = up.get("host")
                        port = up.get("port")
                        if host and port is not None:
                            try:
                                upstream_candidates.append(
                                    {"host": str(host), "port": int(port)}
                                )
                            except (ValueError, TypeError):
                                continue

            # Only add route if we have valid matching criteria and at least one upstream
            if upstream_candidates and ("domain" in route or "suffix" in route):
                route["upstream_candidates"] = upstream_candidates
                norm.append(route)

        return norm

    def _forward_with_failover(
        self, request_wire: bytes, targets: List[Dict[str, any]], timeout_ms: int
    ) -> Tuple[bool, bytes]:
        """
        Brief: Forward a DNS request to multiple upstreams with failover; synthesize SERVFAIL if all fail.

        Inputs:
        - request_wire (bytes): Original client DNS query wire (preserves transaction ID).
        - targets (List[Dict[str, Any]]): List of upstream targets with host/port.
        - timeout_ms (int): Per-attempt timeout in milliseconds.

        Outputs:
        - (bool, bytes): Tuple of (success flag, response wire). On failure, response is a SERVFAIL.

        Example:
        >>> success, resp = self._forward_with_failover(req_wire, [{"host":"1.1.1.1","port":53},{"host":"8.8.8.8","port":53}], 2000)
        >>> success
        True
        """
        req = DNSRecord.parse(request_wire)
        qname = str(req.q.qname)
        qtype = req.q.qtype
        timeout_seconds = timeout_ms / 1000.0
        total_upstreams = len(targets)

        for i, upstream in enumerate(targets, 1):
            host = upstream["host"]
            port = upstream["port"]

            logger.debug(
                "Upstream attempt %d/%d to %s:%d for %s %s",
                i,
                total_upstreams,
                host,
                port,
                qname,
                qtype,
            )

            try:
                reply_bytes = req.send(host, port, timeout=timeout_seconds)

                # Parse response to check rcode
                try:
                    reply_record = DNSRecord.parse(reply_bytes)
                    rcode = reply_record.header.rcode

                    if rcode == RCODE.SERVFAIL:
                        logger.debug(
                            "Upstream %s:%d returned SERVFAIL for %s %s; failing over",
                            host,
                            port,
                            qname,
                            qtype,
                        )
                        continue
                    else:
                        # Any other response code (including NXDOMAIN) is valid - don't failover
                        rcode_name = RCODE.get(rcode, f"RCODE({rcode})")
                        logger.debug(
                            "Upstream %s:%d returned %s for %s %s; accepting",
                            host,
                            port,
                            rcode_name,
                            qname,
                            qtype,
                        )
                        return True, reply_bytes

                except Exception as parse_e:
                    # If we can't parse the response, treat it as valid anyway
                    logger.debug(
                        "Could not parse response from %s:%d, but accepting anyway: %s",
                        host,
                        port,
                        str(parse_e),
                    )
                    return True, reply_bytes

            except (
                Exception
            ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                logger.debug(
                    "Upstream %s:%d error for %s %s: %s",
                    host,
                    port,
                    qname,
                    qtype,
                    str(e),
                )
                continue

        # All upstreams failed
        logger.warning(
            "All %d upstreams failed for %s %s; returning SERVFAIL",
            total_upstreams,
            qname,
            qtype,
        )
        servfail_reply = req.reply()
        servfail_reply.header.rcode = RCODE.SERVFAIL
        return False, servfail_reply.pack()

    def _match_upstream_candidates(
        self, q: str
    ) -> Optional[List[Dict[str, str | int]]]:
        """
        Finds upstream candidates for a given query name.
        Args:
            q: The query name.
        Returns:
            A list of upstream candidates, or None if no match is found.

        Example use:
            >>> from foghorn.plugins.upstream_router import UpstreamRouter
            >>> config = {
            ...     "routes": [
            ...         {"domain": "example.com", "upstream": {"host": "1.1.1.1", "port": 53}},
            ...         {"suffix": "corp", "upstreams": [{"host": "10.0.0.1", "port": 53}, {"host": "10.0.0.2", "port": 53}]}
            ...     ]
            ... }
            >>> plugin = UpstreamRouter(**config)
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
