from __future__ import annotations
from typing import Dict, List, Optional, Tuple

from .base import BasePlugin, PluginContext, PluginDecision

class UpstreamRouterPlugin(BasePlugin):
    """
    Route queries to different upstream DNS servers based on the queried domain.

    Config example:
    {
      "routes": [
        {"domain": "corp.example.com", "upstream": {"host": "10.0.0.53", "port": 53}},
        {"suffix": "internal", "upstream": {"host": "192.168.1.1", "port": 53}},
        {"suffix": ".svc.cluster.local", "upstream": {"host": "127.0.0.1", "port": 1053}}
      ]
    }

    Matching rules:
    - If a route has "domain": exact match on qname (case-insensitive).
    - If a route has "suffix": match if qname equals suffix or ends with "." + suffix (case-insensitive).
    - First matching rule wins.
    """

    def __init__(self, **config):
        super().__init__(**config)
        self.routes: List[Dict] = self._normalize_routes(self.config.get("routes", []))

    def pre_resolve(self, qname: str, qtype: int, ctx: PluginContext) -> Optional[PluginDecision]:
        q = qname.rstrip('.').lower()
        upstream = self._match_upstream(q)
        if upstream is not None:
            ctx.upstream_override = upstream
        # Do not alter decision flow; just annotate context
        return None

    def _normalize_routes(self, routes: List[Dict]) -> List[Dict]:
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
        for r in self.routes:
            if "domain" in r and q == r["domain"]:
                return r["upstream"]
            if "suffix" in r:
                s = r["suffix"]
                if q == s or q.endswith("." + s):
                    return r["upstream"]
        return None
