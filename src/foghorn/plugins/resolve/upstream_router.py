from __future__ import annotations

import logging
from typing import Any

from dnslib import RCODE, DNSRecord
from pydantic import BaseModel, ConfigDict, Field, model_validator

from foghorn.utils import dns_names

from .base import BasePlugin, PluginContext, PluginDecision, plugin_aliases

logger = logging.getLogger(__name__)


class UpstreamRouteTarget(BaseModel):
    """Brief: Single upstream target (host/port or URL-form).

    Inputs:
      - host: Upstream DNS host (host/port form).
      - port: Upstream DNS port (host/port form).
      - url: Optional URL-form upstream (e.g. ``dot://1.1.1.1``).
      - Additional transport/tls/id fields are allowed via ``extra="allow"``.

    Outputs:
      - UpstreamRouteTarget instance with normalized types.

    Notes:
      - Matches top-level ``upstreams.endpoints`` shapes: either explicit
        ``host``/``port`` or a ``url`` scheme form expanded later by
        config_parser / route normalization.
    """

    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    url: str | None = None

    model_config = ConfigDict(extra="allow")

    @model_validator(mode="after")
    def _require_host_port_or_url(self) -> UpstreamRouteTarget:
        """Brief: Require either URL-form or host (+ optional port).

        Inputs:
          - self: Partially validated model.

        Outputs:
          - self when valid.

        Raises:
          - ValueError: When neither url nor host is provided.
        """

        has_url = isinstance(self.url, str) and bool(self.url.strip())
        has_host = isinstance(self.host, str) and bool(self.host.strip())
        if not has_url and not has_host:
            raise ValueError("upstream target requires 'url' or 'host'")
        return self


class UpstreamRoute(BaseModel):
    """Brief: Route definition for UpstreamRouter.

    Inputs:
      - domain: Exact domain to match.
      - suffix: Suffix to match (without leading dot).
      - upstreams: List of upstream targets.

    Outputs:
      - UpstreamRoute instance with normalized types.
    """

    domain: str | None = None
    suffix: str | None = None
    upstreams: list[UpstreamRouteTarget] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


class UpstreamRouterConfig(BaseModel):
    """Brief: Typed configuration model for UpstreamRouter.

    Inputs:
      - routes: List of UpstreamRoute definitions.

    Outputs:
      - UpstreamRouterConfig instance with normalized field types.
    """

    routes: list[UpstreamRoute] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


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
        self.routes: list[dict] = self._normalize_routes(self.config.get("routes", []))
        self._build_route_indexes()

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> PluginDecision | None:
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

        q = dns_names.normalize_name(qname)
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

    def _normalize_route_upstream(self, up: dict[str, Any]) -> dict[str, object] | None:
        """Brief: Normalize one route upstream entry to runtime shape.

        Inputs:
          - up: Raw upstream mapping (host/port and/or url form).

        Outputs:
          - Normalized upstream dict, or None when the entry is invalid.
        """

        try:
            from foghorn.config.config_parser import _normalize_url_form_upstream_entry
        except Exception:  # pragma: no cover - defensive import
            _normalize_url_form_upstream_entry = None  # type: ignore[assignment]

        if _normalize_url_form_upstream_entry is not None and up.get("url") is not None:
            try:
                url_norm = _normalize_url_form_upstream_entry(up)
            except Exception:
                logger.debug(
                    "UpstreamRouter: invalid url-form upstream %r", up, exc_info=True
                )
                return None
            if isinstance(url_norm, dict):
                return dict(url_norm)
            return None

        host = up.get("host")
        port = up.get("port")
        # Host-form entries still require an explicit port (legacy route schema).
        if not host or port is None:
            return None
        try:
            normalized: dict[str, object] = dict(up)
            normalized["host"] = str(host)
            normalized["port"] = int(port)
        except (TypeError, ValueError):
            return None
        return normalized

    def _normalize_routes(self, routes: list[dict]) -> list[dict]:
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
        norm: list[dict] = []
        for r in routes or []:
            route: dict[str, object] = {}
            domain = r.get("domain")
            suffix = r.get("suffix")
            if domain:
                route["domain"] = dns_names.normalize_name(domain)
            if suffix:
                s = dns_names.normalize_name(suffix)
                # Normalize suffix by removing a leading dot for simpler checks
                s = s.removeprefix(".")
                route["suffix"] = s

            # Modern multiple-upstreams format only. Preserve any additional
            # upstream configuration keys (transport/tls/method/headers/etc.) so
            # that routes can use the same rich upstream definitions as the
            # top-level `upstreams` block. URL-form entries are expanded via the
            # shared config_parser helper.
            upstream_candidates: list[dict[str, object]] = []
            multiple_upstreams = r.get("upstreams")
            if multiple_upstreams and isinstance(multiple_upstreams, list):
                for up in multiple_upstreams:
                    if not isinstance(up, dict):
                        continue

                    normalized = self._normalize_route_upstream(up)
                    if normalized is None:
                        continue
                    upstream_candidates.append(normalized)

            # Only add route if we have valid matching criteria and at least one upstream
            if upstream_candidates and ("domain" in route or "suffix" in route):
                route["upstream_candidates"] = upstream_candidates
                norm.append(route)

        return norm

    def _build_route_indexes(self) -> None:
        """Brief: Build exact/suffix indexes for O(label-depth) route matching.

        Inputs:
          - None (uses self.routes).

        Outputs:
          - None; populates self._exact_index and self._suffix_index.

        Notes:
          - Each key maps to the index of the FIRST normalized route defining
            it, which preserves the historical first-match-wins (config order)
            semantics when _match_upstream_candidates selects among matches.
        """

        exact: dict[str, int] = {}
        suffix: dict[str, int] = {}
        for idx, r in enumerate(self.routes):
            domain = r.get("domain")
            if domain is not None and domain not in exact:
                exact[domain] = idx
            sfx = r.get("suffix")
            if sfx is not None and sfx not in suffix:
                suffix[sfx] = idx
        self._exact_index = exact
        self._suffix_index = suffix

    def _forward_with_failover(
        self, request_wire: bytes, targets: list[dict[str, any]], timeout_ms: int
    ) -> tuple[bool, bytes]:
        """Brief: Forward a DNS request to multiple upstreams using the hardened core helper.

        Inputs:
          - request_wire: Original client DNS query wire (preserves transaction ID).
          - targets: List of upstream target mappings. These may include rich upstream
            settings (transport/tls/method/headers) in addition to host/port.
          - timeout_ms: Per-attempt timeout in milliseconds.

        Outputs:
          - (success, response_wire):
              - success=True when an upstream response was obtained.
              - success=False when all upstream attempts failed; response_wire is a
                synthesized SERVFAIL.

        Notes:
          - This method is retained for test coverage and internal use, but all
            network I/O is delegated to foghorn.servers.server.send_query_with_failover
            to ensure consistent hardening (TXID/question validation, truncation
            handling, transport support).
        """

        from foghorn.servers.server import send_query_with_failover

        req = DNSRecord.parse(request_wire)
        qname = str(req.q.qname)
        qtype = req.q.qtype

        reply, _used_upstream, _reason = send_query_with_failover(
            req,
            list(targets or []),
            int(timeout_ms),
            qname,
            qtype,
            max_concurrent=1,
        )
        if reply is not None:
            return True, reply

        servfail_reply = req.reply()
        servfail_reply.header.rcode = RCODE.SERVFAIL
        return False, servfail_reply.pack()

    def _match_upstream_candidates(self, q: str) -> list[dict[str, str | int]] | None:
        """
        Finds upstream candidates for a given query name.

        Uses the precomputed exact/suffix indexes so lookup cost is proportional
        to the number of labels in the query (O(depth)) rather than to the number
        of configured routes. First-match-wins (config order) semantics are
        preserved: when several routes match, the earliest one in the config wins.

        Args:
            q: The query name (normalized: lowercase, no trailing dot).
        Returns:
            A list of upstream candidates, or None if no match is found.

        Example use:
            >>> from foghorn.plugins.upstream_router import UpstreamRouter
            >>> config = {
            ...     "routes": [
            ...         {"domain": "example.com", "upstreams": [{"host": "1.1.1.1", "port": 53}]},
            ...         {"suffix": "corp", "upstreams": [{"host": "10.0.0.1", "port": 53}, {"host": "10.0.0.2", "port": 53}]}
            ...     ]
            ... }
            >>> plugin = UpstreamRouter(**config)
            >>> plugin._match_upstream_candidates("example.com")
            [{'host': '1.1.1.1', 'port': 53}]
            >>> plugin._match_upstream_candidates("server.corp")
            [{'host': '10.0.0.1', 'port': 53}, {'host': '10.0.0.2', 'port': 53}]
        """
        if not q:
            return None

        best = self._exact_index.get(q)
        # Walk the name one label at a time (full name first, then progressively
        # shorter suffixes); keeping the smallest route index among all matches
        # reproduces the old linear scan's first-match-wins ordering.
        sfx = ""
        for label in reversed(q.split(".")):
            sfx = f"{label}.{sfx}" if sfx else label
            idx = self._suffix_index.get(sfx)
            if idx is not None and (best is None or idx < best):
                best = idx

        if best is None:
            return None
        return self.routes[best]["upstream_candidates"]
