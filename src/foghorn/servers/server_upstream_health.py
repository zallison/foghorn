"""Upstream health helper state and payload shaping for admin endpoints."""

from typing import Dict, Optional

from .udp_server import DNSUDPHandler


class _UpstreamHealth:
    """Brief: Describe upstream health state for admin UI payloads.

    Inputs:
      - None (reads DNSUDPHandler.upstream_health state).

    Outputs:
      - describe_upstream returns a dict of upstream status fields or None.
    """

    def upstream_id(self, upstream: Dict) -> str:
        """Brief: Compute a stable upstream identifier.

        Inputs:
          - upstream: Upstream configuration mapping.

        Outputs:
          - str identifier (host:port or URL when available).
        """
        if not isinstance(upstream, dict):
            return ""
        try:
            upstream_id = DNSUDPHandler._upstream_id(upstream)
        except Exception:
            upstream_id = ""
        if upstream_id:
            return str(upstream_id)
        try:
            url = upstream.get("url") or upstream.get("endpoint")
        except Exception:
            url = None
        if url:
            return str(url)
        try:
            host = upstream.get("host")
        except Exception:
            host = None
        try:
            port = upstream.get("port")
        except Exception:
            port = None
        if host or port:
            try:
                return f"{host}:{int(port) if port is not None else 0}"
            except Exception:
                return str(host) if host is not None else ""
        return ""

    def describe_upstream(
        self,
        *,
        role: str,
        upstream: Dict,
        now: float,
        cfg,
    ) -> Optional[Dict[str, object]]:
        """Brief: Build a health/status record for a single upstream.

        Inputs:
          - role: "primary" or "backup" upstream role label.
          - upstream: Upstream configuration mapping.
          - now: Current timestamp (seconds since epoch).
          - cfg: UpstreamHealthConfig (unused but accepted for compatibility).

        Outputs:
          - dict with keys suitable for /api/v1/upstream_status items, or None.

        Example:
          >>> rec = _UPSTREAM_HEALTH.describe_upstream(role="primary", upstream={"host": "1.1.1.1", "port": 53}, now=0.0, cfg=None)
        """
        if not isinstance(upstream, dict):
            return None
        upstream_id = self.upstream_id(upstream)

        try:
            host = upstream.get("host")
        except Exception:
            host = None
        try:
            port = upstream.get("port")
        except Exception:
            port = None

        try:
            transport = upstream.get("transport")
        except Exception:
            transport = None
        if not transport:
            transport = (
                "doh" if upstream.get("url") or upstream.get("endpoint") else "udp"
            )

        url = None
        try:
            url = upstream.get("url") or upstream.get("endpoint")
        except Exception:
            url = None

        entry = None
        if upstream_id:
            entry = DNSUDPHandler.upstream_health.get(upstream_id)

        fail_count = 0.0
        down_until = None
        state = "up"
        if isinstance(entry, dict):
            try:
                fail_count = float(entry.get("fail_count", 0.0) or 0.0)
            except Exception:
                fail_count = 0.0
            try:
                raw_down_until = float(entry.get("down_until", 0.0) or 0.0)
            except Exception:
                raw_down_until = 0.0
            if raw_down_until and raw_down_until > float(now):
                down_until = raw_down_until
                state = "down"
            elif fail_count > 0:
                state = "degraded"

        if not upstream_id:
            upstream_id = self.upstream_id(upstream)

        return {
            "id": upstream_id,
            "role": str(role),
            "state": state,
            "fail_count": fail_count,
            "down_until": down_until,
            "host": str(host) if host is not None else None,
            "port": int(port) if port is not None else None,
            "transport": str(transport) if transport is not None else None,
            "url": str(url) if url is not None else None,
            "config": dict(upstream),
        }


_UPSTREAM_HEALTH = _UpstreamHealth()
