"""Upstream health helper state and payload shaping for admin endpoints."""

from typing import Dict, Optional

from .dns_runtime_state import DNSRuntimeState

_REDACTED_VALUE = "***REDACTED***"
_MAX_LAST_ERROR_LEN = 200
_SENSITIVE_CONFIG_KEYS = frozenset(
    {
        "secret",
        "key",
        "password",
        "token",
        "api_key",
        "private_key",
        "tsig_key",
        "tls_key",
        "ca_file",
        "cert_file",
    }
)


def _redact_upstream_config(upstream: Dict) -> Dict:
    """Brief: Return a recursively redacted copy of upstream config.

    Inputs:
      - upstream: Upstream mapping that may include nested dictionaries.

    Outputs:
      - Dict copy where sensitive keys are replaced with a redaction marker.
    """
    if not isinstance(upstream, dict):
        return {}
    redacted = {}
    for key, value in upstream.items():
        key_str = str(key)
        if key_str.lower() in _SENSITIVE_CONFIG_KEYS:
            redacted[key] = _REDACTED_VALUE
        elif isinstance(value, dict):
            redacted[key] = _redact_upstream_config(value)
        else:
            redacted[key] = value
    return redacted


class _UpstreamHealth:
    """Brief: Describe upstream health state for admin UI payloads.

    Inputs:
      - None (reads DNSRuntimeState.upstream_health state).

    Outputs:
      - upstream_id returns a stable identifier string, or an empty string.
      - describe_upstream returns a dict of upstream status fields, or None.

    Notes:
      - Callers must enforce admin authorization before exposing this payload.
    """

    def _compute_old_upstream_key(self, upstream: Dict) -> str:
        """Brief: Compute upstream key using old scheme (pre-id-field) for migration.

        Inputs:
          - upstream: Upstream configuration mapping.

        Outputs:
          - str old-style identifier (URL or host:port, never config id).
        """
        if not isinstance(upstream, dict):
            return ""
        # Old scheme: URL first, then host:port.
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
            upstream_id = DNSRuntimeState._upstream_id(upstream)
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
          - state is one of: "up", "degraded", "down".

        Example:
          >>> rec = _UPSTREAM_HEALTH.describe_upstream(role="primary", upstream={"host": "1.1.1.1", "port": 53}, now=0.0, cfg=None)

        Raises:
          - ValueError/TypeError if upstream["port"] exists but cannot be
            coerced to an int.
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
            entry = DNSRuntimeState.upstream_health.get(upstream_id)
            # Migrate health data from old key (host:port) to new key (id) if needed.
            if not entry:
                old_key = self._compute_old_upstream_key(upstream)
                if old_key and old_key != upstream_id:
                    old_entry = DNSRuntimeState.upstream_health.get(old_key)
                    if old_entry:
                        # Move the health data to the new key.
                        DNSRuntimeState.upstream_health[upstream_id] = old_entry
                        DNSRuntimeState.upstream_health.pop(old_key, None)
                        entry = old_entry

        fail_count = 0.0
        down_until = None
        last_error = None
        last_error_ts = None
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
            try:
                raw_last_error_ts = float(entry.get("last_error_ts", 0.0) or 0.0)
            except Exception:
                raw_last_error_ts = 0.0
            try:
                raw_last_error = entry.get("last_error")
            except Exception:
                raw_last_error = None
            if raw_down_until and raw_down_until > float(now):
                down_until = raw_down_until
                state = "down"
            if raw_last_error_ts > 0:
                last_error_ts = raw_last_error_ts
            if raw_last_error is not None:
                last_error = str(raw_last_error)[:_MAX_LAST_ERROR_LEN]

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
            "last_error": last_error,
            "last_error_ts": last_error_ts,
            "config": _redact_upstream_config(upstream),
        }


_UPSTREAM_HEALTH = _UpstreamHealth()
