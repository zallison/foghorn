"""Shared DNS runtime/config state for resolver and transport handlers."""

from __future__ import annotations

import time
from typing import Dict, List, Optional

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.resolve.base import BasePlugin


class DNSRuntimeState:
    """Brief: Shared runtime/config state holder for DNS resolver pipelines.

    Inputs:
      - None (class-level state holder configured by DNSServer/runtime snapshots).

    Outputs:
      - Class attributes and helper methods used by UDP handlers, shared
        resolver paths, and admin/status views.
    """

    upstream_addrs: List[Dict] = []
    plugins: List[BasePlugin] = []
    timeout = 2.0
    timeout_ms = 2000
    min_cache_ttl = 60
    stats_collector = None
    dnssec_mode = "ignore"  # ignore | passthrough | validate
    dnssec_validation = "upstream_ad"  # upstream_ad | local | local_extended
    edns_udp_payload = 1232
    enable_ede: bool = False

    # Optional explicit UDP response size ceiling. When None, the effective
    # ceiling is computed from the client EDNS payload size (or 512 for non-EDNS)
    # and edns_udp_payload.
    max_response_bytes: int | None = None

    # Cache prefetch / stale-while-revalidate knobs controlled by DNSServer.
    cache_prefetch_enabled: bool = False
    cache_prefetch_min_ttl: int = 0
    cache_prefetch_max_ttl: int = 0  # 0 == no upper bound
    cache_prefetch_refresh_before_expiry: float = 0.0
    cache_prefetch_allow_stale_after_expiry: float = 0.0

    # Resolver mode and recursion controls.
    resolver_mode: str = "forward"  # forward | recursive | master
    recursive_max_depth: int = 12
    recursive_timeout_ms: int = 2000
    recursive_per_try_timeout_ms: int = 2000
    root_hints_path: Optional[str] = None

    # Upstream selection strategy and concurrency controls (forward mode).
    upstream_strategy: str = "failover"  # failover | round_robin | random
    upstream_max_concurrent: int = 1
    _upstream_rr_index: int = 0

    # AXFR/IXFR transfer policy.
    axfr_enabled: bool = False
    axfr_allow_clients: list[str] = []

    # When False (default), .local is not forwarded upstream.
    forward_local: bool = False

    # Lazy health state for upstreams keyed by a stable upstream identifier.
    upstream_health: Dict[str, Dict[str, float]] = {}

    @staticmethod
    def _upstream_id(up: Dict) -> str:
        """Brief: Compute a stable identifier string for an upstream config.

        Inputs:
          - up: Upstream mapping (may contain 'url' for DoH or 'host'/'port').

        Outputs:
          - str: Identifier suitable for indexing upstream health state.
        """
        if not isinstance(up, dict):
            return ""
        url = up.get("url")
        if url:
            return str(url)
        host = up.get("host")
        port = up.get("port")
        if host is None and port is None:
            return ""
        try:
            return f"{host}:{int(port) if port is not None else 0}"
        except Exception:
            return str(host) if host is not None else ""

    @classmethod
    def _mark_upstreams_down(cls, upstreams: List[Dict], reason: Optional[str]) -> None:
        """Brief: Mark a set of upstreams as temporarily down with backoff.

        Inputs:
          - upstreams: List of upstream config dicts.
          - reason: Optional failure reason (unused, kept for compatibility).

        Outputs:
          - None; updates cls.upstream_health in-place.
        """
        _ = reason
        now = time.time()
        base_delay = 5.0
        max_delay = 300.0

        for up in upstreams or []:
            up_id = cls._upstream_id(up)
            if not up_id:
                continue
            entry = cls.upstream_health.get(up_id) or {
                "fail_count": 0,
                "down_until": 0.0,
            }
            fail_count = int(entry.get("fail_count", 0)) + 1

            a, b = 1, 1
            for _ in range(max(0, fail_count - 1)):
                a, b = b, a + b
            delay = min(base_delay * float(a), max_delay)

            cls.upstream_health[up_id] = {
                "fail_count": float(fail_count),
                "down_until": now + delay,
            }

    @classmethod
    def _mark_upstream_ok(cls, upstream: Optional[Dict]) -> None:
        """Brief: Reset health state for a single upstream on success.

        Inputs:
          - upstream: Upstream config dict or None.

        Outputs:
          - None; updates cls.upstream_health in-place.
        """
        if not upstream or not isinstance(upstream, dict):
            return
        up_id = cls._upstream_id(upstream)
        if not up_id:
            return
        entry = cls.upstream_health.get(up_id)
        if not entry:
            return
        cls.upstream_health[up_id] = {"fail_count": 0.0, "down_until": 0.0}

    @classmethod
    def _cleanup_upstream_health(cls, max_age_hours: float = 24.0) -> None:
        """Brief: Remove stale upstream health entries to prevent unbounded growth.

        Inputs:
          - max_age_hours: Maximum age in hours for healthy entries.

        Outputs:
          - None; modifies cls.upstream_health in-place.
        """
        now = time.time()
        max_age_seconds = float(max_age_hours) * 3600.0
        entries_to_remove: list[str] = []

        for up_id, entry in list(cls.upstream_health.items()):
            if not isinstance(entry, dict):
                entries_to_remove.append(up_id)
                continue

            down_until = float(entry.get("down_until", 0.0) or 0.0)
            if down_until > now:
                continue

            fail_count = float(entry.get("fail_count", 0) or 0)
            if (
                fail_count == 0
                and down_until <= now
                and now - down_until > max_age_seconds
            ):
                entries_to_remove.append(up_id)

        for up_id in entries_to_remove:
            cls.upstream_health.pop(up_id, None)

    def _ensure_edns(self, req: DNSRecord) -> None:
        """Ensure request has EDNS(0) with payload/DO bit aligned to runtime state.

        Inputs:
          - req: DNSRecord to mutate in-place.

        Outputs:
          - None.
        """
        opt_idx = None
        opt_rr = None
        additional = getattr(req, "ar", []) or []
        for idx, rr in enumerate(additional):
            if rr.rtype == QTYPE.OPT:
                opt_idx = idx
                opt_rr = rr
                break

        do_bit = (
            0x8000
            if str(getattr(self, "dnssec_mode", "ignore")).lower()
            in ("passthrough", "validate")
            else 0
        )

        try:
            server_max = int(getattr(self, "edns_udp_payload", 1232) or 1232)
        except Exception:
            server_max = 1232
        if server_max < 512:
            server_max = 512

        if opt_rr is not None:
            try:
                client_payload = int(getattr(opt_rr, "rclass", 0) or 0)
            except Exception:
                client_payload = 0
            if client_payload <= 0:
                payload = server_max
            elif server_max > 0:
                payload = min(client_payload, server_max)
            else:
                payload = client_payload

            try:
                ttl_val = int(getattr(opt_rr, "ttl", 0) or 0)
            except Exception:
                ttl_val = 0
            ext_rcode = (ttl_val >> 24) & 0xFF
            version = (ttl_val >> 16) & 0xFF
            flags = ttl_val & 0xFFFF
            flags = (flags & ~0x8000) | do_bit
            opt_rr.rclass = payload
            opt_rr.ttl = (ext_rcode << 24) | (version << 16) | (flags & 0xFFFF)
            return

        from . import server as _server_mod

        flags_str = "do" if do_bit else ""
        opt_rr = _server_mod.EDNS0(udp_len=server_max, flags=flags_str)
        if opt_idx is None:
            req.add_ar(opt_rr)
        else:
            req.ar[opt_idx] = opt_rr
