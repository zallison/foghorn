from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from typing import Any, Dict

from .meta import FOGHORN_VERSION, get_process_uptime_seconds
from .snapshot import StatsSnapshot


def format_snapshot_json(snapshot: StatsSnapshot) -> str:
    """Format statistics snapshot as single-line JSON with meta information.

    Inputs:
        snapshot: StatsSnapshot to serialize.

    Outputs:
        JSON string (single line, no trailing newline).

    The output is a compact JSON object suitable for structured logging.
    Empty sections are omitted to minimize log size. A top-level 'meta'
    object includes a timestamp, hostname, version, and process uptime.

    Notes:
      - The ``totals`` object always includes ``cache_deny_pre`` and
        ``cache_override_pre`` fields so downstream dashboards can safely
        rely on their presence even when zero.

    Example:
        >>> collector = StatsCollector()
        >>> collector.record_query('1.2.3.4', 'example.com', 'A')
        >>> snap = collector.snapshot()
        >>> json_str = format_snapshot_json(snap)
        >>> 'total_queries' in json_str
        True
    """
    ts = datetime.fromtimestamp(snapshot.created_at, tz=timezone.utc).isoformat()

    try:
        hostname = socket.gethostname()
    except Exception:  # pragma: no cover
        hostname = "unknown-host"

    meta: Dict[str, Any] = {
        "timestamp": ts,
        "hostname": hostname,
        "version": FOGHORN_VERSION,
        "uptime": get_process_uptime_seconds(),
    }

    output: Dict[str, Any] = {
        "ts": ts,
        "totals": snapshot.totals,
        "meta": meta,
    }

    if getattr(snapshot, "dnssec_totals", None):
        output["dnssec"] = snapshot.dnssec_totals

    if getattr(snapshot, "ede_totals", None):
        output["ede"] = snapshot.ede_totals

    if snapshot.uniques:
        output["uniques"] = snapshot.uniques

    if snapshot.rcodes:
        output["rcodes"] = snapshot.rcodes

    if snapshot.qtypes:
        output["qtypes"] = snapshot.qtypes

    if snapshot.decisions:
        output["plugins"] = snapshot.decisions

    if snapshot.upstreams:
        output["upstreams"] = snapshot.upstreams

    if snapshot.top_clients:
        output["top_clients"] = [
            {"client": c, "count": n} for c, n in snapshot.top_clients
        ]

    if snapshot.top_subdomains:
        output["top_subdomains"] = [
            {"domain": d, "count": n} for d, n in snapshot.top_subdomains
        ]

    if snapshot.top_domains:
        output["top_domains"] = [
            {"domain": d, "count": n} for d, n in snapshot.top_domains
        ]

    if snapshot.upstream_rcodes:
        output["upstream_rcodes"] = snapshot.upstream_rcodes

    if snapshot.upstream_qtypes:
        output["upstream_qtypes"] = snapshot.upstream_qtypes

    if snapshot.qtype_qnames:
        output["qtype_qnames"] = snapshot.qtype_qnames

    if snapshot.rcode_domains:
        output["rcode_domains"] = {
            rcode: [{"domain": d, "count": n} for d, n in entries]
            for rcode, entries in snapshot.rcode_domains.items()
        }

    if snapshot.rcode_subdomains:
        output["rcode_subdomains"] = {
            rcode: [{"domain": d, "count": n} for d, n in entries]
            for rcode, entries in snapshot.rcode_subdomains.items()
        }

    if snapshot.cache_hit_domains:
        output["cache_hit_domains"] = [
            {"domain": d, "count": n} for d, n in snapshot.cache_hit_domains
        ]

    if snapshot.cache_miss_domains:
        output["cache_miss_domains"] = [
            {"domain": d, "count": n} for d, n in snapshot.cache_miss_domains
        ]

    if snapshot.cache_hit_subdomains:
        output["cache_hit_subdomains"] = [
            {"domain": d, "count": n} for d, n in snapshot.cache_hit_subdomains
        ]

    if snapshot.cache_miss_subdomains:
        output["cache_miss_subdomains"] = [
            {"domain": d, "count": n} for d, n in snapshot.cache_miss_subdomains
        ]

    if snapshot.latency_stats:
        output["latency"] = snapshot.latency_stats

    if snapshot.latency_recent_stats:
        output["latency_recent"] = snapshot.latency_recent_stats

    if snapshot.rate_limit:
        output["rate_limit"] = snapshot.rate_limit

    return json.dumps(output, separators=(",", ":"))
