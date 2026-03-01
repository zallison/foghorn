from __future__ import annotations

import socket
import time
from typing import Any, Dict

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from ...stats import StatsCollector, StatsSnapshot, get_process_uptime_seconds
from . import admin_logic as _admin_logic
from . import core as web_mod
from .stats_helpers import (
    _build_stats_payload_from_snapshot,
    _build_traffic_payload_from_snapshot,
    _get_stats_snapshot_cached,
    _trim_top_fields,
    _utc_now_iso,
)


def _register_stats_routes(app: FastAPI, auth_dep: Any, version: str) -> None:
    """Register statistics, traffic, upstream status, and ratelimit endpoints.

    Inputs:
      - app: FastAPI application instance.
      - auth_dep: FastAPI dependency for authentication.
      - version: Foghorn version string for meta payloads.

    Outputs:
      - None (routes are registered on the app).
    """

    @app.get("/api/v1/stats", dependencies=[Depends(auth_dep)])
    @app.get("/stats", dependencies=[Depends(auth_dep)], include_in_schema=False)
    async def get_stats(reset: bool = False, top: int = 10) -> Dict[str, Any]:
        """Return statistics snapshot from StatsCollector as JSON.

        Inputs:
          - reset: If True, reset counters after snapshot.
          - top: Optional integer limit for the number of entries returned in
            top_* lists (Top Domains/Subdomains, Top Clients, cache_* and
            rcode/qtype top lists). Defaults to 10.

        Outputs:
          - Dict representing StatsSnapshot fields.
        """

        collector: StatsCollector | None = app.state.stats_collector
        if collector is None:
            return {"status": "disabled", "server_time": _utc_now_iso()}

        t_start = time.time()
        snap: StatsSnapshot = _get_stats_snapshot_cached(collector, bool(reset))
        t_after_snapshot = time.time()

        try:
            hostname = socket.gethostname()
        except Exception:  # pragma: no cover - environment specific
            hostname = "unknown-host"
        try:
            host_ip = socket.gethostbyname(hostname)
        except Exception:  # pragma: no cover - environment specific
            host_ip = "0.0.0.0"

        uptime_seconds = int(round(get_process_uptime_seconds()))

        meta: Dict[str, Any] = {
            "created_at": snap.created_at,
            "server_time": _utc_now_iso(),
            "hostname": hostname,
            "ip": host_ip,
            "version": version,
            "uptime": uptime_seconds,
        }

        # Use get_system_info exposed via the webserver module so that
        # monkeypatching foghorn.servers.webserver.get_system_info in tests
        # transparently affects this route handler.
        system_info = web_mod.get_system_info()
        t_after_system = time.time()

        if getattr(app.state, "debug_stats_timings", False):
            import logging

            logger = logging.getLogger("foghorn.webserver")
            logger.debug(
                "/stats timings: snapshot=%.6fs system_info=%.6fs total=%.6fs",
                t_after_snapshot - t_start,
                t_after_system - t_after_snapshot,
                t_after_system - t_start,
            )

        if snap.uniques:
            meta_with_uniques = meta | snap.uniques
        else:
            meta_with_uniques = meta

        payload = _build_stats_payload_from_snapshot(
            snap,
            meta=meta_with_uniques,
            system_info=system_info,
        )

        try:
            limit = int(top)
        except (TypeError, ValueError):
            limit = 10
        if limit <= 0:
            limit = 10

        _trim_top_fields(
            payload,
            limit,
            [
                "top_clients",
                "top_subdomains",
                "top_domains",
                "cache_hit_domains",
                "cache_miss_domains",
                "cache_hit_subdomains",
                "cache_miss_subdomains",
                "qtype_qnames",
                "rcode_domains",
                "rcode_subdomains",
            ],
        )

        return payload

    @app.get("/api/v1/stats/table/{table_id}", dependencies=[Depends(auth_dep)])
    async def get_stats_table(
        table_id: str,
        group_key: str | None = None,
        page: int = 1,
        page_size: int = 50,
        sort_key: str | None = None,
        sort_dir: str | None = None,
        search: str | None = None,
    ) -> Dict[str, Any]:
        """Brief: Return a server-side paginated/sortable/searchable stats table.

        Inputs:
          - table_id: Identifier for the stats list to render (e.g. cache_miss_domains).
          - group_key: Optional key for grouped tables (e.g. qtype_qnames or rcode_domains).
          - page/page_size/sort_key/sort_dir/search: Standard table controls.

        Outputs:
          - A table payload compatible with admin_logic.build_table_page_payload.
        """

        collector: StatsCollector | None = app.state.stats_collector
        if collector is None:
            raise HTTPException(
                status_code=404,
                detail="stats collector disabled",
            )

        snap: StatsSnapshot = _get_stats_snapshot_cached(collector, reset=False)

        def _pairs_to_rows(pairs: Any) -> list[dict[str, object]]:
            out: list[dict[str, object]] = []
            if not isinstance(pairs, list):
                return out
            for item in pairs:
                if not isinstance(item, (list, tuple)) or len(item) < 2:
                    continue
                name, count = item[0], item[1]
                try:
                    count_i = int(count)
                except Exception:
                    continue
                out.append({"name": str(name), "count": count_i})
            return out

        tid = str(table_id or "").strip()
        rows: list[dict[str, object]] = []
        if tid in {
            "top_clients",
            "top_domains",
            "top_subdomains",
            "cache_hit_domains",
            "cache_miss_domains",
            "cache_hit_subdomains",
            "cache_miss_subdomains",
        }:
            pairs = getattr(snap, tid, None)
            rows = _pairs_to_rows(pairs)
        elif tid in {"qtype_qnames", "rcode_domains", "rcode_subdomains"}:
            if not group_key:
                raise HTTPException(
                    status_code=400,
                    detail="group_key is required for grouped stats tables",
                )
            mapping = getattr(snap, tid, None)
            if not isinstance(mapping, dict):
                rows = []
            else:
                pairs = mapping.get(str(group_key))
                rows = _pairs_to_rows(pairs)
        else:
            raise HTTPException(status_code=404, detail="unknown stats table")

        payload = _admin_logic.build_table_page_payload(
            rows,
            page=page,
            page_size=page_size,
            sort_key=sort_key,
            sort_dir=sort_dir,
            search=search,
            hide_zero_calls=False,
            hide_zero_hits=False,
            show_down_services=True,
            hide_hash_like=False,
            default_sort_key="count",
            default_sort_dir="desc",
        )
        payload["server_time"] = _utc_now_iso()
        payload["table_id"] = tid
        if group_key is not None:
            payload["group_key"] = str(group_key)
        return payload

    @app.post("/api/v1/stats/reset", dependencies=[Depends(auth_dep)])
    @app.post(
        "/stats/reset",
        dependencies=[Depends(auth_dep)],
        include_in_schema=False,
    )
    async def reset_stats() -> Dict[str, Any]:
        """Reset all statistics counters if collector is active."""

        collector: StatsCollector | None = app.state.stats_collector
        if collector is None:
            return {"status": "disabled", "server_time": _utc_now_iso()}
        collector.snapshot(reset=True)
        return {"status": "ok", "server_time": _utc_now_iso()}

    @app.get("/api/v1/traffic", dependencies=[Depends(auth_dep)])
    @app.get("/traffic", dependencies=[Depends(auth_dep)], include_in_schema=False)
    async def get_traffic(top: int = 10) -> Dict[str, Any]:
        """Return a summarized traffic view derived from statistics snapshot."""

        collector: StatsCollector | None = app.state.stats_collector
        if collector is None:
            return {"status": "disabled", "server_time": _utc_now_iso()}
        snap: StatsSnapshot = _get_stats_snapshot_cached(collector, reset=False)

        try:
            hostname = socket.gethostname()
        except Exception:  # pragma: no cover - environment specific
            hostname = "unknown-host"
        try:
            host_ip = socket.gethostbyname(hostname)
        except Exception:  # pragma: no cover - environment specific
            host_ip = "0.0.0.0"

        meta: Dict[str, Any] = {
            "created_at": snap.created_at,
            "server_time": _utc_now_iso(),
            "hostname": hostname,
            "ip": host_ip,
            "version": version,
        }

        try:
            limit = int(top)
        except (TypeError, ValueError):
            limit = 10
        if limit <= 0:
            limit = 10

        return _build_traffic_payload_from_snapshot(snap, meta=meta, top=limit)

    @app.get("/api/v1/upstream_status", dependencies=[Depends(auth_dep)])
    async def get_upstream_status() -> Dict[str, Any]:
        """Return upstream strategy, concurrency, and lazy health state."""

        cfg = app.state.config or {}
        payload = _admin_logic.build_upstream_status_payload(cfg)
        payload["server_time"] = _utc_now_iso()
        return payload

    @app.get("/api/v1/ratelimit", dependencies=[Depends(auth_dep)])
    async def get_rate_limit() -> Dict[str, Any]:
        """Return RateLimit statistics derived from sqlite3 profiles."""

        cfg = app.state.config or {}
        data = web_mod._collect_rate_limit_stats(cfg)
        data["server_time"] = _utc_now_iso()
        return data
