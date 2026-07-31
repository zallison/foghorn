from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import Depends, FastAPI, HTTPException

from ...stats import StatsCollector, StatsSnapshot
from . import admin_logic as _admin_logic
from . import core as web_mod
from . import endpoint_services as _endpoint_services
from .stats_helpers import (
    _get_stats_snapshot_cached,
    _utc_now_iso,
    resolve_stats_table_rows,
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

        t_start = time.time()
        collector: StatsCollector | None = app.state.stats_collector
        _status_code, payload = _endpoint_services.build_stats_result(
            collector=collector,
            reset=bool(reset),
            top=top,
            get_system_info=web_mod.get_system_info,
            version=version,
        )
        t_after_system = time.time()

        if getattr(app.state, "debug_stats_timings", False):
            import logging

            logger = logging.getLogger("foghorn.webserver")
            logger.debug(
                "/stats timings: snapshot=%.6fs system_info=%.6fs total=%.6fs",
                0.0,
                0.0,
                t_after_system - t_start,
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

        tid = str(table_id or "").strip()
        rows, error_code = resolve_stats_table_rows(
            snap,
            table_id=tid,
            group_key=group_key,
        )
        if error_code == "missing_group_key":
            raise HTTPException(
                status_code=400,
                detail="group_key is required for grouped stats tables",
            )
        if error_code == "unknown_table":
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
        _status_code, payload = _endpoint_services.build_stats_reset_result(
            collector=app.state.stats_collector
        )
        return payload

    @app.get("/api/v1/traffic", dependencies=[Depends(auth_dep)])
    @app.get("/traffic", dependencies=[Depends(auth_dep)], include_in_schema=False)
    async def get_traffic(top: int = 10) -> Dict[str, Any]:
        """Return a summarized traffic view derived from statistics snapshot."""
        _status_code, payload = _endpoint_services.build_traffic_result(
            collector=app.state.stats_collector,
            top=top,
            version=version,
        )
        return payload

    @app.get("/api/v1/upstream_status", dependencies=[Depends(auth_dep)])
    async def get_upstream_status() -> Dict[str, Any]:
        """Return upstream strategy, concurrency, and lazy health state."""
        _status_code, payload = _endpoint_services.build_upstream_status_result(
            config=getattr(app.state, "config", None),
            build_payload=_admin_logic.build_upstream_status_payload,
        )
        return payload

    @app.get("/api/v1/ratelimit", dependencies=[Depends(auth_dep)])
    async def get_rate_limit() -> Dict[str, Any]:
        """Return RateLimit statistics derived from sqlite3 profiles."""
        _status_code, payload = _endpoint_services.build_rate_limit_result(
            config=getattr(app.state, "config", None),
            plugins=getattr(app.state, "plugins", None),
            collect_stats=web_mod._collect_rate_limit_stats,
        )
        return payload
