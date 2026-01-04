from __future__ import annotations

"""Query-log and statistics backend abstraction layer.

Inputs:
  - None directly; this package is imported by code that needs a backend
    interface or configuration model for persistent statistics and query logs.

Outputs:
  - Exposes the base backend interface and configuration model used by
    concrete implementations (for example, SQLite, MariaDB/MySQL, MongoDB,
    Redis) to plug into the statistics subsystem.
"""

import logging
from typing import Any, List, Optional

from .base import BaseStatsStore, StatsStoreBackendConfig
from .registry import get_stats_backend_class

__all__ = [
    "BaseStatsStore",
    "StatsStoreBackendConfig",
    "load_stats_store_backend",
]


class MultiStatsStore(BaseStatsStore):
    """Brief: Aggregate backend that fans out writes and reads from the primary.

    Inputs (constructor):
      - backends: Non-empty list of concrete BaseStatsStore instances.

    Outputs:
      - MultiStatsStore instance that:
        - Delegates all read operations (select/export/aggregate/health) to the
          first backend in the list (the primary).
        - Fans out write operations (increment/set/insert/rebuild/close) to all
          backends, logging and continuing on per-backend errors.
    """

    def __init__(self, backends: List[BaseStatsStore], **_: Any) -> None:
        if not backends:
            raise ValueError("MultiStatsStore requires at least one backend")
        self._backends = list(backends)

    # Health and lifecycle -------------------------------------------------
    def health_check(self) -> bool:
        """Brief: Return True when the primary backend reports healthy.

        Inputs:
          - None.

        Outputs:
          - bool from the primary backend's health_check, or True when absent.
        """

        primary = self._backends[0]
        fn = getattr(primary, "health_check", None)
        return bool(fn()) if callable(fn) else True

    def close(self) -> None:
        """Brief: Close all underlying backends, ignoring individual failures.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        for backend in self._backends:
            try:
                backend.close()
            except Exception:
                # Best-effort; logging is deferred to the concrete backend.
                continue

    # Counter API ----------------------------------------------------------
    def increment_count(self, scope: str, key: str, delta: int = 1) -> None:
        for backend in self._backends:
            try:
                backend.increment_count(scope, key, delta)
            except Exception:
                continue

    def set_count(self, scope: str, key: str, value: int) -> None:
        for backend in self._backends:
            try:
                backend.set_count(scope, key, value)
            except Exception:
                continue

    def has_counts(self) -> bool:
        primary = self._backends[0]
        return primary.has_counts()

    def export_counts(self) -> dict[str, dict[str, int]]:
        primary = self._backends[0]
        return primary.export_counts()

    def rebuild_counts_from_query_log(self, logger_obj: Optional["logging.Logger"] = None) -> None:  # type: ignore[name-defined]
        for backend in self._backends:
            try:
                backend.rebuild_counts_from_query_log(logger_obj=logger_obj)
            except Exception:
                continue

    def rebuild_counts_if_needed(
        self,
        force_rebuild: bool = False,
        logger_obj: Optional["logging.Logger"] = None,  # type: ignore[name-defined]
    ) -> None:
        for backend in self._backends:
            try:
                backend.rebuild_counts_if_needed(
                    force_rebuild=force_rebuild, logger_obj=logger_obj
                )
            except Exception:
                continue

    # Query-log API --------------------------------------------------------
    def insert_query_log(
        self,
        ts: float,
        client_ip: str,
        name: str,
        qtype: str,
        upstream_id: Optional[str],
        rcode: Optional[str],
        status: Optional[str],
        error: Optional[str],
        first: Optional[str],
        result_json: str,
    ) -> None:
        for backend in self._backends:
            try:
                backend.insert_query_log(
                    ts,
                    client_ip,
                    name,
                    qtype,
                    upstream_id,
                    rcode,
                    status,
                    error,
                    first,
                    result_json,
                )
            except Exception:
                continue

    def select_query_log(
        self,
        client_ip: Optional[str] = None,
        qtype: Optional[str] = None,
        qname: Optional[str] = None,
        rcode: Optional[str] = None,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> dict[str, Any]:
        primary = self._backends[0]
        return primary.select_query_log(
            client_ip=client_ip,
            qtype=qtype,
            qname=qname,
            rcode=rcode,
            start_ts=start_ts,
            end_ts=end_ts,
            page=page,
            page_size=page_size,
        )

    def aggregate_query_log_counts(
        self,
        start_ts: float,
        end_ts: float,
        interval_seconds: int,
        client_ip: Optional[str] = None,
        qtype: Optional[str] = None,
        qname: Optional[str] = None,
        rcode: Optional[str] = None,
        group_by: Optional[str] = None,
    ) -> dict[str, Any]:
        primary = self._backends[0]
        return primary.aggregate_query_log_counts(
            start_ts=start_ts,
            end_ts=end_ts,
            interval_seconds=interval_seconds,
            client_ip=client_ip,
            qtype=qtype,
            qname=qname,
            rcode=rcode,
            group_by=group_by,
        )

    def has_query_log(self) -> bool:
        primary = self._backends[0]
        return primary.has_query_log()


def _normalize_backend_name(raw: str) -> str:
    """Brief: Normalize a backend identifier or instance name.

    Inputs:
      - raw: Raw string from configuration.

    Outputs:
      - Lowercased, trimmed name with dashes converted to underscores.
    """

    return raw.strip().lower().replace("-", "_")


def _build_backend_from_config(cfg: StatsStoreBackendConfig) -> BaseStatsStore:
    """Brief: Construct a concrete backend from a StatsStoreBackendConfig.

    Inputs:
      - cfg: Parsed backend configuration model.

    Outputs:
      - Concrete BaseStatsStore instance.

    Notes:
      - Supports short backend aliases ("sqlite", "mysql", "mariadb").
      - Additional backends can be wired in later via this helper.
    """

    backend_name = _normalize_backend_name(cfg.backend) if cfg.backend else "sqlite"
    conf = dict(cfg.config or {})

    # Resolve the concrete backend class via the registry, allowing backends to
    # advertise their own aliases.
    backend_cls = get_stats_backend_class(backend_name)

    # Merge any backend-provided default configuration with the user config,
    # giving precedence to values from cfg.config.
    default_conf = getattr(backend_cls, "default_config", {}) or {}
    merged: dict[str, object] = dict(default_conf)
    merged.update(conf)

    # Filter to keyword arguments actually accepted by the backend __init__ so
    # that legacy keys such as "enabled" or "force_rebuild" do not leak into
    # constructors that do not expect them.
    import inspect

    sig = inspect.signature(backend_cls.__init__)
    valid_keys = {
        name
        for name, param in sig.parameters.items()
        if name not in {"self", "args", "kwargs", "*args", "**kwargs"}
        and param.kind
        in {
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        }
    }
    filtered = {k: v for k, v in merged.items() if k in valid_keys}

    backend = backend_cls(**filtered)

    # Derive a stable logical instance name for the backend. When cfg.name is
    # not provided, fall back to the normalized backend alias so that
    # primary_backend can still match by type (for example, "sqlite", "mysql").
    instance_name = _normalize_backend_name(cfg.name) if cfg.name else backend_name

    # Attach a logical name attribute for later selection in MultiStatsStore.
    setattr(backend, "name", instance_name)
    return backend


def load_stats_store_backend(
    persistence_cfg: Optional[dict[str, Any]],
) -> Optional[BaseStatsStore]:
    """Brief: Construct the configured statistics/query-log backend(s).

    Inputs:
      - persistence_cfg: Optional mapping derived from the
        ``statistics.persistence`` configuration block. When None or not a
        mapping, this function returns None.

    Outputs:
      - Backend instance implementing the BaseStatsStore interface, or
        None when persistence is disabled or misconfigured. When multiple
        backends are configured, returns a MultiStatsStore that writes to
        all backends and reads from the first-listed backend.
    """

    if not isinstance(persistence_cfg, dict):
        return None

    backends_cfg = persistence_cfg.get("backends")
    primary_name = (
        _normalize_backend_name(str(persistence_cfg.get("primary_backend", "")))
        if persistence_cfg.get("primary_backend")
        else ""
    )
    backends: List[BaseStatsStore] = []

    if isinstance(backends_cfg, list) and backends_cfg:
        for entry in backends_cfg:
            if not isinstance(entry, dict):
                continue
            backend_name = str(entry.get("backend", "sqlite"))
            cfg = (
                entry.get("config")
                if isinstance(entry.get("config"), dict)
                else {k: v for k, v in entry.items() if k != "backend"}
            )
            model = StatsStoreBackendConfig(backend=backend_name, config=cfg or {})
            backends.append(_build_backend_from_config(model))

        if not backends:
            return None
        if len(backends) == 1:
            return backends[0]

        # When a primary_backend hint is present, prefer the matching backend as
        # the primary without requiring the configuration list to be reordered.
        if primary_name:
            for idx, b in enumerate(backends):
                name = getattr(b, "name", None)
                cls_name = b.__class__.__name__.lower()
                if (
                    isinstance(name, str) and name == primary_name
                ) or cls_name == primary_name:
                    if idx != 0:
                        backends = [b] + backends[:idx] + backends[idx + 1 :]
                    break

        return MultiStatsStore(backends)

    # Legacy single-backend configuration; treat persistence_cfg itself as the
    # SQLite backend config so existing configs continue to work.
    legacy_model = StatsStoreBackendConfig(backend="sqlite", config=persistence_cfg)
    return _build_backend_from_config(legacy_model)
