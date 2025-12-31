"""Brief: Tests for statistics/query-log backend loader and multi-backend wiring.

Inputs:
  - None; uses dummy backends to avoid real DB connections.

Outputs:
  - None; pytest assertions validate loader behaviour for legacy and
    multi-backend configurations.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from foghorn.querylog_backends import (
    BaseStatsStoreBackend,
    StatsStoreBackendConfig,
    load_stats_store_backend,
    MultiStatsStoreBackend,
)


class DummyBackend(BaseStatsStoreBackend):
    """Brief: In-memory dummy backend used to validate loader semantics.

    Inputs (constructor):
      - name: Logical name used to distinguish instances in tests.

    Outputs:
      - Dummy backend that records calls but does not persist to an external DB.
    """

    def __init__(self, name: str = "dummy", **_: Any) -> None:  # type: ignore[override]
        self.name = name
        self.calls: Dict[str, int] = {}

    def _bump(self, method: str) -> None:
        self.calls[method] = self.calls.get(method, 0) + 1

    # Health / lifecycle ---------------------------------------------------
    def health_check(self) -> bool:  # type: ignore[override]
        self._bump("health_check")
        return True

    def close(self) -> None:  # type: ignore[override]
        self._bump("close")

    # Counter API ----------------------------------------------------------
    def increment_count(self, scope: str, key: str, delta: int = 1) -> None:  # type: ignore[override]
        self._bump(f"inc:{scope}:{key}")

    def set_count(self, scope: str, key: str, value: int) -> None:  # type: ignore[override]
        self._bump(f"set:{scope}:{key}")

    def has_counts(self) -> bool:  # type: ignore[override]
        self._bump("has_counts")
        return True

    def export_counts(self) -> Dict[str, Dict[str, int]]:  # type: ignore[override]
        self._bump("export_counts")
        return {"totals": {"total_queries": 1}}

    def rebuild_counts_from_query_log(self, logger_obj: Optional["logging.Logger"] = None) -> None:  # type: ignore[override,name-defined]
        self._bump("rebuild_from_log")

    def rebuild_counts_if_needed(
        self,
        force_rebuild: bool = False,
        logger_obj: Optional["logging.Logger"] = None,  # type: ignore[name-defined]
    ) -> None:  # type: ignore[override]
        self._bump("rebuild_if_needed")

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
    ) -> None:  # type: ignore[override]
        self._bump("insert_query_log")

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
    ) -> Dict[str, Any]:  # type: ignore[override]
        self._bump("select_query_log")
        return {
            "total": 0,
            "page": page,
            "page_size": page_size,
            "total_pages": 0,
            "items": [],
        }

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
    ) -> Dict[str, Any]:  # type: ignore[override]
        self._bump("aggregate_query_log_counts")
        return {
            "start_ts": start_ts,
            "end_ts": end_ts,
            "interval_seconds": interval_seconds,
            "items": [],
        }

    def has_query_log(self) -> bool:  # type: ignore[override]
        self._bump("has_query_log")
        return True


def test_loader_legacy_single_sqlite_config_still_works(monkeypatch) -> None:
    """Brief: Legacy statistics.persistence mapping returns a single backend.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts that a simple mapping without "backends" yields a non-None
        backend instance and does not raise.
    """

    cfg = {
        "db_path": "./config/var/stats.db",
        "batch_writes": True,
        "batch_time_sec": 15.0,
        "batch_max_size": 1000,
    }

    backend = load_stats_store_backend(cfg)
    assert backend is not None
    assert isinstance(backend, BaseStatsStoreBackend)


def test_loader_multi_backend_returns_multi_and_respects_order(monkeypatch) -> None:
    """Brief: statistics.persistence.backends builds a MultiStatsStoreBackend.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts that the loader returns a MultiStatsStoreBackend with backends
        created in the configured order and that reads use the primary.
    """

    created: list[DummyBackend] = []

    def _dummy_ctor(cfg: StatsStoreBackendConfig) -> BaseStatsStoreBackend:
        # Construct named DummyBackend instances in order.
        name = cfg.name or cfg.backend
        b = DummyBackend(name=name)
        created.append(b)
        return b

    from foghorn import querylog_backends as qlb

    monkeypatch.setattr(qlb, "_build_backend_from_config", _dummy_ctor)

    persistence_cfg = {
        "backends": [
            {"backend": "primary", "config": {}},
            {"backend": "secondary", "config": {}},
        ]
    }

    backend = load_stats_store_backend(persistence_cfg)
    assert isinstance(backend, MultiStatsStoreBackend)

    # Loader should have built two DummyBackend instances in order.
    assert [b.name for b in created] == ["primary", "secondary"]

    # Reads go to the primary.
    backend.health_check()
    backend.export_counts()
    backend.select_query_log()
    backend.aggregate_query_log_counts(0.0, 1.0, 1)
    assert created[0].calls.get("health_check", 0) == 1
    assert created[0].calls.get("export_counts", 0) == 1
    assert created[0].calls.get("select_query_log", 0) == 1
    assert created[0].calls.get("aggregate_query_log_counts", 0) == 1
    # Secondary should see no reads.
    assert "health_check" not in created[1].calls

    # Writes fan out to all backends.
    backend.increment_count("totals", "x", 1)
    backend.set_count("totals", "y", 2)
    backend.insert_query_log(
        ts=0.0,
        client_ip="127.0.0.1",
        name="example.com",
        qtype="A",
        upstream_id=None,
        rcode=None,
        status=None,
        error=None,
        first=None,
        result_json="{}",
    )
    backend.rebuild_counts_if_needed(force_rebuild=True)
    backend.close()

    for b in created:
        # Each dummy backend should have seen the write methods at least once.
        assert any(k.startswith("inc:") for k in b.calls)
        assert any(k.startswith("set:") for k in b.calls)
        assert b.calls.get("insert_query_log", 0) == 1
        assert b.calls.get("rebuild_if_needed", 0) == 1
        assert b.calls.get("close", 0) == 1


def test_loader_respects_primary_backend_hint(monkeypatch) -> None:
    """Brief: primary_backend selects the read-primary without reordering config.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts that when primary_backend is set, reads go to the hinted backend
        even if it is not the first entry in statistics.persistence.backends.
    """

    created: list[DummyBackend] = []

    def _dummy_ctor(cfg: StatsStoreBackendConfig) -> BaseStatsStoreBackend:
        # Name dummy backends after their configured instance name when present.
        name = cfg.name or cfg.backend
        b = DummyBackend(name=name)
        created.append(b)
        return b

    from foghorn import querylog_backends as qlb

    monkeypatch.setattr(qlb, "_build_backend_from_config", _dummy_ctor)

    # Configure primary backend name while listing it second in backends.
    persistence_cfg = {
        "primary_backend": "secondary",
        "backends": [
            {"backend": "primary", "config": {}},
            {"backend": "secondary", "config": {}},
        ],
    }

    backend = load_stats_store_backend(persistence_cfg)
    assert isinstance(backend, MultiStatsStoreBackend)

    # Loader still builds in declared order.
    assert [b.name for b in created] == ["primary", "secondary"]

    # Reads should be routed to the backend matching primary_backend ("secondary").
    backend.health_check()
    backend.export_counts()
    backend.select_query_log()
    backend.aggregate_query_log_counts(0.0, 1.0, 1)

    # We expect the "secondary" DummyBackend to see the read calls, while
    # the original first backend either sees none or fewer.
    primary_dummy, secondary_dummy = created
    assert secondary_dummy.calls.get("health_check", 0) == 1
    assert secondary_dummy.calls.get("export_counts", 0) == 1
    assert secondary_dummy.calls.get("select_query_log", 0) == 1
    assert secondary_dummy.calls.get("aggregate_query_log_counts", 0) == 1
