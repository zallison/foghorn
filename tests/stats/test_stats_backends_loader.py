"""Brief: Tests for statistics/query-log backend loader and multi-backend wiring.

Inputs:
  - None; uses dummy backends to avoid real DB connections.

Outputs:
  - None; pytest assertions validate loader behaviour for legacy and
    multi-backend configurations.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, Optional
import pytest

from foghorn.plugins.querylog import (
    BaseStatsStore,
    MultiStatsStore,
    StatsStoreBackendConfig,
    load_stats_store_backend,
)


class DummyBackend(BaseStatsStore):
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
        status: Optional[str] = None,
        source: Optional[str] = None,
        ede_code: Optional[str] = None,
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


def test_multi_stats_store_requires_at_least_one_backend() -> None:
    """Brief: MultiStatsStore raises when constructed with an empty backend list.

    Inputs:
      - None.

    Outputs:
      - None; asserts ValueError for empty backend list input.
    """

    with pytest.raises(ValueError, match="at least one backend"):
        MultiStatsStore([])


def test_multi_stats_store_derives_effective_max_logging_queue_from_backends() -> None:
    """Brief: Queue capacity derives from the smallest valid backend value.

    Inputs:
      - Three dummy backends with mixed queue-capacity attributes:
        one private int, one public string int, and one invalid value.

    Outputs:
      - None; asserts effective queue capacity is the minimum valid parsed value.
    """

    primary = DummyBackend(name="primary")
    secondary = DummyBackend(name="secondary")
    tertiary = DummyBackend(name="tertiary")
    primary._max_logging_queue = 500  # type: ignore[attr-defined]
    secondary.max_logging_queue = "250"  # type: ignore[attr-defined]
    tertiary._max_logging_queue = "not-an-int"  # type: ignore[attr-defined]

    store = MultiStatsStore([primary, secondary, tertiary])
    assert getattr(store, "_max_logging_queue", None) == 250


def test_multi_stats_store_close_without_queue_ignores_backend_close_failures() -> None:
    """Brief: close() continues even when one backend close operation fails.

    Inputs:
      - A healthy dummy backend and one backend that raises in close().

    Outputs:
      - None; asserts close() does not raise and still calls all backends.
    """

    class FailingCloseBackend(DummyBackend):
        def close(self) -> None:  # type: ignore[override]
            self._bump("close")
            raise RuntimeError("close failure")

    healthy = DummyBackend(name="healthy")
    failing = FailingCloseBackend(name="failing")
    store = MultiStatsStore([healthy, failing])

    # No async write was enqueued, so _op_queue should be absent.
    assert getattr(store, "_op_queue", None) is None
    store.close()

    assert healthy.calls.get("close", 0) == 1
    assert failing.calls.get("close", 0) == 1


def test_multi_stats_store_fanout_methods_ignore_per_backend_errors() -> None:
    """Brief: Fan-out methods continue when a secondary backend raises.

    Inputs:
      - Primary dummy backend and one backend that raises for write-like calls.

    Outputs:
      - None; asserts fan-out operations complete, calls reach healthy primary,
        and primary read helpers still return values.
    """

    class RaisingBackend(DummyBackend):
        def increment_count(  # type: ignore[override]
            self, scope: str, key: str, delta: int = 1
        ) -> None:
            self._bump(f"inc:{scope}:{key}")
            raise RuntimeError("increment failure")

        def set_count(self, scope: str, key: str, value: int) -> None:  # type: ignore[override]
            self._bump(f"set:{scope}:{key}")
            raise RuntimeError("set failure")

        def rebuild_counts_from_query_log(  # type: ignore[override]
            self, logger_obj: Optional["logging.Logger"] = None
        ) -> None:
            self._bump("rebuild_from_log")
            raise RuntimeError("rebuild_from_log failure")

        def rebuild_counts_if_needed(  # type: ignore[override]
            self,
            force_rebuild: bool = False,
            logger_obj: Optional["logging.Logger"] = None,  # type: ignore[name-defined]
        ) -> None:
            self._bump("rebuild_if_needed")
            raise RuntimeError("rebuild_if_needed failure")

    primary = DummyBackend(name="primary")
    secondary = RaisingBackend(name="secondary")
    store = MultiStatsStore([primary, secondary])

    store.increment_count("totals", "x", 1)
    store.set_count("totals", "y", 2)
    store.rebuild_counts_from_query_log()
    store.rebuild_counts_if_needed(force_rebuild=True)

    assert any(k.startswith("inc:totals:x") for k in primary.calls)
    assert any(k.startswith("set:totals:y") for k in primary.calls)
    assert primary.calls.get("rebuild_from_log", 0) == 1
    assert primary.calls.get("rebuild_if_needed", 0) == 1

    assert any(k.startswith("inc:totals:x") for k in secondary.calls)
    assert any(k.startswith("set:totals:y") for k in secondary.calls)
    assert secondary.calls.get("rebuild_from_log", 0) == 1
    assert secondary.calls.get("rebuild_if_needed", 0) == 1

    assert store.has_counts() is True
    assert store.has_query_log() is True


def test_loader_returns_none_for_non_mapping_configs() -> None:
    """Brief: Loader returns None when persistence config is not a mapping.

    Inputs:
      - None, string, and integer as persistence config values.

    Outputs:
      - None; asserts all non-mapping inputs return None.
    """

    assert load_stats_store_backend(None) is None
    assert load_stats_store_backend("invalid") is None  # type: ignore[arg-type]
    assert load_stats_store_backend(123) is None  # type: ignore[arg-type]


def test_loader_skips_non_dict_backend_entries_and_returns_none(monkeypatch) -> None:
    """Brief: Loader ignores invalid backend list entries and can return None.

    Inputs:
      - monkeypatch fixture and a backends list containing non-dict entries.

    Outputs:
      - None; asserts no backend is built and return value is None.
    """

    built = {"count": 0}

    def _dummy_ctor(
        cfg: StatsStoreBackendConfig,
    ) -> BaseStatsStore:  # pragma: nocover - should not be called
        built["count"] += 1
        return DummyBackend(name=cfg.backend)

    from foghorn.plugins import querylog as qlb

    monkeypatch.setattr(qlb, "_build_backend_from_config", _dummy_ctor)

    persistence_cfg = {
        "backends": [None, "sqlite", 1, 2.5, []],
    }
    backend = load_stats_store_backend(persistence_cfg)
    assert backend is None
    assert built["count"] == 0


def test_loader_single_backend_list_returns_single_backend_instance(
    monkeypatch,
) -> None:
    """Brief: One configured backend returns a backend instance, not MultiStatsStore.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - None; asserts single-entry backends config returns that one backend.
    """

    created: list[DummyBackend] = []

    def _dummy_ctor(cfg: StatsStoreBackendConfig) -> BaseStatsStore:
        b = DummyBackend(name=cfg.name or cfg.backend)
        created.append(b)
        return b

    from foghorn.plugins import querylog as qlb

    monkeypatch.setattr(qlb, "_build_backend_from_config", _dummy_ctor)

    backend = load_stats_store_backend(
        {"backends": [{"backend": "sqlite", "config": {"db_path": ":memory:"}}]}
    )

    assert len(created) == 1
    assert backend is created[0]
    assert not isinstance(backend, MultiStatsStore)


def test_loader_unmatched_primary_backend_keeps_declared_primary(monkeypatch) -> None:
    """Brief: Unknown primary_backend hint leaves first configured backend primary.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - None; asserts no reordering when primary_backend does not match.
    """

    created: list[DummyBackend] = []

    def _dummy_ctor(cfg: StatsStoreBackendConfig) -> BaseStatsStore:
        b = DummyBackend(name=cfg.name or cfg.backend)
        created.append(b)
        return b

    from foghorn.plugins import querylog as qlb

    monkeypatch.setattr(qlb, "_build_backend_from_config", _dummy_ctor)

    backend = load_stats_store_backend(
        {
            "primary_backend": "does-not-exist",
            "backends": [
                {"backend": "primary", "config": {}},
                {"backend": "secondary", "config": {}},
            ],
        }
    )
    assert isinstance(backend, MultiStatsStore)

    backend.health_check()
    assert created[0].calls.get("health_check", 0) == 1
    assert created[1].calls.get("health_check", 0) == 0


def test_loader_primary_backend_match_at_index_zero_does_not_reorder(
    monkeypatch,
) -> None:
    """Brief: Matching the first backend by primary_backend keeps order unchanged.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - None; asserts primary remains index zero when hint already matches first.
    """

    created: list[DummyBackend] = []

    def _dummy_ctor(cfg: StatsStoreBackendConfig) -> BaseStatsStore:
        b = DummyBackend(name=cfg.name or cfg.backend)
        created.append(b)
        return b

    from foghorn.plugins import querylog as qlb

    monkeypatch.setattr(qlb, "_build_backend_from_config", _dummy_ctor)

    backend = load_stats_store_backend(
        {
            "primary_backend": "primary",
            "backends": [
                {"backend": "primary", "config": {}},
                {"backend": "secondary", "config": {}},
            ],
        }
    )
    assert isinstance(backend, MultiStatsStore)

    backend.health_check()
    assert created[0].calls.get("health_check", 0) == 1
    assert created[1].calls.get("health_check", 0) == 0


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
    assert isinstance(backend, BaseStatsStore)


def test_loader_multi_backend_returns_multi_and_respects_order(monkeypatch) -> None:
    """Brief: statistics.persistence.backends builds a MultiStatsStore.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts that the loader returns a MultiStatsStore with backends
        created in the configured order and that reads use the primary.
    """

    created: list[DummyBackend] = []

    def _dummy_ctor(cfg: StatsStoreBackendConfig) -> BaseStatsStore:
        # Construct named DummyBackend instances in order.
        name = cfg.name or cfg.backend
        b = DummyBackend(name=name)
        created.append(b)
        return b

    from foghorn.plugins import querylog as qlb

    monkeypatch.setattr(qlb, "_build_backend_from_config", _dummy_ctor)

    persistence_cfg = {
        "backends": [
            {"backend": "primary", "config": {}},
            {"backend": "secondary", "config": {}},
        ]
    }

    backend = load_stats_store_backend(persistence_cfg)
    assert isinstance(backend, MultiStatsStore)

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

    def _dummy_ctor(cfg: StatsStoreBackendConfig) -> BaseStatsStore:
        # Name dummy backends after their configured instance name when present.
        name = cfg.name or cfg.backend
        b = DummyBackend(name=name)
        created.append(b)
        return b

    from foghorn.plugins import querylog as qlb

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
    assert isinstance(backend, MultiStatsStore)

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


def test_multi_stats_store_select_query_log_forwards_ede_code(monkeypatch) -> None:
    """Brief: MultiStatsStore forwards ede_code when selecting query-log rows.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - Asserts that select_query_log accepts ede_code and passes it through
        to the primary backend call.
    """

    created: list[DummyBackend] = []

    def _dummy_ctor(cfg: StatsStoreBackendConfig) -> BaseStatsStore:
        name = cfg.name or cfg.backend
        b = DummyBackend(name=name)
        created.append(b)
        return b

    from foghorn.plugins import querylog as qlb

    monkeypatch.setattr(qlb, "_build_backend_from_config", _dummy_ctor)

    persistence_cfg = {
        "backends": [
            {"backend": "primary", "config": {}},
            {"backend": "secondary", "config": {}},
        ]
    }

    backend = load_stats_store_backend(persistence_cfg)
    assert isinstance(backend, MultiStatsStore)
    assert len(created) == 2

    captured_kwargs: Dict[str, Any] = {}

    def _capture_select_query_log(**kwargs: Any) -> Dict[str, Any]:
        captured_kwargs.update(kwargs)
        return {
            "total": 0,
            "page": int(kwargs.get("page", 1)),
            "page_size": int(kwargs.get("page_size", 100)),
            "total_pages": 0,
            "items": [],
        }

    created[0].select_query_log = _capture_select_query_log  # type: ignore[method-assign]

    result = backend.select_query_log(
        source="upstream",
        ede_code="15",
        page=2,
        page_size=25,
    )

    assert captured_kwargs.get("source") == "upstream"
    assert captured_kwargs.get("ede_code") == "15"
    assert captured_kwargs.get("page") == 2
    assert captured_kwargs.get("page_size") == 25
    assert result["page"] == 2
    assert result["page_size"] == 25
    # Reads should still use only the primary backend.
    assert created[1].calls.get("select_query_log", 0) == 0


def test_multi_stats_store_insert_query_log_processed_in_worker_thread(
    monkeypatch,
) -> None:
    """Brief: MultiStatsStore.insert_query_log work runs on the background thread.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that DummyBackend call recording happens from the
        MultiStatsStore worker thread, not the main test thread.
    """

    created: list[DummyBackend] = []

    def _dummy_ctor(cfg: StatsStoreBackendConfig) -> BaseStatsStore:
        name = cfg.name or cfg.backend
        b = DummyBackend(name=name)
        created.append(b)
        return b

    from foghorn.plugins import querylog as qlb

    monkeypatch.setattr(qlb, "_build_backend_from_config", _dummy_ctor)

    persistence_cfg = {
        "backends": [
            {"backend": "primary", "config": {}},
            {"backend": "secondary", "config": {}},
        ]
    }

    backend = load_stats_store_backend(persistence_cfg)
    assert isinstance(backend, MultiStatsStore)

    # Capture the thread names used when DummyBackend records calls.
    thread_names: list[str] = []
    original_bump = DummyBackend._bump

    def _bump_with_thread(self: DummyBackend, method: str) -> None:  # type: ignore[no-untyped-def]
        thread_names.append(threading.current_thread().name)
        original_bump(self, method)

    monkeypatch.setattr(DummyBackend, "_bump", _bump_with_thread)

    # Enqueue a query-log write and wait for the worker to process it.
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

    # Poll for the async worker to record at least one insert_query_log call.
    deadline = time.time() + 2.0
    while time.time() < deadline and not any(
        b.calls.get("insert_query_log", 0) for b in created
    ):
        time.sleep(0.01)

    assert any(b.calls.get("insert_query_log", 0) for b in created)
    # At least one bump should have been recorded from a non-main thread
    # (MultiStatsStore worker thread).
    assert any(name != threading.current_thread().name for name in thread_names)


def test_multi_stats_store_worker_isolates_backend_failures(monkeypatch) -> None:
    """Brief: Failure in one backend's _insert_query_log does not block others.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that when one DummyBackend raises from insert_query_log,
        the other backend still records the call via the worker thread.
    """

    class FailingBackend(DummyBackend):
        def _bump(self, method: str) -> None:  # type: ignore[no-untyped-def]
            # Record that we attempted the call, then raise to simulate failure.
            super()._bump(method)
            if method == "insert_query_log":
                raise RuntimeError("boom")

    created: list[BaseStatsStore] = []

    def _dummy_ctor(cfg: StatsStoreBackendConfig) -> BaseStatsStore:
        if not created:
            b: BaseStatsStore = FailingBackend(name="failing")
        else:
            b = DummyBackend(name="ok")
        created.append(b)
        return b

    from foghorn.plugins import querylog as qlb

    monkeypatch.setattr(qlb, "_build_backend_from_config", _dummy_ctor)

    persistence_cfg = {
        "backends": [
            {"backend": "failing", "config": {}},
            {"backend": "ok", "config": {}},
        ]
    }

    backend = load_stats_store_backend(persistence_cfg)
    assert isinstance(backend, MultiStatsStore)

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

    # Wait for the worker to process the queued operation.
    deadline = time.time() + 2.0
    while time.time() < deadline and (
        len(created) < 2
        or created[1].__class__ is DummyBackend
        and created[1].calls.get("insert_query_log", 0) == 0
    ):
        time.sleep(0.01)

    assert len(created) == 2
    # The failing backend should have attempted insert_query_log once.
    assert isinstance(created[0], FailingBackend)
    assert created[0].calls.get("insert_query_log", 0) == 1
    # The healthy backend should also have seen insert_query_log despite the
    # exception in the first backend.
    assert isinstance(created[1], DummyBackend)
    assert created[1].calls.get("insert_query_log", 0) == 1
