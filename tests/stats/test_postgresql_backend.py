"""Brief: Tests for PostgresStatsStore using a fake PostgreSQL driver.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

import sys
import types
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock

import pytest
import foghorn.plugins.querylog.postgresql as pg_mod
from foghorn.plugins.querylog.base import BaseStatsStore

from foghorn.plugins.querylog.postgresql import PostgresStatsStore
from foghorn.utils import dns_names


class _FakeCursor:
    """Brief: Minimal in-memory cursor emulating the subset of SQL we use.

    Inputs:
      - conn: owning _FakeConn instance.

    Outputs:
      - Cursor with execute(), fetchone(), and iteration over result rows.
    """

    def __init__(self, conn: "_FakeConn") -> None:
        self._conn = conn
        self._rows: List[Tuple[Any, ...]] = []
        self._idx = 0
        self.rowcount = 0

    def execute(
        self, sql: str, params: Tuple[Any, ...] | List[Any] | None = None
    ) -> None:
        """Brief: Execute a subset of SQL statements against in-memory state.

        Inputs:
          - sql: SQL statement string.
          - params: optional parameters tuple/list.

        Outputs:
          - None; internal row buffer is updated for fetch/iteration.
        """

        if params is None:
            params = []
        else:
            params = list(params)

        self._rows = []
        self._idx = 0
        self.rowcount = 0
        self._conn.executed.append((sql, tuple(params)))
        s = sql.strip().lower()

        # Schema creation and index DDL are no-ops for the fake backend.
        if s.startswith("create table") or s.startswith("create index"):
            return

        # Counts table operations.
        if s.startswith("insert into counts"):
            scope, key, value = params[:3]
            value_i = int(value)
            if "counts.value + excluded.value" in s:
                # increment_count path
                old = int(self._conn.counts.get((scope, key), 0))
                self._conn.counts[(scope, key)] = old + value_i
            else:
                # set_count path
                self._conn.counts[(scope, key)] = value_i
            self.rowcount = 1
            return

        if s.startswith("delete from counts"):
            self.rowcount = len(self._conn.counts)
            self._conn.counts.clear()
            return

        if s.startswith("select 1 from counts"):
            self._rows = [(1,)] if self._conn.counts else []
            return

        if s.startswith("select scope, key, value from counts"):
            self._rows = [
                (scope, key, value) for (scope, key), value in self._conn.counts.items()
            ]
            return

        # Query-log presence checks.
        if s.startswith("select 1 from query_log"):
            self._rows = [(1,)] if self._conn.query_log_rows > 0 else []
            return

        if "count(1) from query_log" in s:
            # Used by select_query_log for total row count.
            rows = self._conn.select_rows or []
            self._rows = [(len(rows),)]
            return

        # Query-log inserts.
        if s.startswith("insert into query_log"):
            self._conn.query_log_rows += 1
            return

        # Query-log selection for list view.
        if s.startswith("select id, ts, client_ip, name, qtype, upstream_id"):
            self._rows = list(self._conn.select_rows or [])
            return

        # Aggregate query-log buckets (no group_by).
        if "group by bucket order by bucket" in s and "group_value" not in s:
            self._rows = list(self._conn.aggregate_rows_nogroup or [])
            return

        # Aggregate query-log buckets with group_by.
        if "group by bucket, group_value order by bucket" in s:
            self._rows = list(self._conn.aggregate_rows_group or [])
            return

        # Rebuild query_log scan.
        if s.startswith(
            "select client_ip, name, qtype, upstream_id, rcode, status, error, result_json from query_log"  # noqa: E501
        ):
            self._rows = list(self._conn.rebuild_rows or [])
            return

    def fetchone(self) -> Optional[Tuple[Any, ...]]:
        """Brief: Return the next row from the internal buffer, if any.

        Inputs:
          - None.

        Outputs:
          - Next row tuple or None when exhausted.
        """

        if self._idx >= len(self._rows):
            return None
        row = self._rows[self._idx]
        self._idx += 1
        return row

    def __iter__(self):  # noqa: D401
        """Iterate over buffered rows for ``for row in cursor`` usages."""

        return iter(self._rows)


class _FakeConn:
    """Brief: In-memory connection object backing PostgresStatsStore tests.

    Inputs:
      - kwargs: connection keyword arguments (recorded for assertions).

    Outputs:
      - Connection with cursor(), commit(), and close() methods.
    """

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = dict(kwargs)
        self.closed = False
        self.commit_calls = 0
        self.counts: Dict[tuple[str, str], int] = {}
        self.query_log_rows: int = 0
        self.select_rows: List[Tuple[Any, ...]] | None = None
        self.aggregate_rows_nogroup: List[Tuple[int, int]] | None = None
        self.aggregate_rows_group: List[Tuple[int, Optional[str], int]] | None = None
        self.rebuild_rows: List[Tuple[Any, ...]] | None = None
        self.executed: List[Tuple[str, Tuple[Any, ...]]] = []

    def cursor(self) -> _FakeCursor:
        """Brief: Return a new _FakeCursor bound to this connection.

        Inputs:
          - None.

        Outputs:
          - _FakeCursor instance.
        """

        return _FakeCursor(self)

    def commit(self) -> None:
        """Brief: Commit is a no-op for the in-memory fake connection.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        self.commit_calls += 1
        return None

    def close(self) -> None:
        """Brief: Mark the connection as closed.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        self.closed = True


@pytest.fixture
def fake_postgres_driver(monkeypatch: pytest.MonkeyPatch):
    """Brief: Install a fake psycopg module that returns _FakeConn objects.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; modifies sys.modules so _import_postgres_driver sees the fake driver.
    """

    driver_mod = types.ModuleType("psycopg")

    def _connect(**kwargs: Any) -> _FakeConn:
        return _FakeConn(**kwargs)

    driver_mod.connect = _connect  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "psycopg", driver_mod)


def _make_backend(fake_postgres_driver) -> PostgresStatsStore:  # type: ignore[no-untyped-def]
    """Brief: Helper to construct a backend using the fake PostgreSQL driver.

    Inputs:
      - fake_postgres_driver: fixture ensuring the fake driver is installed.

    Outputs:
      - PostgresStatsStore instance with an in-memory _FakeConn.
    """

    return PostgresStatsStore(
        host="127.0.0.42",
        port=55432,
        user="user",
        password="pw",
        database="db",
        connect_kwargs={"sslmode": "require"},
    )


def test_constructor_builds_connection_kwargs(fake_postgres_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: Constructor passes expected connection kwargs to the driver.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts host/port/database/user/password/connect_kwargs wiring.
    """

    backend = _make_backend(fake_postgres_driver)
    conn = backend._conn  # type: ignore[attr-defined]
    assert isinstance(conn, _FakeConn)
    assert conn.kwargs["host"] == "127.0.0.42"
    assert conn.kwargs["port"] == 55432
    assert conn.kwargs["database"] == "db"
    assert conn.kwargs["user"] == "user"
    assert conn.kwargs["password"] == "pw"
    assert conn.kwargs["sslmode"] == "require"


def test_health_check_true(fake_postgres_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: health_check returns True on a healthy fake connection.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts the successful path.
    """

    backend = _make_backend(fake_postgres_driver)
    assert backend.health_check() is True


def test_close_closes_connection(fake_postgres_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: close() calls the underlying connection's close() method.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts the fake connection is marked closed.
    """

    backend = _make_backend(fake_postgres_driver)
    conn = backend._conn  # type: ignore[attr-defined]
    assert conn.closed is False
    backend.close()
    assert conn.closed is True


def test_counts_increment_set_export_and_has_counts(fake_postgres_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: counts helpers manipulate the in-memory counts mapping.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts increment_count, set_count, has_counts, export_counts.
    """

    backend = _make_backend(fake_postgres_driver)
    conn: _FakeConn = backend._conn  # type: ignore[assignment]

    # Initially no rows.
    assert backend.has_counts() is False

    backend.increment_count("totals", "a", 2)
    backend.increment_count("totals", "a", 3)
    backend.set_count("totals", "b", 7)

    assert backend.has_counts() is True

    exported = backend.export_counts()
    assert exported["totals"]["a"] == 5
    assert exported["totals"]["b"] == 7

    # Underlying in-memory mapping should match.
    assert conn.counts[("totals", "a")] == 5
    assert conn.counts[("totals", "b")] == 7


def test_query_log_presence_and_selection(fake_postgres_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: insert_query_log, has_query_log, and select_query_log cooperate.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts total count and JSON decoding behaviour.
    """

    backend = _make_backend(fake_postgres_driver)
    conn: _FakeConn = backend._conn  # type: ignore[assignment]

    # No rows yet.
    assert backend.has_query_log() is False

    # Simulate that we have at least one row when insert_query_log is used.
    backend.insert_query_log(
        ts=1.0,
        client_ip="1.2.3.4",
        name="example.com",
        qtype="A",
        upstream_id="up1",
        rcode="NOERROR",
        status="ok",
        error=None,
        first="1.2.3.4",
        result_json="{}",
    )
    assert backend.has_query_log() is True

    # Provide explicit rows for select_query_log to iterate.
    conn.select_rows = [
        # Well-formed JSON dict.
        (
            1,
            10.0,
            "1.2.3.4",
            "example.com",
            "A",
            "up1",
            "NOERROR",
            "ok",
            None,
            "1.2.3.4",
            '{"dnssec_status": "dnssec_secure"}',
        ),
        # Non-dict JSON value.
        (
            2,
            11.0,
            "5.6.7.8",
            "other.example",
            "AAAA",
            None,
            None,
            None,
            None,
            None,
            "[1, 2, 3]",
        ),
        # Invalid JSON -> empty result dict.
        (
            3,
            12.0,
            "9.9.9.9",
            "bad.json",
            "TXT",
            None,
            None,
            None,
            None,
            None,
            "not-json",
        ),
    ]

    res = backend.select_query_log(page=1, page_size=10)
    assert res["total"] == 3
    assert res["page"] == 1
    assert res["page_size"] == 10
    assert res["total_pages"] == 1
    assert len(res["items"]) == 3

    first = res["items"][0]
    assert first["id"] == 1
    assert first["result"]["dnssec_status"] == "dnssec_secure"

    second = res["items"][1]
    assert second["id"] == 2
    assert second["result"]["value"] == [1, 2, 3]

    third = res["items"][2]
    assert third["id"] == 3
    assert third["result"] == {}


def test_aggregate_query_log_counts_early_and_dense(fake_postgres_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: aggregate_query_log_counts handles early return and dense buckets.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts early-return branch and zero-filled dense buckets.
    """

    backend = _make_backend(fake_postgres_driver)

    # Early return when interval is invalid or window is empty.
    res_bad = backend.aggregate_query_log_counts(
        start_ts=1.0,
        end_ts=1.0,
        interval_seconds=0,
    )
    assert res_bad["items"] == []

    # Non-grouped path with precomputed bucket rows.
    conn: _FakeConn = backend._conn  # type: ignore[assignment]
    conn.aggregate_rows_nogroup = [
        (0, 2),  # bucket 0 has count 2
        (2, 1),  # bucket 2 has count 1
    ]

    res = backend.aggregate_query_log_counts(
        start_ts=0.0,
        end_ts=30.0,
        interval_seconds=10,
    )
    items = res["items"]
    # Expect three buckets [0,10), [10,20), [20,30).
    assert [i["bucket"] for i in items] == [0, 1, 2]
    counts = {i["bucket"]: i["count"] for i in items}
    assert counts[0] == 2
    assert counts[1] == 0
    assert counts[2] == 1


def test_aggregate_query_log_counts_group_by(fake_postgres_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: aggregate_query_log_counts supports grouped aggregations.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts grouped items shape and labels.
    """

    backend = _make_backend(fake_postgres_driver)
    conn: _FakeConn = backend._conn  # type: ignore[assignment]
    conn.aggregate_rows_group = [
        (0, "A", 2),
        (0, "AAAA", 1),
        (1, "A", 3),
    ]

    res = backend.aggregate_query_log_counts(
        start_ts=0.0,
        end_ts=20.0,
        interval_seconds=10,
        group_by="qtype",
    )

    items = res["items"]
    # Preserve group_by label and group values from fake rows.
    assert {i["group"] for i in items} == {"A", "AAAA"}
    assert all(i["group_by"] == "qtype" for i in items)


def test_rebuild_counts_from_query_log(fake_postgres_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: rebuild_counts_from_query_log aggregates from query_log rows.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts several key counters are populated.
    """

    backend = _make_backend(fake_postgres_driver)
    conn: _FakeConn = backend._conn  # type: ignore[assignment]

    conn.rebuild_rows = [
        (
            "1.2.3.4",  # client_ip
            "www.example.com",  # name
            "A",  # qtype
            "up1",  # upstream_id
            "NOERROR",  # rcode
            "cache_hit",  # status
            None,  # error
            '{"dnssec_status": "dnssec_secure"}',  # result_json
        )
    ]

    backend.rebuild_counts_from_query_log(logger_obj=None)
    counts = backend.export_counts()

    # Totals
    assert counts["totals"]["total_queries"] == 1
    assert counts["totals"]["cache_hits"] == 1
    # Qtypes and clients
    assert counts["qtypes"]["A"] == 1
    assert counts["clients"]["1.2.3.4"] == 1
    # Domains and subdomains
    assert counts["domains"]["example.com"] == 1
    assert counts["sub_domains"]["www.example.com"] == 1
    # Upstreams
    assert any(k.startswith("up1|") for k in counts["upstreams"].keys())
    # DNSSEC
    assert counts["totals"]["dnssec_secure"] == 1


def test_rebuild_counts_if_needed_branches(fake_postgres_driver, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Brief: rebuild_counts_if_needed respects force_rebuild and table state.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that helper calls are gated correctly.
    """

    backend = _make_backend(fake_postgres_driver)

    calls: Dict[str, int] = {"rebuild": 0}

    def fake_rebuild(logger_obj=None) -> None:  # type: ignore[no-untyped-def]
        calls["rebuild"] += 1

    monkeypatch.setattr(backend, "rebuild_counts_from_query_log", fake_rebuild)

    # Case 1: no query_log rows -> no rebuild regardless of force flag.
    monkeypatch.setattr(backend, "has_counts", lambda: False)
    monkeypatch.setattr(backend, "has_query_log", lambda: False)
    backend.rebuild_counts_if_needed(force_rebuild=False, logger_obj=None)
    backend.rebuild_counts_if_needed(force_rebuild=True, logger_obj=None)
    assert calls["rebuild"] == 0

    # Case 2: counts present, query_log present, no force -> no rebuild.
    monkeypatch.setattr(backend, "has_counts", lambda: True)
    monkeypatch.setattr(backend, "has_query_log", lambda: True)
    backend.rebuild_counts_if_needed(force_rebuild=False, logger_obj=None)
    assert calls["rebuild"] == 0

    # Case 3: counts present, query_log present, force -> rebuild once.
    backend.rebuild_counts_if_needed(force_rebuild=True, logger_obj=None)
    assert calls["rebuild"] == 1

    # Case 4: counts empty, query_log present, no force -> rebuild again.
    monkeypatch.setattr(backend, "has_counts", lambda: False)
    backend.rebuild_counts_if_needed(force_rebuild=False, logger_obj=None)
    assert calls["rebuild"] == 2


def test_constructor_without_optional_auth_and_bad_queue_uses_fallback(
    fake_postgres_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Constructor omits optional auth kwargs and defaults bad queue size.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts optional kwargs omission and queue fallback logic.
    """

    backend = PostgresStatsStore(
        host="127.0.0.9",
        port=5432,
        user=None,
        password=None,
        database="db2",
        connect_kwargs=None,
        max_logging_queue="bad-int",  # type: ignore[arg-type]
    )
    conn: _FakeConn = backend._conn  # type: ignore[assignment]

    assert "user" not in conn.kwargs
    assert "password" not in conn.kwargs
    assert backend._max_logging_queue == 16384


def test_close_without_conn_attribute_is_noop(
    fake_postgres_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: close() handles missing _conn attribute safely.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts no exception when _conn is absent.
    """

    backend = _make_backend(fake_postgres_driver)
    del backend._conn
    backend.close()


def test_increment_count_async_dispatches_to_base(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: increment_count() uses BaseStatsStore path when async logging is enabled.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts BaseStatsStore.increment_count is invoked.
    """

    backend = PostgresStatsStore(async_logging=True)
    calls: List[Tuple[str, str, int]] = []

    def fake_base_increment(self, scope: str, key: str, delta: int = 1) -> None:
        calls.append((scope, key, delta))

    monkeypatch.setattr(BaseStatsStore, "increment_count", fake_base_increment)
    monkeypatch.setattr(
        backend,
        "_increment_count",
        lambda *_args, **_kwargs: pytest.fail("_increment_count should not be called"),
    )

    backend.increment_count("totals", "x", 3)
    assert calls == [("totals", "x", 3)]


def test_insert_query_log_async_dispatches_to_base(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: insert_query_log() uses BaseStatsStore queue path when async is enabled.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts BaseStatsStore.insert_query_log is invoked.
    """

    backend = PostgresStatsStore(async_logging=True)
    calls: List[Tuple[Any, ...]] = []

    def fake_base_insert(self, *args: Any) -> None:
        calls.append(args)

    monkeypatch.setattr(BaseStatsStore, "insert_query_log", fake_base_insert)
    monkeypatch.setattr(
        backend,
        "_insert_query_log",
        lambda *_args, **_kwargs: pytest.fail("_insert_query_log should not be called"),
    )

    backend.insert_query_log(
        1.0,
        "1.1.1.1",
        "example.com",
        "A",
        "up",
        "NOERROR",
        "ok",
        None,
        "1.1.1.1",
        "{}",
    )
    assert len(calls) == 1


def test_apply_query_log_retention_returns_when_no_limits(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Retention prune exits early when no retention limits are configured.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts no DB cursor is requested.
    """

    backend = _make_backend(fake_postgres_driver)
    backend._query_log_retention_days = None
    backend._query_log_retention_max_records = None
    backend._query_log_retention_max_bytes = None

    monkeypatch.setattr(
        backend._conn,
        "cursor",
        lambda: pytest.fail("cursor should not be called for no-op retention"),
    )
    backend._apply_query_log_retention()


def test_apply_query_log_retention_returns_when_prune_not_due(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Retention prune exits when cadence checks say pruning is not due.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts no DB cursor is requested.
    """

    backend = _make_backend(fake_postgres_driver)
    backend._query_log_retention_days = 1.0
    backend._query_log_retention_max_records = 10
    backend._query_log_retention_max_bytes = None

    monkeypatch.setattr(
        backend, "_should_run_query_log_retention_prune", lambda **_k: False
    )
    monkeypatch.setattr(
        backend._conn,
        "cursor",
        lambda: pytest.fail("cursor should not be called when prune is not due"),
    )
    backend._apply_query_log_retention()


def test_apply_query_log_retention_runs_limits_and_vacuum(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Retention prune applies cutoff/record/byte limits and triggers vacuum.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts SQL paths execute and post-prune vacuum hook is called.
    """

    backend = _make_backend(fake_postgres_driver)
    backend._query_log_retention_days = 1.0
    backend._query_log_retention_max_records = 5
    backend._query_log_retention_max_bytes = 128

    class _RetentionCursor:
        def __init__(self) -> None:
            self.rowcount = 0
            self.executes: List[Tuple[str, Tuple[Any, ...]]] = []

        def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
            self.executes.append((sql, tuple(params)))
            self.rowcount = 1

    cur = _RetentionCursor()
    prune_calls: List[int] = []
    vacuum_calls: List[float] = []

    monkeypatch.setattr(
        BaseStatsStore,
        "_retention_cutoff_ts",
        staticmethod(lambda _days, now_ts: float(now_ts) - 10.0),
    )
    monkeypatch.setattr(
        backend, "_should_run_query_log_retention_prune", lambda **_k: True
    )
    monkeypatch.setattr(backend._conn, "cursor", lambda: cur)
    monkeypatch.setattr(
        backend,
        "_prune_query_log_to_max_bytes",
        lambda m: prune_calls.append(m) or True,
    )
    monkeypatch.setattr(
        backend,
        "_maybe_vacuum_query_log_table",
        lambda *, now_ts: vacuum_calls.append(now_ts),
    )

    backend._apply_query_log_retention()

    joined_sql = "\n".join(sql for (sql, _params) in cur.executes).lower()
    assert "delete from query_log where ts < %s" in joined_sql
    assert "with doomed as" in joined_sql
    assert prune_calls == [128]
    assert len(vacuum_calls) == 1


def test_prune_query_log_to_max_bytes_returns_false_for_nonpositive_limit(
    fake_postgres_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Byte-prune helper returns False when max_bytes is not positive.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts early-return guard behavior.
    """

    backend = _make_backend(fake_postgres_driver)
    assert backend._prune_query_log_to_max_bytes(0) is False


def test_prune_query_log_to_max_bytes_deletes_and_stops_when_within_limit(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Byte-prune helper deletes rows then stops once size is under limit.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts changed=True path with iterative convergence.
    """

    backend = _make_backend(fake_postgres_driver)

    select_cur_1 = MagicMock()
    select_cur_1.fetchone.return_value = (200, 10)
    delete_cur_1 = MagicMock()
    delete_cur_1.rowcount = 3
    select_cur_2 = MagicMock()
    select_cur_2.fetchone.return_value = (80, 7)

    monkeypatch.setattr(
        backend._conn,
        "cursor",
        MagicMock(side_effect=[select_cur_1, delete_cur_1, select_cur_2]),
    )

    assert backend._prune_query_log_to_max_bytes(100) is True


def test_prune_query_log_to_max_bytes_breaks_on_zero_rowcount(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Byte-prune helper stops when DELETE reports zero affected rows.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts no-change exit when deletions cannot progress.
    """

    backend = _make_backend(fake_postgres_driver)

    select_cur = MagicMock()
    select_cur.fetchone.return_value = (200, 10)
    delete_cur = MagicMock()
    delete_cur.rowcount = 0

    monkeypatch.setattr(
        backend._conn,
        "cursor",
        MagicMock(side_effect=[select_cur, delete_cur]),
    )

    assert backend._prune_query_log_to_max_bytes(100) is False


def test_maybe_vacuum_query_log_table_disabled_is_noop(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Vacuum helper returns immediately when vacuum-on-prune is disabled.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts cursor is never requested.
    """

    backend = _make_backend(fake_postgres_driver)
    backend._retention_vacuum_on_prune = False
    monkeypatch.setattr(
        backend._conn,
        "cursor",
        lambda: pytest.fail("cursor should not be called when vacuum is disabled"),
    )
    backend._maybe_vacuum_query_log_table(now_ts=100.0)


def test_maybe_vacuum_query_log_table_interval_gate(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Vacuum helper respects configured minimum interval between runs.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts interval-gated no-op behavior.
    """

    backend = _make_backend(fake_postgres_driver)
    backend._retention_vacuum_on_prune = True
    backend._retention_vacuum_interval_seconds = 60.0
    backend._retention_last_vacuum_ts = 90.0

    monkeypatch.setattr(
        backend._conn,
        "cursor",
        lambda: pytest.fail(
            "cursor should not be called when interval gate blocks run"
        ),
    )
    backend._maybe_vacuum_query_log_table(now_ts=100.0)


def test_maybe_vacuum_query_log_table_runs_with_autocommit_restore(
    fake_postgres_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Vacuum helper toggles autocommit around VACUUM and restores it.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts VACUUM execution and autocommit restoration.
    """

    backend = _make_backend(fake_postgres_driver)

    class _AutoConn(_FakeConn):
        def __init__(self) -> None:
            super().__init__()
            self.autocommit = False

    conn = _AutoConn()
    cur = MagicMock()
    conn.cursor = MagicMock(return_value=cur)  # type: ignore[method-assign]
    backend._conn = conn
    backend._retention_vacuum_on_prune = True
    backend._retention_vacuum_interval_seconds = None

    backend._maybe_vacuum_query_log_table(now_ts=123.0)
    cur.execute.assert_called_once_with("VACUUM ANALYZE query_log")
    assert conn.autocommit is False
    assert backend._retention_last_vacuum_ts == 123.0


def test_maybe_vacuum_query_log_table_bad_last_timestamp_still_runs(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Vacuum helper treats malformed previous timestamp as not-yet-run.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts fallback branch executes VACUUM.
    """

    backend = _make_backend(fake_postgres_driver)
    backend._retention_vacuum_on_prune = True
    backend._retention_vacuum_interval_seconds = 60.0
    backend._retention_last_vacuum_ts = object()
    cur = MagicMock()
    monkeypatch.setattr(backend._conn, "cursor", lambda: cur)

    backend._maybe_vacuum_query_log_table(now_ts=100.0)
    cur.execute.assert_called_once_with("VACUUM ANALYZE query_log")


def test_select_query_log_filters_are_normalized(
    fake_postgres_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: select_query_log normalizes and applies all filter operands.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts WHERE fragments and bound params include normalized values.
    """

    backend = _make_backend(fake_postgres_driver)
    conn: _FakeConn = backend._conn  # type: ignore[assignment]
    conn.select_rows = [
        (1, 1.0, "1.2.3.4", "example.com", "A", None, "NOERROR", "ok", None, None, "{}")
    ]
    conn.executed.clear()

    backend.select_query_log(
        client_ip=" 1.2.3.4 ",
        qtype=" a ",
        qname="Example.COM",
        rcode=" noerror ",
        status=" OK ",
        source=" Upstream ",
        start_ts=10,
        end_ts=20.0,
        page=1,
        page_size=10,
    )

    count_sql, count_params = next(
        (sql, params)
        for (sql, params) in conn.executed
        if "SELECT COUNT(1) FROM query_log" in sql
    )
    assert "client_ip = %s" in count_sql
    assert "qtype = %s" in count_sql
    assert "name = %s" in count_sql
    assert "rcode = %s" in count_sql
    assert "LOWER(COALESCE(status, '')) = %s" in count_sql
    assert "LOWER(result_json) LIKE %s OR LOWER(result_json) LIKE %s" in count_sql
    assert "ts >= %s" in count_sql
    assert "ts < %s" in count_sql
    assert count_params == (
        "1.2.3.4",
        "A",
        dns_names.normalize_name("Example.COM"),
        "NOERROR",
        "ok",
        '%"source":"upstream"%',
        '%"source": "upstream"%',
        10.0,
        20.0,
    )


def test_aggregate_query_log_counts_applies_filters_with_invalid_group_by(
    fake_postgres_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Aggregate API applies filters even when group_by is unknown.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts non-grouped query path and normalized params.
    """

    backend = _make_backend(fake_postgres_driver)
    conn: _FakeConn = backend._conn  # type: ignore[assignment]
    conn.aggregate_rows_nogroup = [(0, 4)]
    conn.executed.clear()

    result = backend.aggregate_query_log_counts(
        start_ts=0.0,
        end_ts=20.0,
        interval_seconds=10,
        client_ip=" 1.2.3.4 ",
        qtype=" a ",
        qname="Example.Com",
        rcode=" noerror ",
        group_by="not-a-group",
    )
    assert result["items"][0]["count"] == 4

    agg_sql, agg_params = next(
        (sql, params)
        for (sql, params) in conn.executed
        if "GROUP BY bucket ORDER BY bucket ASC" in sql
    )
    assert "group_value" not in agg_sql
    assert agg_params == (
        0.0,
        10,
        0.0,
        20.0,
        "1.2.3.4",
        "A",
        dns_names.normalize_name("Example.Com"),
        "NOERROR",
    )


def test_aggregate_query_log_counts_skips_bad_rows_non_grouped(
    fake_postgres_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Non-grouped aggregate rows skip entries that cannot be coerced to ints.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts invalid rows are ignored.
    """

    backend = _make_backend(fake_postgres_driver)
    conn: _FakeConn = backend._conn  # type: ignore[assignment]
    conn.aggregate_rows_nogroup = [("bad", 1), (1, "2")]

    result = backend.aggregate_query_log_counts(
        start_ts=0.0,
        end_ts=20.0,
        interval_seconds=10,
    )
    counts = {item["bucket"]: item["count"] for item in result["items"]}
    assert counts == {0: 0, 1: 2}


def test_aggregate_query_log_counts_skips_bad_rows_grouped(
    fake_postgres_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Grouped aggregate rows skip entries with invalid bucket/count values.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts only parseable grouped rows are returned.
    """

    backend = _make_backend(fake_postgres_driver)
    conn: _FakeConn = backend._conn  # type: ignore[assignment]
    conn.aggregate_rows_group = [("bad", "A", 1), (1, "A", "3")]

    result = backend.aggregate_query_log_counts(
        start_ts=0.0,
        end_ts=20.0,
        interval_seconds=10,
        group_by="qtype",
    )
    assert result["items"] == [
        {
            "bucket": 1,
            "bucket_start_ts": 10.0,
            "bucket_end_ts": 20.0,
            "group_by": "qtype",
            "group": "A",
            "count": 3,
        }
    ]


def test_aggregate_query_log_counts_handles_bucket_limit_rejection(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Aggregate API returns empty items when bucket-limit validation rejects input.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts ValueError from bucket limit helper is handled.
    """

    backend = _make_backend(fake_postgres_driver)
    conn: _FakeConn = backend._conn  # type: ignore[assignment]
    conn.aggregate_rows_nogroup = [(0, 1)]

    def _raise_value_error(*_args: Any, **_kwargs: Any) -> int:
        raise ValueError("too many buckets")

    monkeypatch.setattr(
        pg_mod, "enforce_query_log_aggregate_bucket_limit", _raise_value_error
    )

    result = backend.aggregate_query_log_counts(
        start_ts=0.0,
        end_ts=20.0,
        interval_seconds=10,
    )
    assert result["items"] == []


def test_rebuild_counts_from_query_log_branch_matrix(
    fake_postgres_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Rebuild path covers deny/override, miss, upstream outcomes, and DNSSEC branches.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts counters for multiple non-trivial row shapes.
    """

    backend = _make_backend(fake_postgres_driver)
    conn: _FakeConn = backend._conn  # type: ignore[assignment]
    conn.rebuild_rows = [
        (
            "",
            "example.org",
            None,
            "up2",
            "SERVFAIL",
            "deny_pre",
            None,
            '{"dnssec_status":"dnssec_bogus"}',
        ),
        (
            "5.5.5.5",
            "sub.test.example.org",
            "AAAA",
            "up3",
            None,
            "timeout",
            None,
            "not-json",
        ),
        (
            "8.8.8.8",
            "",
            "A",
            "up4",
            "NOERROR",
            None,
            None,
            "",
        ),
    ]

    backend.rebuild_counts_from_query_log(logger_obj=None)
    counts = backend.export_counts()

    assert counts["totals"]["total_queries"] == 3
    assert counts["totals"]["cache_deny_pre"] == 1
    assert counts["totals"]["cache_null"] == 1
    assert counts["totals"]["cache_misses"] == 2
    assert counts["totals"]["dnssec_bogus"] == 1
    assert counts["domains"]["example.org"] == 2
    assert counts["cache_miss_domains"]["example.org"] == 1
    assert counts["cache_miss_subdomains"]["sub.test.example.org"] == 1
    assert counts["rcode_domains"]["SERVFAIL|example.org"] == 1
    assert counts["upstreams"]["up2|deny_pre|SERVFAIL"] == 1
    assert counts["upstreams"]["up3|timeout|UNKNOWN"] == 1
    assert counts["upstreams"]["up4|success|NOERROR"] == 1


def test_apply_query_log_retention_without_cutoff_uses_record_limit(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Retention prune supports record-only mode when cutoff is unavailable.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts cutoff branch is skipped and record-limit SQL still runs.
    """

    backend = _make_backend(fake_postgres_driver)
    backend._query_log_retention_days = None
    backend._query_log_retention_max_records = 10
    backend._query_log_retention_max_bytes = None

    class _Cursor:
        def __init__(self) -> None:
            self.rowcount = 1
            self.executes: List[Tuple[str, Tuple[Any, ...]]] = []

        def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
            self.executes.append((sql, tuple(params)))
            self.rowcount = 1

    cur = _Cursor()
    vacuum_calls: List[float] = []
    monkeypatch.setattr(
        BaseStatsStore, "_retention_cutoff_ts", staticmethod(lambda _days, now_ts: None)
    )
    monkeypatch.setattr(
        backend, "_should_run_query_log_retention_prune", lambda **_k: True
    )
    monkeypatch.setattr(backend._conn, "cursor", lambda: cur)
    monkeypatch.setattr(
        backend,
        "_maybe_vacuum_query_log_table",
        lambda *, now_ts: vacuum_calls.append(now_ts),
    )

    backend._apply_query_log_retention()
    joined_sql = "\n".join(sql for (sql, _params) in cur.executes).lower()
    assert "delete from query_log where ts < %s" not in joined_sql
    assert "with doomed as" in joined_sql
    assert len(vacuum_calls) == 1


def test_apply_query_log_retention_changed_false_skips_vacuum(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Retention prune commits but avoids vacuum when no rows changed.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts changed=False path in retention apply helper.
    """

    backend = _make_backend(fake_postgres_driver)
    backend._query_log_retention_days = 1.0
    backend._query_log_retention_max_records = None
    backend._query_log_retention_max_bytes = None

    class _Cursor:
        def __init__(self) -> None:
            self.rowcount = 0
            self.executes: List[Tuple[str, Tuple[Any, ...]]] = []

        def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
            self.executes.append((sql, tuple(params)))
            self.rowcount = 0

    cur = _Cursor()
    monkeypatch.setattr(
        BaseStatsStore,
        "_retention_cutoff_ts",
        staticmethod(lambda _days, now_ts: float(now_ts) - 5.0),
    )
    monkeypatch.setattr(
        backend, "_should_run_query_log_retention_prune", lambda **_k: True
    )
    monkeypatch.setattr(backend._conn, "cursor", lambda: cur)
    monkeypatch.setattr(
        backend,
        "_maybe_vacuum_query_log_table",
        lambda **_k: pytest.fail("vacuum should not run when nothing changed"),
    )

    backend._apply_query_log_retention()
    joined_sql = "\n".join(sql for (sql, _params) in cur.executes).lower()
    assert "delete from query_log where ts < %s" in joined_sql


def test_prune_query_log_to_max_bytes_exhausts_max_passes(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Byte-prune helper returns after bounded max_passes when progress continues.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts loop-exhaustion return path.
    """

    backend = _make_backend(fake_postgres_driver)
    state = {"cursor_calls": 0}

    class _SelectCursor:
        def execute(self, _sql: str, _params: Tuple[Any, ...] = ()) -> None:
            return None

        def fetchone(self) -> Tuple[int, int]:
            return (1000, 100)

    class _DeleteCursor:
        rowcount = 1

        def execute(self, _sql: str, _params: Tuple[Any, ...] = ()) -> None:
            return None

    def _cursor_factory():
        state["cursor_calls"] += 1
        if state["cursor_calls"] % 2 == 1:
            return _SelectCursor()
        return _DeleteCursor()

    monkeypatch.setattr(backend._conn, "cursor", _cursor_factory)
    assert backend._prune_query_log_to_max_bytes(100) is True
    assert state["cursor_calls"] == 64


def test_rebuild_counts_from_query_log_deny_subdomain_and_no_upstream(
    fake_postgres_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Rebuild skips subdomain cache-miss and upstream counters for deny/no-upstream rows.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts deny_pre subdomain rows do not emit miss-subdomain or upstream keys.
    """

    backend = _make_backend(fake_postgres_driver)
    conn: _FakeConn = backend._conn  # type: ignore[assignment]
    conn.rebuild_rows = [
        (
            "2.2.2.2",
            "deny.sub.example.org",
            "TXT",
            None,
            "NXDOMAIN",
            "deny_pre",
            None,
            "",
        ),
    ]

    backend.rebuild_counts_from_query_log(logger_obj=None)
    counts = backend.export_counts()
    assert "cache_miss_subdomains" not in counts
    assert "upstreams" not in counts


def test_batch_writes_flush_on_read_paths(
    fake_postgres_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Batched count writes flush when read paths are invoked.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.

    Outputs:
      - None; asserts write commit is deferred until a read flushes the batch.
    """

    backend = PostgresStatsStore(
        batch_writes=True,
        batch_max_size=100,
        batch_time_sec=9999.0,
    )
    conn: _FakeConn = backend._conn  # type: ignore[assignment]
    baseline_commits = int(conn.commit_calls)

    backend.increment_count("totals", "batched", 1)
    assert conn.commit_calls == baseline_commits

    exported = backend.export_counts()
    assert conn.commit_calls == (baseline_commits + 1)
    assert exported["totals"]["batched"] == 1


def test_batch_writes_defer_retention_until_flush(
    fake_postgres_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Query-log retention runs once after a batched flush.

    Inputs:
      - fake_postgres_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts retention is not evaluated at enqueue time.
    """

    backend = PostgresStatsStore(
        batch_writes=True,
        batch_max_size=100,
        batch_time_sec=9999.0,
    )
    retention_calls: List[str] = []
    monkeypatch.setattr(
        backend,
        "_apply_query_log_retention",
        lambda: retention_calls.append("called"),
    )

    backend.insert_query_log(
        ts=1.0,
        client_ip="203.0.113.1",
        name="example.org",
        qtype="A",
        upstream_id="up1",
        rcode="NOERROR",
        status="ok",
        error=None,
        first="1.2.3.4",
        result_json="{}",
    )
    assert retention_calls == []

    assert backend.has_query_log() is True
    assert retention_calls == ["called"]
