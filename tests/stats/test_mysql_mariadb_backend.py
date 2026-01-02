"""
Brief: Tests for MySqlStatsStoreBackend using a fake MySQL/MariaDB driver.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

import sys
import types
from typing import Any, Dict, List, Optional, Tuple

import pytest

from foghorn.plugins.querylog.mysql_mariadb import MySqlStatsStoreBackend


class _FakeCursor:
    """Brief: Minimal in-memory cursor emulating the subset of SQL we use in tests.

    Inputs:
      - conn: owning _FakeConn instance.

    Outputs:
      - Cursor with execute(), fetchone(), and iteration over result rows.
    """

    def __init__(self, conn: "_FakeConn") -> None:
        self._conn = conn
        self._rows: List[Tuple[Any, ...]] = []
        self._idx = 0

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
        s = sql.strip().lower()

        # Schema creation is a no-op for the fake backend.
        if s.startswith("create table"):
            return

        # Counts table operations.
        if s.startswith("insert into counts"):
            scope, key, value = params[:3]
            value_i = int(value)
            if "value + values(value)" in s:
                # increment_count path
                old = int(self._conn.counts.get((scope, key), 0))
                self._conn.counts[(scope, key)] = old + value_i
            else:
                # set_count path
                self._conn.counts[(scope, key)] = value_i
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
        if "group by bucket order by bucket" in s:
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
    """Brief: In-memory connection object backing MySqlStatsStoreBackend tests.

    Inputs:
      - kwargs: connection keyword arguments (recorded for assertions).

    Outputs:
      - Connection with cursor(), commit(), and close() methods.
    """

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = dict(kwargs)
        self.closed = False
        self.counts: Dict[tuple[str, str], int] = {}
        self.query_log_rows: int = 0
        self.select_rows: List[Tuple[Any, ...]] | None = None
        self.aggregate_rows_nogroup: List[Tuple[int, int]] | None = None
        self.aggregate_rows_group: List[Tuple[int, Optional[str], int]] | None = None
        self.rebuild_rows: List[Tuple[Any, ...]] | None = None

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
def fake_mysql_driver(monkeypatch: pytest.MonkeyPatch):
    """Brief: Install a fake mysql.connector module that returns _FakeConn objects.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; modifies sys.modules so _import_mysql_driver sees the fake driver.
    """
    driver_mod = types.ModuleType("mysql.connector")

    def _connect(**kwargs: Any) -> _FakeConn:
        return _FakeConn(**kwargs)

    driver_mod.connect = _connect  # type: ignore[attr-defined]

    mysql_pkg = types.ModuleType("mysql")
    mysql_pkg.connector = driver_mod  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "mysql", mysql_pkg)
    monkeypatch.setitem(sys.modules, "mysql.connector", driver_mod)


def _make_backend(fake_mysql_driver) -> MySqlStatsStoreBackend:  # type: ignore[no-untyped-def]
    """Brief: Helper to construct a backend using the fake MySQL driver.

    Inputs:
      - fake_mysql_driver: fixture ensuring the fake driver is installed.

    Outputs:
      - MySqlStatsStoreBackend instance with an in-memory _FakeConn.
    """
    return MySqlStatsStoreBackend(
        host="127.0.0.42",
        port=3307,
        user="user",
        password="pw",
        database="db",
        connect_kwargs={"ssl": True},
    )


def test_constructor_builds_connection_kwargs(fake_mysql_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: Constructor passes expected connection kwargs to the driver.

    Inputs:
      - fake_mysql_driver: fixture installing fake driver.

    Outputs:
      - None; asserts host/port/database/user/password/connect_kwargs wiring.
    """
    backend = _make_backend(fake_mysql_driver)
    conn = backend._conn  # type: ignore[attr-defined]
    assert isinstance(conn, _FakeConn)
    assert conn.kwargs["host"] == "127.0.0.42"
    assert conn.kwargs["port"] == 3307
    assert conn.kwargs["database"] == "db"
    assert conn.kwargs["user"] == "user"
    assert conn.kwargs["password"] == "pw"
    assert conn.kwargs["ssl"] is True


def test_health_check_true_and_false(fake_mysql_driver, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Brief: health_check returns True on success and False when cursor() fails.

    Inputs:
      - fake_mysql_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts both True and False branches.
    """
    backend = _make_backend(fake_mysql_driver)
    assert backend.health_check() is True

    class BoomConn:
        def cursor(self) -> Any:  # noqa: D401
            """Always raise to simulate a connection failure."""

            raise RuntimeError("boom")

    backend._conn = BoomConn()  # type: ignore[assignment]
    assert backend.health_check() is False


def test_close_closes_connection(fake_mysql_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: close() calls the underlying connection's close() method.

    Inputs:
      - fake_mysql_driver: fixture installing fake driver.

    Outputs:
      - None; asserts the fake connection is marked closed.
    """
    backend = _make_backend(fake_mysql_driver)
    conn = backend._conn  # type: ignore[attr-defined]
    assert conn.closed is False
    backend.close()
    assert conn.closed is True


def test_counts_increment_set_export_and_has_counts(fake_mysql_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: counts helpers manipulate the in-memory counts mapping.

    Inputs:
      - fake_mysql_driver: fixture installing fake driver.

    Outputs:
      - None; asserts increment_count, set_count, has_counts, export_counts.
    """
    backend = _make_backend(fake_mysql_driver)
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


def test_query_log_presence_and_selection(fake_mysql_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: insert_query_log, has_query_log, and select_query_log cooperate.

    Inputs:
      - fake_mysql_driver: fixture installing fake driver.

    Outputs:
      - None; asserts total count and JSON decoding behaviour.
    """
    backend = _make_backend(fake_mysql_driver)
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


def test_aggregate_query_log_counts_early_and_dense(fake_mysql_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: aggregate_query_log_counts handles early return and dense buckets.

    Inputs:
      - fake_mysql_driver: fixture installing fake driver.

    Outputs:
      - None; asserts early-return branch and zero-filled dense buckets.
    """
    backend = _make_backend(fake_mysql_driver)

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


def test_aggregate_query_log_counts_group_by(fake_mysql_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: aggregate_query_log_counts supports grouped aggregations.

    Inputs:
      - fake_mysql_driver: fixture installing fake driver.

    Outputs:
      - None; asserts grouped items shape and labels.
    """
    backend = _make_backend(fake_mysql_driver)
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


def test_rebuild_counts_from_query_log(fake_mysql_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: rebuild_counts_from_query_log aggregates from query_log rows.

    Inputs:
      - fake_mysql_driver: fixture installing fake driver.

    Outputs:
      - None; asserts several key counters are populated.
    """
    backend = _make_backend(fake_mysql_driver)
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


def test_rebuild_counts_if_needed_branches(fake_mysql_driver, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Brief: rebuild_counts_if_needed respects force_rebuild and table state.

    Inputs:
      - fake_mysql_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that helper calls are gated correctly.
    """
    backend = _make_backend(fake_mysql_driver)

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
