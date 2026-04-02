"""Brief: Tests for MongoStatsStore using a fake MongoDB/pymongo driver.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

import sys
import types
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pytest
import foghorn.plugins.querylog.mongodb as mongo_mod
from foghorn.plugins.querylog.base import BaseStatsStore

from foghorn.plugins.querylog.mongodb import MongoStatsStore


class _FakeCollection:
    """Brief: In-memory collection used to emulate MongoDB behaviour in tests.

    Inputs:
      - name: Logical collection name ("counts" or "query_log").

    Outputs:
      - Collection object with a minimal subset of pymongo's API used by
        MongoStatsStore (update_one, find_one, find, insert_one, count_documents,
        aggregate, create_index).
    """

    def __init__(self, name: str) -> None:
        self.name = name
        # For counts, we model documents as mapping (scope, key) -> int value.
        self.counts: Dict[Tuple[str, str], int] = {}
        # For query_log, we track number of rows for presence checks.
        self.query_log_rows: int = 0
        self.insert_many_calls: int = 0
        self.created_indexes: List[Tuple[Tuple[Any, ...], Dict[str, Any]]] = []
        self.deleted_filters: List[Dict[str, Any]] = []
        self.last_count_filter: Dict[str, Any] | None = None
        self.last_find_filter: Dict[str, Any] | None = None
        self.last_find_projection: Dict[str, Any] | None = None
        self.last_aggregate_pipeline: List[Dict[str, Any]] | None = None
        # Pre-baked rows for select_query_log tests.
        self.select_docs: List[Dict[str, Any]] | None = None
        # Pre-baked rows for aggregate_query_log_counts tests.
        self.aggregate_rows_nogroup: List[Tuple[int, int]] | None = None
        self.aggregate_rows_group: List[Tuple[int, Optional[str], int]] | None = None
        # Pre-baked rows for rebuild_counts_from_query_log tests.
        self.rebuild_docs: List[Dict[str, Any]] | None = None

    # Schema helpers ---------------------------------------------------------
    def create_index(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401
        """Brief: Index creation is a no-op for the fake collection."""
        self.created_indexes.append((tuple(args), dict(kwargs)))

        return None

    # Counts helpers ---------------------------------------------------------
    def update_one(
        self, flt: Dict[str, Any], update: Dict[str, Any], upsert: bool = False
    ) -> None:  # noqa: D401
        """Brief: Apply $inc/$set updates against the in-memory counts mapping.

        Inputs:
          - flt: Filter with "scope" and "key".
          - update: Update document containing $inc or $set for "value".
          - upsert: Ignored; always treated as True.

        Outputs:
          - None; self.counts is updated in place.
        """

        if self.name != "counts":
            return
        scope = str(flt.get("scope"))
        key = str(flt.get("key"))
        cur = int(self.counts.get((scope, key), 0))
        if "$inc" in update and "value" in update["$inc"]:
            cur += int(update["$inc"]["value"])
        if "$set" in update and "value" in update["$set"]:
            cur = int(update["$set"]["value"])
        self.counts[(scope, key)] = cur

    def find_one(
        self, flt: Dict[str, Any] | None = None, proj: Dict[str, Any] | None = None
    ) -> Optional[Dict[str, Any]]:  # noqa: D401
        """Brief: Return a single document from counts or query_log.

        Inputs:
          - flt: Unused; any filter matches for presence checks.
          - proj: Unused beyond presence checks.

        Outputs:
          - Minimal document or None when the collection is empty.
        """

        if self.name == "counts":
            return {"_id": 1} if self.counts else None
        if self.name == "query_log":
            return {"_id": 1} if self.query_log_rows > 0 else None
        return None

    def find(
        self, flt: Dict[str, Any] | None = None, proj: Dict[str, Any] | None = None
    ) -> "_FakeCursor":  # noqa: D401
        """Brief: Return a cursor over synthetic documents.

        Inputs:
          - flt: Filter mapping (ignored for these tests).
          - proj: Projection mapping (ignored for these tests).

        Outputs:
          - _FakeCursor over select_docs, rebuild_docs, or counts docs.
        """
        self.last_find_filter = dict(flt or {})
        self.last_find_projection = dict(proj or {})

        if self.name == "counts":
            # Used by export_counts; synthesise docs from the mapping.
            docs: List[Dict[str, Any]] = []
            for (scope, key), value in self.counts.items():
                docs.append({"scope": scope, "key": key, "value": value})
            return _FakeCursor(docs)

        # For query_log selection vs rebuild, prefer explicit fixtures.
        if self.rebuild_docs is not None:
            return _FakeCursor(list(self.rebuild_docs))
        if self.select_docs is not None:
            return _FakeCursor(list(self.select_docs))
        return _FakeCursor([])

    # Query-log helpers ------------------------------------------------------
    def insert_one(self, doc: Dict[str, Any]) -> None:  # noqa: D401
        """Brief: Record that a query_log document was inserted.

        Inputs:
          - doc: Ignored for now; only increments query_log_rows.

        Outputs:
          - None.
        """

        if self.name == "query_log":
            self.query_log_rows += 1

    def insert_many(self, docs: List[Dict[str, Any]]) -> None:  # noqa: D401
        """Brief: Record a batched query_log insert operation.

        Inputs:
          - docs: Sequence of query-log documents.

        Outputs:
          - None; increments query_log row count and batch call count.
        """

        if self.name == "query_log":
            self.insert_many_calls += 1
            self.query_log_rows += len(list(docs))

    def count_documents(self, flt: Dict[str, Any]) -> int:  # noqa: D401
        """Brief: Return the number of documents matching the filter.

        Inputs:
          - flt: Unused; we defer to select_docs length when present.

        Outputs:
          - Integer row count.
        """
        self.last_count_filter = dict(flt or {})

        if self.name != "query_log":
            return 0
        if self.select_docs is not None:
            return len(self.select_docs)
        return 0

    def delete_many(self, flt: Dict[str, Any]) -> None:  # noqa: D401
        """Brief: Delete documents matching the filter from the fake collection.

        Inputs:
          - flt: Filter mapping (ignored for counts; we always clear all rows).

        Outputs:
          - None; clears in-memory state for the appropriate collection.
        """
        self.deleted_filters.append(dict(flt or {}))

        if self.name == "counts":
            # Clear all aggregate counters before a rebuild.
            self.counts.clear()
        elif self.name == "query_log":
            # For rebuilds we do not currently delete query_log rows.
            # Keep this as a no-op for tests.
            return None

    def aggregate(
        self, pipeline: Iterable[Dict[str, Any]]
    ) -> Iterable[Dict[str, Any]]:  # noqa: D401
        """Brief: Return preconfigured aggregate rows.

        Inputs:
          - pipeline: Aggregation pipeline (ignored).

        Outputs:
          - Iterable of bucket/group documents.
        """
        self.last_aggregate_pipeline = list(pipeline)

        if self.name != "query_log":
            return []
        if self.aggregate_rows_group is not None:
            out = []
            for bucket, group_value, c in self.aggregate_rows_group:
                out.append(
                    {"_id": {"bucket": bucket, "group_value": group_value}, "c": c}
                )
            return out
        if self.aggregate_rows_nogroup is not None:
            out = []
            for bucket, c in self.aggregate_rows_nogroup:
                out.append({"_id": bucket, "c": c})
            return out
        return []


class _FakeCursor:
    """Brief: Minimal cursor wrapper for lists of documents.

    Inputs:
      - docs: Sequence of row dictionaries.

    Outputs:
      - Cursor supporting iteration, sort(), skip(), and limit().
    """

    def __init__(self, docs: List[Dict[str, Any]]) -> None:
        self._docs = list(docs)

    # Iteration --------------------------------------------------------------
    def __iter__(self) -> "_FakeCursor":  # noqa: D401
        """Iterate over the buffered documents."""

        return iter(self._docs)  # type: ignore[return-value]

    # Chainable operations used by MongoStatsStore ---------------------------
    def sort(self, _spec: List[Tuple[str, int]]) -> "_FakeCursor":  # noqa: D401
        """Brief: Sorting is a no-op for the fake cursor."""

        return self

    def skip(self, _n: int) -> "_FakeCursor":  # noqa: D401
        """Brief: Skipping is a no-op for the fake cursor in tests."""

        return self

    def limit(self, _n: int) -> "_FakeCursor":  # noqa: D401
        """Brief: Limiting is a no-op for the fake cursor in tests."""

        return self


class _FakeDB:
    """Brief: Simple mapping from collection name to _FakeCollection.

    Inputs:
      - None.

    Outputs:
      - Object whose __getitem__ returns collections.
    """

    def __init__(self) -> None:
        self._collections: Dict[str, _FakeCollection] = {}

    def __getitem__(self, name: str) -> _FakeCollection:  # noqa: D401
        """Return an existing collection or create a new one by name."""

        if name not in self._collections:
            self._collections[name] = _FakeCollection(name)
        return self._collections[name]


class _FakeAdmin:
    """Brief: Minimal admin interface providing command().

    Inputs:
      - None.

    Outputs:
      - Object whose command("ping") succeeds.
    """

    def __init__(self) -> None:
        self.calls: Dict[str, int] = {}

    def command(self, name: str) -> Dict[str, Any]:  # noqa: D401
        """Record that a command was invoked and return a dummy reply."""

        self.calls[name] = self.calls.get(name, 0) + 1
        if name == "ping":
            return {"ok": 1}
        return {"ok": 0}


class _FakeMongoClient:
    """Brief: In-memory MongoClient backing MongoStatsStore tests.

    Inputs:
      - *args/**kwargs: Recorded for assertions about constructor wiring.

    Outputs:
      - Client exposing __getitem__ for DB access, .admin.command("ping"), and
        close() tracking a closed flag.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._args = list(args)
        self.kwargs = dict(kwargs)
        self.databases: Dict[str, _FakeDB] = {}
        self.closed = False
        self.admin = _FakeAdmin()

    def __getitem__(self, name: str) -> _FakeDB:  # noqa: D401
        """Return or create a fake database by name."""

        if name not in self.databases:
            self.databases[name] = _FakeDB()
        return self.databases[name]

    def close(self) -> None:  # noqa: D401
        """Mark the client as closed."""

        self.closed = True


@pytest.fixture
def fake_mongo_driver(monkeypatch: pytest.MonkeyPatch):
    """Brief: Install a fake pymongo module that yields _FakeMongoClient objects.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; modifies sys.modules so _import_mongo_driver sees the fake driver.
    """

    driver_mod = types.ModuleType("pymongo")
    driver_mod.MongoClient = _FakeMongoClient  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "pymongo", driver_mod)


def _make_backend(
    fake_mongo_driver, **kwargs: Any
) -> MongoStatsStore:  # type: ignore[no-untyped-def]
    """Brief: Helper to construct a backend using the fake MongoDB driver.

    Inputs:
      - fake_mongo_driver: fixture ensuring the fake driver is installed.

    Outputs:
      - MongoStatsStore instance with an in-memory _FakeMongoClient.
    """

    base: Dict[str, Any] = {
        "uri": "mongodb://example/",
        "database": "db",
        "connect_kwargs": {"tls": True},
    }
    base.update(kwargs)
    return MongoStatsStore(
        **base,
    )


def test_constructor_builds_connection_kwargs(fake_mongo_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: Constructor passes expected arguments to MongoClient.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts uri and connect_kwargs wiring.
    """

    backend = _make_backend(fake_mongo_driver)
    client = backend._client  # type: ignore[attr-defined]
    assert isinstance(client, _FakeMongoClient)
    # URI should be the first positional argument.
    assert client._args[0] == "mongodb://example/"
    assert client.kwargs["tls"] is True


def test_health_check_true_and_false(fake_mongo_driver, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Brief: health_check returns True on success and False on failure.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts both True and False paths.
    """

    backend = _make_backend(fake_mongo_driver)
    assert backend.health_check() is True

    class BoomClient:
        def __init__(self) -> None:
            self.admin = self

        def command(self, _name: str) -> Dict[str, Any]:  # noqa: D401
            """Always raise to simulate a connectivity failure."""

            raise RuntimeError("boom")

    backend._client = BoomClient()  # type: ignore[assignment]
    assert backend.health_check() is False


def test_close_closes_client(fake_mongo_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: close() calls the underlying client's close() method.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts the fake client is marked closed.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    assert client.closed is False
    backend.close()
    assert client.closed is True


def test_counts_increment_set_export_and_has_counts(fake_mongo_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: counts helpers manipulate the in-memory counts mapping.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts increment_count, set_count, has_counts, export_counts.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    db = client.databases["db"]
    counts_coll: _FakeCollection = db["counts"]

    # Initially no rows.
    assert backend.has_counts() is False

    backend.increment_count("totals", "a", 2)
    backend.increment_count("totals", "a", 3)
    backend.set_count("totals", "b", 7)

    # Wait for the async worker queue to process all pending count operations so
    # that export_counts() sees the updated values deterministically.
    backend._op_queue.join()  # type: ignore[attr-defined]

    assert backend.has_counts() is True

    exported = backend.export_counts()
    assert exported["totals"]["a"] == 5
    assert exported["totals"]["b"] == 7

    # Underlying in-memory mapping should match.
    assert counts_coll.counts[("totals", "a")] == 5
    assert counts_coll.counts[("totals", "b")] == 7


def test_query_log_presence_and_selection(fake_mongo_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: insert_query_log, has_query_log, and select_query_log cooperate.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts total count and JSON decoding behaviour.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    db = client.databases["db"]
    qcoll: _FakeCollection = db["query_log"]

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

    # Wait for the async worker queue to process the insert so has_query_log()
    # observes at least one stored document.
    backend._op_queue.join()  # type: ignore[attr-defined]

    assert backend.has_query_log() is True

    # Provide explicit docs for select_query_log to iterate.
    qcoll.select_docs = [
        # Well-formed JSON dict.
        {
            "_id": "1",
            "ts": 10.0,
            "client_ip": "1.2.3.4",
            "name": "example.com",
            "qtype": "A",
            "upstream_id": "up1",
            "rcode": "NOERROR",
            "status": "ok",
            "error": None,
            "first": "1.2.3.4",
            "result_json": '{"dnssec_status": "dnssec_secure"}',
        },
        # Non-dict JSON value.
        {
            "_id": "2",
            "ts": 11.0,
            "client_ip": "5.6.7.8",
            "name": "other.example",
            "qtype": "AAAA",
            "upstream_id": None,
            "rcode": None,
            "status": None,
            "error": None,
            "first": None,
            "result_json": "[1, 2, 3]",
        },
        # Invalid JSON -> empty result dict.
        {
            "_id": "3",
            "ts": 12.0,
            "client_ip": "9.9.9.9",
            "name": "bad.json",
            "qtype": "TXT",
            "upstream_id": None,
            "rcode": None,
            "status": None,
            "error": None,
            "first": None,
            "result_json": "not-json",
        },
    ]

    res = backend.select_query_log(page=1, page_size=10)
    assert res["total"] == 3
    assert res["page"] == 1
    assert res["page_size"] == 10
    assert res["total_pages"] == 1
    assert len(res["items"]) == 3

    first = res["items"][0]
    assert first["id"] == "1"
    assert first["result"]["dnssec_status"] == "dnssec_secure"

    second = res["items"][1]
    assert second["id"] == "2"
    assert second["result"]["value"] == [1, 2, 3]

    third = res["items"][2]
    assert third["id"] == "3"
    assert third["result"] == {}


def test_aggregate_query_log_counts_early_and_dense(fake_mongo_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: aggregate_query_log_counts handles early return and dense buckets.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts early-return branch and zero-filled dense buckets.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    db = client.databases["db"]
    qcoll: _FakeCollection = db["query_log"]

    # Early return when interval is invalid or window is empty.
    res_bad = backend.aggregate_query_log_counts(
        start_ts=1.0,
        end_ts=1.0,
        interval_seconds=0,
    )
    assert res_bad["items"] == []

    # Non-grouped path with precomputed bucket rows.
    qcoll.aggregate_rows_nogroup = [
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


def test_aggregate_query_log_counts_group_by(fake_mongo_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: aggregate_query_log_counts supports grouped aggregations.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts grouped items shape and labels.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    db = client.databases["db"]
    qcoll: _FakeCollection = db["query_log"]

    qcoll.aggregate_rows_group = [
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


def test_rebuild_counts_from_query_log(fake_mongo_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: rebuild_counts_from_query_log aggregates from query_log docs.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts several key counters are populated.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    db = client.databases["db"]
    qcoll: _FakeCollection = db["query_log"]

    qcoll.rebuild_docs = [
        {
            "client_ip": "1.2.3.4",
            "name": "www.example.com",
            "qtype": "A",
            "upstream_id": "up1",
            "rcode": "NOERROR",
            "status": "cache_hit",
            "error": None,
            "result_json": '{"dnssec_status": "dnssec_secure"}',
        }
    ]

    backend.rebuild_counts_from_query_log(logger_obj=None)

    # Wait for the async worker queue to process all increment_count operations
    # scheduled during the rebuild so that export_counts() sees a consistent
    # snapshot.
    backend._op_queue.join()  # type: ignore[attr-defined]

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


def test_rebuild_counts_if_needed_branches(fake_mongo_driver, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Brief: rebuild_counts_if_needed respects force_rebuild and collection state.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that helper calls are gated correctly.
    """

    backend = _make_backend(fake_mongo_driver)

    calls: Dict[str, int] = {"rebuild": 0}

    def fake_rebuild(logger_obj=None) -> None:  # type: ignore[no-untyped-def]
        calls["rebuild"] += 1

    monkeypatch.setattr(backend, "rebuild_counts_from_query_log", fake_rebuild)

    # Case 1: no query_log docs -> no rebuild regardless of force flag.
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


def test_batch_writes_flush_query_log_on_read(fake_mongo_driver) -> None:  # type: ignore[no-untyped-def]
    """Brief: Batched Mongo query-log writes flush before read operations.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts buffered docs are written via insert_many before has_query_log.
    """

    backend = _make_backend(
        fake_mongo_driver,
        batch_writes=True,
        batch_max_size=100,
        batch_time_sec=9999.0,
    )
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]

    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=1.0,
        client_ip="192.0.2.1",
        name="example.org",
        qtype="A",
        upstream_id="up1",
        rcode="NOERROR",
        status="ok",
        error=None,
        first="1.2.3.4",
        result_json="{}",
    )
    assert qcoll.query_log_rows == 0
    assert qcoll.insert_many_calls == 0

    assert backend.has_query_log() is True
    assert qcoll.query_log_rows == 1
    assert qcoll.insert_many_calls == 1


def test_batch_writes_flush_query_log_on_close(
    fake_mongo_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: close() flushes any pending batched Mongo query-log writes.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts one pending document is persisted during close().
    """

    backend = _make_backend(
        fake_mongo_driver,
        batch_writes=True,
        batch_max_size=100,
        batch_time_sec=9999.0,
    )
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]

    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=2.0,
        client_ip="192.0.2.2",
        name="close-flush.example",
        qtype="A",
        upstream_id="up2",
        rcode="NOERROR",
        status="ok",
        error=None,
        first="1.2.3.4",
        result_json="{}",
    )
    assert qcoll.query_log_rows == 0

    backend.close()
    assert qcoll.query_log_rows == 1
    assert qcoll.insert_many_calls == 1


def test_class_aliases_include_mongo_and_mongodb() -> None:
    """Brief: MongoStatsStore advertises expected backend aliases.

    Inputs:
      - None.

    Outputs:
      - None; asserts canonical and compatibility aliases are present.
    """

    assert "mongo" in MongoStatsStore.aliases
    assert "mongodb" in MongoStatsStore.aliases


def test_constructor_without_uri_auth_and_with_bad_queue_fallback(
    fake_mongo_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Constructor host/port path omits optional auth and normalizes queue size.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts kwargs wiring without URI and invalid queue fallback.
    """

    backend = MongoStatsStore(
        uri=None,
        host="127.0.0.9",
        port=27018,
        username=None,
        password=None,
        database="db2",
        connect_kwargs=None,
        max_logging_queue="bad-int",  # type: ignore[arg-type]
    )
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    assert client._args == []
    assert client.kwargs["host"] == "127.0.0.9"
    assert client.kwargs["port"] == 27018
    assert "username" not in client.kwargs
    assert "password" not in client.kwargs
    assert backend._max_logging_queue == 16384


def test_constructor_creates_ttl_index_when_retention_days_set(
    fake_mongo_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: TTL index is created when native TTL retention is enabled.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts idx_query_log_ts_ttl index metadata.
    """

    backend = _make_backend(
        fake_mongo_driver,
        retention_days=1.5,
        retention_native_ttl=True,
    )
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]
    ttl_entries = [
        kwargs
        for (_args, kwargs) in qcoll.created_indexes
        if kwargs.get("name") == "idx_query_log_ts_ttl"
    ]
    assert len(ttl_entries) == 1
    assert ttl_entries[0]["expireAfterSeconds"] == int(1.5 * 86400.0)


def test_close_without_client_attribute_is_noop(
    fake_mongo_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: close() tolerates a missing _client attribute.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts defensive close path does not raise.
    """

    backend = _make_backend(fake_mongo_driver)
    del backend._client
    backend.close()


def test_maybe_flush_pending_query_log_docs_locked_branches(
    fake_mongo_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Batch flush helper handles empty, threshold-hit, and disabled paths.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts conditional flush behavior across key branches.
    """

    backend = _make_backend(
        fake_mongo_driver,
        batch_writes=True,
        batch_max_size=2,
        batch_time_sec=9999.0,
    )
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]

    with backend._batch_lock:
        backend._maybe_flush_pending_query_log_docs_locked()
        backend._pending_query_log_docs.append({"ts": 1.0})
        backend._pending_query_log_retention = False
        backend._maybe_flush_pending_query_log_docs_locked()
    assert qcoll.insert_many_calls == 0

    with backend._batch_lock:
        backend._pending_query_log_docs.append({"ts": 2.0})
        backend._pending_query_log_retention = False
        backend._maybe_flush_pending_query_log_docs_locked()
    assert qcoll.insert_many_calls == 1

    backend._batch_writes = False
    with backend._batch_lock:
        backend._pending_query_log_docs = [{"ts": 3.0}]
        backend._maybe_flush_pending_query_log_docs_locked()
    assert backend._pending_query_log_docs == [{"ts": 3.0}]


def test_apply_query_log_retention_returns_early_when_no_limits(
    fake_mongo_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Retention helper exits immediately when all limits are disabled.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts no delete operation is attempted.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]

    backend._query_log_retention_days = None
    backend._query_log_retention_max_records = None
    backend._query_log_retention_max_bytes = None
    backend._apply_query_log_retention()
    assert qcoll.deleted_filters == []


def test_apply_query_log_retention_returns_early_when_prune_not_due(
    fake_mongo_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Retention helper exits when cadence gate reports prune is not due.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts no delete operation is attempted.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]

    backend._query_log_retention_days = 1.0
    backend._query_log_retention_max_records = 10
    backend._query_log_retention_max_bytes = None
    monkeypatch.setattr(
        backend, "_should_run_query_log_retention_prune", lambda **_k: False
    )

    backend._apply_query_log_retention()
    assert qcoll.deleted_filters == []


def test_apply_query_log_retention_applies_cutoff_and_record_limit(
    fake_mongo_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Retention helper applies cutoff deletion and record-limit pruning.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts cutoff delete and max-record helper invocation.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]
    prune_calls: List[int] = []

    backend._query_log_retention_days = 1.0
    backend._query_log_retention_max_records = 7
    backend._query_log_retention_max_bytes = None
    monkeypatch.setattr(
        BaseStatsStore,
        "_retention_cutoff_ts",
        staticmethod(lambda _days, now_ts: float(now_ts) - 5.0),
    )
    monkeypatch.setattr(
        backend, "_should_run_query_log_retention_prune", lambda **_k: True
    )
    monkeypatch.setattr(
        backend,
        "_prune_query_log_to_max_records",
        lambda n: prune_calls.append(int(n)),
    )

    backend._apply_query_log_retention()
    assert prune_calls == [7]
    assert any("ts" in flt for flt in qcoll.deleted_filters)


def test_apply_query_log_retention_max_bytes_paths(
    fake_mongo_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Byte-cap retention handles both keep-list and delete-all branches.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts both $nin retention and full-delete fallback paths.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]
    backend._query_log_retention_days = None
    backend._query_log_retention_max_records = None
    backend._query_log_retention_max_bytes = 15

    monkeypatch.setattr(
        backend, "_should_run_query_log_retention_prune", lambda **_k: True
    )
    monkeypatch.setattr(
        backend,
        "_estimate_query_log_doc_bytes",
        lambda doc: {"a": 10, "b": 10}.get(doc.get("_id"), 1),
    )

    qcoll.select_docs = [
        {"_id": "a", "result_json": "{}"},
        {"_id": None, "result_json": "{}"},
        {"_id": "b", "result_json": "{}"},
    ]
    backend._apply_query_log_retention()
    assert qcoll.deleted_filters[-1] == {"_id": {"$nin": ["a"]}}

    qcoll.select_docs = [{"_id": None, "result_json": "{}"}]
    backend._apply_query_log_retention()
    assert qcoll.deleted_filters[-1] == {}


class _PruneCursor:
    """Brief: Cursor test-double that applies skip/limit before iteration.

    Inputs:
      - docs: Documents to expose via iteration.

    Outputs:
      - Cursor with sort(), skip(), limit(), and iteration support.
    """

    def __init__(self, docs: List[Dict[str, Any] | object]) -> None:
        self._docs = list(docs)
        self._skip = 0
        self._limit: Optional[int] = None

    def sort(self, _spec: List[Tuple[str, int]]) -> "_PruneCursor":
        """Brief: Sorting is intentionally a no-op for this test helper."""

        return self

    def skip(self, n: int) -> "_PruneCursor":
        """Brief: Record skip offset for iteration slicing."""

        self._skip = int(n)
        return self

    def limit(self, n: int) -> "_PruneCursor":
        """Brief: Record iteration limit for slicing."""

        self._limit = int(n)
        return self

    def __iter__(self):
        """Brief: Iterate over sliced documents."""

        docs = self._docs[self._skip :]
        if self._limit is not None:
            docs = docs[: self._limit]
        return iter(docs)


def test_prune_query_log_to_max_records_branches(
    fake_mongo_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Record-retention helper covers guard, malformed, and valid cutoff paths.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts delete filter shape for a valid cutoff document.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]

    backend._prune_query_log_to_max_records(0)
    assert qcoll.deleted_filters == []

    monkeypatch.setattr(
        qcoll,
        "find",
        lambda *_args, **_kwargs: _PruneCursor([1, 2]),  # type: ignore[list-item]
    )
    backend._prune_query_log_to_max_records(1)
    assert qcoll.deleted_filters == []

    monkeypatch.setattr(
        qcoll,
        "find",
        lambda *_args, **_kwargs: _PruneCursor([{"_id": "missing-ts"}]),
    )
    backend._prune_query_log_to_max_records(1)
    assert qcoll.deleted_filters == []

    monkeypatch.setattr(
        qcoll,
        "find",
        lambda *_args, **_kwargs: _PruneCursor(
            [
                {"ts": 30.0, "_id": "c"},
                {"ts": 20.0, "_id": "b"},
                {"ts": 10.0, "_id": "a"},
            ]
        ),
    )
    backend._prune_query_log_to_max_records(2)
    assert qcoll.deleted_filters[-1] == {
        "$or": [
            {"ts": {"$lt": 10.0}},
            {"ts": 10.0, "_id": {"$lte": "a"}},
        ]
    }


def test_estimate_query_log_doc_bytes_handles_none_and_non_string() -> None:
    """Brief: Document byte estimator skips None and stringifies non-string fields.

    Inputs:
      - None.

    Outputs:
      - None; asserts deterministic estimate for a mixed-value payload.
    """

    payload = {
        "client_ip": "1.2.3.4",
        "name": None,
        "qtype": "A",
        "upstream_id": 7,
        "rcode": "NOERROR",
        "status": None,
        "error": "boom",
        "first": 123,
        "result_json": "{}",
    }
    expected = (
        64
        + len("1.2.3.4".encode("utf-8"))
        + len("A".encode("utf-8"))
        + len("7".encode("utf-8"))
        + len("NOERROR".encode("utf-8"))
        + len("boom".encode("utf-8"))
        + len("123".encode("utf-8"))
        + len("{}".encode("utf-8"))
    )
    assert MongoStatsStore._estimate_query_log_doc_bytes(payload) == expected


def test_select_query_log_filters_are_normalized(
    fake_mongo_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: select_query_log normalizes filter inputs before querying Mongo.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts normalized count filter fields and time bounds.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]
    qcoll.select_docs = [
        {
            "_id": "1",
            "ts": 1.0,
            "client_ip": "1.2.3.4",
            "name": "example.com",
            "qtype": "A",
            "upstream_id": None,
            "rcode": "NOERROR",
            "status": "ok",
            "error": None,
            "first": None,
            "result_json": "{}",
        }
    ]

    backend.select_query_log(
        client_ip=" 1.2.3.4 ",
        qtype=" a ",
        qname="Example.COM.",
        rcode=" noerror ",
        status=" OK ",
        source=" Upstream ",
        start_ts=10,
        end_ts=20.0,
        page=1,
        page_size=10,
    )

    flt = qcoll.last_count_filter
    assert flt is not None
    assert flt["client_ip"] == "1.2.3.4"
    assert flt["qtype"] == "A"
    assert flt["name"] == "example.com"
    assert flt["rcode"] == "NOERROR"
    assert flt["status"] == {"$regex": "^OK$", "$options": "i"}
    assert flt["ts"] == {"$gte": 10.0, "$lt": 20.0}
    assert len(flt["$or"]) == 2


def test_aggregate_query_log_counts_invalid_group_and_filter_normalization(
    fake_mongo_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Aggregate API applies normalized filters when group_by is invalid.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts non-grouped pipeline shape and normalized match filters.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]
    qcoll.aggregate_rows_nogroup = [(0, 4)]

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

    pipeline = qcoll.last_aggregate_pipeline
    assert pipeline is not None
    assert "group_value" not in pipeline[1]["$project"]
    assert pipeline[0]["$match"]["client_ip"] == "1.2.3.4"
    assert pipeline[0]["$match"]["qtype"] == "A"
    assert pipeline[0]["$match"]["name"] == "example.com"
    assert pipeline[0]["$match"]["rcode"] == "NOERROR"


def test_aggregate_query_log_counts_skips_bad_rows_grouped(
    fake_mongo_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Grouped aggregate path skips rows with invalid bucket/count values.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts only parseable grouped rows are retained.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]
    qcoll.aggregate_rows_group = [("bad", "A", 1), (1, "A", "3")]

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
    fake_mongo_driver, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Aggregate API returns empty items on bucket-limit validation errors.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts ValueError handling from limit enforcement helper.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]
    qcoll.aggregate_rows_nogroup = [(0, 1)]

    def _raise_value_error(*_args: Any, **_kwargs: Any) -> int:
        raise ValueError("too many buckets")

    monkeypatch.setattr(
        mongo_mod, "enforce_query_log_aggregate_bucket_limit", _raise_value_error
    )

    result = backend.aggregate_query_log_counts(
        start_ts=0.0,
        end_ts=20.0,
        interval_seconds=10,
    )
    assert result["items"] == []


def test_rebuild_counts_from_query_log_branch_matrix(
    fake_mongo_driver,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Rebuild path covers deny/miss/upstream and DNSSEC branch combinations.

    Inputs:
      - fake_mongo_driver: fixture installing fake driver.

    Outputs:
      - None; asserts counters for representative branch-heavy query-log rows.
    """

    backend = _make_backend(fake_mongo_driver)
    client: _FakeMongoClient = backend._client  # type: ignore[assignment]
    qcoll: _FakeCollection = client.databases["db"]["query_log"]
    qcoll.rebuild_docs = [
        {
            "client_ip": "",
            "name": "example.org",
            "qtype": None,
            "upstream_id": "up2",
            "rcode": "SERVFAIL",
            "status": "deny_pre",
            "error": None,
            "result_json": '{"dnssec_status":"dnssec_bogus"}',
        },
        {
            "client_ip": "5.5.5.5",
            "name": "sub.test.example.org",
            "qtype": "AAAA",
            "upstream_id": "up3",
            "rcode": None,
            "status": "timeout",
            "error": None,
            "result_json": "not-json",
        },
        {
            "client_ip": "8.8.8.8",
            "name": "",
            "qtype": "A",
            "upstream_id": "up4",
            "rcode": "NOERROR",
            "status": None,
            "error": None,
            "result_json": "",
        },
    ]

    backend.rebuild_counts_from_query_log(logger_obj=None)
    backend._op_queue.join()  # type: ignore[attr-defined]
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
