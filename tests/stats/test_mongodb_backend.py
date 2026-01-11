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
        # Pre-baked rows for select_query_log tests.
        self.select_docs: List[Dict[str, Any]] | None = None
        # Pre-baked rows for aggregate_query_log_counts tests.
        self.aggregate_rows_nogroup: List[Tuple[int, int]] | None = None
        self.aggregate_rows_group: List[Tuple[int, Optional[str], int]] | None = None
        # Pre-baked rows for rebuild_counts_from_query_log tests.
        self.rebuild_docs: List[Dict[str, Any]] | None = None

    # Schema helpers ---------------------------------------------------------
    def create_index(self, *_args: Any, **_kwargs: Any) -> None:  # noqa: D401
        """Brief: Index creation is a no-op for the fake collection."""

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

    def count_documents(self, flt: Dict[str, Any]) -> int:  # noqa: D401
        """Brief: Return the number of documents matching the filter.

        Inputs:
          - flt: Unused; we defer to select_docs length when present.

        Outputs:
          - Integer row count.
        """

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


def _make_backend(fake_mongo_driver) -> MongoStatsStore:  # type: ignore[no-untyped-def]
    """Brief: Helper to construct a backend using the fake MongoDB driver.

    Inputs:
      - fake_mongo_driver: fixture ensuring the fake driver is installed.

    Outputs:
      - MongoStatsStore instance with an in-memory _FakeMongoClient.
    """

    return MongoStatsStore(
        uri="mongodb://example/",
        database="db",
        connect_kwargs={"tls": True},
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
