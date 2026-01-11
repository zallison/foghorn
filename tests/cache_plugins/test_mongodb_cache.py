"""Brief: Unit tests for the MongoDB-backed cache plugin.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from typing import Any, Dict, Optional
import importlib
import sys

import pytest

from foghorn.plugins.cache import mongodb_cache as mongodb_cache_mod
from foghorn.plugins.cache.registry import get_cache_plugin_class, load_cache_plugin


class FakeMongoCollection:
    """Brief: Minimal in-memory MongoDB collection substitute for tests.

    Inputs:
      - None.

    Outputs:
      - FakeMongoCollection instance backed by a simple dict.
    """

    def __init__(self) -> None:
        self.docs: Dict[str, Dict[str, Any]] = {}
        self.create_index_calls: list[tuple[str, int]] = []
        self.raise_on_find_one = False
        self.raise_on_delete_one = False
        self.raise_on_delete_many = False
        self.raise_on_replace_one = False
        self.raise_on_create_index = False

    def create_index(
        self, field: str, expireAfterSeconds: int = 0
    ) -> None:  # noqa: N803
        """Brief: Record requested TTL index creation.

        Inputs:
          - field: Field name.
          - expireAfterSeconds: Expiry seconds for MongoDB TTL index.

        Outputs:
          - None.
        """

        if self.raise_on_create_index:
            raise RuntimeError("create_index failed")
        self.create_index_calls.append((field, int(expireAfterSeconds)))

    def find_one(
        self, filter: Dict[str, Any], projection: Optional[Dict[str, int]] = None
    ) -> Optional[Dict[str, Any]]:  # noqa: D417
        """Brief: Return a stored document by _id.

        Inputs:
          - filter: Query mapping containing an _id.
          - projection: Optional projection mapping (ignored).

        Outputs:
          - Optional[dict]: Stored document or None.
        """

        if self.raise_on_find_one:
            raise RuntimeError("find_one failed")
        doc_id = filter.get("_id")
        return self.docs.get(doc_id)

    def replace_one(
        self, filter: Dict[str, Any], doc: Dict[str, Any], upsert: bool = True
    ) -> None:
        """Brief: Upsert a document by _id.

        Inputs:
          - filter: Query mapping containing an _id.
          - doc: Replacement document.
          - upsert: Whether to upsert (ignored; always upserts).

        Outputs:
          - None.
        """

        if self.raise_on_replace_one:
            raise RuntimeError("replace_one failed")
        doc_id = filter.get("_id") or doc.get("_id")
        assert doc_id is not None
        self.docs[str(doc_id)] = dict(doc)

    def delete_one(self, filter: Dict[str, Any]) -> None:
        """Brief: Delete a single document by _id.

        Inputs:
          - filter: Query mapping containing an _id.

        Outputs:
          - None.
        """

        if self.raise_on_delete_one:
            raise RuntimeError("delete_one failed")
        doc_id = filter.get("_id")
        if doc_id is not None:
            self.docs.pop(str(doc_id), None)

    def delete_many(self, filter: Dict[str, Any]) -> Any:
        """Brief: Delete many documents whose expires_at is <= given cutoff.

        Inputs:
          - filter: Mapping with an expires_at $lte cutoff.

        Outputs:
          - Object with deleted_count attribute indicating removed documents.
        """

        if self.raise_on_delete_many:
            raise RuntimeError("delete_many failed")

        cond = filter.get("expires_at", {})
        cutoff = cond.get("$lte")

        removed = 0
        if cutoff is None:
            removed = len(self.docs)
            self.docs.clear()
        else:
            for doc_id, doc in list(self.docs.items()):
                expires_at = doc.get("expires_at")
                if expires_at is not None and expires_at <= cutoff:
                    removed += 1
                    self.docs.pop(doc_id, None)

        class Result:
            deleted_count: int

            def __init__(self, n: int) -> None:
                self.deleted_count = int(n)

        return Result(removed)


class FakeMongoDatabase:
    """Brief: Minimal in-memory MongoDB database wrapper.

    Inputs:
      - client: Owning FakeMongoClient.
      - name: Database name.

    Outputs:
      - FakeMongoDatabase providing collection access via __getitem__.
    """

    def __init__(self, client: "FakeMongoClient", name: str) -> None:
        self._client = client
        self._name = name

    def __getitem__(self, name: str) -> FakeMongoCollection:
        """Brief: Return or create a collection by name.

        Inputs:
          - name: Collection name.

        Outputs:
          - FakeMongoCollection instance.
        """

        return self._client._get_collection(self._name, name)


class FakeMongoClient:
    """Brief: Minimal in-memory MongoDB client substitute for tests.

    Inputs:
      - uri: MongoDB connection URI.

    Outputs:
      - FakeMongoClient with database/collection hierarchy backed by dicts.
    """

    def __init__(self, uri: str) -> None:
        self.uri = uri
        self._collections: Dict[tuple[str, str], FakeMongoCollection] = {}

    def _get_collection(self, database: str, collection: str) -> FakeMongoCollection:
        key = (str(database), str(collection))
        if key not in self._collections:
            self._collections[key] = FakeMongoCollection()
        return self._collections[key]

    def __getitem__(self, name: str) -> FakeMongoDatabase:
        """Brief: Return a database wrapper with collection access.

        Inputs:
          - name: Database name.

        Outputs:
          - FakeMongoDatabase instance.
        """

        return FakeMongoDatabase(self, name)


def _fake_pymongo_module() -> object:
    """Brief: Build a minimal module-like object exposing FakeMongoClient.

    Inputs:
      - None.

    Outputs:
      - Object with a MongoClient attribute pointing to FakeMongoClient.
    """

    return type("FakePymongoModule", (), {"MongoClient": FakeMongoClient})()


def _fake_pymongo_module_with_failing_index() -> object:
    """Brief: Build a pymongo-like module whose index creation fails.

    Inputs:
      - None.

    Outputs:
      - Object with MongoClient that raises from create_index.
    """

    class ClientWithFailingIndex(FakeMongoClient):
        def _get_collection(self, database: str, collection: str) -> FakeMongoCollection:  # type: ignore[override]
            coll = super()._get_collection(database, collection)
            coll.raise_on_create_index = True
            return coll

    return type(
        "FakePymongoModuleFailingIndex", (), {"MongoClient": ClientWithFailingIndex}
    )()


def test_registry_resolves_mongodb_aliases_to_plugin_class() -> None:
    """Brief: Cache plugin registry exposes mongodb/mongo aliases.

    Inputs:
      - None.

    Outputs:
      - None; asserts alias resolution returns the expected class.
    """

    cls = get_cache_plugin_class("mongodb")
    assert cls.__name__ == "MongoDBCache"

    cls2 = get_cache_plugin_class("mongo")
    assert cls2 is cls


def test_import_pymongo_success_uses_importlib(monkeypatch) -> None:
    """Brief: _import_pymongo delegates to importlib.import_module.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts the returned object comes from import_module.
    """

    sentinel = object()

    real_import = importlib.import_module

    def _fake_import(name: str, package=None):  # type: ignore[no-untyped-def]
        if name == "pymongo":
            return sentinel
        return real_import(name, package=package)

    monkeypatch.setattr(importlib, "import_module", _fake_import)

    assert mongodb_cache_mod._import_pymongo() is sentinel


def test_import_pymongo_missing_dependency_raises_helpful_error(monkeypatch) -> None:
    """Brief: _import_pymongo raises ImportError with install hint when pymongo is absent.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts error message mentions pip install pymongo.
    """

    monkeypatch.delitem(sys.modules, "pymongo", raising=False)

    real_import = importlib.import_module

    def _fake_import(name: str, package=None):  # type: ignore[no-untyped-def]
        if name == "pymongo":
            raise ModuleNotFoundError("No module named pymongo")
        return real_import(name, package=package)

    monkeypatch.setattr(importlib, "import_module", _fake_import)

    with pytest.raises(ImportError) as excinfo:
        _ = mongodb_cache_mod._import_pymongo()

    msg = str(excinfo.value).lower()
    assert "pip install pymongo" in msg


def test_stable_digest_for_key_is_deterministic_and_hex() -> None:
    """Brief: _stable_digest_for_key returns a deterministic hex digest.

    Inputs:
      - None.

    Outputs:
      - None; asserts stability and hex characters.
    """

    key = ("example.com", 1)
    digest1 = mongodb_cache_mod._stable_digest_for_key(key)
    digest2 = mongodb_cache_mod._stable_digest_for_key(key)
    assert digest1 == digest2
    assert all(c in "0123456789abcdef" for c in digest1)


def test_encode_decode_roundtrip_bytes_and_pickled() -> None:
    """Brief: Helper encode/decode functions support bytes and arbitrary objects.

    Inputs:
      - None.

    Outputs:
      - None; asserts flags and round-trips for bytes and dict objects.
    """

    raw = b"wire-bytes"
    payload, is_pickle = mongodb_cache_mod._encode_value(raw)
    assert payload == raw
    assert is_pickle == 0
    assert mongodb_cache_mod._decode_value(payload, is_pickle) == raw

    obj = {"name": "example.com", "qtype": 1}
    payload2, is_pickle2 = mongodb_cache_mod._encode_value(obj)
    assert is_pickle2 == 1
    assert mongodb_cache_mod._decode_value(payload2, is_pickle2) == obj


def test_mongodb_cache_init_uses_uri_and_creates_ttl_index(monkeypatch) -> None:
    """Brief: MongoDBCache honors uri config and creates a TTL index.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts a FakeMongoCollection is created and index requested.
    """

    monkeypatch.setattr(
        mongodb_cache_mod,
        "_import_pymongo",
        lambda: _fake_pymongo_module(),
    )

    uri = "mongodb://localhost:27017"
    plugin = mongodb_cache_mod.MongoDBCache(
        uri=uri, database="db", collection="col", min_cache_ttl=-5
    )

    assert plugin.min_cache_ttl == 0

    coll = plugin._collection
    assert isinstance(coll, FakeMongoCollection)
    assert coll.create_index_calls == [("expires_at", 0)]


def test_mongodb_cache_init_falls_back_to_host_port_and_defaults(monkeypatch) -> None:
    """Brief: MongoDBCache builds URI from host/port and normalizes db/collection.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts init succeeds with various malformed settings.
    """

    monkeypatch.setattr(
        mongodb_cache_mod,
        "_import_pymongo",
        lambda: _fake_pymongo_module(),
    )

    plugin = mongodb_cache_mod.MongoDBCache(
        host="example-cache",
        port="not-an-int",
        database=123,
        collection="  ",
    )

    assert isinstance(plugin._collection, FakeMongoCollection)


def test_mongodb_cache_init_tolerates_ttl_index_errors(monkeypatch) -> None:
    """Brief: MongoDBCache ignores TTL index creation failures.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts __init__ does not raise when create_index fails.
    """

    monkeypatch.setattr(
        mongodb_cache_mod,
        "_import_pymongo",
        lambda: _fake_pymongo_module_with_failing_index(),
    )

    _ = mongodb_cache_mod.MongoDBCache(uri="mongodb://localhost:27017")


def _make_plugin_with_fake_mongo(
    monkeypatch,
) -> tuple[mongodb_cache_mod.MongoDBCache, FakeMongoCollection]:
    """Brief: Helper to build a MongoDBCache wired to FakeMongoCollection.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - (plugin, collection) pair for use in tests.
    """

    monkeypatch.setattr(
        mongodb_cache_mod,
        "_import_pymongo",
        lambda: _fake_pymongo_module(),
    )

    plugin = mongodb_cache_mod.MongoDBCache(uri="mongodb://localhost:27017")
    coll = plugin._collection
    assert isinstance(coll, FakeMongoCollection)
    return plugin, coll


def test_mongodb_cache_mongo_id_for_key_wraps_stable_digest(monkeypatch) -> None:
    """Brief: _mongo_id_for_key delegates to _stable_digest_for_key.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts output matches helper function.
    """

    plugin, _ = _make_plugin_with_fake_mongo(monkeypatch)
    key = ("example.com", 1)
    assert plugin._mongo_id_for_key(key) == mongodb_cache_mod._stable_digest_for_key(
        key
    )


def test_mongodb_cache_get_and_get_with_meta_roundtrip(monkeypatch) -> None:
    """Brief: set(), get(), and get_with_meta() round-trip values and metadata.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts value, remaining seconds, and original TTL are correct.
    """

    plugin, _ = _make_plugin_with_fake_mongo(monkeypatch)

    key = ("example.com", 1)
    plugin.set(key, 60, b"wire-bytes")

    assert plugin.get(key) == b"wire-bytes"

    value, remaining, ttl_original = plugin.get_with_meta(key)
    assert value == b"wire-bytes"
    assert ttl_original == 60
    assert remaining is None or remaining >= 0.0


def test_mongodb_cache_get_miss_and_payload_none(monkeypatch) -> None:
    """Brief: get() returns None when document is missing or has no payload.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts None is returned for missing and payload=None cases.
    """

    plugin, coll = _make_plugin_with_fake_mongo(monkeypatch)

    key = ("example.com", 1)
    assert plugin.get(key) is None

    doc_id = plugin._mongo_id_for_key(key)
    coll.docs[doc_id] = {"_id": doc_id, "value": None, "is_pickle": 1}
    assert plugin.get(key) is None


def test_mongodb_cache_get_handles_expired_and_decode_errors(monkeypatch) -> None:
    """Brief: get() deletes expired entries and tolerates decode errors.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts expired and corrupt entries behave as cache misses.
    """

    plugin, coll = _make_plugin_with_fake_mongo(monkeypatch)

    key = ("expired.com", 1)
    doc_id = plugin._mongo_id_for_key(key)

    now = mongodb_cache_mod._dt.datetime.utcnow()
    coll.docs[doc_id] = {
        "_id": doc_id,
        "value": b"payload",
        "is_pickle": 0,
        "expires_at": now - mongodb_cache_mod._dt.timedelta(seconds=10),
    }

    assert plugin.get(key) is None
    assert doc_id not in coll.docs

    key2 = ("badpickle.com", 1)
    doc_id2 = plugin._mongo_id_for_key(key2)
    coll.docs[doc_id2] = {
        "_id": doc_id2,
        "value": b"not-a-pickle",
        "is_pickle": 1,
    }

    assert plugin.get(key2) is None


def test_mongodb_cache_get_handles_backend_find_and_delete_errors(monkeypatch) -> None:
    """Brief: get() handles backend find/delete failures as cache misses.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts get() returns None when backend operations raise.
    """

    plugin, coll = _make_plugin_with_fake_mongo(monkeypatch)

    key = ("example.com", 1)
    doc_id = plugin._mongo_id_for_key(key)
    now = mongodb_cache_mod._dt.datetime.utcnow()
    coll.docs[doc_id] = {
        "_id": doc_id,
        "value": b"payload",
        "is_pickle": 0,
        "expires_at": now - mongodb_cache_mod._dt.timedelta(seconds=10),
    }

    coll.raise_on_find_one = True
    assert plugin.get(key) is None

    coll.raise_on_find_one = False
    coll.raise_on_delete_one = True
    assert plugin.get(key) is None


def test_mongodb_cache_get_with_meta_variants(monkeypatch) -> None:
    """Brief: get_with_meta() handles TTL, expiry, malformed TTL, and payload None.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts different document shapes yield expected triples.
    """

    plugin, coll = _make_plugin_with_fake_mongo(monkeypatch)

    key = ("example.com", 1)
    doc_id = plugin._mongo_id_for_key(key)
    now = mongodb_cache_mod._dt.datetime.utcnow()

    coll.docs[doc_id] = {
        "_id": doc_id,
        "value": b"payload",
        "is_pickle": 0,
        "expires_at": now + mongodb_cache_mod._dt.timedelta(seconds=10),
        "ttl": 10,
    }
    value, remaining, ttl = plugin.get_with_meta(key)
    assert value == b"payload"
    assert ttl == 10
    assert remaining is not None and remaining > 0

    key_expired = ("expired.com", 1)
    doc_id_expired = plugin._mongo_id_for_key(key_expired)
    coll.docs[doc_id_expired] = {
        "_id": doc_id_expired,
        "value": b"payload",
        "is_pickle": 0,
        "expires_at": now - mongodb_cache_mod._dt.timedelta(seconds=5),
        "ttl": 10,
    }
    value2, remaining2, ttl2 = plugin.get_with_meta(key_expired)
    assert value2 is None
    assert remaining2 is None
    assert ttl2 is None

    key_bad_ttl = ("badttl.com", 1)
    doc_id_bad_ttl = plugin._mongo_id_for_key(key_bad_ttl)
    coll.docs[doc_id_bad_ttl] = {
        "_id": doc_id_bad_ttl,
        "value": b"payload",
        "is_pickle": 0,
        "expires_at": now + mongodb_cache_mod._dt.timedelta(seconds=5),
        "ttl": "not-an-int",
    }
    value3, remaining3, ttl3 = plugin.get_with_meta(key_bad_ttl)
    assert value3 == b"payload"
    assert remaining3 is not None and remaining3 > 0
    assert ttl3 is None

    key_payload_none = ("nopayload.com", 1)
    doc_id_payload_none = plugin._mongo_id_for_key(key_payload_none)
    coll.docs[doc_id_payload_none] = {
        "_id": doc_id_payload_none,
        "value": None,
        "is_pickle": 0,
        "expires_at": now + mongodb_cache_mod._dt.timedelta(seconds=5),
    }
    value4, remaining4, ttl4 = plugin.get_with_meta(key_payload_none)
    assert value4 is None
    assert remaining4 is None
    assert ttl4 is None


def test_mongodb_cache_get_with_meta_handles_backend_errors(monkeypatch) -> None:
    """Brief: get_with_meta() tolerates backend find/delete and decode failures.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts failures are surfaced as cache misses with None metadata.
    """

    plugin, coll = _make_plugin_with_fake_mongo(monkeypatch)

    key = ("example.com", 1)
    doc_id = plugin._mongo_id_for_key(key)
    now = mongodb_cache_mod._dt.datetime.utcnow()

    coll.raise_on_find_one = True
    value, remaining, ttl = plugin.get_with_meta(key)
    assert value is None and remaining is None and ttl is None

    coll.raise_on_find_one = False
    coll.docs[doc_id] = {
        "_id": doc_id,
        "value": b"not-a-pickle",
        "is_pickle": 1,
        "expires_at": now + mongodb_cache_mod._dt.timedelta(seconds=5),
        "ttl": 10,
    }
    coll.raise_on_delete_one = True
    value2, remaining2, ttl2 = plugin.get_with_meta(key)
    assert value2 is None and remaining2 is None and ttl2 is None


def test_mongodb_cache_set_respects_ttl_and_handles_errors(monkeypatch) -> None:
    """Brief: set() ignores non-positive TTLs and tolerates backend failures.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts ttl<=0 is ignored and replace_one errors are swallowed.
    """

    plugin, coll = _make_plugin_with_fake_mongo(monkeypatch)

    key = ("example.com", 1)
    plugin.set(key, 0, b"payload")
    assert not coll.docs

    coll.raise_on_replace_one = True
    plugin.set(key, 10, b"payload")
    assert not coll.docs


def test_mongodb_cache_purge_variants(monkeypatch) -> None:
    """Brief: purge() returns an int and handles backend edge cases.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts normal, missing deleted_count, and bad types all return ints.
    """

    plugin, coll = _make_plugin_with_fake_mongo(monkeypatch)

    now = mongodb_cache_mod._dt.datetime.utcnow()
    coll.docs["a"] = {
        "_id": "a",
        "expires_at": now - mongodb_cache_mod._dt.timedelta(seconds=1),
    }
    coll.docs["b"] = {
        "_id": "b",
        "expires_at": now + mongodb_cache_mod._dt.timedelta(seconds=10),
    }

    removed = plugin.purge()
    assert isinstance(removed, int) and removed >= 1

    def _delete_many_no_deleted_count(filter: Dict[str, Any]) -> object:  # type: ignore[no-untyped-def]
        class Result:
            pass

        return Result()

    coll.raise_on_delete_many = False
    coll.delete_many = _delete_many_no_deleted_count  # type: ignore[assignment]
    assert plugin.purge() == 0

    class ResultBadCount:
        def __init__(self) -> None:
            self.deleted_count = "not-an-int"

    def _delete_many_bad_deleted_count(filter: Dict[str, Any]) -> ResultBadCount:  # type: ignore[no-untyped-def]
        return ResultBadCount()

    coll.delete_many = _delete_many_bad_deleted_count  # type: ignore[assignment]
    assert plugin.purge() == 0

    def _delete_many_raises(filter: Dict[str, Any]) -> None:  # type: ignore[no-untyped-def]
        raise RuntimeError("delete_many failed")

    coll.delete_many = _delete_many_raises  # type: ignore[assignment]
    assert plugin.purge() == 0


def test_load_cache_plugin_mongodb_raises_helpful_error_when_dependency_missing(
    monkeypatch,
) -> None:
    """Brief: Instantiating the mongodb cache plugin errors clearly when pymongo is missing.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts ImportError message contains install hint.
    """

    monkeypatch.delitem(sys.modules, "pymongo", raising=False)

    real_import = importlib.import_module

    def _fake_import(name: str, package=None):  # type: ignore[no-untyped-def]
        if name == "pymongo":
            raise ModuleNotFoundError("No module named pymongo")
        return real_import(name, package=package)

    monkeypatch.setattr(importlib, "import_module", _fake_import)

    with pytest.raises(ImportError) as excinfo:
        _ = load_cache_plugin(
            {
                "module": "mongodb",
                "config": {"uri": "mongodb://localhost:27017"},
            }
        )

    msg = str(excinfo.value).lower()
    assert "pip install pymongo" in msg


def test_registry_loads_mongodb_cache_from_mapping(monkeypatch) -> None:
    """Brief: load_cache_plugin supports mapping config for mongodb cache.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts returned instance type.
    """

    monkeypatch.setattr(
        mongodb_cache_mod,
        "_import_pymongo",
        lambda: _fake_pymongo_module(),
    )

    inst = load_cache_plugin(
        {
            "module": "mongodb",
            "config": {"uri": "mongodb://localhost:27017"},
        }
    )
    assert inst.__class__.__name__ == "MongoDBCache"
