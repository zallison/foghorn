from __future__ import annotations

import datetime as _dt
import hashlib
import importlib
import pickle
from typing import Any, Optional, Tuple

from .base import CachePlugin, cache_aliases


def _import_pymongo() -> Any:
    """Brief: Import the optional `pymongo` dependency.

    Inputs:
      - None.

    Outputs:
      - pymongo module.

    Notes:
      - This is intentionally lazy so that importing foghorn.cache_plugins works
        even when `pymongo` is not installed.
    """

    try:
        return importlib.import_module("pymongo")
    except Exception as exc:  # pragma: no cover
        raise ImportError(
            "MongoDBCache requires the optional 'pymongo' dependency. "
            "Install it with: pip install pymongo"
        ) from exc


def _stable_digest_for_key(key: Tuple[str, int]) -> str:
    """Brief: Create a stable digest for a CachePlugin key.

    Inputs:
      - key: Tuple[str, int] cache key (qname, qtype).

    Outputs:
      - str: Hex digest suitable for embedding in a MongoDB _id.

    Notes:
      - We hash a pickle of the key to avoid ambiguities with string joining.
    """

    payload = pickle.dumps(key, protocol=pickle.HIGHEST_PROTOCOL)
    return hashlib.sha256(payload).hexdigest()


def _encode_value(value: Any) -> Tuple[bytes, int]:
    """Brief: Encode a cache value for MongoDB storage.

    Inputs:
      - value: Any Python object.

    Outputs:
      - (payload, is_pickle):
          - payload: bytes to store.
          - is_pickle: 1 when payload is pickle-encoded, 0 otherwise.
    """

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value), 0
    return pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL), 1


def _decode_value(payload: bytes, is_pickle: int) -> Any:
    """Brief: Decode a stored MongoDB payload.

    Inputs:
      - payload: Stored bytes.
      - is_pickle: 1 if payload is a pickle.

    Outputs:
      - Any: Decoded object.
    """

    if int(is_pickle) == 1:
        return pickle.loads(payload)
    return payload


@cache_aliases("mongodb", "mongo")
class MongoDBCache(CachePlugin):
    """MongoDB-backed DNS cache plugin.

    Brief:
      Persistent CachePlugin implementation that stores entries in a MongoDB
      collection with per-entry expiry timestamps and original TTL metadata.

    Inputs:
      - **config:
          - uri (str): MongoDB connection URI (for example,
            'mongodb://localhost:27017'). When provided, it takes precedence
            over host/port.
          - host (str): MongoDB host (default '127.0.0.1') when uri is not
            provided.
          - port (int): MongoDB port (default 27017) when uri is not provided.
          - database (str): Database name (default 'foghorn_cache').
          - collection (str): Collection name (default 'dns_cache').
          - min_cache_ttl (int): Optional cache TTL floor used by the resolver.

    Outputs:
      - MongoDBCache instance.

    Example:
      cache:
        module: mongodb
        config:
          uri: mongodb://localhost:27017
          database: foghorn_cache
          collection: dns_cache
    """

    def __init__(self, **config: object) -> None:
        """Brief: Initialize the MongoDB-backed cache plugin.

        Inputs:
          - **config: See class docstring.

        Outputs:
          - None.
        """

        self.min_cache_ttl: int = max(0, int(config.get("min_cache_ttl", 0) or 0))

        uri_obj = config.get("uri") or config.get("url")
        if isinstance(uri_obj, str) and uri_obj.strip():
            uri = uri_obj.strip()
        else:
            host = str(config.get("host", "127.0.0.1") or "127.0.0.1")
            try:
                port = int(config.get("port", 27017) or 27017)
            except Exception:
                port = 27017
            uri = f"mongodb://{host}:{port}"

        database = config.get("database", "foghorn_cache")
        if not isinstance(database, str) or not database.strip():
            database = "foghorn_cache"

        collection = config.get("collection", "dns_cache")
        if not isinstance(collection, str) or not collection.strip():
            collection = "dns_cache"

        pymongo = _import_pymongo()
        self._client = pymongo.MongoClient(uri)
        self._collection = self._client[str(database)][str(collection)]

        # Best-effort creation of a TTL index on expires_at. MongoDB will use
        # the per-document expires_at value and automatically remove expired
        # documents; purge() also does a manual best-effort cleanup.
        try:
            self._collection.create_index("expires_at", expireAfterSeconds=0)
        except Exception:  # pragma: no cover - defensive index creation
            pass

    def _mongo_id_for_key(self, key: Tuple[str, int]) -> str:
        """Brief: Map a CachePlugin key to a MongoDB _id value.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - str: Stable hex digest for use as _id.
        """

        return _stable_digest_for_key(key)

    def get(self, key: Tuple[str, int]) -> Any | None:
        """Brief: Lookup a cached entry.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - Any | None: Cached value if present; otherwise None.
        """

        doc_id = self._mongo_id_for_key(key)
        try:
            doc = self._collection.find_one(
                {"_id": doc_id},
                projection={"value": 1, "is_pickle": 1, "expires_at": 1},
            )
        except Exception:
            return None

        if not doc:
            return None

        expires_at = doc.get("expires_at")
        now = _dt.datetime.utcnow()
        if isinstance(expires_at, _dt.datetime) and expires_at <= now:
            # Treat as expired and best-effort delete.
            try:
                self._collection.delete_one({"_id": doc_id})
            except Exception:
                pass
            return None

        payload = doc.get("value")
        is_pickle = doc.get("is_pickle", 1)
        if payload is None:
            return None

        try:
            return _decode_value(bytes(payload), int(is_pickle))
        except Exception:
            try:
                self._collection.delete_one({"_id": doc_id})
            except Exception:
                pass
            return None

    def get_with_meta(
        self, key: Tuple[str, int]
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Lookup a cached entry and return metadata.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - (value_or_None, seconds_remaining_or_None, original_ttl_or_None)
        """

        doc_id = self._mongo_id_for_key(key)
        try:
            doc = self._collection.find_one(
                {"_id": doc_id},
                projection={"value": 1, "is_pickle": 1, "expires_at": 1, "ttl": 1},
            )
        except Exception:
            return None, None, None

        if not doc:
            return None, None, None

        now = _dt.datetime.utcnow()
        expires_at = doc.get("expires_at")
        ttl_original: Optional[int] = None
        if "ttl" in doc and doc["ttl"] is not None:
            try:
                ttl_original = int(doc["ttl"])
            except Exception:
                ttl_original = None

        seconds_remaining: Optional[float] = None
        if isinstance(expires_at, _dt.datetime):
            delta = (expires_at - now).total_seconds()
            if delta <= 0:
                # Expired; treat as miss and best-effort delete.
                try:
                    self._collection.delete_one({"_id": doc_id})
                except Exception:
                    pass
                return None, None, None
            seconds_remaining = float(delta)

        payload = doc.get("value")
        is_pickle = doc.get("is_pickle", 1)
        if payload is None:
            return None, None, None

        try:
            value = _decode_value(bytes(payload), int(is_pickle))
        except Exception:
            try:
                self._collection.delete_one({"_id": doc_id})
            except Exception:
                pass
            return None, None, None

        return value, seconds_remaining, ttl_original

    def set(self, key: Tuple[str, int], ttl: int, value: Any) -> None:
        """Brief: Store a value under key with a TTL.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).
          - ttl: int time-to-live in seconds.
          - value: Cached value.

        Outputs:
          - None.
        """

        ttl_int = max(0, int(ttl))
        if ttl_int <= 0:
            return

        doc_id = self._mongo_id_for_key(key)
        payload, is_pickle = _encode_value(value)

        now = _dt.datetime.utcnow()
        expires_at = now + _dt.timedelta(seconds=ttl_int)

        doc = {
            "_id": doc_id,
            "value": payload,
            "is_pickle": int(is_pickle),
            "ttl": int(ttl_int),
            "expires_at": expires_at,
        }

        try:
            self._collection.replace_one({"_id": doc_id}, doc, upsert=True)
        except Exception:
            # Best-effort only; failures are treated as cache miss.
            return

    def purge(self) -> int:
        """Brief: Purge expired entries.

        Inputs:
          - None.

        Outputs:
          - int: Number of entries removed (best-effort).

        Notes:
          - MongoDB TTL indexes remove expired documents automatically when
            available. This method also issues a best-effort manual delete for
            entries whose expires_at is in the past.
        """

        now = _dt.datetime.utcnow()
        try:
            result = self._collection.delete_many({"expires_at": {"$lte": now}})
        except Exception:
            return 0
        deleted = getattr(result, "deleted_count", None)
        try:
            return int(deleted) if deleted is not None else 0
        except Exception:
            return 0
