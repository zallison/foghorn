"""
Brief: Tests for SQLite3TTLCache, the sqlite-backed TTL cache implementation.

Inputs:
  - None

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

import time
from typing import Any

from foghorn.cache_backends.sqlite_ttl import SQLite3TTLCache


def test_sqlite_ttl_cache_set_get_and_encoding_decoding(tmp_path) -> None:
    """Brief: set/get round-trip values and use pickle only when needed.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - None; asserts bytes are stored raw and non-bytes via pickle.
    """

    db_path = tmp_path / "cache" / "ttl.sqlite"
    cache = SQLite3TTLCache(str(db_path), namespace="testcache", create_dir=True)

    # Bytes are stored without pickle.
    cache.set("raw-bytes", ttl=60, value=b"value")
    with cache._lock:  # type: ignore[attr-defined]
        cur = cache._conn.cursor()  # type: ignore[attr-defined]
        cur.execute(
            "SELECT value_blob, value_is_pickle FROM testcache WHERE key_blob IS NOT NULL"
        )
        row = cur.fetchone()
    assert row is not None
    value_blob, value_is_pickle = row
    assert bytes(value_blob) == b"value"
    assert int(value_is_pickle) == 0

    # Non-bytes use pickle.
    cache.set("tuple-key", ttl=60, value={"a": 1})
    value = cache.get("tuple-key")
    assert value == {"a": 1}


def test_sqlite_ttl_cache_get_miss_and_expiry(tmp_path) -> None:
    """Brief: get() treats missing, malformed, and expired rows as misses.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - None; asserts counters and None returns for these cases.
    """

    cache = SQLite3TTLCache(str(tmp_path / "ttl.sqlite"), namespace="c")

    # Missing key -> miss.
    assert cache.get("missing") is None
    assert cache.cache_misses >= 1

    # Expired key is removed and treated as miss.
    cache.set("soon", ttl=0, value=b"x")
    assert cache.get("soon") is None

    # Malformed expiry row -> deleted and treated as miss.
    with cache._lock:  # type: ignore[attr-defined]
        cur = cache._conn.cursor()  # type: ignore[attr-defined]
        cur.execute("UPDATE c SET expiry='not-a-number' WHERE key_blob IS NOT NULL")
        cache._conn.commit()  # type: ignore[attr-defined]
    assert cache.get("soon") is None


def test_sqlite_ttl_cache_get_with_meta_returns_value_and_remaining(tmp_path) -> None:
    """Brief: get_with_meta returns value, remaining seconds, and original TTL.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - None; asserts positive and negative remaining as hits/misses.
    """

    cache = SQLite3TTLCache(str(tmp_path / "ttl.sqlite"), namespace="m")

    cache.set("k", ttl=1, value=b"v")
    value, remaining, ttl_i = cache.get_with_meta("k")
    assert value == b"v"
    assert ttl_i == 1
    assert remaining is not None and remaining <= 1.0

    # Sleep so that entry becomes expired but still present in DB.
    time.sleep(1.2)
    value2, remaining2, ttl_i2 = cache.get_with_meta("k")
    assert value2 == b"v"
    assert ttl_i2 == 1
    assert remaining2 is not None and remaining2 < 0


def test_sqlite_ttl_cache_get_with_meta_malformed_and_decode_error(
    tmp_path, monkeypatch
) -> None:
    """Brief: get_with_meta handles malformed expiry/ttl and decode failures.

    Inputs:
      - tmp_path: pytest temporary directory fixture.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that malformed rows and decode errors yield misses.
    """

    cache = SQLite3TTLCache(str(tmp_path / "ttl.sqlite"), namespace="e")
    cache.set("k", ttl=60, value=b"v")

    # Corrupt expiry and ttl so conversion fails.
    with cache._lock:  # type: ignore[attr-defined]
        cur = cache._conn.cursor()  # type: ignore[attr-defined]
        cur.execute("UPDATE e SET expiry='bad', ttl='also-bad'")
        cache._conn.commit()  # type: ignore[attr-defined]

    v, rem, ttl_i = cache.get_with_meta("k")
    assert (v, rem, ttl_i) == (None, None, None)

    # Now restore a good row but force _decode to raise to hit the decode path.
    cache.set("k2", ttl=60, value=b"ok")

    def boom_decode(payload: bytes, is_pickle: int) -> Any:  # type: ignore[no-untyped-def]
        raise RuntimeError("boom")

    monkeypatch.setattr(SQLite3TTLCache, "_decode", staticmethod(boom_decode))

    v2, rem2, ttl_i2 = cache.get_with_meta("k2")
    assert (v2, rem2, ttl_i2) == (None, None, None)


def test_sqlite_ttl_cache_delete_and_purge(tmp_path) -> None:
    """Brief: delete() removes a single key and purge() removes expired entries.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - None; asserts delete return count and purge behavior.
    """

    cache = SQLite3TTLCache(str(tmp_path / "ttl.sqlite"), namespace="d")

    cache.set("k1", ttl=60, value=b"1")
    cache.set("k2", ttl=0, value=b"2")

    assert cache.delete("missing") == 0
    assert cache.delete("k1") == 1

    # Only k2 remains and is expired; purge should remove it.
    removed = cache.purge()
    assert removed >= 1


def test_sqlite_ttl_cache_context_manager_and_close(tmp_path) -> None:
    """Brief: Context manager and close() cleanly close the sqlite connection.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - None; asserts __enter__/__exit__/close/__del__ do not raise.
    """

    db_path = tmp_path / "ttl.sqlite"

    with SQLite3TTLCache(str(db_path), namespace="ctx") as cache:
        cache.set("k", ttl=60, value=b"v")
        assert cache.get("k") == b"v"

    # After context exit, close() should be idempotent.
    cache.close()
