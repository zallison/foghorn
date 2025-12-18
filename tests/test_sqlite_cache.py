"""Brief: Unit tests for foghorn.sqlite_cache.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from typing import Any

from foghorn.sqlite_cache import SQLite3TTLCache


def test_sqlite_ttl_cache_roundtrip_arbitrary_key_and_value(tmp_path) -> None:
    """Brief: SQLite3TTLCache supports arbitrary Python keys/values via pickling.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - None.
    """

    cache = SQLite3TTLCache(str(tmp_path / "cache.db"), table="generic")
    key = ("k", 123, ("nested", True))
    value: Any = {"a": 1, "b": [1, 2, 3]}

    cache.set(key, 60, value)
    assert cache.get(key) == value


def test_sqlite_ttl_cache_expiry_enforced_in_get(tmp_path, monkeypatch) -> None:
    """Brief: get() returns None after expiry but get_with_meta returns negative remaining.

    Inputs:
      - tmp_path: pytest temporary directory.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None.
    """

    import foghorn.sqlite_cache as mod

    t = {"now": 1000.0}

    def _now() -> float:
        return float(t["now"])

    monkeypatch.setattr(mod.time, "time", _now)

    cache = SQLite3TTLCache(str(tmp_path / "cache.db"), table="generic")
    key = "hello"
    cache.set(key, 2, b"world")

    assert cache.get(key) == b"world"

    t["now"] = 1003.0
    assert cache.get(key) is None

    # The row was removed by get(); reinsert and verify meta behavior.
    t["now"] = 2000.0
    cache.set(key, 2, b"world")

    t["now"] = 2003.0
    v, remaining, ttl = cache.get_with_meta(key)
    assert v == b"world"
    assert remaining is not None and remaining < 0
    assert ttl == 2


def test_sqlite_ttl_cache_delete(tmp_path) -> None:
    """Brief: delete() removes entries.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - None.
    """

    cache = SQLite3TTLCache(str(tmp_path / "cache.db"), table="generic")
    cache.set("k", 60, b"v")
    assert cache.get("k") == b"v"
    assert cache.delete("k") == 1
    assert cache.get("k") is None


def test_sqlite_ttl_cache_purge_removes_expired(tmp_path, monkeypatch) -> None:
    """Brief: purge() removes expired entries.

    Inputs:
      - tmp_path: pytest temporary directory.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None.
    """

    import foghorn.sqlite_cache as mod

    t = {"now": 1000.0}

    def _now() -> float:
        return float(t["now"])

    monkeypatch.setattr(mod.time, "time", _now)

    cache = SQLite3TTLCache(str(tmp_path / "cache.db"), table="generic")
    cache.set("k1", 1, b"v1")
    cache.set("k2", 10, b"v2")

    t["now"] = 1002.0
    removed = cache.purge()
    assert removed >= 1
    assert cache.get("k1") is None
    assert cache.get("k2") == b"v2"
