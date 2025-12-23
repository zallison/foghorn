"""Brief: Unit tests for the sqlite3-backed cache plugin.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from typing import Any

import pytest

from foghorn.cache_plugins.registry import load_cache_plugin
from foghorn.cache_plugins.sqlite_cache import SQLite3CachePlugin


def test_sqlite3_cache_creates_parent_directory(tmp_path) -> None:
    """Brief: Plugin creates the db directory when it does not exist.

    Inputs:
      - tmp_path: pytest temporary path fixture.

    Outputs:
      - None; asserts db file is created in a newly created directory.
    """

    db_path = tmp_path / "nested" / "dns_cache.db"
    assert not db_path.parent.exists()

    plugin = SQLite3CachePlugin(db_path=str(db_path))
    plugin.set(("example.com", 1), 60, b"wire")

    assert db_path.parent.exists()
    assert db_path.exists()


def test_sqlite3_cache_roundtrip_bytes(tmp_path, monkeypatch) -> None:
    """Brief: set/get round-trips raw bytes and enforces expiry in get().

    Inputs:
      - tmp_path: pytest temporary path fixture.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts bytes round-trip, get_with_meta returns remaining, and
        get() misses after expiry.
    """

    import foghorn.cache_backends.sqlite_ttl as mod

    db_path = tmp_path / "dns_cache.db"
    plugin = SQLite3CachePlugin(db_path=str(db_path))

    # Freeze time for deterministic TTL behavior.
    t = {"now": 1000.0}

    def _now() -> float:
        return float(t["now"])

    monkeypatch.setattr(mod.time, "time", _now)

    key = ("example.com", 1)
    plugin.set(key, 2, b"wire-bytes")

    assert plugin.get(key) == b"wire-bytes"

    t["now"] = 1001.0
    value, remaining, ttl = plugin.get_with_meta(key)
    assert value == b"wire-bytes"
    assert remaining is not None and remaining == pytest.approx(1.0)
    assert ttl == 2

    # After expiry, get() should treat the entry as a miss.
    t["now"] = 1003.0
    assert plugin.get(key) is None


def test_sqlite3_cache_snapshot_includes_counters(tmp_path) -> None:
    """Brief: get_http_snapshot exposes per-cache counters in caches/summary.

    Inputs:
      - tmp_path: pytest temporary path fixture.

    Outputs:
      - None; asserts snapshot contains counter keys for the primary cache.
    """

    db_path = tmp_path / "dns_cache.db"
    plugin = SQLite3CachePlugin(db_path=str(db_path))

    # Exercise the cache a bit so counters are non-zero.
    key = ("example.com", 1)
    plugin.set(key, 60, b"wire-bytes")
    assert plugin.get(key) == b"wire-bytes"
    assert plugin.get(("other.com", 1)) is None

    snap = plugin.get_http_snapshot()
    assert "summary" in snap
    assert "caches" in snap

    summary = snap["summary"]
    assert isinstance(summary, dict)
    # Counter keys should be present when the backend exposes them.
    assert "calls_total" in summary
    assert "cache_hits" in summary
    assert "cache_misses" in summary

    caches = snap["caches"]
    assert isinstance(caches, list) and caches
    primary = caches[0]
    assert "label" in primary and "dns_cache" in primary["label"]
    assert "calls_total" in primary


@pytest.mark.parametrize(
    "value",
    [
        {"a": 1, "b": [1, 2, 3]},
        ("tuple", 123),
    ],
)
def test_sqlite3_cache_roundtrip_pickled_objects(tmp_path, value: Any) -> None:
    """Brief: Non-bytes values are stored via pickle and returned on get().

    Inputs:
      - tmp_path: pytest temporary path fixture.
      - value: Arbitrary non-bytes object.

    Outputs:
      - None; asserts value equality after a set/get.
    """

    plugin = SQLite3CachePlugin(db_path=str(tmp_path / "dns_cache.db"))
    key = ("example.com", 28)

    plugin.set(key, 60, value)
    assert plugin.get(key) == value


def test_registry_loads_sqlite3_cache_from_mapping(tmp_path) -> None:
    """Brief: load_cache_plugin supports mapping config for sqlite3 cache.

    Inputs:
      - tmp_path: pytest temporary path fixture.

    Outputs:
      - None; asserts returned instance type.
    """

    db_path = tmp_path / "dns_cache.db"
    inst = load_cache_plugin({"module": "sqlite3", "config": {"db_path": str(db_path)}})
    assert isinstance(inst, SQLite3CachePlugin)
