"""Brief: Unit tests for the sqlite3-backed cache plugin.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from typing import Any
import threading
import time

import pytest

from foghorn.plugins.cache.registry import load_cache_plugin
from foghorn.plugins.cache.sqlite_cache import SQLite3Cache


def test_sqlite3_cache_creates_parent_directory(tmp_path) -> None:
    """Brief: Plugin creates the db directory when it does not exist.

    Inputs:
      - tmp_path: pytest temporary path fixture.

    Outputs:
      - None; asserts db file is created in a newly created directory.
    """

    db_path = tmp_path / "nested" / "dns_cache.db"
    assert not db_path.parent.exists()

    plugin = SQLite3Cache(db_path=str(db_path))
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

    import foghorn.plugins.cache.backends.sqlite_ttl as mod

    db_path = tmp_path / "dns_cache.db"
    plugin = SQLite3Cache(db_path=str(db_path))

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
    plugin = SQLite3Cache(db_path=str(db_path))

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

    plugin = SQLite3Cache(db_path=str(tmp_path / "dns_cache.db"))
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
    assert isinstance(inst, SQLite3Cache)


def test_sqlite3_cache_db_path_and_namespace_validation(tmp_path) -> None:
    """Brief: __init__ falls back to path/default and validates namespace.

    Inputs:
      - tmp_path: pytest temporary path fixture.

    Outputs:
      - None; asserts path fallback and namespace ValueError.
    """

    # When only "path" is provided, db_path should resolve from it.
    db_path = tmp_path / "via_path.db"
    plugin = SQLite3Cache(path=str(db_path))
    assert plugin.db_path.endswith("via_path.db")

    # When neither db_path nor path is provided, plugin should use the default.
    plugin_default = SQLite3Cache()
    assert "dns_cache.db" in plugin_default.db_path

    # Invalid/empty namespace should raise ValueError.
    with pytest.raises(ValueError):
        SQLite3Cache(db_path=str(db_path), namespace="  ")


def test_sqlite3_cache_targets_cache_summary(monkeypatch, tmp_path) -> None:
    """Brief: get_http_snapshot summarizes BasePlugin._targets_cache via helper.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - tmp_path: pytest temporary path fixture.

    Outputs:
      - None; asserts a plugin_targets row is present for a fake plugin cache.
    """

    db_path = tmp_path / "dns_cache.db"
    plugin = SQLite3Cache(db_path=str(db_path))

    class DummyCache:
        def __init__(self) -> None:
            # Single live entry and one expired to exercise counting.
            now = time.time()
            self._lock = threading.RLock()
            self._store = {("k", 1): (now + 10.0, b"v"), ("k", 2): (now - 10.0, b"v2")}
            self.calls_total = 3
            self.cache_hits = 2
            self.cache_misses = 1

    class DummyPlugin:
        def __init__(self) -> None:
            self.name = "dummy"
            self._targets_cache = DummyCache()

    from foghorn.servers import udp_server as udp_mod

    monkeypatch.setattr(udp_mod.DNSUDPHandler, "plugins", [DummyPlugin()])

    snap = plugin.get_http_snapshot()
    caches = snap["caches"]
    assert any(row["label"] == "plugin_targets:dummy" for row in caches)


def test_sqlite3_cache_admin_descriptor_shape(tmp_path) -> None:
    """Brief: get_admin_ui_descriptor returns expected kind/layout structure.

    Inputs:
      - tmp_path: pytest temporary path fixture.

    Outputs:
      - None; asserts descriptor keys and section definitions.
    """

    db_path = tmp_path / "dns_cache.db"
    plugin = SQLite3Cache(db_path=str(db_path))
    desc = plugin.get_admin_ui_descriptor()

    assert desc["kind"] == "cache_sqlite"
    assert isinstance(desc.get("name"), str)
    layout = desc["layout"]
    assert isinstance(layout, dict)
    sections = layout.get("sections")
    assert isinstance(sections, list) and sections


def test_sqlite3_cache_purge_returns_int(tmp_path) -> None:
    """Brief: purge() delegates to backend and returns an int.

    Inputs:
      - tmp_path: pytest temporary path fixture.

    Outputs:
      - None; asserts return type is int.
    """

    db_path = tmp_path / "dns_cache.db"
    plugin = SQLite3Cache(db_path=str(db_path))
    assert isinstance(plugin.purge(), int)


def test_sqlite3_cache_purge_and_close_dont_raise(tmp_path, monkeypatch) -> None:
    """Brief: purge() returns int and close() tolerates backend errors.

    Inputs:
      - tmp_path: pytest temporary path fixture.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts purge returns an int and close/__del__ swallow backend errors.
    """

    db_path = tmp_path / "dns_cache.db"
    plugin = SQLite3Cache(db_path=str(db_path))

    # Ensure purge delegates to the backend and returns an int.
    assert isinstance(plugin.purge(), int)

    # Make backend.close() raise and ensure plugin.close()/__del__ ignore it.
    backend = plugin._cache

    def _boom() -> None:
        raise RuntimeError("close failed")

    monkeypatch.setattr(backend, "close", _boom)

    # Should not raise even though the underlying close() fails.
    plugin.close()
    plugin.__del__()


def test_sqlite3_cache_snapshot_includes_decorated_registry(
    monkeypatch, tmp_path
) -> None:
    """Brief: get_http_snapshot includes decorated cache registry entries.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - tmp_path: pytest temporary path fixture.

    Outputs:
      - None; asserts decorated rows reflect registry data and skip bad entries.
    """

    plugin = SQLite3Cache(db_path=str(tmp_path / "dns_cache.db"))

    # Fake two registry entries: one valid, one missing module/qualname.
    good_entry = {
        "module": "foghorn.example",
        "qualname": "fn",
        "ttl": 30,
        "backend": "ttlcache",
        "maxsize": 128,
        "size_current": 10,
        "calls_total": 5,
        "cache_hits": 3,
        "cache_misses": 2,
    }
    bad_entry = {"module": "", "qualname": ""}

    def _fake_get_registered_cached():
        return [good_entry, bad_entry]

    # Import inside function, so patch on the module path used there.
    import foghorn.utils.register_caches as reg_mod

    monkeypatch.setattr(reg_mod, "get_registered_cached", _fake_get_registered_cached)

    snapshot = plugin.get_http_snapshot()
    decorated = snapshot["decorated"]
    assert any(row["module"] == "foghorn.example" for row in decorated)
