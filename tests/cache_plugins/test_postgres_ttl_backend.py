"""Tests for PostgreSQL TTL cache backend covering major branches.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import hashlib
import types
from typing import Any, List, Optional, Tuple

import pytest

import foghorn.plugins.cache.backends.postgres_ttl as postgres_mod


class FakeCursor:
    def __init__(self) -> None:
        self.executes: List[Tuple[str, tuple]] = []
        self._rows: List[tuple] = []
        self._idx = 0
        self.rowcount = 0

    def queue_rows(self, rows: List[tuple]) -> None:
        self._rows.extend(rows)

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.executes.append((sql, params))

    def fetchone(self) -> Optional[tuple]:
        if self._idx < len(self._rows):
            r = self._rows[self._idx]
            self._idx += 1
            return r
        return None

    def fetchall(self) -> List[tuple]:
        r = self._rows[self._idx :]
        self._idx = len(self._rows)
        return r


class FakeConn:
    def __init__(self) -> None:
        self.cursors: List[FakeCursor] = []
        self.closed = False
        self.last_cursor: Optional[FakeCursor] = None

    def cursor(self) -> FakeCursor:
        c = FakeCursor()
        self.cursors.append(c)
        self.last_cursor = c
        return c

    def commit(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class FakeDriver:
    def __init__(self, conn: FakeConn) -> None:
        self.conn = conn
        self.kwargs: Optional[dict] = None

    def connect(self, **kwargs: Any) -> FakeConn:
        self.kwargs = kwargs
        return self.conn


def test_import_driver_prefers_psycopg(monkeypatch) -> None:
    """Test that psycopg (v3) is preferred over psycopg2."""
    psycopg_mod = types.ModuleType("psycopg")
    monkeypatch.setitem(__import__("sys").modules, "psycopg", psycopg_mod)

    driver = postgres_mod._import_postgres_driver()
    assert driver is psycopg_mod


def test_import_driver_falls_back_to_psycopg2(monkeypatch) -> None:
    """Test fallback to psycopg2 when psycopg unavailable."""
    import builtins

    real_import = builtins.__import__
    psycopg2_mod = types.ModuleType("psycopg2")

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[no-untyped-def]
        if name == "psycopg":
            raise ModuleNotFoundError(name)
        if name == "psycopg2":
            return psycopg2_mod
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    driver = postgres_mod._import_postgres_driver()
    assert driver is psycopg2_mod


def test_import_driver_raises_when_missing(monkeypatch) -> None:
    """Test RuntimeError when no driver available."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[no-untyped-def]
        if name in ("psycopg", "psycopg2"):
            raise ModuleNotFoundError(name)
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(RuntimeError, match="PostgreSQL driver"):
        postgres_mod._import_postgres_driver()


def _init_cache_with_fake_conn(
    monkeypatch,
    *,
    namespace: str = "cache",
    user: Optional[str] = "u",
    password: Optional[str] = "p",
    connect_kwargs: Optional[dict] = None,
):
    """Helper to initialize cache with fake connection."""
    conn = FakeConn()
    driver = FakeDriver(conn)
    monkeypatch.setattr(postgres_mod, "_import_postgres_driver", lambda: driver)
    cache = postgres_mod.PostgresTTLCache(
        namespace=namespace,
        host="h",
        port=5432,
        user=user,
        password=password,
        database="db",
        connect_kwargs=(
            connect_kwargs if connect_kwargs is not None else {"sslmode": "require"}
        ),
    )
    return cache, conn, driver


def test_init_builds_kwargs_and_creates_schema(monkeypatch) -> None:
    """Test connection kwargs building and schema creation."""
    cache, conn, driver = _init_cache_with_fake_conn(monkeypatch)

    assert driver.kwargs is not None
    assert driver.kwargs["host"] == "h"
    assert driver.kwargs["port"] == 5432
    assert driver.kwargs["database"] == "db"
    assert driver.kwargs["user"] == "u"
    assert driver.kwargs["password"] == "p"
    assert driver.kwargs["sslmode"] == "require"

    # Verify schema was created
    joined_sql = "\n".join(sql for (sql, _p) in conn.last_cursor.executes)
    assert "CREATE TABLE IF NOT EXISTS" in joined_sql
    assert "CREATE INDEX IF NOT EXISTS" in joined_sql


def test_init_rejects_invalid_namespace_before_driver_import(monkeypatch) -> None:
    """Test invalid namespace fails fast before driver import."""
    called = False

    def fake_driver_import():
        nonlocal called
        called = True
        return FakeDriver(FakeConn())

    monkeypatch.setattr(postgres_mod, "_import_postgres_driver", fake_driver_import)
    with pytest.raises(ValueError, match="namespace must match"):
        postgres_mod.PostgresTTLCache(namespace="bad-name")
    assert called is False


def test_init_omits_optional_kwargs_when_none(monkeypatch) -> None:
    """Test connect kwargs omit optional fields when values are not set."""
    _cache, _conn, driver = _init_cache_with_fake_conn(
        monkeypatch,
        user=None,
        password=None,
        connect_kwargs={},
    )

    assert driver.kwargs is not None
    assert "user" not in driver.kwargs
    assert "password" not in driver.kwargs
    assert "sslmode" not in driver.kwargs


def test_non_bytes_keys_use_safe_serializer(monkeypatch) -> None:
    """Test digest/blob helper paths serialize non-bytes keys."""
    calls: List[Any] = []

    def fake_safe_serialize(value: Any) -> bytes:
        calls.append(value)
        return b"serialized-key"

    key = {"zone": "example.org", "rrtype": "A"}
    monkeypatch.setattr(postgres_mod, "safe_serialize", fake_safe_serialize)

    digest = postgres_mod._stable_digest_for_key(key)
    assert digest == hashlib.sha256(b"serialized-key").digest()
    assert postgres_mod._encode_key_blob(key) == b"serialized-key"
    assert calls == [key, key]


def test_get_with_meta_miss(monkeypatch) -> None:
    """Test get_with_meta() returns (None, None, None) on miss."""
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    result = cache.get_with_meta(b"m1")
    assert result == (None, None, None)


def test_get_returns_none_on_miss(monkeypatch) -> None:
    """Test get() returns None when no row exists."""
    cache, _conn, _ = _init_cache_with_fake_conn(monkeypatch)
    assert cache.get(b"missing") is None


def test_get_returns_value_when_not_expired(monkeypatch) -> None:
    """Test get() returns decoded value when expiry is in the future."""
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    cur = FakeCursor()
    cur.queue_rows([(b"value", postgres_mod.RAW_BYTES_FLAG, 120.0)])
    monkeypatch.setattr(conn, "cursor", lambda: cur)
    monkeypatch.setattr(postgres_mod.time, "time", lambda: 100.0)

    assert cache.get(b"k1") == b"value"
    assert all("DELETE FROM" not in sql for (sql, _params) in cur.executes)


def test_get_treats_invalid_expiry_as_expired(monkeypatch) -> None:
    """Test get() expires rows when expiry cannot be parsed."""
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    cur = FakeCursor()
    cur.queue_rows([(b"value", postgres_mod.RAW_BYTES_FLAG, object())])
    monkeypatch.setattr(conn, "cursor", lambda: cur)
    monkeypatch.setattr(postgres_mod.time, "time", lambda: 100.0)

    assert cache.get(b"k2") is None
    assert any("DELETE FROM" in sql for (sql, _params) in cur.executes)


def test_get_with_meta_returns_value_and_metadata(monkeypatch) -> None:
    """Test get_with_meta() returns value, remaining TTL, and original TTL."""
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    cur = FakeCursor()
    cur.queue_rows([(b"value", postgres_mod.RAW_BYTES_FLAG, 30, 130.0)])
    monkeypatch.setattr(conn, "cursor", lambda: cur)
    monkeypatch.setattr(postgres_mod.time, "time", lambda: 100.0)

    value, remaining, ttl = cache.get_with_meta(b"m2")
    assert value == b"value"
    assert remaining == 30.0
    assert ttl == 30


def test_get_with_meta_handles_invalid_ttl_and_expiry(monkeypatch) -> None:
    """Test get_with_meta() coercion fallback for malformed ttl/expiry fields."""
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    cur = FakeCursor()
    cur.queue_rows([(b"value", postgres_mod.RAW_BYTES_FLAG, "bad-ttl", object())])
    monkeypatch.setattr(conn, "cursor", lambda: cur)
    monkeypatch.setattr(postgres_mod.time, "time", lambda: 100.0)

    assert cache.get_with_meta(b"m3") == (None, None, None)
    assert any("DELETE FROM" in sql for (sql, _params) in cur.executes)


def test_set_and_purge(monkeypatch) -> None:
    """Test set() and purge() operations."""
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)

    # Test set
    cache.set(b"key", 300, b"value")
    assert any(
        "INSERT INTO" in sql and "ON CONFLICT" in sql
        for (sql, _p) in conn.last_cursor.executes
    )

    # Test purge
    new_cur = FakeCursor()
    new_cur.rowcount = 5
    monkeypatch.setattr(conn, "cursor", lambda: new_cur)
    removed = cache.purge()
    assert removed == 5


def test_set_clamps_negative_ttl_to_zero(monkeypatch) -> None:
    """Test set() clamps negative TTL values to zero."""
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    monkeypatch.setattr(postgres_mod.time, "time", lambda: 100.0)
    cache.set(b"neg", -30, b"value")

    assert conn.last_cursor is not None
    _sql, params = conn.last_cursor.executes[-1]
    assert params[4] == 0
    assert params[5] == 100.0


def test_encode_decode_bytes(monkeypatch) -> None:
    """Test encode/decode for raw bytes."""
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    raw = b"data"
    encoded, flag = cache._encode(raw)
    assert encoded == raw
    assert flag == 0
    assert cache._decode(encoded, flag) == raw


def test_encode_decode_safe_serialized(monkeypatch) -> None:
    """Test encode/decode for safely serialized objects."""
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    obj = {"x": 1, "y": 2}
    encoded, flag = cache._encode(obj)
    assert flag == 2
    assert cache._decode(encoded, flag) == obj


def test_decode_unknown_flag_raises() -> None:
    """Test _decode() raises for unsupported encoding flags."""
    with pytest.raises(ValueError, match="Unsupported cache payload encoding flag"):
        postgres_mod.PostgresTTLCache._decode(b"data", 99)


def test_close(monkeypatch) -> None:
    """Test close() closes connection."""
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    cache.close()
    assert conn.closed is True


def test_close_with_exception(monkeypatch) -> None:
    """Test close() handles exceptions gracefully."""
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)

    # Make close raise
    def raise_error():
        raise RuntimeError("Close failed")

    monkeypatch.setattr(conn, "close", raise_error)
    # Should not raise
    cache.close()


def test_close_when_connection_attribute_missing(monkeypatch) -> None:
    """Test close() no-ops when _conn attribute is absent."""
    cache, _conn, _ = _init_cache_with_fake_conn(monkeypatch)
    del cache._conn
    cache.close()
