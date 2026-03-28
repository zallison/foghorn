"""Tests for PostgreSQL TTL cache backend covering major branches.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

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


def _init_cache_with_fake_conn(monkeypatch, *, namespace: str = "cache"):
    """Helper to initialize cache with fake connection."""
    conn = FakeConn()
    driver = FakeDriver(conn)
    monkeypatch.setattr(postgres_mod, "_import_postgres_driver", lambda: driver)
    cache = postgres_mod.PostgresTTLCache(
        namespace=namespace,
        host="h",
        port=5432,
        user="u",
        password="p",
        database="db",
        connect_kwargs={"sslmode": "require"},
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


def test_get_with_meta_miss(monkeypatch) -> None:
    """Test get_with_meta() returns (None, None, None) on miss."""
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    result = cache.get_with_meta(b"m1")
    assert result == (None, None, None)


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
