"""Tests for MySQL TTL cache backend covering major branches.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import time
import types
from typing import Any, List, Optional, Tuple

import pytest

import foghorn.plugins.cache.backends.mysql_ttl as mysql_mod


class FakeCursor:
    def __init__(self, script: Optional[List[Tuple[str, tuple]]] = None) -> None:
        # script is not strictly used; we record executes, and fetchone returns from queue
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


def test_import_driver_prefers_mariadb_by_default(monkeypatch) -> None:
    # Provide fake mariadb and mysql.connector modules and ensure mariadb wins by default
    sys = __import__("sys")

    mariadb_mod = types.ModuleType("mariadb")
    monkeypatch.setitem(sys.modules, "mariadb", mariadb_mod)

    mysql_pkg = types.ModuleType("mysql")
    mysql_connector = types.ModuleType("mysql.connector")
    mysql_pkg.connector = mysql_connector
    monkeypatch.setitem(sys.modules, "mysql", mysql_pkg)
    monkeypatch.setitem(sys.modules, "mysql.connector", mysql_connector)

    driver, param_style = mysql_mod._import_mysql_driver()
    assert driver is mariadb_mod
    assert param_style == "qmark"


def test_import_driver_falls_back_to_mysql_connector(monkeypatch) -> None:
    # Provide only mysql.connector; default path should fall back to it
    sys = __import__("sys")
    sys.modules.pop("mariadb", None)

    # Ensure a real mariadb package in the environment can't be imported.
    import builtins

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[no-untyped-def]
        if name == "mariadb":
            raise ModuleNotFoundError(name)
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    mysql_pkg = types.ModuleType("mysql")
    mysql_connector = types.ModuleType("mysql.connector")
    mysql_pkg.connector = mysql_connector
    monkeypatch.setitem(sys.modules, "mysql", mysql_pkg)
    monkeypatch.setitem(sys.modules, "mysql.connector", mysql_connector)

    driver, param_style = mysql_mod._import_mysql_driver()
    assert driver is mysql_connector
    assert param_style == "format"


def test_import_driver_explicit_mysql_connector_wins_over_mariadb(monkeypatch) -> None:
    # When driver is explicitly set, respect it even if mariadb is available.
    sys = __import__("sys")

    mariadb_mod = types.ModuleType("mariadb")
    monkeypatch.setitem(sys.modules, "mariadb", mariadb_mod)

    mysql_pkg = types.ModuleType("mysql")
    mysql_connector = types.ModuleType("mysql.connector")
    mysql_pkg.connector = mysql_connector
    monkeypatch.setitem(sys.modules, "mysql", mysql_pkg)
    monkeypatch.setitem(sys.modules, "mysql.connector", mysql_connector)

    driver, param_style = mysql_mod._import_mysql_driver(
        driver="mysql-connector-python"
    )
    assert driver is mysql_connector
    assert param_style == "format"


def test_import_driver_explicit_mysql_alias_wins_over_mariadb(monkeypatch) -> None:
    # 'mysql' should be accepted as an alias for mysql-connector-python.
    sys = __import__("sys")

    mariadb_mod = types.ModuleType("mariadb")
    monkeypatch.setitem(sys.modules, "mariadb", mariadb_mod)

    mysql_pkg = types.ModuleType("mysql")
    mysql_connector = types.ModuleType("mysql.connector")
    mysql_pkg.connector = mysql_connector
    monkeypatch.setitem(sys.modules, "mysql", mysql_pkg)
    monkeypatch.setitem(sys.modules, "mysql.connector", mysql_connector)

    driver, param_style = mysql_mod._import_mysql_driver(driver="mysql")
    assert driver is mysql_connector
    assert param_style == "format"


def test_import_driver_raises_when_missing(monkeypatch) -> None:
    # Remove both modules and ensure RuntimeError
    sys = __import__("sys")
    sys.modules.pop("mysql.connector", None)
    sys.modules.pop("mysql", None)
    sys.modules.pop("mariadb", None)

    import builtins

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[no-untyped-def]
        if name in ("mysql.connector", "mariadb") or (
            name == "mysql" and fromlist == ("connector",)
        ):
            raise ModuleNotFoundError(name)
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(RuntimeError):
        mysql_mod._import_mysql_driver()


def _init_cache_with_fake_conn(
    monkeypatch,
    *,
    namespace: str = "ttl_cache",
    user: Optional[str] = "u",
    password: Optional[str] = "p",
    connect_kwargs: Optional[dict] = None,
):
    """Brief: Build a MySQLTTLCache bound to fake driver/connection objects.

    Inputs:
      - monkeypatch: pytest fixture used to patch driver import.
      - namespace: SQL table namespace to use.
      - user: Optional user name.
      - password: Optional password.
      - connect_kwargs: Additional connect kwargs.

    Outputs:
      - tuple[MySQLTTLCache, FakeConn, FakeDriver].
    """
    conn = FakeConn()
    driver = FakeDriver(conn)
    monkeypatch.setattr(
        mysql_mod, "_import_mysql_driver", lambda **_: (driver, "format")
    )
    cache = mysql_mod.MySQLTTLCache(
        host="h",
        port=3306,
        user=user,
        password=password,
        database="db",
        namespace=namespace,
        connect_kwargs=connect_kwargs or {"autocommit": True},
    )
    return cache, conn, driver


def _bind_single_cursor(conn: FakeConn, cursor: FakeCursor) -> None:
    """Brief: Force a fake connection to reuse one cursor for all operations.

    Inputs:
      - conn: Fake connection whose cursor method is replaced.
      - cursor: Cursor instance to return for each cursor() call.

    Outputs:
      - None.
    """

    conn.cursor = lambda: cursor  # type: ignore[method-assign]


def test_init_builds_kwargs_and_creates_schema(monkeypatch) -> None:
    cache, conn, driver = _init_cache_with_fake_conn(
        monkeypatch, connect_kwargs={"opt": 1}
    )

    # Validate connect kwargs
    assert driver.kwargs is not None
    assert driver.kwargs["host"] == "h"
    assert driver.kwargs["port"] == 3306
    assert driver.kwargs["database"] == "db"
    assert driver.kwargs["user"] == "u"
    assert driver.kwargs["password"] == "p"
    assert driver.kwargs["opt"] == 1

    # Validate that schema was created: look for CREATE TABLE and INDEX executes
    joined_sql = (
        "\n".join(sql for (sql, _p) in conn.last_cursor.executes)
        if conn.last_cursor
        else ""
    )
    assert "CREATE TABLE IF NOT EXISTS" in joined_sql
    assert "CREATE INDEX IF NOT EXISTS" in joined_sql


def test_get_no_row(monkeypatch) -> None:
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    # No rows queued -> fetchone returns None
    val = cache.get(("key", 1))
    assert val is None
    assert cache.cache_misses == 1
    assert cache.calls_total == 1


def test_get_expired_path(monkeypatch) -> None:
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    past = time.time() - 1.0
    cur = conn.last_cursor
    cur.queue_rows([(b"v", 0, past)])
    val = cache.get("k2")
    assert val is None
    assert cache.cache_misses >= 1


def test_get_with_meta_miss(monkeypatch) -> None:
    """Test get_with_meta misses when row not found."""
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    val, rem, ttl = cache.get_with_meta("m1")
    assert (val, rem, ttl) == (None, None, None)
    assert cache.cache_misses == 1


def test_set_and_purge(monkeypatch) -> None:
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    cache.set("akey", 10, b"avalue")
    # Verify INSERT with ON DUPLICATE KEY UPDATE executed
    assert any(
        "INSERT INTO" in sql and "ON DUPLICATE KEY UPDATE" in sql
        for (sql, _p) in conn.last_cursor.executes
    )

    # Purge path: create new cursor and set rowcount
    new_cur = FakeCursor()
    new_cur.rowcount = 3
    monkeypatch.setattr(conn, "cursor", lambda: new_cur)
    removed = cache.purge()
    assert removed == 3
    assert cache.evictions_total >= 3
    assert cache.evictions_ttl >= 3


def test_close(monkeypatch) -> None:
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    cache.close()
    assert conn.closed is True


def test_normalize_mysql_driver_name_variants() -> None:
    assert mysql_mod._normalize_mysql_driver_name(None) is None
    assert mysql_mod._normalize_mysql_driver_name(1) is None
    assert mysql_mod._normalize_mysql_driver_name(" auto ") is None
    assert mysql_mod._normalize_mysql_driver_name("maria_db") == "mariadb"
    assert (
        mysql_mod._normalize_mysql_driver_name("mysql.connector")
        == "mysql-connector-python"
    )
    assert (
        mysql_mod._normalize_mysql_driver_name(" connector ")
        == "mysql-connector-python"
    )

    with pytest.raises(ValueError):
        mysql_mod._normalize_mysql_driver_name("postgres")


def test_normalize_driver_fallbacks_variants() -> None:
    assert mysql_mod._normalize_driver_fallbacks(None) is None
    assert mysql_mod._normalize_driver_fallbacks("auto") is None
    assert mysql_mod._normalize_driver_fallbacks("none") == []
    assert mysql_mod._normalize_driver_fallbacks("mysql") == ["mysql-connector-python"]
    assert mysql_mod._normalize_driver_fallbacks(["mariadb", None, "mysql"]) == [
        "mariadb",
        "mysql-connector-python",
    ]
    assert mysql_mod._normalize_driver_fallbacks(123) is None


def test_driver_order_from_config_deduplicates_and_honors_none() -> None:
    assert mysql_mod._driver_order_from_config() == [
        "mariadb",
        "mysql-connector-python",
    ]
    assert mysql_mod._driver_order_from_config(
        driver="mariadb", driver_fallback="none"
    ) == ["mariadb"]
    assert mysql_mod._driver_order_from_config(
        driver="mysql",
        driver_fallback=["mysql", "mariadb", "mariadb"],
    ) == ["mysql-connector-python", "mariadb"]


def test_get_hit_returns_value_and_counts_hit(monkeypatch) -> None:
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    future = time.time() + 60
    cur = FakeCursor()
    cur.queue_rows([(b"payload", mysql_mod.RAW_BYTES_FLAG, future)])
    _bind_single_cursor(conn, cur)

    val = cache.get("key-hit")
    assert val == b"payload"
    assert cache.cache_hits == 1
    assert cache.cache_misses == 0


def test_get_invalid_expiry_deletes_and_misses(monkeypatch) -> None:
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    cur = FakeCursor()
    cur.queue_rows([(b"payload", mysql_mod.RAW_BYTES_FLAG, "bad-expiry")])
    _bind_single_cursor(conn, cur)

    val = cache.get("key-bad-expiry")
    assert val is None
    assert cache.cache_misses == 1
    assert any("DELETE FROM" in sql for sql, _ in cur.executes)


def test_get_decode_failure_deletes_and_misses(monkeypatch) -> None:
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    future = time.time() + 60
    cur = FakeCursor()
    cur.queue_rows([(b"payload", 999, future)])
    _bind_single_cursor(conn, cur)

    val = cache.get("key-bad-decode")
    assert val is None
    assert cache.cache_misses == 1
    assert any("DELETE FROM" in sql for sql, _ in cur.executes)


def test_get_with_meta_hit_and_expired_paths(monkeypatch) -> None:
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    now = time.time()
    cur = FakeCursor()
    cur.queue_rows(
        [
            (b"hit", mysql_mod.RAW_BYTES_FLAG, now + 5, 30),
            (b"stale", mysql_mod.RAW_BYTES_FLAG, now - 1, 30),
        ]
    )
    _bind_single_cursor(conn, cur)

    value_hit, remaining_hit, ttl_hit = cache.get_with_meta("meta-hit")
    value_stale, remaining_stale, ttl_stale = cache.get_with_meta("meta-stale")

    assert value_hit == b"hit"
    assert remaining_hit is not None and remaining_hit >= 0
    assert ttl_hit == 30
    assert value_stale == b"stale"
    assert remaining_stale is not None and remaining_stale < 0
    assert ttl_stale == 30
    assert cache.cache_hits == 1
    assert cache.cache_misses == 1


def test_get_with_meta_handles_bad_ttl_or_decode(monkeypatch) -> None:
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    cur = FakeCursor()
    cur.queue_rows(
        [
            (b"v1", mysql_mod.RAW_BYTES_FLAG, time.time() + 10, "bad-ttl"),
            (b"v2", 999, time.time() + 10, 5),
        ]
    )
    _bind_single_cursor(conn, cur)

    assert cache.get_with_meta("meta-bad-ttl") == (None, None, None)
    assert cache.get_with_meta("meta-bad-decode") == (None, None, None)
    assert cache.cache_misses >= 2


def test_set_clamps_negative_ttl(monkeypatch) -> None:
    cache, conn, _ = _init_cache_with_fake_conn(monkeypatch)
    cur = FakeCursor()
    _bind_single_cursor(conn, cur)

    cache.set("akey", -100, "value")
    params = cur.executes[-1][1]
    assert int(params[4]) == 0
