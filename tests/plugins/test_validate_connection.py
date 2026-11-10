"""Tests for validate_connection() pre-flight checks on backend plugins.

Brief: Verifies that BaseStatsStore and CachePlugin define the
validate_connection() interface, that every concrete backend implements it,
and that probes return False (never raise) when the backing service is
offline. Uses closed local ports and stubbed driver handles so no real
network services are required.

Inputs:
  - None (pytest fixtures only).

Outputs:
  - None (pytest assertions).
"""

import socket

import pytest


def _closed_port() -> int:
    """Brief: Get a TCP port that is very likely closed on loopback.

    Inputs:
      - None
    Outputs:
      - int: A port number just released by the test process.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# ---------------------------------------------------------------------------
# Base class interface
# ---------------------------------------------------------------------------


def test_cache_plugin_base_validate_connection_raises():
    """Brief: CachePlugin.validate_connection is an interface method.

    Inputs:
      - None
    Outputs:
      - None; asserts NotImplementedError for unimplemented subclasses.
    """

    from foghorn.plugins.cache.base import CachePlugin

    class _Unimplemented(CachePlugin):
        pass

    with pytest.raises(NotImplementedError):
        _Unimplemented().validate_connection()


def test_base_stats_store_validate_connection_raises():
    """Brief: BaseStatsStore.validate_connection is an interface method.

    Inputs:
      - None
    Outputs:
      - None; asserts NotImplementedError for unimplemented subclasses.
    """

    from foghorn.plugins.querylog.base import BaseStatsStore

    class _Unimplemented(BaseStatsStore):
        def __init__(self, **kwargs) -> None:
            return None

    with pytest.raises(NotImplementedError):
        _Unimplemented().validate_connection()


# ---------------------------------------------------------------------------
# Cache backends
# ---------------------------------------------------------------------------


def test_in_memory_ttl_cache_validate_connection_true():
    """Brief: The in-memory cache always reports reachable.

    Inputs:
      - None
    Outputs:
      - None; asserts validate_connection() is True.
    """

    from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache

    assert InMemoryTTLCache().validate_connection() is True


def test_null_cache_validate_connection_true():
    """Brief: The null cache always reports reachable.

    Inputs:
      - None
    Outputs:
      - None; asserts validate_connection() is True.
    """

    from foghorn.plugins.cache.none import NullCache

    assert NullCache().validate_connection() is True


def test_redis_cache_validate_connection_offline_is_false():
    """Brief: Redis PING against a closed port reports False, never raises.

    Inputs:
      - None
    Outputs:
      - None; asserts validate_connection() is False for an offline server.
    """

    from foghorn.plugins.cache.redis_cache import RedisCache

    cache = RedisCache(host="127.0.0.1", port=_closed_port(), socket_timeout=0.5)
    assert cache.validate_connection() is False


def test_memcached_cache_validate_connection_offline_is_false():
    """Brief: Memcached version probe against a closed port reports False.

    Inputs:
      - None
    Outputs:
      - None; asserts validate_connection() is False for an offline server.
    """

    from foghorn.plugins.cache.memcached_cache import MemcachedCache

    cache = MemcachedCache(host="127.0.0.1", port=_closed_port(), timeout=0.5)
    assert cache.validate_connection() is False


def test_sqlite3_cache_validate_connection_true(tmp_path):
    """Brief: A real SQLite3 cache reports reachable after construction.

    Inputs:
      - tmp_path fixture.
    Outputs:
      - None; asserts validate_connection() is True.
    """

    from foghorn.plugins.cache.sqlite_cache import SQLite3Cache

    cache = SQLite3Cache(db_path=str(tmp_path / "cache.db"))
    try:
        assert cache.validate_connection() is True
    finally:
        cache.close()


def test_mongodb_cache_validate_connection_stub():
    """Brief: MongoDB probe delegates to the driver ping command.

    Inputs:
      - None (stubbed pymongo client).
    Outputs:
      - None; asserts True on success and False on driver failure.
    """

    from foghorn.plugins.cache.mongodb_cache import MongoDBCache

    class _Admin:
        def __init__(self, fail):
            self._fail = fail

        def command(self, name):
            if self._fail:
                raise RuntimeError("offline")
            return {"ok": 1}

    class _Client:
        def __init__(self, fail):
            self.admin = _Admin(fail)

    ok_cache = MongoDBCache.__new__(MongoDBCache)
    ok_cache._client = _Client(fail=False)
    assert ok_cache.validate_connection() is True

    bad_cache = MongoDBCache.__new__(MongoDBCache)
    bad_cache._client = _Client(fail=True)
    assert bad_cache.validate_connection() is False


def test_postgres_ttl_backend_validate_connection_probe():
    """Brief: PostgresTTLCache probe runs SELECT 1 on the live connection.

    Inputs:
      - None (stubbed psycopg2-style connection).
    Outputs:
      - None; asserts True on success and False when the driver fails.
    """

    from foghorn.plugins.cache.backends.postgres_ttl import PostgresTTLCache

    class _Cursor:
        def __init__(self, fail):
            self._fail = fail

        def execute(self, sql):
            assert sql == "SELECT 1"
            if self._fail:
                raise RuntimeError("offline")

        def fetchone(self):
            return (1,)

    class _Conn:
        def __init__(self, fail):
            self._fail = fail

        def cursor(self):
            return _Cursor(self._fail)

    ok_cache = PostgresTTLCache.__new__(PostgresTTLCache)
    ok_cache._conn = _Conn(fail=False)
    assert ok_cache.validate_connection() is True

    bad_cache = PostgresTTLCache.__new__(PostgresTTLCache)
    bad_cache._conn = _Conn(fail=True)
    assert bad_cache.validate_connection() is False


def test_mysql_ttl_backend_validate_connection_probe():
    """Brief: MySQLTTLCache probe runs SELECT 1 under the backend lock.

    Inputs:
      - None (stubbed driver connection).
    Outputs:
      - None; asserts True on success and False when the driver fails.
    """

    import threading

    from foghorn.plugins.cache.backends.mysql_ttl import MySQLTTLCache

    class _Cursor:
        def __init__(self, fail):
            self._fail = fail

        def execute(self, sql):
            assert sql == "SELECT 1"
            if self._fail:
                raise RuntimeError("offline")

        def fetchone(self):
            return (1,)

    class _Conn:
        def __init__(self, fail):
            self._fail = fail

        def cursor(self):
            return _Cursor(self._fail)

    ok_cache = MySQLTTLCache.__new__(MySQLTTLCache)
    ok_cache._lock = threading.Lock()
    ok_cache._conn = _Conn(fail=False)
    assert ok_cache.validate_connection() is True

    bad_cache = MySQLTTLCache.__new__(MySQLTTLCache)
    bad_cache._lock = threading.Lock()
    bad_cache._conn = _Conn(fail=True)
    assert bad_cache.validate_connection() is False


def test_sqlite_ttl_backend_validate_connection_probe():
    """Brief: SQLite3TTLCache probe runs SELECT 1 under the backend lock.

    Inputs:
      - None (stubbed sqlite3-style connection).
    Outputs:
      - None; asserts True on success and False when the driver fails.
    """

    import sqlite3
    import threading

    from foghorn.plugins.cache.backends.sqlite_ttl import SQLite3TTLCache

    ok_cache = SQLite3TTLCache.__new__(SQLite3TTLCache)
    ok_cache._lock = threading.Lock()
    ok_cache._conn = sqlite3.connect(":memory:")
    assert ok_cache.validate_connection() is True

    class _BrokenConn:
        def cursor(self):
            raise RuntimeError("offline")

    bad_cache = SQLite3TTLCache.__new__(SQLite3TTLCache)
    bad_cache._lock = threading.Lock()
    bad_cache._conn = _BrokenConn()
    assert bad_cache.validate_connection() is False


def test_delegating_cache_plugins_use_backend_probe(monkeypatch):
    """Brief: Postgres/MySQL/SQLite cache plugins delegate to their backend.

    Inputs:
      - monkeypatch fixture.
    Outputs:
      - None; asserts validate_connection mirrors the backend probe result.
    """

    from foghorn.plugins.cache.mysql_mariadb_cache import MySqlCache
    from foghorn.plugins.cache.postgres_cache import PostgresCache
    from foghorn.plugins.cache.sqlite_cache import SQLite3Cache

    for cls in (PostgresCache, MySqlCache):
        obj = cls.__new__(cls)
        seen = {}

        class _Backend:
            def validate_connection(self, _seen=seen):
                _seen["called"] = True
                return False

        obj._cache = _Backend()
        assert obj.validate_connection() is False
        assert seen.get("called") is True

    sqlite_obj = SQLite3Cache.__new__(SQLite3Cache)

    class _SqliteBackend:
        def validate_connection(self):
            return True

    sqlite_obj._cache = _SqliteBackend()
    assert sqlite_obj.validate_connection() is True


# ---------------------------------------------------------------------------
# Query-log backends
# ---------------------------------------------------------------------------


def test_sqlite_stats_store_validate_connection_true(tmp_path):
    """Brief: A real SQLite stats store reports reachable.

    Inputs:
      - tmp_path fixture.
    Outputs:
      - None; asserts validate_connection() is True.
    """

    from foghorn.plugins.querylog.sqlite import SqliteStatsStore

    store = SqliteStatsStore(db_path=str(tmp_path / "stats.db"))
    try:
        assert store.validate_connection() is True
    finally:
        store.close()


def test_postgres_stats_store_offline_raises_at_construction():
    """Brief: An offline PostgreSQL store fails eagerly at construction.

    Inputs:
      - None (closed local port).
    Outputs:
      - None; asserts the driver raises so startup aborts pre-flight.
    """

    import psycopg2

    from foghorn.plugins.querylog.postgresql import PostgresStatsStore

    with pytest.raises(psycopg2.Error):
        PostgresStatsStore(host="127.0.0.1", port=_closed_port(), database="foghorn")


def test_json_logging_validate_connection_delegates_to_health(monkeypatch, tmp_path):
    """Brief: File-backed logging delegates to its health_check probe.

    Inputs:
      - monkeypatch/tmp_path fixtures.
    Outputs:
      - None; asserts validate_connection mirrors health_check.
    """

    from foghorn.plugins.querylog.json_logging import JsonLogging

    store = JsonLogging(file_path=str(tmp_path / "query.log"))
    try:
        assert store.validate_connection() is True
        monkeypatch.setattr(JsonLogging, "health_check", lambda self: False)
        assert store.validate_connection() is False
    finally:
        store.close()


def test_multi_stats_store_validate_connection_primary(caplog):
    """Brief: MultiStatsStore treats only the primary as fatal.

    Inputs:
      - caplog fixture.
    Outputs:
      - None; asserts primary failure is False, secondary failure is True with
        a WARNING log naming the secondary backend.
    """

    import logging

    from foghorn.plugins.querylog import MultiStatsStore

    class _Backend:
        def __init__(self, ok, label="backend"):
            self._ok = ok
            self.label = label

        def validate_connection(self):
            return self._ok

        def health_check(self):
            return self._ok

    primary_ok = _Backend(ok=True, label="primary")
    secondary_bad = _Backend(ok=False, label="secondary")
    store = MultiStatsStore([primary_ok, secondary_bad])
    with caplog.at_level(logging.WARNING, logger="foghorn.plugins.querylog"):
        assert store.validate_connection() is True
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("secondary" in msg and "_Backend" in msg for msg in warnings)

    store_bad_primary = MultiStatsStore([_Backend(ok=False), _Backend(ok=True)])
    assert store_bad_primary.validate_connection() is False


def test_multi_stats_store_validate_connection_secondary_exception_is_warning(caplog):
    """Brief: A raising secondary validate_connection is a WARNING, not fatal.

    Inputs:
      - caplog fixture.
    Outputs:
      - None; asserts True plus a WARNING that names the secondary backend.
    """

    import logging

    from foghorn.plugins.querylog import MultiStatsStore

    class _Ok:
        def validate_connection(self):
            return True

    class _Boom:
        def validate_connection(self):
            raise RuntimeError("offline secondary")

    store = MultiStatsStore([_Ok(), _Boom()])
    with caplog.at_level(logging.WARNING, logger="foghorn.plugins.querylog"):
        assert store.validate_connection() is True
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "secondary" in msg and "_Boom" in msg and "offline secondary" in msg
        for msg in warnings
    )
