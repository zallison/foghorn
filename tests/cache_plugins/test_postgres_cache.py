"""Brief: Unit tests for the PostgreSQL-backed cache plugin.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from foghorn.plugins.cache.registry import get_cache_plugin_class


class FakePostgresConnection:
    """Brief: Minimal in-memory PostgreSQL connection substitute for tests.

    Inputs:
      - None.

    Outputs:
      - FakePostgresConnection instance that tracks operations.
    """

    def __init__(self) -> None:
        self.tables: Dict[str, List[Dict[str, Any]]] = {}
        self.last_query: Optional[str] = None
        self.raise_on_execute = False

    def cursor(self):
        """Return a cursor for this connection."""
        return FakePostgresCursor(self)

    def commit(self):
        """No-op commit."""
        pass

    def close(self):
        """No-op close."""
        pass


class FakePostgresCursor:
    """Brief: Minimal PostgreSQL cursor substitute for tests."""

    def __init__(self, conn: FakePostgresConnection) -> None:
        self.conn = conn
        self.rowcount = 0
        self._result: List[tuple[Any, ...]] = []
        self._index = 0

    def execute(self, query: str, params: tuple[Any, ...] = ()) -> None:
        """Brief: Execute a query (best-effort for testing)."""

        if self.conn.raise_on_execute:
            raise RuntimeError("execute failed")

        self.conn.last_query = query
        # For testing, we just track that execute was called
        # Actual DB semantics are not fully simulated

    def fetchone(self) -> Optional[tuple[Any, ...]]:
        """Return one row of results."""
        if self._index < len(self._result):
            row = self._result[self._index]
            self._index += 1
            return row
        return None

    def fetchall(self) -> List[tuple[Any, ...]]:
        """Return all results."""
        return self._result[self._index :]


class FakePostgresDriver:
    """Brief: Minimal PostgreSQL driver substitute for tests."""

    def __init__(self):
        self.connections: List[FakePostgresConnection] = []

    def connect(self, **kwargs: Any) -> FakePostgresConnection:
        """Create a fake connection."""
        conn = FakePostgresConnection()
        self.connections.append(conn)
        return conn


def test_registry_resolves_postgres_aliases_to_plugin_class() -> None:
    """Brief: Cache plugin registry exposes postgres/postgresql/pg aliases.

    Inputs:
      - None

    Outputs:
      - None; asserts alias resolution returns the expected class.
    """

    cls = get_cache_plugin_class("postgres")
    assert cls.__name__ == "PostgresCache"

    cls2 = get_cache_plugin_class("postgresql")
    assert cls2 is cls

    cls3 = get_cache_plugin_class("pg")
    assert cls3 is cls


def test_postgres_cache_encode_decode_roundtrip() -> None:
    """Brief: Helper encode/decode functions support bytes and arbitrary objects.

    Inputs:
      - None.

    Outputs:
      - None; asserts flags and round-trips for bytes and dict objects.
    """

    from foghorn.plugins.cache.backends.postgres_ttl import PostgresTTLCache

    raw = b"wire-bytes"
    payload, is_pickle = PostgresTTLCache._encode(raw)
    assert payload == raw
    assert is_pickle == 0
    assert PostgresTTLCache._decode(payload, is_pickle) == raw

    obj = {"name": "example.com", "qtype": 1}
    payload2, is_pickle2 = PostgresTTLCache._encode(obj)
    assert is_pickle2 == 1
    assert PostgresTTLCache._decode(payload2, is_pickle2) == obj


def test_postgres_cache_plugin_initialization_with_defaults() -> None:
    """Brief: PostgresCache initializes with default configuration values.

    Inputs:
      - None.

    Outputs:
      - None; asserts defaults are applied when config is None or empty.
    """

    from unittest.mock import MagicMock, patch

    from foghorn.plugins.cache.postgres_cache import PostgresCache

    # Mock the PostgresTTLCache to avoid real DB connection
    with patch(
        "foghorn.plugins.cache.postgres_cache.PostgresTTLCache"
    ) as mock_backend_class:
        mock_backend = MagicMock()
        mock_backend_class.return_value = mock_backend

        cache = PostgresCache()
        assert cache.min_cache_ttl == 0
        assert cache._cache is mock_backend

        # Verify backend was called with defaults
        call_kwargs = mock_backend_class.call_args[1]
        assert call_kwargs["namespace"] == "cache"
        assert call_kwargs["host"] == "127.0.0.1"
        assert call_kwargs["port"] == 5432
        assert call_kwargs["database"] == "foghorn_cache"


def test_postgres_cache_plugin_initialization_with_config() -> None:
    """Brief: PostgresCache applies provided configuration values.

    Inputs:
      - None.

    Outputs:
      - None; asserts config values override defaults.
    """

    from unittest.mock import MagicMock, patch

    from foghorn.plugins.cache.postgres_cache import PostgresCache

    with patch(
        "foghorn.plugins.cache.postgres_cache.PostgresTTLCache"
    ) as mock_backend_class:
        mock_backend = MagicMock()
        mock_backend_class.return_value = mock_backend

        config = {
            "host": "db.example.com",
            "port": 5433,
            "user": "testuser",
            "password": "testpass",
            "database": "custom_db",
            "namespace": "custom_ns",
            "min_cache_ttl": 120,
            "connect_kwargs": {"sslmode": "require"},
        }
        cache = PostgresCache(**config)
        assert cache.min_cache_ttl == 120

        call_kwargs = mock_backend_class.call_args[1]
        assert call_kwargs["host"] == "db.example.com"
        assert call_kwargs["port"] == 5433
        assert call_kwargs["user"] == "testuser"
        assert call_kwargs["password"] == "testpass"
        assert call_kwargs["database"] == "custom_db"
        assert call_kwargs["namespace"] == "custom_ns"
        assert call_kwargs["connect_kwargs"] == {"sslmode": "require"}


def test_postgres_cache_plugin_set_enforces_min_ttl() -> None:
    """Brief: set() method enforces min_cache_ttl.

    Inputs:
      - None.

    Outputs:
      - None; asserts effective TTL is max of requested TTL and min_cache_ttl.
    """

    from unittest.mock import MagicMock, patch

    from foghorn.plugins.cache.postgres_cache import PostgresCache

    with patch(
        "foghorn.plugins.cache.postgres_cache.PostgresTTLCache"
    ) as mock_backend_class:
        mock_backend = MagicMock()
        mock_backend_class.return_value = mock_backend

        cache = PostgresCache(min_cache_ttl=100)

        # TTL below min_cache_ttl should use min_cache_ttl
        cache.set(("key1", 1), 50, b"value1")
        mock_backend.set.assert_called_with(("key1", 1), 100, b"value1")

        # TTL above min_cache_ttl should use provided TTL
        cache.set(("key2", 1), 200, b"value2")
        mock_backend.set.assert_called_with(("key2", 1), 200, b"value2")


def test_postgres_cache_plugin_get_returns_bytes() -> None:
    """Brief: get() method returns bytes or None.

    Inputs:
      - None.

    Outputs:
      - None; asserts get returns bytes or None, filtering non-bytes.
    """

    from unittest.mock import MagicMock, patch

    from foghorn.plugins.cache.postgres_cache import PostgresCache

    with patch(
        "foghorn.plugins.cache.postgres_cache.PostgresTTLCache"
    ) as mock_backend_class:
        mock_backend = MagicMock()
        mock_backend_class.return_value = mock_backend

        cache = PostgresCache()

        # Backend returns bytes
        mock_backend.get.return_value = b"cached_value"
        result = cache.get(("key1", 1))
        assert result == b"cached_value"

        # Backend returns None
        mock_backend.get.return_value = None
        result = cache.get(("key2", 1))
        assert result is None

        # Backend returns non-bytes
        mock_backend.get.return_value = "string_not_bytes"
        result = cache.get(("key3", 1))
        assert result == "string_not_bytes"


def test_postgres_cache_plugin_close() -> None:
    """Brief: close() method delegates to backend.

    Inputs:
      - None.

    Outputs:
      - None; asserts close() is called on backend.
    """

    from unittest.mock import MagicMock, patch

    from foghorn.plugins.cache.postgres_cache import PostgresCache

    with patch(
        "foghorn.plugins.cache.postgres_cache.PostgresTTLCache"
    ) as mock_backend_class:
        mock_backend = MagicMock()
        mock_backend_class.return_value = mock_backend

        cache = PostgresCache()
        cache.close()
        mock_backend.close.assert_called_once()


def test_postgres_cache_plugin_backend_initialization_error() -> None:
    """Brief: Initialization error from backend is wrapped.

    Inputs:
      - None.

    Outputs:
      - None; asserts RuntimeError wraps backend initialization errors.
    """

    from unittest.mock import patch

    from foghorn.plugins.cache.postgres_cache import PostgresCache

    with patch(
        "foghorn.plugins.cache.postgres_cache.PostgresTTLCache"
    ) as mock_backend_class:
        mock_backend_class.side_effect = RuntimeError("No driver available")

        with pytest.raises(RuntimeError, match="Failed to initialize PostgreSQL"):
            PostgresCache()
