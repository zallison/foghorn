"""Brief: Unit tests for the MySQL/MariaDB-backed cache plugin.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from foghorn.plugins.cache.registry import get_cache_plugin_class
from foghorn.plugins.cache.safe_codec import SAFE_SERIALIZED_FLAG


class FakeMySQLConnection:
    """Brief: Minimal in-memory MySQL connection substitute for tests.

    Inputs:
      - None.

    Outputs:
      - FakeMySQLConnection instance that tracks operations.
    """

    def __init__(self) -> None:
        self.tables: Dict[str, List[Dict[str, Any]]] = {}
        self.last_query: Optional[str] = None
        self.raise_on_execute = False

    def cursor(self):
        """Return a cursor for this connection."""
        return FakeMySQLCursor(self)

    def commit(self):
        """No-op commit."""
        pass

    def close(self):
        """No-op close."""
        pass


class FakeMySQLCursor:
    """Brief: Minimal MySQL cursor substitute for tests."""

    def __init__(self, conn: FakeMySQLConnection) -> None:
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


class FakeMySQLDriver:
    """Brief: Minimal MySQL driver substitute for tests."""

    def __init__(self):
        self.connections: List[FakeMySQLConnection] = []

    def connect(self, **kwargs: Any) -> FakeMySQLConnection:
        """Create a fake connection."""
        conn = FakeMySQLConnection()
        self.connections.append(conn)
        return conn


def test_registry_resolves_mysql_aliases_to_plugin_class() -> None:
    """Brief: Cache plugin registry exposes mysql/mariadb aliases.

    Inputs:
      - None

    Outputs:
      - None; asserts alias resolution returns the expected class.
    """

    cls = get_cache_plugin_class("mysql")
    assert cls.__name__ == "MySqlCache"

    cls2 = get_cache_plugin_class("mariadb")
    assert cls2 is cls

    cls3 = get_cache_plugin_class("mysql_cache")
    assert cls3 is cls


def test_mysql_cache_namespace_validation(monkeypatch) -> None:
    """Brief: MySQLTTLCache rejects invalid namespace names.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts ValueError on invalid namespace.
    """

    from foghorn.plugins.cache.backends.mysql_ttl import MySQLTTLCache

    # Invalid namespace should fail before driver check
    with pytest.raises(ValueError, match="must match"):
        # This should fail on namespace validation, not driver import
        MySQLTTLCache(namespace="123invalid")


def test_mysql_cache_encode_decode_roundtrip() -> None:
    """Brief: Helper encode/decode functions support bytes and arbitrary objects.

    Inputs:
      - None.

    Outputs:
      - None; asserts flags and round-trips for bytes and dict objects.
    """

    from foghorn.plugins.cache.backends.mysql_ttl import MySQLTTLCache

    raw = b"wire-bytes"
    payload, is_pickle = MySQLTTLCache._encode(raw)
    assert payload == raw
    assert is_pickle == 0
    assert MySQLTTLCache._decode(payload, is_pickle) == raw

    obj = {"name": "example.com", "qtype": 1}
    payload2, is_pickle2 = MySQLTTLCache._encode(obj)
    assert is_pickle2 == SAFE_SERIALIZED_FLAG
    assert MySQLTTLCache._decode(payload2, is_pickle2) == obj


def test_mysql_cache_plugin_initialization_defaults() -> None:
    """Brief: MySqlCache initializes with default configuration values.

    Inputs:
      - None.

    Outputs:
      - None; asserts defaults are applied.
    """

    from unittest.mock import MagicMock, patch

    from foghorn.plugins.cache.mysql_mariadb_cache import MySqlCache

    with patch(
        "foghorn.plugins.cache.mysql_mariadb_cache.MySQLTTLCache"
    ) as mock_backend:
        mock_instance = MagicMock()
        mock_backend.return_value = mock_instance

        cache = MySqlCache()
        assert cache.min_cache_ttl == 0

        call_kwargs = mock_backend.call_args[1]
        assert call_kwargs["host"] == "127.0.0.1"
        assert call_kwargs["port"] == 3306
        assert call_kwargs["database"] == "foghorn_cache"
        assert call_kwargs["namespace"] == "dns_cache"


def test_mysql_cache_plugin_initialization_custom_config() -> None:
    """Brief: MySqlCache applies custom configuration values.

    Inputs:
      - None.

    Outputs:
      - None; asserts config values override defaults.
    """

    from unittest.mock import MagicMock, patch

    from foghorn.plugins.cache.mysql_mariadb_cache import MySqlCache

    with patch(
        "foghorn.plugins.cache.mysql_mariadb_cache.MySQLTTLCache"
    ) as mock_backend:
        mock_instance = MagicMock()
        mock_backend.return_value = mock_instance

        config = {
            "host": "db.local",
            "port": "3307",
            "user": "testuser",
            "password": "testpass",
            "database": "custom_db",
            "namespace": "custom_ns",
            "min_cache_ttl": 120,
            "connect_kwargs": {"autocommit": True},
        }
        cache = MySqlCache(**config)
        assert cache.min_cache_ttl == 120

        call_kwargs = mock_backend.call_args[1]
        assert call_kwargs["host"] == "db.local"
        assert call_kwargs["port"] == 3307
        assert call_kwargs["user"] == "testuser"
        assert call_kwargs["password"] == "testpass"
        assert call_kwargs["database"] == "custom_db"
        assert call_kwargs["namespace"] == "custom_ns"
        assert call_kwargs["connect_kwargs"] == {"autocommit": True}


def test_mysql_cache_plugin_fallback_namespace_to_table() -> None:
    """Brief: namespace falls back to table config key.

    Inputs:
      - None.

    Outputs:
      - None; asserts table key used when namespace missing.
    """

    from unittest.mock import MagicMock, patch

    from foghorn.plugins.cache.mysql_mariadb_cache import MySqlCache

    with patch(
        "foghorn.plugins.cache.mysql_mariadb_cache.MySQLTTLCache"
    ) as mock_backend:
        mock_instance = MagicMock()
        mock_backend.return_value = mock_instance

        config = {"table": "legacy_table_name"}
        MySqlCache(**config)

        call_kwargs = mock_backend.call_args[1]
        assert call_kwargs["namespace"] == "legacy_table_name"


def test_mysql_cache_plugin_invalid_port_defaults() -> None:
    """Brief: Invalid port value falls back to default.

    Inputs:
      - None.

    Outputs:
      - None; asserts port defaults when conversion fails.
    """

    from unittest.mock import MagicMock, patch

    from foghorn.plugins.cache.mysql_mariadb_cache import MySqlCache

    with patch(
        "foghorn.plugins.cache.mysql_mariadb_cache.MySQLTTLCache"
    ) as mock_backend:
        mock_instance = MagicMock()
        mock_backend.return_value = mock_instance

        config = {"port": "not_a_number"}
        MySqlCache(**config)

        call_kwargs = mock_backend.call_args[1]
        assert call_kwargs["port"] == 3306


def test_mysql_cache_plugin_invalid_config_types() -> None:
    """Brief: Invalid config types are sanitized.

    Inputs:
      - None.

    Outputs:
      - None; asserts bad types are corrected.
    """

    from unittest.mock import MagicMock, patch

    from foghorn.plugins.cache.mysql_mariadb_cache import MySqlCache

    with patch(
        "foghorn.plugins.cache.mysql_mariadb_cache.MySQLTTLCache"
    ) as mock_backend:
        mock_instance = MagicMock()
        mock_backend.return_value = mock_instance

        config = {
            "database": "",  # Empty string
            "namespace": None,  # None value
            "connect_kwargs": "not a dict",  # Bad type
            "user": None,
            "password": None,
        }
        MySqlCache(**config)

        call_kwargs = mock_backend.call_args[1]
        assert call_kwargs["database"] == "foghorn_cache"
        assert call_kwargs["namespace"] == "dns_cache"
        assert call_kwargs["connect_kwargs"] is None
        assert call_kwargs["user"] is None
        assert call_kwargs["password"] is None


def test_mysql_cache_plugin_min_ttl_enforcement() -> None:
    """Brief: min_cache_ttl negative values are clamped to 0.

    Inputs:
      - None.

    Outputs:
      - None; asserts negative TTL becomes 0.
    """

    from unittest.mock import MagicMock, patch

    from foghorn.plugins.cache.mysql_mariadb_cache import MySqlCache

    with patch(
        "foghorn.plugins.cache.mysql_mariadb_cache.MySQLTTLCache"
    ) as mock_backend:
        mock_instance = MagicMock()
        mock_backend.return_value = mock_instance

        config = {"min_cache_ttl": -100}
        cache = MySqlCache(**config)
        assert cache.min_cache_ttl == 0


def test_mysql_cache_plugin_methods_delegate() -> None:
    """Brief: Cache methods delegate to backend.

    Inputs:
      - None.

    Outputs:
      - None; asserts method calls reach backend.
    """

    from unittest.mock import MagicMock, patch

    from foghorn.plugins.cache.mysql_mariadb_cache import MySqlCache

    with patch(
        "foghorn.plugins.cache.mysql_mariadb_cache.MySQLTTLCache"
    ) as mock_backend:
        mock_instance = MagicMock()
        mock_backend.return_value = mock_instance
        mock_instance.get.return_value = b"cached_value"
        mock_instance.get_with_meta.return_value = (b"value", 50.0, 60)
        mock_instance.purge.return_value = 5

        cache = MySqlCache()

        # Test get
        result = cache.get(("example.com", 1))
        assert result == b"cached_value"
        mock_instance.get.assert_called_with(("example.com", 1))

        # Test get_with_meta
        result = cache.get_with_meta(("example.com", 1))
        assert result == (b"value", 50.0, 60)
        mock_instance.get_with_meta.assert_called_with(("example.com", 1))

        # Test set
        cache.set(("example.com", 1), 60, b"value")
        mock_instance.set.assert_called_with(("example.com", 1), 60, b"value")

        # Test purge
        result = cache.purge()
        assert result == 5
        mock_instance.purge.assert_called_once()

        # Test close
        cache.close()
        mock_instance.close.assert_called_once()


def test_mysql_cache_plugin_close_handles_exceptions() -> None:
    """Brief: close() handles backend exceptions gracefully.

    Inputs:
      - None.

    Outputs:
      - None; asserts exceptions are suppressed.
    """

    from unittest.mock import MagicMock, patch

    from foghorn.plugins.cache.mysql_mariadb_cache import MySqlCache

    with patch(
        "foghorn.plugins.cache.mysql_mariadb_cache.MySQLTTLCache"
    ) as mock_backend:
        mock_instance = MagicMock()
        mock_backend.return_value = mock_instance
        mock_instance.close.side_effect = RuntimeError("Connection failed")

        cache = MySqlCache()
        # Should not raise
        cache.close()
