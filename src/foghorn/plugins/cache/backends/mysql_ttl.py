from __future__ import annotations

import hashlib
import logging
import pickle
import threading
import time
from typing import Any, Optional, Tuple

_logger = logging.getLogger(__name__)


def _normalize_mysql_driver_name(raw: object) -> str | None:
    """Brief: Normalize a MySQL driver name from config.

    Inputs:
        raw: Candidate value (string-like) from config.

    Outputs:
        str | None: Canonical driver key ('mariadb' or 'mysql-connector-python'),
        or None when raw is missing/empty/auto.
    """

    if raw is None:
        return None
    if not isinstance(raw, str):
        return None

    value = raw.strip().lower().replace("_", "-").replace(" ", "")
    if not value or value in {"auto", "default"}:
        return None

    if value in {"mariadb", "maria-db"}:
        return "mariadb"
    if value in {
        "mysql",
        "mysql-connector-python",
        "mysql.connector",
        "mysql-connector",
        "mysqlconnector",
        "mysql-connector/py",
        "connector",
    }:
        return "mysql-connector-python"

    raise ValueError(
        "mysql driver must be one of 'auto', 'mariadb', 'mysql', or 'mysql-connector-python'"
    )


def _normalize_driver_fallbacks(raw: object) -> list[str] | None:
    """Brief: Normalize driver fallback configuration.

    Inputs:
        raw: Candidate fallback config from YAML (string or list of strings).

    Outputs:
        list[str] | None:
          - None for default behavior (auto fallback)
          - [] for explicit no-fallback (none)
          - list of canonical driver keys
    """

    if raw is None:
        return None

    if isinstance(raw, str):
        v = raw.strip().lower().replace("_", "-").replace(" ", "")
        if not v or v in {"auto", "default"}:
            return None
        if v in {"none", "no", "false", "off"}:
            return []
        return [_normalize_mysql_driver_name(raw)]  # type: ignore[list-item]

    if isinstance(raw, list):
        out: list[str] = []
        for item in raw:
            if item is None:
                continue
            name = _normalize_mysql_driver_name(item)
            if name is None:
                continue
            out.append(name)
        return out

    return None


def _driver_order_from_config(
    *,
    driver: object = None,
    driver_fallback: object = None,
) -> list[str]:
    """Brief: Compute the driver import order based on config.

    Inputs:
        driver: Preferred driver name ('auto'|'mariadb'|'mysql-connector-python').
        driver_fallback: Fallback policy ('auto'|'none'|<driver>|[<driver>,...]).

    Outputs:
        list[str]: Ordered list of canonical driver keys to try.
    """

    preferred = _normalize_mysql_driver_name(driver)
    fallbacks = _normalize_driver_fallbacks(driver_fallback)

    # Default order: prefer mariadb, then mysql-connector-python.
    default_order = ["mariadb", "mysql-connector-python"]

    if preferred is None:
        if fallbacks == []:
            return [default_order[0]]
        return default_order

    if fallbacks is None:
        fallbacks = [d for d in default_order if d != preferred]

    order = [preferred] + list(fallbacks or [])

    seen: set[str] = set()
    out: list[str] = []
    for item in order:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _import_mysql_driver(
    *,
    driver: object = None,
    driver_fallback: object = None,
) -> tuple[object, str]:
    """Import and return a DB-API compatible MySQL/MariaDB driver module.

    Inputs:
        driver: Preferred driver name.
        driver_fallback: Fallback policy.

    Outputs:
        Tuple of (driver_module, param_style):
          - driver_module: DB-API like module exposing a ``connect`` callable.
          - param_style: Either 'qmark' for ? placeholders or 'format' for %s.

    Raises:
        RuntimeError: When no supported MySQL/MariaDB driver is available.
        ValueError: When driver/driver_fallback values are invalid.
    """

    order = _driver_order_from_config(driver=driver, driver_fallback=driver_fallback)

    last_exc: Exception | None = None
    for choice in order:
        try:
            if choice == "mariadb":
                # pragma: disable E402
                import mariadb as driver_mod  # type: ignore[import]

                return driver_mod, "qmark"

            if choice == "mysql-connector-python":
                # pragma: disable E402
                import mysql.connector as driver_mod  # type: ignore[import]

                return driver_mod, "format"

        except ImportError as exc:  # pragma: no cover - import-path dependent
            last_exc = exc
            continue

    raise RuntimeError(
        "No supported MySQL/MariaDB driver found; install either 'mariadb' or "
        "'mysql-connector-python' to use MySQLTTLCache"
    ) from last_exc


def _stable_digest_for_key(key: Any) -> str:
    """Brief: Create a stable digest for a cache key.

    Inputs:
      - key: Any Python object.

    Outputs:
      - str: Hex digest suitable for use as a database primary key.

    Notes:
      - We hash a pickle of the key to avoid ambiguities.
    """

    payload = pickle.dumps(key, protocol=pickle.HIGHEST_PROTOCOL)
    return hashlib.sha256(payload).hexdigest()


class MySQLTTLCache:
    """MySQL/MariaDB-backed TTL cache for arbitrary Python keys and values.

    Brief:
      A thread-safe key/value store with per-entry TTL semantics backed by
      MySQL/MariaDB. This is intended to be reusable by multiple parts of
      Foghorn without each subsystem re-implementing connection management,
      directory creation, TTL bookkeeping, and serialization.

    Inputs (constructor):
      - db_path: Not used (for interface compatibility).
      - host: Database host (default "127.0.0.1").
      - port: Database port (default 3306).
      - user: Database username.
      - password: Database password.
      - database: Database name (default "foghorn_cache").
      - namespace: Table name to store entries (default "ttl_cache").
      - connect_kwargs: Optional mapping of additional keyword arguments passed
        through to the underlying driver's ``connect`` function.
      - driver: Preferred DB driver (auto|mariadb|mysql-connector-python or mysql).
      - driver_fallback: Fallback policy for driver import:
          - auto (default): try the other driver as a fallback.
          - none: do not fall back.
          - <driver> or [<driver>, ...]: explicit fallback list.

    Outputs:
      - MySQLTTLCache instance.

    Notes:
      - Keys and values are stored as BLOBs. Bytes-like objects are stored
        directly; other objects are stored as pickles.
      - get() enforces expiry (expired entries are treated as misses and are
        removed).
      - get_with_meta() returns the value even when expired (with a negative
        seconds_remaining) so callers can implement stale-while-revalidate.
      - All DB operations are synchronized with an RLock.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        *,
        host: str = "127.0.0.1",
        port: int = 3306,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: str = "foghorn_cache",
        namespace: str = "ttl_cache",
        connect_kwargs: Optional[dict[str, Any]] = None,
        driver: Optional[str] = None,
        driver_fallback: object = None,
    ) -> None:
        """Brief: Initialize the MySQL TTL cache and ensure schema exists.

        Inputs:
          - db_path: Ignored (for interface compatibility with SQLite backend).
          - host: MySQL host.
          - port: MySQL port.
          - user: Username.
          - password: Password.
          - database: Database name.
          - namespace: Table name.
          - connect_kwargs: Additional connection kwargs.

        Outputs:
          - None.
        """

        driver, param_style = _import_mysql_driver(
            driver=driver, driver_fallback=driver_fallback
        )
        self._param_style = param_style
        self._placeholder = "%s" if param_style == "format" else "?"

        # Validate namespace/table name
        if not isinstance(namespace, str) or not namespace.strip():
            raise ValueError("namespace must be a non-empty string")

        import re

        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", namespace):
            raise ValueError(
                f"namespace {namespace!r} must match ^[A-Za-z_][A-Za-z0-9_]*$"
            )

        self.namespace = str(namespace)

        # Per-cache access counters used by admin snapshots.
        self.calls_total: int = 0
        self.cache_hits: int = 0
        self.cache_misses: int = 0

        # Eviction counters (best-effort) for diagnostics.
        self.evictions_total: int = 0
        self.evictions_ttl: int = 0

        self._lock = threading.RLock()

        kwargs: dict[str, Any] = {
            "host": host,
            "port": int(port),
            "database": database,
        }
        if user is not None:
            kwargs["user"] = user
        if password is not None:
            kwargs["password"] = password
        if connect_kwargs:
            kwargs.update(dict(connect_kwargs))

        self._conn = driver.connect(**kwargs)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Brief: Create the TTL cache table and indexes.

        Inputs:
            None.

        Outputs:
            None; creates the table if it does not already exist.
        """

        conn = self._conn
        cur = conn.cursor()

        table = self.namespace
        cur.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {table} (
                key_digest BINARY(32) PRIMARY KEY,
                key_blob LONGBLOB NOT NULL,
                key_is_pickle INTEGER NOT NULL DEFAULT 0,
                expiry DOUBLE NOT NULL,
                ttl INTEGER NOT NULL,
                value_blob LONGBLOB NOT NULL,
                value_is_pickle INTEGER NOT NULL DEFAULT 0
            ) ENGINE=InnoDB
            """
        )

        # Create index if it doesn't exist (best-effort; ignore if unsupported)
        try:
            cur.execute(
                f"CREATE INDEX IF NOT EXISTS {table}_expiry_idx ON {table} (expiry)"
            )
        except (
            Exception
        ):  # pragma: nocover - Some older MySQL versions may not support this
            try:
                cur.execute(f"CREATE INDEX {table}_expiry_idx ON {table} (expiry)")
            except Exception:  # pragma: nocover - Index may already exist
                pass

        conn.commit()

    @staticmethod
    def _encode(obj: Any) -> Tuple[bytes, int]:
        """Brief: Encode an arbitrary Python object for MySQL storage.

        Inputs:
          - obj: Any Python object.

        Outputs:
          - (payload, is_pickle):
              - payload: bytes to store.
              - is_pickle: 1 when payload is pickle-encoded, 0 otherwise.
        """

        if isinstance(obj, (bytes, bytearray, memoryview)):
            return bytes(obj), 0
        return pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL), 1

    @staticmethod
    def _decode(payload: bytes, is_pickle: int) -> Any:
        """Brief: Decode a stored MySQL payload.

        Inputs:
          - payload: Stored bytes.
          - is_pickle: 1 if payload is a pickle.

        Outputs:
          - Any: Decoded object.
        """

        if int(is_pickle) == 1:
            return pickle.loads(payload)
        return payload

    def get(self, key: Any) -> Any | None:
        """Brief: Lookup a cached entry enforcing expiry.

        Inputs:
          - key: Any key object.

        Outputs:
          - Any | None: Cached value if present and not expired; otherwise None.
        """

        key_digest = bytes.fromhex(_stable_digest_for_key(key))
        now = time.time()

        table = self.namespace
        with self._lock:
            self.calls_total += 1

            cur = self._conn.cursor()
            cur.execute(
                f"SELECT value_blob, value_is_pickle, expiry FROM {table} WHERE key_digest={self._placeholder}",
                (key_digest,),
            )
            row = cur.fetchone()

        if not row:
            self.cache_misses += 1
            return None

        value_blob, value_is_pickle, expiry = row
        try:
            expiry_f = float(expiry)
        except Exception:  # pragma: nocover - defensive
            cur = self._conn.cursor()
            cur.execute(
                f"DELETE FROM {table} WHERE key_digest={self._placeholder}",
                (key_digest,),
            )
            self._conn.commit()
            self.cache_misses += 1
            return None

        if now >= expiry_f:
            cur = self._conn.cursor()
            cur.execute(
                f"DELETE FROM {table} WHERE key_digest={self._placeholder}",
                (key_digest,),
            )
            self._conn.commit()
            self.cache_misses += 1
            try:
                self.evictions_total += 1
                self.evictions_ttl += 1
            except Exception:  # pragma: nocover - defensive
                pass
            return None

        try:
            value = self._decode(bytes(value_blob), int(value_is_pickle))
        except Exception:  # pragma: nocover - defensive
            cur = self._conn.cursor()
            cur.execute(
                f"DELETE FROM {table} WHERE key_digest={self._placeholder}",
                (key_digest,),
            )
            self._conn.commit()
            self.cache_misses += 1
            return None

        self.cache_hits += 1
        return value

    def get_with_meta(
        self, key: Any
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Lookup a cached entry and return metadata.

        Inputs:
          - key: Any key object.

        Outputs:
          - (value_or_None, seconds_remaining_or_None, original_ttl_or_None)

        Notes:
          - This method intentionally does not purge expired entries.
        """

        key_digest = bytes.fromhex(_stable_digest_for_key(key))
        now = time.time()

        table = self.namespace
        with self._lock:
            self.calls_total += 1
            cur = self._conn.cursor()
            cur.execute(
                f"SELECT value_blob, value_is_pickle, expiry, ttl FROM {table} WHERE key_digest={self._placeholder}",
                (key_digest,),
            )
            row = cur.fetchone()

        if not row:
            self.cache_misses += 1
            return None, None, None

        value_blob, value_is_pickle, expiry, ttl = row

        try:
            expiry_f = float(expiry)
            ttl_i = int(ttl)
            remaining = float(expiry_f - now)
        except Exception:  # pragma: nocover - defensive
            self.cache_misses += 1
            return None, None, None

        try:
            value = self._decode(bytes(value_blob), int(value_is_pickle))
        except Exception:  # pragma: nocover - defensive
            try:
                self.cache_misses += 1
            except Exception:  # pragma: nocover - defensive
                pass
            return None, None, None

        if remaining >= 0:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

        return value, remaining, ttl_i

    def set(self, key: Any, ttl: int, value: Any) -> None:
        """Brief: Store a value under a key with TTL.

        Inputs:
          - key: Any key object.
          - ttl: Time-to-live in seconds.
          - value: Any value.

        Outputs:
          - None.
        """

        ttl_int = max(0, int(ttl))
        expiry = time.time() + ttl_int

        key_digest = bytes.fromhex(_stable_digest_for_key(key))
        key_blob, key_is_pickle = self._encode(key)
        value_blob, value_is_pickle = self._encode(value)

        table = self.namespace
        placeholder = self._placeholder
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                f"""
                INSERT INTO {table}
                (key_digest, key_blob, key_is_pickle, expiry, ttl, value_blob, value_is_pickle)
                VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})
                ON DUPLICATE KEY UPDATE
                key_blob=VALUES(key_blob),
                key_is_pickle=VALUES(key_is_pickle),
                expiry=VALUES(expiry),
                ttl=VALUES(ttl),
                value_blob=VALUES(value_blob),
                value_is_pickle=VALUES(value_is_pickle)
                """,
                (
                    key_digest,
                    key_blob,
                    int(key_is_pickle),
                    float(expiry),
                    int(ttl_int),
                    value_blob,
                    int(value_is_pickle),
                ),
            )
            self._conn.commit()

    def purge(self) -> int:
        """Brief: Purge expired entries.

        Inputs:
          - None.

        Outputs:
          - int: Number of entries removed (best-effort).
        """

        now = time.time()
        table = self.namespace
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                f"DELETE FROM {table} WHERE expiry <= {self._placeholder}",
                (float(now),),
            )
            removed = int(cur.rowcount or 0)
            self._conn.commit()
        if removed > 0:
            try:
                self.evictions_total += removed
                self.evictions_ttl += removed
            except Exception:  # pragma: nocover - defensive
                pass
        return removed

    def close(self) -> None:
        """Brief: Close the underlying connection.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
