"""MySQL/MariaDB-backed secrets store.

Brief:
  Persists SecretRecord rows in a configurable table. Reuses foghorn
  db_drivers import helpers and sql_safety identifier validation.

Inputs:
  - host/port/user/password/database/table (+ driver options)

Outputs:
  - MySqlSecrets instance implementing SecretsStore.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

from foghorn.plugins.db_drivers import import_mysql_driver
from foghorn.plugins.sql_safety import validate_sql_identifier, validate_sql_placeholder

from .base import SecretRecord, SecretsStore, secret_aliases

logger = logging.getLogger(__name__)

_TABLE_MAX_LENGTH = 64


@secret_aliases("mysql", "mariadb", "mysql_secrets", "mariadb_secrets")
class MySqlSecrets(SecretsStore):
    """Brief: MySQL/MariaDB secrets backend.

    Inputs (**config):
      - host, port, user, password, database, table
      - driver / driver_fallback / connect_kwargs

    Outputs:
      - MySqlSecrets instance.
    """

    def __init__(self, **config: object) -> None:
        """Brief: Connect and ensure secrets schema exists.

        Inputs:
          - **config: See class docstring.

        Outputs:
          - None.
        """

        super().__init__(**config)

        driver, param_style = import_mysql_driver(
            driver=config.get("driver"),
            driver_fallback=config.get("driver_fallback"),
            consumer_name="MySqlSecrets",
        )
        self._placeholder = validate_sql_placeholder(
            "%s" if param_style == "format" else "?",
            allowed_placeholders={"%s", "?"},
        )

        table_raw = config.get("table") or config.get("namespace") or "secrets"
        self._table = validate_sql_identifier(
            str(table_raw),
            field_name="table",
            max_length=_TABLE_MAX_LENGTH,
        )

        host = str(config.get("host", "127.0.0.1") or "127.0.0.1")
        try:
            port = int(config.get("port", 3306) or 3306)
        except Exception:
            port = 3306
        user = config.get("user")
        password = config.get("password")
        database = str(config.get("database") or "foghorn_secrets")

        kwargs: dict[str, Any] = {
            "host": host,
            "port": port,
            "database": database,
        }
        if isinstance(user, str):
            kwargs["user"] = user
        if isinstance(password, str):
            kwargs["password"] = password
        connect_kwargs = config.get("connect_kwargs")
        if isinstance(connect_kwargs, dict):
            kwargs.update(dict(connect_kwargs))

        self._lock = threading.RLock()
        self._conn = driver.connect(**kwargs)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Brief: Create secrets table if missing.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        table = self._table
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {table} (
                    id VARCHAR(254) NOT NULL PRIMARY KEY,
                    kind VARCHAR(32) NOT NULL,
                    name VARCHAR(255) NULL,
                    algorithm VARCHAR(64) NULL,
                    secret LONGBLOB NULL,
                    token LONGBLOB NULL,
                    cert_pem LONGBLOB NULL,
                    key_pem LONGBLOB NULL,
                    ca_pem LONGBLOB NULL,
                    zone VARCHAR(255) NULL,
                    key_type VARCHAR(16) NULL,
                    private_key_pem LONGBLOB NULL,
                    extra_json LONGTEXT NULL,
                    meta_json LONGTEXT NULL,
                    updated_at DOUBLE NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            try:
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS {table}_kind_idx ON {table} (kind)"
                )
            except Exception:
                try:
                    cur.execute(f"CREATE INDEX {table}_kind_idx ON {table} (kind)")
                except Exception:
                    pass
            try:
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS {table}_zone_idx ON {table} (zone, key_type)"
                )
            except Exception:
                try:
                    cur.execute(
                        f"CREATE INDEX {table}_zone_idx ON {table} (zone, key_type)"
                    )
                except Exception:
                    pass
            self._conn.commit()

    def _ph(self, n: int = 1) -> str:
        """Brief: Build comma-separated SQL placeholders.

        Inputs:
          - n: Placeholder count.

        Outputs:
          - str of placeholders.
        """

        return ", ".join([self._placeholder] * max(1, int(n)))

    @staticmethod
    def _blob(value: object | None) -> bytes | None:
        """Brief: Coerce optional text/bytes to bytes for BLOB columns.

        Inputs:
          - value: str/bytes/None.

        Outputs:
          - bytes or None.
        """

        if value is None:
            return None
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)
        return str(value).encode("utf-8")

    @staticmethod
    def _text_from_blob(value: object | None) -> str | None:
        """Brief: Decode optional BLOB to UTF-8 text.

        Inputs:
          - value: DB cell.

        Outputs:
          - str or None.
        """

        if value is None:
            return None
        if isinstance(value, (bytes, bytearray, memoryview)):
            try:
                return bytes(value).decode("utf-8")
            except Exception:
                return bytes(value).decode("utf-8", errors="replace")
        return str(value)

    def _row_to_record(self, row: Any) -> SecretRecord:
        """Brief: Map a DB row tuple to SecretRecord.

        Inputs:
          - row: Ordered tuple matching SELECT column order.

        Outputs:
          - SecretRecord.
        """

        (
            sid,
            kind,
            name,
            algorithm,
            secret,
            token,
            cert_pem,
            key_pem,
            ca_pem,
            zone,
            key_type,
            private_key_pem,
            extra_json,
            meta_json,
            _updated_at,
        ) = row

        extra: dict[str, Any] = {}
        meta: dict[str, Any] = {}
        if extra_json:
            try:
                parsed = json.loads(
                    extra_json
                    if isinstance(extra_json, str)
                    else bytes(extra_json).decode("utf-8")
                )
                if isinstance(parsed, dict):
                    extra = parsed
            except Exception:
                pass
        if meta_json:
            try:
                parsed = json.loads(
                    meta_json
                    if isinstance(meta_json, str)
                    else bytes(meta_json).decode("utf-8")
                )
                if isinstance(parsed, dict):
                    meta = parsed
            except Exception:
                pass

        return SecretRecord(
            id=str(sid),
            kind=str(kind),
            backend_id=self.backend_id,
            name=str(name) if name is not None else None,
            algorithm=str(algorithm) if algorithm is not None else None,
            secret=self._text_from_blob(secret),
            token=self._text_from_blob(token),
            cert_pem=bytes(cert_pem) if cert_pem is not None else None,
            key_pem=bytes(key_pem) if key_pem is not None else None,
            ca_pem=bytes(ca_pem) if ca_pem is not None else None,
            zone=str(zone) if zone is not None else None,
            key_type=str(key_type) if key_type is not None else None,
            private_key_pem=(
                bytes(private_key_pem) if private_key_pem is not None else None
            ),
            extra=extra,
            meta=meta,
        )

    def validate_connection(self) -> bool:
        """Brief: Return True when SELECT 1 succeeds.

        Inputs:
          - None.

        Outputs:
          - bool.
        """

        try:
            with self._lock:
                cur = self._conn.cursor()
                cur.execute("SELECT 1")
                cur.fetchone()
            return True
        except Exception:
            logger.debug("MySqlSecrets validate_connection failed", exc_info=True)
            return False

    def get(self, secret_id: str) -> SecretRecord | None:
        """Brief: Fetch one secret by primary key id.

        Inputs:
          - secret_id: Row id.

        Outputs:
          - SecretRecord or None.
        """

        sid = str(secret_id).strip()
        if not sid:
            return None
        sql = (
            f"SELECT id, kind, name, algorithm, secret, token, cert_pem, key_pem, "
            f"ca_pem, zone, key_type, private_key_pem, extra_json, meta_json, updated_at "
            f"FROM {self._table} WHERE id = {self._placeholder}"
        )
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(sql, (sid,))
            row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def list(self, kind: str | None = None) -> list[SecretRecord]:
        """Brief: List secrets, optionally filtered by kind.

        Inputs:
          - kind: Optional kind filter.

        Outputs:
          - list[SecretRecord].
        """

        cols = (
            "id, kind, name, algorithm, secret, token, cert_pem, key_pem, "
            "ca_pem, zone, key_type, private_key_pem, extra_json, meta_json, updated_at"
        )
        with self._lock:
            cur = self._conn.cursor()
            if kind:
                cur.execute(
                    f"SELECT {cols} FROM {self._table} WHERE kind = {self._placeholder} "
                    f"ORDER BY id",
                    (str(kind).strip().lower(),),
                )
            else:
                cur.execute(f"SELECT {cols} FROM {self._table} ORDER BY id")
            rows = list(cur.fetchall() or [])
        return [self._row_to_record(r) for r in rows]

    def put(self, record: SecretRecord) -> None:
        """Brief: Insert or replace a secret row.

        Inputs:
          - record: SecretRecord to persist.

        Outputs:
          - None.
        """

        import time

        sid = str(record.id).strip()
        if not sid:
            raise ValueError("SecretRecord.id is required for put()")
        kind = str(record.kind).strip().lower()
        now = float(time.time())
        extra_json = json.dumps(record.extra or {}) if record.extra else None
        meta_json = json.dumps(record.meta or {}) if record.meta else None

        ph = self._ph(15)
        sql = (
            f"REPLACE INTO {self._table} ("
            f"id, kind, name, algorithm, secret, token, cert_pem, key_pem, ca_pem, "
            f"zone, key_type, private_key_pem, extra_json, meta_json, updated_at"
            f") VALUES ({ph})"
        )
        params = (
            sid,
            kind,
            record.name,
            record.algorithm,
            self._blob(record.secret),
            self._blob(record.token),
            record.cert_pem,
            record.key_pem,
            record.ca_pem,
            record.zone,
            record.key_type,
            record.private_key_pem,
            extra_json,
            meta_json,
            now,
        )
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(sql, params)
            self._conn.commit()

    def close(self) -> None:
        """Brief: Close the DB connection.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        try:
            with self._lock:
                self._conn.close()
        except Exception:
            pass
