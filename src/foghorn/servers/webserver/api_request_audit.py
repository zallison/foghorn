"""Append-only API request auditing with sensitive-data redaction.

Brief:
  Provides a best-effort request audit sink for the admin HTTP API that writes
  one row per request into a SQLite database. The table is append-only via
  SQL triggers that abort UPDATE/DELETE operations.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


logger = logging.getLogger("foghorn.webserver")

_API_ALIAS_PREFIXES = (
    "/api/",
    "/config",
    "/stats",
    "/traffic",
    "/health",
    "/about",
    "/ready",
    "/logs",
    "/query_log",
    "/reload",
    "/restart",
)
_SENSITIVE_KEY_RE = re.compile(
    r"(pass|password|passwd|secret|token|api[-_]?key|authorization|cookie|session|credential|private[-_]?key)",
    re.IGNORECASE,
)
_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "cookie",
    "set-cookie",
}


def is_api_request_path(path: str) -> bool:
    """Brief: Return whether a request path is considered an admin API call.

    Inputs:
      - path: HTTP request path.

    Outputs:
      - bool.
    """

    path_text = str(path or "")
    return path_text.startswith(_API_ALIAS_PREFIXES)


def _iso_utc_now() -> str:
    """Brief: Return current UTC timestamp in ISO-8601 format.

    Inputs:
      - None.

    Outputs:
      - str UTC timestamp.
    """

    return datetime.now(timezone.utc).isoformat()


def _looks_sensitive_key(key: str) -> bool:
    """Brief: Return True when the key name implies a secret value.

    Inputs:
      - key: Candidate dictionary/header/query key.

    Outputs:
      - bool.
    """

    key_text = str(key or "").strip().lower()
    if key_text in _SENSITIVE_HEADER_NAMES:
        return True
    return bool(_SENSITIVE_KEY_RE.search(key_text))


def _digest_text(value: str) -> str:
    """Brief: Return short sha256 digest marker for redacted values.

    Inputs:
      - value: Raw sensitive value.

    Outputs:
      - str marker in format [REDACTED:sha256:...].
    """

    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"[REDACTED:sha256:{digest}]"


def redact_sensitive(value: Any, *, key: str | None = None) -> Any:
    """Brief: Recursively redact sensitive fields from a value.

    Inputs:
      - value: Arbitrary object (mapping/list/scalar).
      - key: Optional parent key associated with value.

    Outputs:
      - Redacted value with original shape preserved where possible.
    """

    if key is not None and _looks_sensitive_key(key):
        return _digest_text(str(value or ""))

    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key_text = str(k)
            out[key_text] = redact_sensitive(v, key=key_text)
        return out

    if isinstance(value, list):
        return [redact_sensitive(item, key=key) for item in value]

    if isinstance(value, tuple):
        return [redact_sensitive(item, key=key) for item in value]

    return value


def redact_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Brief: Redact sensitive HTTP header values.

    Inputs:
      - headers: Header mapping.

    Outputs:
      - dict with secret-like header values redacted.
    """

    out: dict[str, Any] = {}
    for k, v in dict(headers or {}).items():
        key_text = str(k)
        if _looks_sensitive_key(key_text):
            out[key_text] = _digest_text(str(v or ""))
        else:
            out[key_text] = v
    return out


def _resolve_default_db_path(config_path: str | None) -> Path:
    """Brief: Resolve default SQLite path for API audit logs.

    Inputs:
      - config_path: Optional active config file path.

    Outputs:
      - Path to default sqlite file.
    """

    if isinstance(config_path, str) and config_path.strip():
        base_dir = Path(config_path).expanduser().resolve().parent
        return base_dir / "api-request-audit.sqlite3"
    return Path.cwd() / "api-request-audit.sqlite3"


def _resolve_db_path(web_cfg: Dict[str, Any], config_path: str | None) -> Path:
    """Brief: Resolve configured SQLite path for API audit logs.

    Inputs:
      - web_cfg: server.http/webserver config mapping.
      - config_path: Optional active config file path.

    Outputs:
      - Path to SQLite database file.
    """

    audit_cfg = web_cfg.get("api_request_audit")
    db_path_obj: object | None = None
    if isinstance(audit_cfg, dict):
        db_path_obj = audit_cfg.get("db_path")

    if isinstance(db_path_obj, str) and db_path_obj.strip():
        p = Path(db_path_obj).expanduser()
        if not p.is_absolute():
            if isinstance(config_path, str) and config_path.strip():
                p = Path(config_path).expanduser().resolve().parent / p
            else:
                p = Path.cwd() / p
        return p.resolve()
    return _resolve_default_db_path(config_path)


@dataclass
class ApiRequestAuditLogger:
    """Brief: Append-only SQLite logger for API request audit events.

    Inputs:
      - enabled: Whether logging is active.
      - db_path: Path to SQLite file.

    Outputs:
      - Logger instance with log_event() method for request records.
    """

    enabled: bool
    db_path: Path | None = None

    def __post_init__(self) -> None:
        """Brief: Initialize lock and schema state.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        self._lock = threading.RLock()
        self._schema_ready = False

    @classmethod
    def from_web_cfg(
        cls, web_cfg: Dict[str, Any], *, config_path: str | None = None
    ) -> "ApiRequestAuditLogger":
        """Brief: Build logger from webserver configuration.

        Inputs:
          - web_cfg: server.http/webserver config mapping.
          - config_path: Optional active config path.

        Outputs:
          - ApiRequestAuditLogger configured from api_request_audit options.
        """

        audit_cfg = web_cfg.get("api_request_audit")
        enabled = True
        if isinstance(audit_cfg, dict) and "enabled" in audit_cfg:
            enabled = bool(audit_cfg.get("enabled"))

        if not enabled:
            return cls(enabled=False, db_path=None)

        db_path = _resolve_db_path(web_cfg, config_path)
        return cls(enabled=True, db_path=db_path)

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        """Brief: Create append-only audit table/triggers when needed.

        Inputs:
          - conn: Open SQLite connection.

        Outputs:
          - None.
        """

        if self._schema_ready:
            return
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_request_audit (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              created_at TEXT NOT NULL,
              created_at_ts REAL NOT NULL,
              method TEXT NOT NULL,
              path TEXT NOT NULL,
              query_json TEXT NOT NULL,
              headers_json TEXT NOT NULL,
              body_json TEXT,
              status_code INTEGER,
              duration_ms REAL,
              client_ip TEXT,
              error_text TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS api_request_audit_no_update
            BEFORE UPDATE ON api_request_audit
            BEGIN
              SELECT RAISE(ABORT, 'api_request_audit is append-only');
            END
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS api_request_audit_no_delete
            BEFORE DELETE ON api_request_audit
            BEGIN
              SELECT RAISE(ABORT, 'api_request_audit is append-only');
            END
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_api_request_audit_created_at_ts
            ON api_request_audit(created_at_ts)
            """
        )
        self._schema_ready = True

    def log_event(
        self,
        *,
        method: str,
        path: str,
        query: Dict[str, Any] | None,
        headers: Dict[str, Any] | None,
        body: Any | None,
        status_code: int | None,
        duration_ms: float | None,
        client_ip: str | None,
        error_text: str | None = None,
    ) -> None:
        """Brief: Persist one API request audit row (best effort).

        Inputs:
          - method/path: Request method and path.
          - query: Query params mapping.
          - headers: Header mapping.
          - body: Optional parsed body content.
          - status_code: Response status code.
          - duration_ms: Request duration in milliseconds.
          - client_ip: Best-effort client IP.
          - error_text: Optional error message.

        Outputs:
          - None. Failures are logged and swallowed.
        """

        if not self.enabled or self.db_path is None:
            return
        if not is_api_request_path(path):
            return

        created_at = _iso_utc_now()
        created_at_ts = datetime.now(timezone.utc).timestamp()
        safe_query = redact_sensitive(dict(query or {}))
        safe_headers = redact_headers(dict(headers or {}))
        safe_body = redact_sensitive(body) if body is not None else None

        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning(
                "Unable to create API audit DB directory %s: %s",
                self.db_path.parent,
                exc,
            )
            return

        try:
            with self._lock:
                conn = sqlite3.connect(str(self.db_path), timeout=5.0)
                try:
                    conn.execute("PRAGMA journal_mode=WAL")
                    self._ensure_schema(conn)
                    conn.execute(
                        """
                        INSERT INTO api_request_audit (
                          created_at,
                          created_at_ts,
                          method,
                          path,
                          query_json,
                          headers_json,
                          body_json,
                          status_code,
                          duration_ms,
                          client_ip,
                          error_text
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            created_at,
                            float(created_at_ts),
                            str(method or ""),
                            str(path or ""),
                            json.dumps(safe_query, ensure_ascii=False),
                            json.dumps(safe_headers, ensure_ascii=False),
                            (
                                json.dumps(safe_body, ensure_ascii=False)
                                if safe_body is not None
                                else None
                            ),
                            (int(status_code) if status_code is not None else None),
                            (
                                float(duration_ms)
                                if duration_ms is not None
                                else None
                            ),
                            str(client_ip or ""),
                            (str(error_text) if error_text else None),
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()
        except Exception as exc:
            logger.warning("Failed to persist API audit event: %s", exc)

