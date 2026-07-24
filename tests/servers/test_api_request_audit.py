"""Tests for append-only API request audit logging with redaction."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from foghorn.servers.webserver.api_request_audit import (
    ApiRequestAuditLogger,
    _DEFAULT_AUDIT_RETENTION_MAX_DB_BYTES,
    _DEFAULT_AUDIT_RETENTION_MAX_RECORDS,
    _DEFAULT_AUDIT_RETENTION_PRUNE_EVERY_N_INSERTS,
)


def test_api_request_audit_logger_redacts_sensitive_values_and_inserts_rows(
    tmp_path: Path,
) -> None:
    """Brief: Logger inserts one row and redacts sensitive query/header/body values.

    Inputs:
      - tmp_path: Pytest temporary directory fixture.

    Outputs:
      - None; asserts row contents and redaction markers.
    """

    db_path = tmp_path / "api-audit.sqlite3"
    logger = ApiRequestAuditLogger(enabled=True, db_path=db_path)

    logger.log_event(
        method="POST",
        path="/api/v1/admin/config/verify",
        query={"token": "my-secret-token", "q": "example"},
        headers={
            "authorization": "Bearer abc123",
            "x-api-key": "key-secret",
            "x-request-id": "req-1",
        },
        body={"password": "p@ssw0rd", "nested": {"client_secret": "foo"}},
        status_code=200,
        duration_ms=4.2,
        client_ip="127.0.0.1",
        error_text=None,
    )

    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT method, path, query_json, headers_json, body_json, status_code FROM api_request_audit"
        ).fetchone()
    finally:
        conn.close()

    assert row is not None
    method, path, query_json, headers_json, body_json, status_code = row
    assert method == "POST"
    assert path == "/api/v1/admin/config/verify"
    assert int(status_code) == 200

    query_obj = json.loads(str(query_json))
    headers_obj = json.loads(str(headers_json))
    body_obj = json.loads(str(body_json))

    assert str(query_obj["token"]).startswith("[REDACTED:sha256:")
    assert query_obj["q"] == "example"
    assert str(headers_obj["authorization"]).startswith("[REDACTED:sha256:")
    assert str(headers_obj["x-api-key"]).startswith("[REDACTED:sha256:")
    assert headers_obj["x-request-id"] == "req-1"
    assert str(body_obj["password"]).startswith("[REDACTED:sha256:")
    assert str(body_obj["nested"]["client_secret"]).startswith("[REDACTED:sha256:")


def test_api_request_audit_control_row_has_created_timestamp(
    tmp_path: Path,
) -> None:
    """Brief: Control table stores a created-at timestamp for allow_delete gate row.

    Inputs:
      - tmp_path: Pytest temporary directory fixture.

    Outputs:
      - None; asserts control row includes a non-empty created timestamp.
    """

    db_path = tmp_path / "control-created-at.sqlite3"
    logger = ApiRequestAuditLogger(enabled=True, db_path=db_path)
    logger.log_event(
        method="GET",
        path="/api/v1/health",
        query={},
        headers={},
        body=None,
        status_code=200,
        duration_ms=1.0,
        client_ip="127.0.0.1",
        error_text=None,
    )

    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            """
            SELECT created_at
            FROM api_request_audit_control
            WHERE key = 'allow_delete'
            """
        ).fetchone()
    finally:
        conn.close()

    assert row is not None
    (created_at,) = row
    assert isinstance(created_at, str)
    assert created_at.strip() != ""


def test_api_request_audit_from_web_cfg_parses_retention_options(
    tmp_path: Path,
) -> None:
    """Brief: from_web_cfg should parse retention and db_path settings.

    Inputs:
      - tmp_path: Pytest temporary directory fixture.

    Outputs:
      - None; asserts logger fields match configured retention values.
    """

    logger = ApiRequestAuditLogger.from_web_cfg(
        {
            "api_request_audit": {
                "enabled": True,
                "db_path": str(tmp_path / "audit.sqlite3"),
                "retention_max_records": 123,
                "retention_max_age_seconds": 600,
                "retention_max_db_bytes": 99999,
                "retention_prune_every_n_inserts": 7,
            }
        }
    )
    assert logger.enabled is True
    assert logger.db_path == (tmp_path / "audit.sqlite3").resolve()
    assert logger.retention_max_records == 123
    assert float(logger.retention_max_age_seconds or 0) == 600.0
    assert logger.retention_max_db_bytes == 99999
    assert logger.retention_prune_every_n_inserts == 7

def test_api_request_audit_from_web_cfg_applies_default_retention_guardrails() -> None:
    """Brief: from_web_cfg applies bounded retention defaults when unset.

    Inputs:
      - None.

    Outputs:
      - None; asserts default record/db-size retention safeguards are enabled.
    """

    logger = ApiRequestAuditLogger.from_web_cfg({})
    assert logger.enabled is True
    assert logger.retention_max_records == int(_DEFAULT_AUDIT_RETENTION_MAX_RECORDS)
    assert logger.retention_max_db_bytes == int(_DEFAULT_AUDIT_RETENTION_MAX_DB_BYTES)
    assert logger.retention_prune_every_n_inserts == int(
        _DEFAULT_AUDIT_RETENTION_PRUNE_EVERY_N_INSERTS
    )


def test_api_request_audit_from_web_cfg_allows_explicit_retention_disable() -> None:
    """Brief: Explicit non-positive retention values disable corresponding defaults.

    Inputs:
      - None.

    Outputs:
      - None; asserts operator-provided disable values take precedence.
    """

    logger = ApiRequestAuditLogger.from_web_cfg(
        {
            "api_request_audit": {
                "enabled": True,
                "retention_max_records": 0,
                "retention_max_db_bytes": 0,
            }
        }
    )
    assert logger.enabled is True
    assert logger.retention_max_records is None
    assert logger.retention_max_db_bytes is None


def test_api_request_audit_retention_max_records_prunes_oldest(
    tmp_path: Path,
) -> None:
    """Brief: Retention max-record policy should prune oldest rows on insert.

    Inputs:
      - tmp_path: Pytest temporary directory fixture.

    Outputs:
      - None; asserts row count is bounded and oldest ids are pruned.
    """

    db_path = tmp_path / "retention.sqlite3"
    logger = ApiRequestAuditLogger(
        enabled=True,
        db_path=db_path,
        retention_max_records=3,
        retention_prune_every_n_inserts=1,
    )
    for idx in range(5):
        logger.log_event(
            method="GET",
            path="/api/v1/health",
            query={"idx": idx},
            headers={},
            body=None,
            status_code=200,
            duration_ms=1.0,
            client_ip="127.0.0.1",
            error_text=None,
        )

    conn = sqlite3.connect(str(db_path))
    try:
        row_count = int(
            conn.execute("SELECT COUNT(*) FROM api_request_audit").fetchone()[0]
        )
        first_id = int(
            conn.execute(
                "SELECT id FROM api_request_audit ORDER BY id ASC LIMIT 1"
            ).fetchone()[0]
        )
        last_id = int(
            conn.execute(
                "SELECT id FROM api_request_audit ORDER BY id DESC LIMIT 1"
            ).fetchone()[0]
        )
    finally:
        conn.close()

    assert row_count == 3
    assert first_id == 3
    assert last_id == 5


def test_api_request_audit_table_is_append_only(tmp_path: Path) -> None:
    """Brief: UPDATE/DELETE against api_request_audit fail due to append-only triggers.

    Inputs:
      - tmp_path: Pytest temporary directory fixture.

    Outputs:
      - None; asserts trigger-enforced write protections.
    """

    db_path = tmp_path / "append-only.sqlite3"
    logger = ApiRequestAuditLogger(enabled=True, db_path=db_path)
    logger.log_event(
        method="GET",
        path="/api/v1/health",
        query={},
        headers={},
        body=None,
        status_code=200,
        duration_ms=1.0,
        client_ip="127.0.0.1",
        error_text=None,
    )

    conn = sqlite3.connect(str(db_path))
    try:
        try:
            conn.execute("UPDATE api_request_audit SET path = '/api/v1/hacked' WHERE id = 1")
            assert False, "UPDATE unexpectedly succeeded"
        except sqlite3.DatabaseError as exc:
            assert "append-only" in str(exc)
        try:
            conn.execute("DELETE FROM api_request_audit WHERE id = 1")
            assert False, "DELETE unexpectedly succeeded"
        except sqlite3.DatabaseError as exc:
            assert "append-only" in str(exc)
    finally:
        conn.close()
