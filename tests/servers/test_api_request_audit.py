"""Tests for append-only API request audit logging with redaction."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from foghorn.servers.webserver.api_request_audit import ApiRequestAuditLogger


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
