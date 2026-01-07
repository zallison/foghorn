"""Brief: Tests for the JSON file logging-only BaseStatsStore implementation.

Inputs:
  - None; uses a temporary directory provided by pytest's tmp_path fixture.

Outputs:
  - None; pytest assertions validate constructor behaviour, header line format,
    append-only JSON logging, and health/close semantics.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from foghorn.plugins.querylog.json_logging import JsonLogging
from foghorn.stats import FOGHORN_VERSION


def test_json_logging_creates_directory_and_writes_header(tmp_path: Path) -> None:
    """Brief: Constructor creates parent directory and writes a start header.

    Inputs:
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts the log file exists with a header line containing the
        Foghorn version and a JSON start marker string.
    """

    log_dir = tmp_path / "logs" / "nested"
    log_file = log_dir / "queries.jsonl"

    backend = JsonLogging(file_path=str(log_file), async_logging=False)

    assert backend.health_check() is True
    assert log_file.exists()

    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 1

    meta = json.loads(lines[0])
    assert meta["version"] == f"v{FOGHORN_VERSION}"
    assert "log_start" in meta
    assert "hostname" in meta
    assert isinstance(meta["hostname"], str) and meta["hostname"]


def test_insert_query_log_appends_single_json_line(tmp_path: Path) -> None:
    """Brief: insert_query_log appends a compact JSON record to the file.

    Inputs:
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts the second line in the log file is valid JSON containing
        the expected fields and parsed result payload.
    """

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(file_path=str(log_file), async_logging=False)

    payload = {"answers": ["1.2.3.4"], "dnssec_status": "dnssec_secure"}

    backend.insert_query_log(
        ts=123.456,
        client_ip="192.0.2.1",
        name="example.com",
        qtype="A",
        upstream_id="up-1",
        rcode="NOERROR",
        status="ok",
        error=None,
        first="1.2.3.4",
        result_json=json.dumps(payload),
    )

    lines = log_file.read_text(encoding="utf-8").splitlines()
    # First line is the header; second line should be the JSON payload.
    assert len(lines) == 2

    record = json.loads(lines[1])
    assert record["ts"] == pytest.approx(123.456)
    assert record["client_ip"] == "192.0.2.1"
    assert record["name"] == "example.com"
    assert record["qtype"] == "A"
    assert record["upstream_id"] == "up-1"
    assert record["rcode"] == "NOERROR"
    assert record["status"] == "ok"
    assert record["error"] is None
    assert record["first"] == "1.2.3.4"
    assert record["result"] == payload


def test_insert_query_log_is_noop_when_unhealthy(tmp_path: Path) -> None:
    """Brief: insert_query_log becomes a no-op after the backend is closed.

    Inputs:
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts that closing the backend prevents additional lines from
        being appended beyond the initial header.
    """

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(file_path=str(log_file), async_logging=False)

    # Capture initial contents (header line) and then close the backend.
    initial_lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(initial_lines) == 1

    backend.close()
    assert backend.health_check() is False

    backend.insert_query_log(
        ts=0.0,
        client_ip="198.51.100.1",
        name="test.example",
        qtype="A",
        upstream_id=None,
        rcode=None,
        status=None,
        error=None,
        first=None,
        result_json="{}",
    )

    # No additional lines should have been added after close().
    final_lines = log_file.read_text(encoding="utf-8").splitlines()
    assert final_lines == initial_lines
