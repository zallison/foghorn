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

    # Call the private helper directly so that we avoid depending on the async
    # worker queue timing in tests.
    backend._insert_query_log(  # type: ignore[attr-defined]
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

    # Directly call the private helper to exercise the health_check() guard in a
    # deterministic way without relying on async processing.
    backend._insert_query_log(  # type: ignore[attr-defined]
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


def test_close_is_idempotent(tmp_path: Path) -> None:
    """Brief: close() can be called multiple times without raising.

    Inputs:
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts repeated close calls keep the backend unhealthy.
    """

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(file_path=str(log_file), async_logging=False)

    backend.close()
    backend.close()

    assert backend.health_check() is False


def test_insert_query_log_handles_invalid_result_json(tmp_path: Path) -> None:
    """Brief: insert_query_log handles malformed result_json defensively.

    Inputs:
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts that invalid JSON does not raise and does not attach a
        result field to the stored record.
    """

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(file_path=str(log_file), async_logging=False)

    # Call the private helper directly so that we deterministically exercise the
    # defensive JSON parsing logic without relying on the async worker queue.
    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=123.0,
        client_ip="203.0.113.1",
        name="bad-json.example",
        qtype="A",
        upstream_id=None,
        rcode=None,
        status=None,
        error=None,
        first=None,
        result_json="{this is not valid json}",
    )

    lines = log_file.read_text(encoding="utf-8").splitlines()
    # First line is the header; second line should be the JSON payload without
    # a "result" field when the result_json is malformed.
    assert len(lines) == 2

    record = json.loads(lines[1])
    assert record["client_ip"] == "203.0.113.1"
    assert "result" not in record


def test_insert_query_log_ignores_non_object_result_json(tmp_path: Path) -> None:
    """Brief: insert_query_log only stores result when parsed payload is a dict.

    Inputs:
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts valid non-object JSON result payloads are ignored.
    """

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(file_path=str(log_file), async_logging=False)

    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=124.0,
        client_ip="203.0.113.2",
        name="non-object.example",
        qtype="A",
        upstream_id=None,
        rcode=None,
        status=None,
        error=None,
        first=None,
        result_json='["1.2.3.4"]',
    )

    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    record = json.loads(lines[1])
    assert record["client_ip"] == "203.0.113.2"
    assert "result" not in record


def test_json_logging_invalid_max_logging_queue_falls_back_to_default(
    tmp_path: Path,
) -> None:
    """Brief: Invalid max_logging_queue values fall back to the default size.

    Inputs:
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts constructor normalization applies default queue capacity.
    """

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(
        file_path=str(log_file),
        async_logging=False,
        max_logging_queue="not-an-int",
    )

    assert backend._max_logging_queue == 16384  # type: ignore[attr-defined]


def test_json_logging_retention_max_records(tmp_path: Path) -> None:
    """Brief: JsonLogging keeps only newest N records when configured.

    Inputs:
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts retention_max_records trims older JSONL records.
    """

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(
        file_path=str(log_file),
        async_logging=False,
        retention_max_records=2,
    )

    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=1.0,
        client_ip="192.0.2.1",
        name="first.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=2.0,
        client_ip="192.0.2.2",
        name="second.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=3.0,
        client_ip="192.0.2.3",
        name="third.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend.close()

    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    meta = json.loads(lines[0])
    assert "log_start" in meta
    kept_names = [json.loads(line)["name"] for line in lines[1:]]
    assert kept_names == ["second.example", "third.example"]


def test_json_logging_retention_max_bytes_keeps_latest_record(tmp_path: Path) -> None:
    """Brief: Byte-cap retention drops oldest records to stay within the cap.

    Inputs:
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts byte-cap retention keeps the newest matching-size row.
    """

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(
        file_path=str(log_file),
        async_logging=False,
        retention_max_bytes=10_000_000,
    )

    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=1.0,
        client_ip="192.0.2.1",
        name="alpha.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )

    lines_after_first = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines_after_first) == 2
    header_line = lines_after_first[0]
    first_row = lines_after_first[1]
    # Cap header + exactly one similarly-sized row.
    backend._query_log_retention_max_bytes = (  # type: ignore[attr-defined]
        len(header_line.encode("utf-8")) + 1 + len(first_row.encode("utf-8")) + 1
    )

    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=2.0,
        client_ip="192.0.2.2",
        name="bravo.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend.close()

    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["name"] == "bravo.example"


def test_json_logging_retention_prune_every_n_inserts(tmp_path: Path) -> None:
    """Brief: Prune cadence can defer retention until N inserts are observed.

    Inputs:
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts max-record prune runs only on configured insert cadence.
    """

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(
        file_path=str(log_file),
        async_logging=False,
        retention_max_records=1,
        retention_prune_every_n_inserts=3,
    )

    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=1.0,
        client_ip="192.0.2.1",
        name="first.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=2.0,
        client_ip="192.0.2.2",
        name="second.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    # Not yet at insert #3, so retention should still be deferred.
    mid_lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(mid_lines) == 3

    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=3.0,
        client_ip="192.0.2.3",
        name="third.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend.close()

    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["name"] == "third.example"


def test_json_logging_retention_days(monkeypatch, tmp_path: Path) -> None:
    """Brief: JsonLogging prunes records older than the retention_days cutoff.

    Inputs:
        monkeypatch: pytest monkeypatch fixture.
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts old JSONL records are removed by days-based retention.
    """

    import foghorn.plugins.querylog.json_logging as json_logging_mod

    now_ts = 15.0 * 86400.0
    monkeypatch.setattr(json_logging_mod.time, "time", lambda: now_ts)

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(
        file_path=str(log_file),
        async_logging=False,
        retention_days=2.0,
    )
    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=now_ts - (3.0 * 86400.0),
        client_ip="198.51.100.1",
        name="old.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=now_ts - 86400.0,
        client_ip="198.51.100.2",
        name="fresh.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend.close()

    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    kept = json.loads(lines[1])
    assert kept["name"] == "fresh.example"


def test_json_logging_retention_days_and_max_records(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Brief: JsonLogging applies days and max-record retention together.

    Inputs:
        monkeypatch: pytest monkeypatch fixture.
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts combined retention keeps only recent newest records.
    """

    import foghorn.plugins.querylog.json_logging as json_logging_mod

    now_ts = 30.0 * 86400.0
    monkeypatch.setattr(json_logging_mod.time, "time", lambda: now_ts)

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(
        file_path=str(log_file),
        async_logging=False,
        retention_days=4.0,
        retention_max_records=2,
    )
    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=now_ts - (10.0 * 86400.0),
        client_ip="203.0.113.1",
        name="expired.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=now_ts - (3.0 * 86400.0),
        client_ip="203.0.113.2",
        name="older.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=now_ts - (2.0 * 86400.0),
        client_ip="203.0.113.3",
        name="newer.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend._insert_query_log(  # type: ignore[attr-defined]
        ts=now_ts - 86400.0,
        client_ip="203.0.113.4",
        name="newest.example",
        qtype="A",
        upstream_id=None,
        rcode="NOERROR",
        status="ok",
        error=None,
        first=None,
        result_json="{}",
    )
    backend.close()

    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    kept_names = [json.loads(line)["name"] for line in lines[1:]]
    assert kept_names == ["newer.example", "newest.example"]


def test_json_logging_retention_days_keeps_malformed_and_missing_ts_lines(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Brief: Days retention keeps malformed and missing-ts lines defensively.

    Inputs:
        monkeypatch: pytest monkeypatch fixture.
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts old ts rows are pruned while malformed/no-ts rows remain.
    """

    import foghorn.plugins.querylog.json_logging as json_logging_mod

    now_ts = 40.0 * 86400.0
    monkeypatch.setattr(json_logging_mod.time, "time", lambda: now_ts)

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(
        file_path=str(log_file),
        async_logging=False,
        retention_days=2.0,
    )

    header = log_file.read_text(encoding="utf-8").splitlines()[0]
    old_line = json.dumps(
        {"ts": now_ts - (5.0 * 86400.0), "name": "old.example"},
        separators=(",", ":"),
    )
    malformed_line = '{"name":"malformed.example"'
    no_ts_line = json.dumps({"name": "missing-ts.example"}, separators=(",", ":"))
    fresh_line = json.dumps(
        {"ts": now_ts - 1800.0, "name": "fresh.example"},
        separators=(",", ":"),
    )
    log_file.write_text(
        "\n".join([header, old_line, malformed_line, no_ts_line, "", fresh_line])
        + "\n",
        encoding="utf-8",
    )

    with backend._io_lock:  # type: ignore[attr-defined]
        backend._apply_query_log_retention_locked()  # type: ignore[attr-defined]
    backend.close()

    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert lines == [header, malformed_line, no_ts_line, fresh_line]


def test_json_logging_retention_max_records_without_header_marker(
    tmp_path: Path,
) -> None:
    """Brief: Max-record retention works when first line is JSON without log_start.

    Inputs:
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts first-line JSON without a header marker is treated as data.
    """

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(
        file_path=str(log_file),
        async_logging=False,
        retention_max_records=2,
    )

    lines_in = [
        json.dumps({"name": "first.example"}, separators=(",", ":")),
        json.dumps({"name": "second.example"}, separators=(",", ":")),
        json.dumps({"name": "third.example"}, separators=(",", ":")),
    ]
    log_file.write_text("\n".join(lines_in) + "\n", encoding="utf-8")

    with backend._io_lock:  # type: ignore[attr-defined]
        backend._apply_query_log_retention_locked()  # type: ignore[attr-defined]
    backend.close()

    lines = log_file.read_text(encoding="utf-8").splitlines()
    kept_names = [json.loads(line)["name"] for line in lines]
    assert kept_names == ["second.example", "third.example"]


def test_json_logging_retention_returns_early_for_empty_log_file(
    tmp_path: Path,
) -> None:
    """Brief: Retention no-ops when the log file is empty.

    Inputs:
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts empty files remain empty during retention compaction.
    """

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(
        file_path=str(log_file),
        async_logging=False,
        retention_max_records=1,
    )

    log_file.write_text("", encoding="utf-8")

    with backend._io_lock:  # type: ignore[attr-defined]
        backend._apply_query_log_retention_locked()  # type: ignore[attr-defined]
    backend.close()

    assert log_file.read_text(encoding="utf-8") == ""


def test_json_logging_retention_max_records_tolerates_malformed_first_line(
    tmp_path: Path,
) -> None:
    """Brief: Retention treats malformed first line as data when no header is found.

    Inputs:
        tmp_path: pytest-provided temporary directory path.

    Outputs:
        None; asserts malformed leading content does not break max-record prune.
    """

    log_file = tmp_path / "queries.jsonl"
    backend = JsonLogging(
        file_path=str(log_file),
        async_logging=False,
        retention_max_records=2,
    )

    malformed_line = '{"name":"broken-first-line"'
    lines_in = [
        malformed_line,
        json.dumps({"name": "second.example"}, separators=(",", ":")),
        json.dumps({"name": "third.example"}, separators=(",", ":")),
    ]
    log_file.write_text("\n".join(lines_in) + "\n", encoding="utf-8")

    with backend._io_lock:  # type: ignore[attr-defined]
        backend._apply_query_log_retention_locked()  # type: ignore[attr-defined]
    backend.close()

    lines = log_file.read_text(encoding="utf-8").splitlines()
    kept_names = [json.loads(line)["name"] for line in lines]
    assert kept_names == ["second.example", "third.example"]
