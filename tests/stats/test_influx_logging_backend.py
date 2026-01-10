"""Brief: Tests for the InfluxDB logging-only BaseStatsStore implementation.

Inputs:
  - None; uses a fake requests.Session injected via monkeypatch.

Outputs:
  - None; pytest assertions validate constructor behavior, health/close
    semantics, helper formatting, and insert_query_log posting.
"""

from __future__ import annotations

import json
import types
from typing import Any, Dict, List

import pytest

from foghorn.plugins.querylog.influxdb import (
    InfluxLogging,
    _format_line_protocol,
)


class _FakeResponse:
    """Brief: Minimal fake HTTP response used by the fake Session.

    Inputs:
      - status_code: Integer HTTP status code.
      - text: Response body text.

    Outputs:
      - Object exposing status_code and text attributes.
    """

    def __init__(self, status_code: int = 204, text: str = "") -> None:
        self.status_code = int(status_code)
        self.text = text


class _FakeSession:
    """Brief: Fake requests.Session capturing post() calls for assertions.

    Inputs:
      - **kwargs: Arbitrary keyword arguments from Session construction.

    Outputs:
      - Session-like object with post() and close() methods.
    """

    def __init__(self, **kwargs: Any) -> None:  # pragma: no cover - trivial init
        self.kwargs = dict(kwargs)
        self.posts: List[Dict[str, Any]] = []
        self.closed = False
        self.next_response: _FakeResponse = _FakeResponse()

    def post(
        self,
        url: str,
        params: Dict[str, Any] | None = None,
        data: bytes | str | None = None,
        headers: Dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> _FakeResponse:
        """Brief: Record a POST request and return the configured response.

        Inputs:
          - url: Request URL.
          - params: Query parameters mapping.
          - data: Request body (bytes or string).
          - headers: Request headers mapping.
          - timeout: Timeout value.

        Outputs:
          - _FakeResponse instance configured on the session.
        """

        record = {
            "url": url,
            "params": dict(params or {}),
            "data": data,
            "headers": dict(headers or {}),
            "timeout": timeout,
        }
        self.posts.append(record)
        return self.next_response

    def close(self) -> None:
        """Brief: Mark the session as closed for later assertions.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        self.closed = True


def test_format_line_protocol_includes_tags_fields_and_timestamp() -> None:  # type: ignore[no-untyped-def]
    """Brief: _format_line_protocol escapes tags/fields and appends ns timestamp.

    Inputs:
      - None.

    Outputs:
      - None; asserts key substrings are present in the formatted line.
    """

    line = _format_line_protocol(
        measurement="m name",
        tags={"host": "example.com", "rc": "NO ERROR"},
        fields={"v": 1, "ok": True, "msg": "hi there"},
        ts=123.0,
    )

    # Measurement and tags should be escaped.
    assert line.startswith("m\\ name,host=example.com,rc=NO\\ ERROR ")
    # Fields should contain integer, boolean, and string representations.
    assert "v=1i" in line
    assert "ok=true" in line
    assert 'msg="hi there"' in line
    # Final token should be an integer nanosecond timestamp.
    ns_str = line.rsplit(" ", 1)[-1]
    assert ns_str.isdigit()
    assert int(ns_str) == 123_000_000_000


def test_influx_logging_constructor_posts_start_marker_and_is_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: Constructor wires a fake Session and posts a log_start marker.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - None; asserts a POST is made on construction and health_check is True.
    """

    import foghorn.plugins.querylog.influxdb as influx_mod

    _FakeSession()

    def _session_factory(**kwargs: Any) -> _FakeSession:  # type: ignore[no-untyped-def]
        return _FakeSession(**kwargs)

    monkeypatch.setattr(
        influx_mod, "requests", types.SimpleNamespace(Session=_session_factory)
    )

    backend = InfluxLogging(
        write_url="http://influx.local/write",
        org="org1",
        bucket="bucket1",
        precision="ns",
        token="tok",
        timeout=1.5,
    )

    assert backend.health_check() is True
    # The constructor should have issued exactly one POST for the meta marker.
    session = backend._session  # type: ignore[attr-defined]
    assert isinstance(session, _FakeSession)
    assert len(session.posts) == 1
    rec = session.posts[0]
    assert rec["url"] == "http://influx.local/write"
    assert rec["params"]["precision"] == "ns"
    assert rec["params"]["org"] == "org1"
    assert rec["params"]["bucket"] == "bucket1"
    assert rec["headers"].get("Authorization") == "Token tok"


def test_influx_logging_close_marks_unhealthy_and_closes_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: close() closes the underlying session and flips the healthy flag.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - None; asserts health_check transitions from True to False and session
        close() is invoked.
    """

    import types as _types
    import foghorn.plugins.querylog.influxdb as influx_mod

    def _session_factory(**kwargs: Any) -> _FakeSession:  # type: ignore[no-untyped-def]
        return _FakeSession(**kwargs)

    monkeypatch.setattr(
        influx_mod, "requests", _types.SimpleNamespace(Session=_session_factory)
    )

    backend = InfluxLogging(write_url="http://influx")
    session = backend._session  # type: ignore[attr-defined]
    assert isinstance(session, _FakeSession)
    assert backend.health_check() is True
    backend.close()
    assert backend.health_check() is False
    assert session.closed is True


def test_insert_query_log_posts_line_protocol_and_parses_result_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # type: ignore[no-untyped-def]
    """Brief: insert_query_log serializes tags/fields into line protocol.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - None; asserts a second POST is made with expected line content and that
        dnssec_status is included when present in result_json.
    """

    import types as _types
    import foghorn.plugins.querylog.influxdb as influx_mod

    def _session_factory(**kwargs: Any) -> _FakeSession:  # type: ignore[no-untyped-def]
        return _FakeSession(**kwargs)

    monkeypatch.setattr(
        influx_mod, "requests", _types.SimpleNamespace(Session=_session_factory)
    )

    backend = InfluxLogging(write_url="http://influx")
    session = backend._session  # type: ignore[attr-defined]

    payload = {"dnssec_status": "dnssec_secure"}
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

    # Wait for any queued operations in the async worker to complete so that
    # the underlying _insert_query_log implementation has a chance to run.
    op_queue = getattr(backend, "_op_queue", None)
    if op_queue is not None:
        op_queue.join()

    # Expect two posts total: one meta marker from __init__ and one data point.
    assert len(session.posts) == 2
    line = (
        session.posts[1]["data"].decode("utf-8")
        if isinstance(session.posts[1]["data"], bytes)
        else session.posts[1]["data"]
    )
    assert line.startswith("foghorn_query_log,")
    # Tags
    assert "client_ip=192.0.2.1" in line
    assert "qtype=A" in line
    assert "upstream_id=up-1" in line
    assert "rcode=NOERROR" in line
    assert "status=ok" in line
    # Fields
    assert "count=1i" in line
    assert 'name="example.com"' in line
    assert 'first="1.2.3.4"' in line
    assert 'dnssec_status="dnssec_secure"' in line


def test_insert_query_log_marks_unhealthy_on_http_error(monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    """Brief: HTTP error responses keep logging but do not flip healthy flag.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - None; asserts that a 5xx response is logged but backend remains healthy
        so subsequent calls still attempt writes.
    """

    import types as _types
    import foghorn.plugins.querylog.influxdb as influx_mod

    class _ErrorSession(_FakeSession):
        def __init__(self, **kwargs: Any) -> None:  # type: ignore[no-untyped-def]
            super().__init__(**kwargs)
            self.next_response = _FakeResponse(status_code=500, text="boom")

    def _session_factory(**kwargs: Any) -> _ErrorSession:  # type: ignore[no-untyped-def]
        return _ErrorSession(**kwargs)

    monkeypatch.setattr(
        influx_mod, "requests", _types.SimpleNamespace(Session=_session_factory)
    )

    backend = InfluxLogging(write_url="http://influx")
    session = backend._session  # type: ignore[attr-defined]

    backend.insert_query_log(
        ts=0.0,
        client_ip="203.0.113.1",
        name="err.example",
        qtype="AAAA",
        upstream_id=None,
        rcode=None,
        status=None,
        error=None,
        first=None,
        result_json="{}",
    )

    # A second POST should have been attempted despite the HTTP 500 response.
    assert len(session.posts) == 2
    assert backend.health_check() is True


def test_insert_query_log_returns_early_when_unhealthy(monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    """Brief: insert_query_log is a no-op once the backend has been closed.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - None; asserts no additional POSTs occur after close(), beyond the
        construction-time meta marker.
    """

    import types as _types
    import foghorn.plugins.querylog.influxdb as influx_mod

    def _session_factory(**kwargs: Any) -> _FakeSession:  # type: ignore[no-untyped-def]
        return _FakeSession(**kwargs)

    monkeypatch.setattr(
        influx_mod, "requests", _types.SimpleNamespace(Session=_session_factory)
    )

    backend = InfluxLogging(write_url="http://influx")
    session = backend._session  # type: ignore[attr-defined]
    initial_posts = list(session.posts)

    backend.close()
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

    assert session.posts == initial_posts
