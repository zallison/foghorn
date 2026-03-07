"""Branch-focused tests for upstream health payload helpers.

Brief:
  Exercise non-trivial branches in _UpstreamHealth.upstream_id() and
  _UpstreamHealth.describe_upstream(), including defensive fallback paths.

Inputs:
  - _UPSTREAM_HEALTH singleton and DNSRuntimeState shared health map.

Outputs:
  - Assertions that branch outcomes match expected ids, state, and payload shape.
"""

from __future__ import annotations

from collections.abc import Iterable

import pytest

from foghorn.servers.dns_runtime_state import DNSRuntimeState
from foghorn.servers.server_upstream_health import _UPSTREAM_HEALTH


class RaisingGetDict(dict):
    """Brief: Dict test helper that can raise for selected keys.

    Inputs:
      - args/kwargs: Standard dict constructor values.
      - raise_keys: Iterable of keys that should raise in get().

    Outputs:
      - Mapping object with deterministic get() exception behavior.
    """

    def __init__(self, *args, raise_keys: Iterable[str] = (), **kwargs) -> None:
        """Brief: Initialize storage and key-specific failure behavior.

        Inputs:
          - *args/**kwargs: Values forwarded to dict.__init__.
          - raise_keys: Keys that should raise when queried via get().

        Outputs:
          - None.
        """

        super().__init__(*args, **kwargs)
        self._raise_keys = set(raise_keys)

    def get(self, key, default=None):  # noqa: ANN001,ANN201
        """Brief: Return key value or raise for configured keys.

        Inputs:
          - key: Key to retrieve.
          - default: Fallback value for missing keys.

        Outputs:
          - Value for key/default, unless key is configured to raise.
        """

        if key in self._raise_keys:
            raise RuntimeError(f"boom:{key}")
        return super().get(key, default)


@pytest.fixture(autouse=True)
def clear_upstream_health_state() -> None:
    """Brief: Reset shared upstream health state around each test.

    Inputs:
      - None.

    Outputs:
      - None; DNSRuntimeState.upstream_health is cleared before/after test.
    """

    DNSRuntimeState.upstream_health.clear()
    yield
    DNSRuntimeState.upstream_health.clear()


def test_upstream_id_returns_empty_for_non_dict() -> None:
    """Brief: upstream_id() returns empty identifier for non-mapping input.

    Inputs:
      - Non-dict upstream value.

    Outputs:
      - Empty string identifier.
    """

    assert _UPSTREAM_HEALTH.upstream_id("not-a-dict") == ""


def test_upstream_id_prefers_dns_udp_handler_id(monkeypatch) -> None:
    """Brief: upstream_id() returns DNSRuntimeState._upstream_id result when set.

    Inputs:
      - monkeypatch replacing DNSRuntimeState._upstream_id.

    Outputs:
      - Stringified handler-provided upstream id.
    """

    monkeypatch.setattr(DNSRuntimeState, "_upstream_id", staticmethod(lambda _u: 123))
    assert _UPSTREAM_HEALTH.upstream_id({"host": "1.1.1.1", "port": 53}) == "123"


@pytest.mark.parametrize(
    ("upstream", "expected"),
    [
        (
            {"url": "https://resolver.example/dns-query"},
            "https://resolver.example/dns-query",
        ),
        (
            {"endpoint": "https://resolver.example/dns-query"},
            "https://resolver.example/dns-query",
        ),
        ({"host": "8.8.8.8", "port": "53"}, "8.8.8.8:53"),
        ({"host": "8.8.8.8", "port": "bad"}, "8.8.8.8"),
        ({"port": 53}, "None:53"),
        ({}, ""),
    ],
)
def test_upstream_id_fallback_shapes(
    monkeypatch, upstream: dict, expected: str
) -> None:
    """Brief: upstream_id() fallback branches derive id from url/endpoint/host/port.

    Inputs:
      - monkeypatch forcing DNSRuntimeState._upstream_id to return empty.
      - upstream: Config shape driving fallback path.

    Outputs:
      - Expected fallback identifier.
    """

    monkeypatch.setattr(DNSRuntimeState, "_upstream_id", staticmethod(lambda _u: ""))
    assert _UPSTREAM_HEALTH.upstream_id(upstream) == expected


def test_upstream_id_handles_handler_and_get_exceptions(monkeypatch) -> None:
    """Brief: upstream_id() tolerates handler/get errors and returns empty id.

    Inputs:
      - monkeypatch forcing DNSRuntimeState._upstream_id to raise.
      - RaisingGetDict that raises for url/endpoint/host/port keys.

    Outputs:
      - Empty identifier without propagating exceptions.
    """

    def _raise(_u: dict) -> str:
        raise RuntimeError("boom")

    monkeypatch.setattr(DNSRuntimeState, "_upstream_id", staticmethod(_raise))
    upstream = RaisingGetDict(
        {"host": "x", "port": 53}, raise_keys=("url", "endpoint", "host", "port")
    )
    assert _UPSTREAM_HEALTH.upstream_id(upstream) == ""


def test_describe_upstream_returns_none_for_non_dict() -> None:
    """Brief: describe_upstream() returns None for invalid upstream type.

    Inputs:
      - Non-dict upstream value.

    Outputs:
      - None.
    """

    assert (
        _UPSTREAM_HEALTH.describe_upstream(role="primary", upstream="bad", now=1000.0, cfg=None)  # type: ignore[arg-type]
        is None
    )


def test_describe_upstream_default_up_state_and_udp_inference() -> None:
    """Brief: describe_upstream() defaults to up state and udp transport.

    Inputs:
      - Upstream with host/port and no health entry.

    Outputs:
      - state='up', fail_count=0, down_until=None, transport='udp'.
    """

    record = _UPSTREAM_HEALTH.describe_upstream(
        role="primary",
        upstream={"host": "1.1.1.1", "port": 53},
        now=1000.0,
        cfg=None,
    )
    assert record is not None
    assert record["state"] == "up"
    assert record["fail_count"] == 0.0
    assert record["down_until"] is None
    assert record["transport"] == "udp"
    assert record["port"] == 53


def test_describe_upstream_infers_doh_transport_from_url() -> None:
    """Brief: describe_upstream() infers DoH transport when url is configured.

    Inputs:
      - URL-based upstream without explicit transport.

    Outputs:
      - transport='doh' and url echoed into payload.
    """

    record = _UPSTREAM_HEALTH.describe_upstream(
        role="primary",
        upstream={"url": "https://resolver.example/dns-query"},
        now=1000.0,
        cfg=None,
    )
    assert record is not None
    assert record["transport"] == "doh"
    assert record["url"] == "https://resolver.example/dns-query"


@pytest.mark.parametrize(
    ("health_entry", "expected_state", "expected_down_until"),
    [
        ({"fail_count": 3.0, "down_until": 1010.0}, "down", 1010.0),
        ({"fail_count": 2.0, "down_until": 999.0}, "degraded", None),
    ],
)
def test_describe_upstream_health_state_transitions(
    health_entry: dict[str, float],
    expected_state: str,
    expected_down_until: float | None,
) -> None:
    """Brief: describe_upstream() computes down/degraded from health entry.

    Inputs:
      - health_entry with fail_count/down_until values.

    Outputs:
      - Expected state and down_until payload fields.
    """

    upstream = {"host": "9.9.9.9", "port": 53}
    up_id = _UPSTREAM_HEALTH.upstream_id(upstream)
    DNSRuntimeState.upstream_health[up_id] = health_entry

    record = _UPSTREAM_HEALTH.describe_upstream(
        role="backup",
        upstream=upstream,
        now=1000.0,
        cfg=None,
    )

    assert record is not None
    assert record["state"] == expected_state
    assert record["down_until"] == expected_down_until


def test_describe_upstream_handles_non_dict_or_corrupt_health_entry() -> None:
    """Brief: describe_upstream() ignores malformed health values defensively.

    Inputs:
      - Non-dict health entry and dict health entry with unparseable values.

    Outputs:
      - Payload remains in up state with fail_count/down_until defaults.
    """

    upstream = {"host": "4.4.4.4", "port": 53}
    up_id = _UPSTREAM_HEALTH.upstream_id(upstream)

    DNSRuntimeState.upstream_health[up_id] = "not-a-dict"
    rec1 = _UPSTREAM_HEALTH.describe_upstream(
        role="primary",
        upstream=upstream,
        now=1000.0,
        cfg=None,
    )
    assert rec1 is not None
    assert rec1["state"] == "up"
    assert rec1["fail_count"] == 0.0
    assert rec1["down_until"] is None

    DNSRuntimeState.upstream_health[up_id] = {"fail_count": "bad", "down_until": "bad"}
    rec2 = _UPSTREAM_HEALTH.describe_upstream(
        role="primary",
        upstream=upstream,
        now=1000.0,
        cfg=None,
    )
    assert rec2 is not None
    assert rec2["state"] == "up"
    assert rec2["fail_count"] == 0.0
    assert rec2["down_until"] is None


def test_describe_upstream_handles_transport_host_port_url_get_exceptions() -> None:
    """Brief: describe_upstream() handles selected get() exceptions defensively.

    Inputs:
      - Dict raising for host/port/transport keys.
      - Dict raising for url/endpoint keys with explicit transport.

    Outputs:
      - First payload falls back to udp with None host/port.
      - Second payload keeps explicit transport with None url.
    """

    upstream1 = RaisingGetDict(
        {"url": "https://resolver.example/dns-query"},
        raise_keys=("host", "port", "transport"),
    )
    rec1 = _UPSTREAM_HEALTH.describe_upstream(
        role="primary",
        upstream=upstream1,
        now=1000.0,
        cfg=None,
    )
    assert rec1 is not None
    assert rec1["host"] is None
    assert rec1["port"] is None
    assert rec1["transport"] == "doh"

    upstream2 = RaisingGetDict(
        {"host": "1.1.1.1", "port": 53, "transport": "udp"},
        raise_keys=("url", "endpoint"),
    )
    rec2 = _UPSTREAM_HEALTH.describe_upstream(
        role="backup",
        upstream=upstream2,
        now=1000.0,
        cfg=None,
    )
    assert rec2 is not None
    assert rec2["transport"] == "udp"
    assert rec2["url"] is None


def test_describe_upstream_empty_upstream_exercises_id_recompute_branch() -> None:
    """Brief: describe_upstream() recomputes id when initial upstream id is empty.

    Inputs:
      - Empty upstream dict.

    Outputs:
      - Record is returned with empty id and default up-state fields.
    """

    record = _UPSTREAM_HEALTH.describe_upstream(
        role="primary",
        upstream={},
        now=1000.0,
        cfg=None,
    )
    assert record is not None
    assert record["id"] == ""
    assert record["state"] == "up"
    assert record["config"] == {}


def test_describe_upstream_raises_for_unparseable_port() -> None:
    """Brief: describe_upstream() raises when port cannot be coerced to int.

    Inputs:
      - Upstream with non-numeric port string.

    Outputs:
      - ValueError raised during payload shaping.
    """

    with pytest.raises(ValueError):
        _UPSTREAM_HEALTH.describe_upstream(
            role="primary",
            upstream={"host": "1.1.1.1", "port": "bad", "transport": "udp"},
            now=1000.0,
            cfg=None,
        )
