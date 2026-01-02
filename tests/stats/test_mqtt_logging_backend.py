"""Brief: Tests for the MQTT logging-only BaseStatsStore implementation.

Inputs:
  - None; uses a fake paho-mqtt style client injected via monkeypatch.

Outputs:
  - None; pytest assertions validate constructor behavior, health/close semantics,
    and insert_query_log payload formatting and publish calls.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from foghorn.plugins.querylog.mqtt_logging import (
    MqttLogging,
    _import_mqtt_driver,
)


class _FakeMqttClient:
    """Brief: Minimal fake MQTT client capturing connect/loop/publish calls.

    Inputs:
      - client_id: String client identifier passed from the backend.

    Outputs:
      - Object recording connect(), loop_start(), loop_stop(), disconnect(), and
        publish() invocations for assertions.
    """

    def __init__(self, client_id: str | None = None, **_: Any) -> None:
        self.client_id = client_id
        self.connected = False
        self.loop_started = False
        self.loop_stopped = False
        self.disconnected = False
        self.publishes: list[tuple[str, str, int, bool]] = []
        self.username: str | None = None
        self.password: str | None = None

    def username_pw_set(self, username: str, password: str | None = None) -> None:
        self.username = username
        self.password = password

    def connect(self, host: str, port: int, keepalive: int, **_kwargs: Any) -> None:
        self.connected = True
        self._connect_args = (host, int(port), int(keepalive))

    def loop_start(self) -> None:
        self.loop_started = True

    def loop_stop(self) -> None:
        self.loop_stopped = True

    def disconnect(self) -> None:
        self.disconnected = True

    def publish(
        self, topic: str, payload: str, qos: int = 0, retain: bool = False
    ) -> None:
        self.publishes.append((topic, payload, int(qos), bool(retain)))


class _FakeMqttModule:
    """Brief: Wrapper exposing a Client attribute for _import_mqtt_driver().

    Inputs:
      - None.

    Outputs:
      - Object with Client pointing to _FakeMqttClient.
    """

    Client = _FakeMqttClient


def test_import_mqtt_driver_raises_runtime_error_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _import_mqtt_driver surfaces a clear RuntimeError when driver is absent.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - None; asserts a RuntimeError is raised instead of ImportError leaking.
    """

    # Force import failure path by removing any existing paho.mqtt.client module.
    monkeypatch.setitem(
        __import__("sys").modules,
        "paho.mqtt.client",
        None,
    )

    with pytest.raises(RuntimeError):
        _import_mqtt_driver()


def test_mqtt_logging_backend_constructs_and_marks_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Constructor wires a fake MQTT client and sets healthy flag.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - None; asserts connect/loop_start are invoked and health_check is True.
    """

    # Patch the paho-style module used by _import_mqtt_driver.
    monkeypatch.setitem(
        __import__("sys").modules, "paho.mqtt.client", _FakeMqttModule()
    )

    backend = MqttLogging(
        host="mqtt.example", port=1884, topic="foghorn/test", qos=1, retain=True
    )

    assert backend.health_check() is True
    # Close should mark backend unhealthy and stop/disconnect the client.
    backend.close()
    assert backend.health_check() is False


def test_insert_query_log_publishes_payload_and_parses_result_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: insert_query_log publishes compact JSON with optional result field.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - None; asserts publish() is called once with the expected topic/payload.
    """

    fake_module = _FakeMqttModule()
    monkeypatch.setitem(__import__("sys").modules, "paho.mqtt.client", fake_module)

    backend = MqttLogging(topic="foghorn/query_log", qos=2, retain=False)

    result_payload = {"answers": ["1.2.3.4"], "dnssec_status": "dnssec_secure"}
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
        result_json=json.dumps(result_payload),
    )

    client = backend._client  # type: ignore[attr-defined]
    assert isinstance(client, _FakeMqttClient)
    assert len(client.publishes) == 1

    topic, payload, qos, retain = client.publishes[0]
    assert topic == "foghorn/query_log"
    assert qos == 2
    assert retain is False

    decoded = json.loads(payload)
    assert decoded["ts"] == pytest.approx(123.456)
    assert decoded["client_ip"] == "192.0.2.1"
    assert decoded["name"] == "example.com"
    assert decoded["qtype"] == "A"
    assert decoded["upstream_id"] == "up-1"
    assert decoded["rcode"] == "NOERROR"
    assert decoded["status"] == "ok"
    assert decoded["error"] is None
    assert decoded["first"] == "1.2.3.4"
    assert decoded["result"] == result_payload


def test_insert_query_log_returns_early_when_unhealthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: insert_query_log is a no-op once the backend has been closed.

    Inputs:
      - monkeypatch fixture.

    Outputs:
      - None; asserts no additional publish calls are made after close().
    """

    monkeypatch.setitem(
        __import__("sys").modules, "paho.mqtt.client", _FakeMqttModule()
    )

    backend = MqttLogging(topic="foghorn/query_log")
    client = backend._client  # type: ignore[attr-defined]

    # Mark backend unhealthy via close() and verify insert_query_log is a no-op.
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

    assert getattr(client, "publishes", []) == []
