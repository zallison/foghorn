"""
Brief: Tests for foghorn.plugins.querylog.mqtt_logging.MqttLogging.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import json
import types

import pytest


def _install_fake_paho_client(monkeypatch):
    """Brief: Install a fake paho.mqtt.client module for testing.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - fake_client_cls: The fake Client class used in the test.
    """

    publishes = []

    class FakeClient:  # type: ignore[too-many-instance-attributes]
        def __init__(self, *_, **__):  # type: ignore[no-untyped-def]
            self.publishes = publishes

        def username_pw_set(self, *_, **__):  # type: ignore[no-untyped-def]
            return None

        def connect(self, *_, **__):  # type: ignore[no-untyped-def]
            return 0

        def loop_start(self):  # type: ignore[no-untyped-def]
            return None

        def publish(self, topic, payload, qos=0, retain=False):  # type: ignore[no-untyped-def]
            self.publishes.append((topic, payload, qos, retain))
            return None

        def loop_stop(self):  # type: ignore[no-untyped-def]
            return None

        def disconnect(self):  # type: ignore[no-untyped-def]
            return None

    fake_module = types.SimpleNamespace(Client=FakeClient)

    import sys

    monkeypatch.setitem(sys.modules, "paho.mqtt.client", fake_module)
    return FakeClient, publishes


def test_mqtt_logging_publishes_log_start_on_connect(monkeypatch):
    """Brief: MqttLogging publishes a log_start marker to the meta topic.

    Inputs:
      - monkeypatch: pytest fixture to install fake MQTT client and hostname.

    Outputs:
      - None; asserts one publish to f"{topic}/meta" with expected payload fields
        and qos/retain values.
    """

    FakeClient, publishes = _install_fake_paho_client(monkeypatch)

    # Make hostname deterministic for the payload assertion.
    import socket

    monkeypatch.setattr(socket, "gethostname", lambda: "test-host")

    from foghorn.plugins.querylog.mqtt_logging import MqttLogging

    logger = MqttLogging(topic="foghorn/query_log", qos=1, retain=True)

    assert isinstance(logger._client, FakeClient)  # type: ignore[attr-defined]
    assert len(publishes) == 1

    topic, payload, qos, retain = publishes[0]
    assert topic == "foghorn/query_log/meta"
    assert qos == 1
    assert retain is True

    decoded = json.loads(payload)
    assert decoded["event"] == "log_start"
    assert decoded["version"] == 1
    assert decoded["hostname"] == "test-host"
    assert isinstance(decoded["ts"], (int, float))