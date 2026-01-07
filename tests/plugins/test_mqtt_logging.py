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
import time

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
            self.wills = []

        def username_pw_set(self, *_, **__):  # type: ignore[no-untyped-def]
            return None

        def connect(self, *_, **__):  # type: ignore[no-untyped-def]
            return 0

        def loop_start(self):  # type: ignore[no-untyped-def]
            return None

        def publish(self, topic, payload, qos=0, retain=False):  # type: ignore[no-untyped-def]
            self.publishes.append((topic, payload, qos, retain))
            return None

        def will_set(self, topic, payload, qos=0, retain=False):  # type: ignore[no-untyped-def]
            self.wills.append((topic, payload, qos, retain))
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

    # Make hostname and time deterministic for the payload assertion.
    import socket

    monkeypatch.setattr(socket, "gethostname", lambda: "test-host")
    monkeypatch.setattr(time, "time", lambda: 123.0)

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

    # # TODO:  Verify that a Last Will and Testament is
    # #        configured on the same meta topic.
    # # client = logger._client  # type: ignore[attr-defined]
    # # assert isinstance(client.wills, list)
    # # assert len(client.wills) == 1

    # # will_topic, will_payload, will_qos, will_retain = client.wills[0]
    # # assert will_topic == "foghorn/query_log/meta"
    # # assert will_qos == 1
    # # assert will_retain is False

    # # will_decoded = json.loads(will_payload)
    # # assert will_decoded["event"] == "log_disconnect"
    # # assert will_decoded["version"] == 1
    # # assert will_decoded["hostname"] == "test-host"
    # # assert will_decoded["ts"] == 123.0
