"""MQTT logging-only implementation of the BaseStatsStore interface.

Inputs:
  - Constructed via a configuration mapping passed through StatsStoreBackendConfig
    with backend-specific fields such as host, port, username, and topic.

Outputs:
  - Concrete backend instance that can be used to publish query-log entries over
    MQTT. This backend is intentionally *write-only* for query logs and does not
    implement statistics aggregation or read APIs.

Notes:
  - This backend is meant for side-channel logging/streaming of DNS query-log
    events (for example, into an external metrics pipeline). It is *not*
    suitable as the primary statistics backend for StatsCollector. Methods other
    than insert_query_log, health_check, and close are left unimplemented so
    that NotImplementedError continues to be raised if they are called.
"""

from __future__ import annotations

import json
import logging
import socket
import time
from typing import Any, Dict, Optional

from .base import BaseStatsStore

logger = logging.getLogger(__name__)


def _import_mqtt_driver():
    """Import and return a paho-mqtt style client module.

    Inputs:
        None.

    Outputs:
        Module exposing a Client class compatible with paho-mqtt.

    Raises:
        RuntimeError: When no supported MQTT driver is available.
    """

    # Honour any pre-injected paho-style client in sys.modules so that tests can
    # provide a fake driver (for example, via monkeypatch.setitem). When present
    # and not None, this takes precedence over importing the real package.
    import sys

    injected = sys.modules.get("paho.mqtt.client")
    if injected is not None:
        return injected

    try:
        import paho.mqtt.client as mqtt  # type: ignore[import]

        return mqtt
    except Exception as exc:  # pragma: no cover - environment specific
        raise RuntimeError(
            "No supported MQTT client library found; install 'paho-mqtt' to "
            "use the MqttLogging"
        ) from exc


class MqttLogging(BaseStatsStore):
    """MQTT-backed logging-only backend.

    # Aliases used by the stats backend registry.
    aliases = ("mqtt", "broker")

    Inputs (constructor):
        host: MQTT broker host (default "127.0.0.1").
        port: MQTT broker port (default 1883).
        topic: Base MQTT topic to publish query-log messages to
            (default "foghorn/query_log").
        client_id: Optional client identifier; when None, the MQTT library
            chooses one.
        username: Optional username for broker authentication.
        password: Optional password for broker authentication.
        keepalive: Keepalive interval in seconds (default 60).
        qos: QoS level for publishes (0, 1, or 2; default 1). For statistics
            logging we default to QoS 1 so that each query_log entry is
            delivered "at least once" to the broker. QoS 0 is fire-and-forget
            and can silently drop log messages under transient network or
            broker issues.
        retain: Whether to set the retain flag on published messages
            (default False).
        connect_kwargs: Optional mapping of additional keyword arguments passed
            through to the MQTT client's connect() method (for example,
            ssl options or socket options).

    Outputs:
        Initialized MqttLogging instance connected to the broker and
        ready to publish query-log entries.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1883,
        topic: str = "foghorn/query_log",
        client_id: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        keepalive: int = 60,
        qos: int = 1,
        retain: bool = False,
        connect_kwargs: Optional[Dict[str, Any]] = None,
        async_logging: bool = False,
        **_: Any,
    ) -> None:
        mqtt = _import_mqtt_driver()
        logger.warning("Log start published")
        self._host = host
        self._port = int(port)
        self._topic = topic
        self._keepalive = int(keepalive)
        self._qos = int(qos)
        self._retain = bool(retain)

        # Logging behaviour: allow callers to opt into async queuing via
        # ``async_logging``; MQTT logging defaults to synchronous behaviour so
        # tests and callers see publishes immediately.
        self._async_logging = bool(async_logging)

        self._client = mqtt.Client(client_id=client_id or "foghorn_mqtt_logger")
        if username is not None:
            self._client.username_pw_set(username=username, password=password)

        meta_topic = f"{self._topic}/meta"

        # # ### TODO: Figure out why the will fires every other second.
        # # ## Configure a Last Will and Testament on the same metadata topic so that
        # # ## consumers can observe unexpected disconnects as a retained event.
        # # try:
        # #     if hasattr(self._client, "will_set"):
        # #         disconnect_payload = {
        # #             "event": "log_disconnect",
        # #             "ts": float(time.time()),
        # #             "version": 1,
        # #             "hostname": socket.gethostname(),
        # #         }
        # #         disconnect_data = json.dumps(
        # #             disconnect_payload, separators=(",", ":")
        # #         )
        # #         self._client.will_set(
        # #             meta_topic,
        # #             disconnect_data,
        # #             qos=self._qos,
        # #             retain=True,
        # #         )
        # # except Exception:  # pragma: no cover - defensive
        # #     logger.exception("Failed to configure MQTT query_log disconnect LWT")

        kw = dict(connect_kwargs or {})

        # Establish connection and start the background network loop so that
        # publish() calls succeed without explicit per-call loop management.
        self._client.connect(self._host, self._port, self._keepalive, **kw)
        self._client.loop_start()

        # Publish a best-effort "log_start" marker to a metadata topic so
        # downstream consumers can detect when a new logging session begins.
        try:
            start_payload = {
                "event": "log_start",
                "ts": float(time.time()),
                "version": 1,
                "hostname": socket.gethostname(),
            }
            start_data = json.dumps(start_payload, separators=(",", ":"))
            self._client.publish(
                meta_topic,
                start_data,
                qos=self._qos,
                retain=self._retain,
            )
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to publish MQTT query_log start marker")

        self._healthy = True

    # ------------------------------------------------------------------
    # Health and lifecycle
    # ------------------------------------------------------------------
    def health_check(self) -> bool:  # type: ignore[override]
        """Return True when the underlying MQTT client is considered usable.

        Inputs:
            None.

        Outputs:
            bool: True when the client was initialized successfully.
        """

        return bool(self._healthy)

    def close(self) -> None:  # type: ignore[override]
        """Close the underlying MQTT client and stop its network loop.

        Inputs:
            None.

        Outputs:
            None; subsequent publishes will fail.
        """

        try:
            client = getattr(self, "_client", None)
            if client is not None:
                try:
                    client.loop_stop()
                except Exception:  # pragma: no cover - defensive
                    logger.exception("Error while stopping MQTT client loop")
                try:
                    client.disconnect()
                except Exception:  # pragma: no cover - defensive
                    logger.exception("Error while disconnecting MQTT client")
        finally:
            self._healthy = False

    # ------------------------------------------------------------------
    # Query-log API (write-only)
    # ------------------------------------------------------------------
    def insert_query_log(
        self,
        ts: float,
        client_ip: str,
        name: str,
        qtype: str,
        upstream_id: Optional[str],
        rcode: Optional[str],
        status: Optional[str],
        error: Optional[str],
        first: Optional[str],
        result_json: str,
    ) -> None:  # type: ignore[override]
        """Dispatch a DNS query-log entry synchronously or via async worker.

        Inputs:
            ts: Unix timestamp (float seconds).
            client_ip: Client IP address string.
            name: Normalized query name.
            qtype: Query type string.
            upstream_id: Optional upstream identifier.
            rcode: Optional DNS response code.
            status: Optional high-level status string.
            error: Optional error summary.
            first: Optional first answer value.
            result_json: JSON-encoded result payload from the resolver.

        Outputs:
            None; publishes immediately when async_logging is False, otherwise
            enqueues the operation on the BaseStatsStore worker queue.
        """

        if getattr(self, "_async_logging", False):
            super().insert_query_log(
                ts,
                client_ip,
                name,
                qtype,
                upstream_id,
                rcode,
                status,
                error,
                first,
                result_json,
            )
        else:
            self._insert_query_log(
                ts,
                client_ip,
                name,
                qtype,
                upstream_id,
                rcode,
                status,
                error,
                first,
                result_json,
            )

    def _insert_query_log(
        self,
        ts: float,
        client_ip: str,
        name: str,
        qtype: str,
        upstream_id: Optional[str],
        rcode: Optional[str],
        status: Optional[str],
        error: Optional[str],
        first: Optional[str],
        result_json: str,
    ) -> None:  # type: ignore[override]
        """Publish a DNS query-log entry as a JSON message to MQTT.

        Inputs:
            ts: Unix timestamp (float seconds).
            client_ip: Client IP address string.
            name: Normalized query name.
            qtype: Query type string.
            upstream_id: Optional upstream identifier.
            rcode: Optional DNS response code.
            status: Optional high-level status string.
            error: Optional error summary.
            first: Optional first answer value.
            result_json: JSON-encoded result payload from the resolver.

        Outputs:
            None; best-effort publish to the configured MQTT topic.
        """

        if not self._healthy:
            return

        payload = {
            "ts": float(ts),
            "client_ip": client_ip,
            "name": name,
            "qtype": qtype,
            "upstream_id": upstream_id,
            "rcode": rcode,
            "status": status,
            "error": error,
            "first": first,
        }

        # Include the original result_json as a nested object when possible so
        # that downstream consumers can access full resolver responses.
        try:
            parsed_result = json.loads(result_json) if result_json else None
        except Exception:
            parsed_result = None
        if parsed_result is not None:
            payload["result"] = parsed_result

        try:
            data = json.dumps(payload, separators=(",", ":"))
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to encode MQTT query_log payload as JSON")
            return

        try:
            self._client.publish(self._topic, data, qos=self._qos, retain=self._retain)
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to publish query_log message to MQTT")

    # All other BaseStatsStore methods (counters, export, rebuild,
    # select_query_log, aggregate_query_log_counts, has_query_log) are
    # intentionally left unimplemented so that the base class raises
    # NotImplementedError when they are called. This enforces that the MQTT
    # backend is used strictly as a logging sink and not as a statistics store.
