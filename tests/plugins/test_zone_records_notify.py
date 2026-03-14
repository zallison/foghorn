"""Brief: Unit tests for foghorn.plugins.resolve.zone_records.notify.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import threading

from dnslib import OPCODE, QTYPE, DNSRecord

from foghorn.plugins.resolve.zone_records import notify


class _FlakyStr:
    """Brief: String-like object that raises once then returns a value.

    Inputs:
      - value: string to return after the first failure.

    Outputs:
      - Instance usable as a str() input.
    """

    def __init__(self, value: str) -> None:
        self._value = value
        self._calls = 0

    def __str__(self) -> str:
        self._calls += 1
        if self._calls == 1:
            raise ValueError("boom")
        return self._value


class _DummyPlugin:
    """Brief: Minimal plugin-like object for exercising notify helpers.

    Inputs:
      - with_lock: if True, install a lock and learned dict.
      - delay: optional axfr notify delay.

    Outputs:
      - Object with the attributes expected by record_axfr_client/send_notify_for_zones.
    """

    def __init__(self, *, with_lock: bool = True, delay: object = None) -> None:
        if with_lock:
            self._axfr_notify_lock = threading.RLock()
            self._axfr_notify_learned: dict = {}
        self._axfr_notify_delay = delay
        self._axfr_notify_static_targets = []


def test_record_axfr_client_noop_on_blank_zone_or_host() -> None:
    """Brief: record_axfr_client should return early on empty zone or host.

    Inputs:
      - plugin: dummy plugin with a notify lock.

    Outputs:
      - None: Asserts learned targets remain empty.
    """
    plugin = _DummyPlugin(with_lock=True, delay=None)

    notify.record_axfr_client(plugin, "", "203.0.113.5")
    notify.record_axfr_client(plugin, "example.com", "   ")

    assert plugin._axfr_notify_learned == {}


def test_record_axfr_client_returns_when_lock_missing() -> None:
    """Brief: record_axfr_client should do nothing if plugin has no lock.

    Inputs:
      - plugin: dummy plugin without _axfr_notify_lock.

    Outputs:
      - None: Asserts no learned targets are recorded.
    """

    class NoLock:
        _axfr_notify_learned: dict = {}
        _axfr_notify_delay = None

    plugin = NoLock()
    notify.record_axfr_client(plugin, "example.com", "203.0.113.5")
    assert plugin._axfr_notify_learned == {}


def test_record_axfr_client_records_target_and_returns_when_delay_unset() -> None:
    """Brief: Learned target is recorded but no NOTIFY is sent when delay is unset.

    Inputs:
      - plugin: dummy plugin with lock and delay None.

    Outputs:
      - None: Asserts learned targets are updated.
    """
    plugin = _DummyPlugin(with_lock=True, delay=None)

    notify.record_axfr_client(plugin, "Example.COM.", "203.0.113.5")

    learned = plugin._axfr_notify_learned.get("example.com")
    assert learned is not None
    assert "203.0.113.5:53/tcp" in learned


def test_record_axfr_client_str_exceptions_are_handled() -> None:
    """Brief: record_axfr_client should tolerate str() failures for inputs.

    Inputs:
      - zone_apex: object that fails once on str().
      - client_ip: object that fails once on str().

    Outputs:
      - None: Asserts learned targets are recorded.
    """
    plugin = _DummyPlugin(with_lock=True, delay=None)

    zone = _FlakyStr("Example.COM.")
    ip = _FlakyStr("203.0.113.5")

    notify.record_axfr_client(plugin, zone, ip)

    learned = plugin._axfr_notify_learned.get("example.com")
    assert learned is not None
    assert "203.0.113.5:53/tcp" in learned


def test_record_axfr_client_schedules_delayed_notify(monkeypatch) -> None:
    """Brief: Positive delay should schedule a delayed NOTIFY.

    Inputs:
      - delay: positive float-like value.

    Outputs:
      - None: Asserts schedule_delayed_notify is invoked.
    """
    plugin = _DummyPlugin(with_lock=True, delay=1.25)

    calls: list[tuple[str, dict, float]] = []

    def fake_schedule(zone_apex: str, target: dict, delay_s: float) -> None:
        calls.append((zone_apex, dict(target), float(delay_s)))

    monkeypatch.setattr(notify, "schedule_delayed_notify", fake_schedule, raising=True)

    notify.record_axfr_client(plugin, "example.com", "203.0.113.5")

    assert calls
    zone_apex, target, delay_s = calls[0]
    assert zone_apex == "example.com"
    assert target["host"] == "203.0.113.5"
    assert delay_s == 1.25


def test_record_axfr_client_sends_immediate_notify(monkeypatch) -> None:
    """Brief: Zero/negative delay should trigger an immediate NOTIFY send.

    Inputs:
      - delay: non-positive value.

    Outputs:
      - None: Asserts send_notify_to_target is invoked.
    """
    plugin = _DummyPlugin(with_lock=True, delay=0)

    calls: list[tuple[str, dict]] = []

    def fake_send(zone_apex: str, target: dict) -> None:
        calls.append((zone_apex, dict(target)))

    monkeypatch.setattr(notify, "send_notify_to_target", fake_send, raising=True)

    notify.record_axfr_client(plugin, "example.com", "203.0.113.5")

    assert calls
    assert calls[0][0] == "example.com"


def test_send_notify_to_target_returns_on_blank_apex_or_host(monkeypatch) -> None:
    """Brief: send_notify_to_target should bail out when required fields are missing.

    Inputs:
      - zone_apex: empty string.
      - target: missing host.

    Outputs:
      - None: Asserts no transport functions are called.
    """
    tcp_calls: list[tuple] = []

    def fake_tcp(*args, **kwargs):  # noqa: ANN001
        tcp_calls.append((args, kwargs))

    monkeypatch.setattr(notify, "tcp_query", fake_tcp, raising=True)

    notify.send_notify_to_target("", {"host": "192.0.2.1"})
    notify.send_notify_to_target("example.com", {"host": ""})

    assert tcp_calls == []


def test_send_notify_to_target_tcp_calls_tcp_query(monkeypatch) -> None:
    """Brief: TCP transport should call tcp_query with a NOTIFY message.

    Inputs:
      - zone_apex: apex name.
      - target: tcp target mapping.

    Outputs:
      - None: Asserts tcp_query is called and the wire message is a NOTIFY(SOA).
    """
    calls: list[tuple] = []

    def fake_tcp(host: str, port: int, wire: bytes, **kwargs):  # noqa: ANN001
        calls.append((host, port, wire, kwargs))

    monkeypatch.setattr(notify, "tcp_query", fake_tcp, raising=True)

    notify.send_notify_to_target(
        "Example.COM.",
        {"host": "192.0.2.1", "port": 5353, "timeout_ms": 1234, "transport": "tcp"},
    )

    assert len(calls) == 1
    host, port, wire, kwargs = calls[0]
    assert host == "192.0.2.1"
    assert port == 5353
    assert kwargs["connect_timeout_ms"] == 1234
    assert kwargs["read_timeout_ms"] == 1234

    msg = DNSRecord.parse(wire)
    assert msg.header.opcode == OPCODE.NOTIFY
    assert msg.questions[0].qtype == QTYPE.SOA
    assert str(msg.questions[0].qname).lower().endswith("example.com.")


def test_send_notify_to_target_dot_calls_dot_query(monkeypatch) -> None:
    """Brief: DoT transport should call dot_query with TLS args.

    Inputs:
      - target: dot transport mapping.

    Outputs:
      - None: Asserts dot_query is called.
    """
    calls: list[tuple] = []

    def fake_dot(host: str, port: int, wire: bytes, **kwargs):  # noqa: ANN001
        calls.append((host, port, wire, kwargs))

    monkeypatch.setattr(notify, "dot_query", fake_dot, raising=True)

    notify.send_notify_to_target(
        "example.com",
        {
            "host": "192.0.2.2",
            "port": 853,
            "timeout_ms": 2000,
            "transport": "dot",
            "server_name": "sec.example",
            "verify": False,
            "ca_file": "/tmp/ca.pem",
        },
    )

    assert len(calls) == 1
    host, port, wire, kwargs = calls[0]
    assert host == "192.0.2.2"
    assert port == 853
    assert kwargs["server_name"] == "sec.example"
    assert kwargs["verify"] is False
    assert kwargs["ca_file"] == "/tmp/ca.pem"

    msg = DNSRecord.parse(wire)
    assert msg.header.opcode == OPCODE.NOTIFY


def test_send_notify_for_zones_returns_on_empty_input(monkeypatch) -> None:
    """Brief: send_notify_for_zones should no-op on empty zone list.

    Inputs:
      - zone_apexes: empty list.

    Outputs:
      - None: Asserts no NOTIFY sends are attempted.
    """

    class Plugin:
        _axfr_notify_static_targets: list = []
        _axfr_notify_learned: dict = {}

    calls: list[tuple[str, dict]] = []

    def fake_send(zone_apex: str, target: dict) -> None:
        calls.append((zone_apex, dict(target)))

    monkeypatch.setattr(notify, "send_notify_to_target", fake_send, raising=True)

    notify.send_notify_for_zones(Plugin(), [])

    assert calls == []


def test_send_notify_for_zones_with_lock_snapshots_learned_targets(monkeypatch) -> None:
    """Brief: send_notify_for_zones should snapshot learned targets under lock.

    Inputs:
      - plugin: object with _axfr_notify_lock and _axfr_notify_learned.

    Outputs:
      - None: Asserts learned targets are used when sending NOTIFY.
    """

    class Plugin:
        def __init__(self) -> None:
            self._axfr_notify_lock = threading.RLock()
            self._axfr_notify_static_targets: list = []
            self._axfr_notify_learned = {
                "example.com": {"h:53/tcp": {"host": "203.0.113.5", "port": 53}},
            }

    calls: list[tuple[str, dict]] = []

    def fake_send(zone_apex: str, target: dict) -> None:
        calls.append((zone_apex, dict(target)))

    monkeypatch.setattr(notify, "send_notify_to_target", fake_send, raising=True)

    notify.send_notify_for_zones(Plugin(), ["example.com"])

    assert calls
    assert all(z == "example.com" for (z, _t) in calls)


def test_send_notify_for_zones_skips_local_self_loop_targets(monkeypatch) -> None:
    """Brief: send_notify_for_zones should skip targets matching local listeners.

    Inputs:
      - plugin: object with static+learned NOTIFY targets.

    Outputs:
      - None: Asserts local target is filtered while remote target is sent.
    """

    class Plugin:
        _axfr_notify_static_targets = [
            {"host": "127.0.0.1", "port": 53, "transport": "tcp"},
            {"host": "203.0.113.5", "port": 53, "transport": "tcp"},
        ]
        _axfr_notify_learned = {}

    calls: list[tuple[str, dict]] = []

    def fake_send(zone_apex: str, target: dict) -> None:
        calls.append((zone_apex, dict(target)))

    monkeypatch.setattr(
        notify,
        "_resolve_target_ips",
        lambda host: {str(host)},
        raising=True,
    )
    monkeypatch.setattr(
        notify,
        "_get_local_dns_listener_endpoints",
        lambda: {("127.0.0.1", 53)},
        raising=True,
    )
    monkeypatch.setattr(notify, "send_notify_to_target", fake_send, raising=True)

    notify.send_notify_for_zones(Plugin(), ["example.com"])
    assert calls == [
        ("example.com", {"host": "203.0.113.5", "port": 53, "transport": "tcp"})
    ]


def test_send_notify_for_zones_without_lock_uses_learned_snapshot(monkeypatch) -> None:
    """Brief: send_notify_for_zones should work even when plugin has no lock.

    Inputs:
      - plugin: object with learned targets but no _axfr_notify_lock.

    Outputs:
      - None: Asserts send_notify_to_target is called for zones with targets only.
    """

    class Plugin:
        _axfr_notify_static_targets: list = []
        _axfr_notify_learned = {
            "example.com": {"h:53/tcp": {"host": "203.0.113.5", "port": 53}},
            "junk": "not-a-dict",
        }

    calls: list[tuple[str, dict]] = []

    def fake_send(zone_apex: str, target: dict) -> None:
        calls.append((zone_apex, dict(target)))

    monkeypatch.setattr(notify, "send_notify_to_target", fake_send, raising=True)

    notify.send_notify_for_zones(Plugin(), ["", "example.com", "missing.com"])

    assert calls
    assert all(z == "example.com" for (z, _t) in calls)


def test_schedule_delayed_notify_immediate_when_delay_non_positive(monkeypatch) -> None:
    """Brief: schedule_delayed_notify should send immediately when delay <= 0.

    Inputs:
      - delay_s: non-positive delay.

    Outputs:
      - None: Asserts send_notify_to_target is called.
    """
    calls: list[tuple[str, dict]] = []

    def fake_send(zone_apex: str, target: dict) -> None:
        calls.append((zone_apex, dict(target)))

    monkeypatch.setattr(notify, "send_notify_to_target", fake_send, raising=True)

    notify.schedule_delayed_notify("example.com", {"host": "192.0.2.1"}, 0.0)

    assert calls


def test_schedule_delayed_notify_uses_timer_when_delay_positive(monkeypatch) -> None:
    """Brief: schedule_delayed_notify should schedule a background Timer when delay > 0.

    Inputs:
      - delay_s: positive delay.

    Outputs:
      - None: Asserts Timer is started and the callback triggers a NOTIFY send.
    """
    send_calls: list[tuple[str, dict]] = []

    def fake_send(zone_apex: str, target: dict) -> None:
        send_calls.append((zone_apex, dict(target)))

    monkeypatch.setattr(notify, "send_notify_to_target", fake_send, raising=True)

    class FakeTimer:
        last = None

        def __init__(self, delay: float, cb):  # noqa: ANN001
            self.delay = delay
            self.cb = cb
            self.daemon = False
            self.started = False
            FakeTimer.last = self

        def start(self) -> None:
            self.started = True

    monkeypatch.setattr(notify.threading, "Timer", FakeTimer, raising=True)

    notify.schedule_delayed_notify("example.com", {"host": "192.0.2.1"}, 0.5)

    t = FakeTimer.last
    assert t is not None
    assert t.delay == 0.5
    assert t.daemon is True
    assert t.started is True

    # Simulate timer firing.
    t.cb()
    assert send_calls
