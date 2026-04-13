"""Brief: Unit tests for foghorn.plugins.resolve.zone_records.notify.

Inputs:
  - None.

Outputs:
  - None.
"""

from __future__ import annotations
import importlib

import threading

from dnslib import OPCODE, QTYPE, DNSRecord

from foghorn.plugins.resolve.zone_records import notify


class _DummyPlugin:
    """Brief: Minimal plugin-like object for notify helper tests.

    Inputs:
      - None.

    Outputs:
      - Object with notify-related attributes.
    """

    def __init__(self) -> None:
        self._axfr_notify_lock = threading.RLock()
        self._axfr_notify_static_targets: list[dict] = []
        self._axfr_notify_allow_private_targets = False
        self._axfr_notify_min_interval_seconds = 1.0
        self._axfr_notify_rate_limit_per_target_per_minute = 60
        self._axfr_notify_send_history: dict[str, list[float]] = {}
        self._axfr_notify_last_sent: dict[str, float] = {}
        self._axfr_notify_target_allowlist = None
        self._axfr_notify_target_allowlist_hosts: set[str] = set()
        self._axfr_notify_target_allowlist_networks: list[object] = []


def test_record_axfr_client_is_noop() -> None:
    """Brief: record_axfr_client does not mutate plugin state."""
    plugin = _DummyPlugin()
    notify.record_axfr_client(plugin, "example.com", "203.0.113.5")
    assert plugin._axfr_notify_send_history == {}
    assert plugin._axfr_notify_last_sent == {}


def test_send_notify_to_target_returns_on_blank_apex_or_host(monkeypatch) -> None:
    """Brief: send_notify_to_target bails when required fields are missing."""
    tcp_calls: list[tuple] = []

    def fake_tcp(*args, **kwargs):  # noqa: ANN001
        tcp_calls.append((args, kwargs))

    monkeypatch.setattr(notify, "tcp_query", fake_tcp, raising=True)

    notify.send_notify_to_target("", {"host": "192.0.2.1"})
    notify.send_notify_to_target("example.com", {"host": ""})

    assert tcp_calls == []


def test_send_notify_to_target_tcp_calls_tcp_query(monkeypatch) -> None:
    """Brief: TCP transport emits a NOTIFY(SOA) message."""
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


def test_send_notify_for_zones_skips_local_self_loop_targets(monkeypatch) -> None:
    """Brief: self-loop targets are filtered while remote targets are sent."""

    class Plugin(_DummyPlugin):
        def __init__(self) -> None:
            super().__init__()
            self._axfr_notify_allow_private_targets = True
            self._axfr_notify_min_interval_seconds = 0.0
            self._axfr_notify_static_targets = [
                {"host": "127.0.0.1", "port": 53, "transport": "tcp"},
                {"host": "203.0.113.5", "port": 53, "transport": "tcp"},
            ]

    calls: list[tuple[str, dict]] = []

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
    monkeypatch.setattr(
        notify,
        "send_notify_to_target",
        lambda z, t: calls.append((z, dict(t))),
        raising=True,
    )

    notify.send_notify_for_zones(Plugin(), ["example.com"])

    assert calls == [
        ("example.com", {"host": "203.0.113.5", "port": 53, "transport": "tcp"}),
    ]


def test_send_notify_for_zones_blocks_private_targets_by_default(monkeypatch) -> None:
    """Brief: private targets are blocked unless explicitly allowed."""

    class Plugin(_DummyPlugin):
        def __init__(self) -> None:
            super().__init__()
            self._axfr_notify_static_targets = [
                {"host": "192.168.1.20", "port": 53, "transport": "tcp"},
            ]
            self._axfr_notify_min_interval_seconds = 0.0

    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        notify, "_is_local_notify_target", lambda _t: False, raising=True
    )
    monkeypatch.setattr(
        notify,
        "send_notify_to_target",
        lambda z, t: calls.append((z, dict(t))),
        raising=True,
    )

    notify.send_notify_for_zones(Plugin(), ["example.com"])
    assert calls == []


def test_send_notify_for_zones_throttles_repeated_sends(monkeypatch) -> None:
    """Brief: min-interval/rate-limit checks suppress rapid repeat sends."""

    class Plugin(_DummyPlugin):
        def __init__(self) -> None:
            super().__init__()
            self._axfr_notify_allow_private_targets = True
            self._axfr_notify_min_interval_seconds = 3600.0
            self._axfr_notify_rate_limit_per_target_per_minute = 1
            self._axfr_notify_static_targets = [
                {"host": "203.0.113.7", "port": 53, "transport": "tcp"},
            ]

    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        notify, "_is_local_notify_target", lambda _t: False, raising=True
    )
    monkeypatch.setattr(
        notify,
        "send_notify_to_target",
        lambda z, t: calls.append((z, dict(t))),
        raising=True,
    )

    plugin = Plugin()
    notify.send_notify_for_zones(plugin, ["example.com"])
    notify.send_notify_for_zones(plugin, ["example.com"])

    assert len(calls) == 1


def test_schedule_delayed_notify_deduplicates_existing_timer(monkeypatch) -> None:
    """Brief: scheduling the same zone/target cancels the previous timer."""
    send_calls: list[tuple[str, dict]] = []

    monkeypatch.setattr(
        notify,
        "send_notify_to_target",
        lambda z, t: send_calls.append((z, dict(t))),
        raising=True,
    )

    class FakeTimer:
        created: list["FakeTimer"] = []

        def __init__(self, delay: float, cb):  # noqa: ANN001
            self.delay = delay
            self.cb = cb
            self.daemon = False
            self.started = False
            self.cancelled = False
            FakeTimer.created.append(self)

        def start(self) -> None:
            self.started = True

        def cancel(self) -> None:
            self.cancelled = True

    monkeypatch.setattr(notify.threading, "Timer", FakeTimer, raising=True)

    target = {"host": "192.0.2.1", "port": 53, "transport": "tcp"}
    notify.schedule_delayed_notify("example.com", target, 0.5)
    notify.schedule_delayed_notify("example.com", target, 0.5)

    assert len(FakeTimer.created) == 2
    assert FakeTimer.created[0].cancelled is True
    assert FakeTimer.created[1].started is True
    FakeTimer.created[1].cb()
    assert send_calls


def test_send_notify_for_zones_blocks_mixed_public_private_resolution(
    monkeypatch,
) -> None:
    """Brief: target is blocked when resolution includes any private IP and policy disallows it."""

    class Plugin(_DummyPlugin):
        def __init__(self) -> None:
            super().__init__()
            self._axfr_notify_static_targets = [
                {"host": "notify.example", "port": 53, "transport": "tcp"},
            ]
            self._axfr_notify_min_interval_seconds = 0.0

    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        notify, "_is_local_notify_target", lambda _t: False, raising=True
    )
    monkeypatch.setattr(
        notify,
        "_resolve_target_ips",
        lambda _host: {"203.0.113.7", "10.0.0.7"},
        raising=True,
    )
    monkeypatch.setattr(
        notify,
        "send_notify_to_target",
        lambda z, t: calls.append((z, dict(t))),
        raising=True,
    )

    notify.send_notify_for_zones(Plugin(), ["example.com"])
    assert calls == []


def test_should_send_notify_allows_after_rolling_window(monkeypatch) -> None:
    """Brief: per-target rate limiter allows send again once 60-second window elapses."""
    plugin = _DummyPlugin()
    plugin._axfr_notify_min_interval_seconds = 0.0
    plugin._axfr_notify_rate_limit_per_target_per_minute = 1
    target = {"host": "203.0.113.7", "port": 53, "transport": "tcp"}

    times = iter([100.0, 100.1, 161.2])
    monkeypatch.setattr(notify.time, "monotonic", lambda: next(times), raising=True)

    assert notify._should_send_notify(plugin, target) is True
    assert notify._should_send_notify(plugin, target) is False
    assert notify._should_send_notify(plugin, target) is True


def test_is_local_notify_target_matches_local_interface_ip(monkeypatch) -> None:
    """Brief: self-loop detection matches local interface IPs as well as bind endpoints."""
    target = {"host": "resolver.local", "port": 5300}
    monkeypatch.setattr(
        notify,
        "_resolve_target_ips",
        lambda _h: {"198.51.100.44"},
        raising=True,
    )
    monkeypatch.setattr(
        notify,
        "_get_local_interface_ips",
        lambda: {"198.51.100.44"},
        raising=True,
    )
    monkeypatch.setattr(
        notify,
        "_get_local_dns_listener_endpoints",
        lambda: {("0.0.0.0", 5300)},
        raising=True,
    )
    assert notify._is_local_notify_target(target) is True


def test_send_notify_for_zones_allows_target_when_hostname_is_allowlisted(
    monkeypatch,
) -> None:
    """Brief: hostname allowlist permits matching NOTIFY target."""

    class Plugin(_DummyPlugin):
        def __init__(self) -> None:
            super().__init__()
            self._axfr_notify_static_targets = [
                {"host": "notify.example.com", "port": 53, "transport": "tcp"},
            ]
            self._axfr_notify_min_interval_seconds = 0.0
            self._axfr_notify_allow_private_targets = True
            self._axfr_notify_target_allowlist = ["notify.example.com"]
            self._axfr_notify_target_allowlist_hosts = {"notify.example.com"}

    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        notify, "_is_local_notify_target", lambda _t: False, raising=True
    )
    monkeypatch.setattr(
        notify,
        "send_notify_to_target",
        lambda z, t: calls.append((z, dict(t))),
        raising=True,
    )

    notify.send_notify_for_zones(Plugin(), ["example.com"])
    assert len(calls) == 1


def test_send_notify_for_zones_allows_target_when_ip_matches_allowlist_cidr(
    monkeypatch,
) -> None:
    """Brief: CIDR allowlist permits NOTIFY target when all resolved IPs are in range."""

    ip_networks = importlib.import_module("foghorn.utils.ip_networks")

    class Plugin(_DummyPlugin):
        def __init__(self) -> None:
            super().__init__()
            self._axfr_notify_static_targets = [
                {"host": "notify.example.com", "port": 53, "transport": "tcp"},
            ]
            self._axfr_notify_min_interval_seconds = 0.0
            self._axfr_notify_allow_private_targets = True
            self._axfr_notify_target_allowlist = ["203.0.113.0/24"]
            self._axfr_notify_target_allowlist_networks = [
                ip_networks.parse_network("203.0.113.0/24", strict=False),
            ]

    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        notify, "_is_local_notify_target", lambda _t: False, raising=True
    )
    monkeypatch.setattr(
        notify,
        "_resolve_target_ips",
        lambda _host: {"203.0.113.99"},
        raising=True,
    )
    monkeypatch.setattr(
        notify,
        "send_notify_to_target",
        lambda z, t: calls.append((z, dict(t))),
        raising=True,
    )

    notify.send_notify_for_zones(Plugin(), ["example.com"])
    assert len(calls) == 1


def test_send_notify_for_zones_blocks_target_when_resolution_mixes_allowlisted_and_non_allowlisted_ips(
    monkeypatch,
) -> None:
    """Brief: allowlist rejects hostnames resolving to any non-allowlisted IP."""

    ip_networks = importlib.import_module("foghorn.utils.ip_networks")

    class Plugin(_DummyPlugin):
        def __init__(self) -> None:
            super().__init__()
            self._axfr_notify_static_targets = [
                {"host": "notify.example.com", "port": 53, "transport": "tcp"},
            ]
            self._axfr_notify_min_interval_seconds = 0.0
            self._axfr_notify_allow_private_targets = True
            self._axfr_notify_target_allowlist = ["203.0.113.0/24"]
            self._axfr_notify_target_allowlist_networks = [
                ip_networks.parse_network("203.0.113.0/24", strict=False),
            ]

    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        notify, "_is_local_notify_target", lambda _t: False, raising=True
    )
    monkeypatch.setattr(
        notify,
        "_resolve_target_ips",
        lambda _host: {"203.0.113.99", "198.51.100.77"},
        raising=True,
    )
    monkeypatch.setattr(
        notify,
        "send_notify_to_target",
        lambda z, t: calls.append((z, dict(t))),
        raising=True,
    )

    notify.send_notify_for_zones(Plugin(), ["example.com"])
    assert calls == []


def test_send_notify_for_zones_allows_target_when_allowlist_unset(monkeypatch) -> None:
    """Brief: targets are not blocked by allowlist checks when allowlist is unset."""

    class Plugin(_DummyPlugin):
        def __init__(self) -> None:
            super().__init__()
            self._axfr_notify_static_targets = [
                {"host": "203.0.113.20", "port": 53, "transport": "tcp"},
            ]
            self._axfr_notify_min_interval_seconds = 0.0
            self._axfr_notify_allow_private_targets = True

    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        notify, "_is_local_notify_target", lambda _t: False, raising=True
    )
    monkeypatch.setattr(
        notify,
        "send_notify_to_target",
        lambda z, t: calls.append((z, dict(t))),
        raising=True,
    )

    notify.send_notify_for_zones(Plugin(), ["example.com"])
    assert len(calls) == 1


def test_zone_records_setup_splits_notify_allowlist_hosts_and_networks() -> None:
    """Brief: ZoneRecords setup parses NOTIFY target allowlist into host and CIDR buckets."""
    mod = importlib.import_module("foghorn.plugins.resolve.zone_records")
    ZoneRecords = mod.ZoneRecords

    plugin = ZoneRecords(
        records=[
            "example.com|SOA|300|ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300",
        ],
        axfr_notify_target_allowlist=["notify.example.com", "203.0.113.0/24"],
    )
    plugin.setup()

    assert plugin._axfr_notify_target_allowlist == [
        "notify.example.com",
        "203.0.113.0/24",
    ]
    assert plugin._axfr_notify_target_allowlist_hosts == {"notify.example.com"}
    assert len(plugin._axfr_notify_target_allowlist_networks) == 1


def test_schedule_delayed_notify_separate_targets_keep_separate_timers(
    monkeypatch,
) -> None:
    """Brief: timers for different targets do not cancel each other."""
    monkeypatch.setattr(
        notify,
        "send_notify_to_target",
        lambda *_args, **_kwargs: None,
        raising=True,
    )

    class FakeTimer:
        created: list["FakeTimer"] = []

        def __init__(self, delay: float, cb):  # noqa: ANN001
            self.delay = delay
            self.cb = cb
            self.daemon = False
            self.started = False
            self.cancelled = False
            FakeTimer.created.append(self)

        def start(self) -> None:
            self.started = True

        def cancel(self) -> None:
            self.cancelled = True

    monkeypatch.setattr(notify.threading, "Timer", FakeTimer, raising=True)

    notify.schedule_delayed_notify(
        "example.com",
        {"host": "192.0.2.1", "port": 53, "transport": "tcp"},
        0.5,
    )
    notify.schedule_delayed_notify(
        "example.com",
        {"host": "192.0.2.2", "port": 53, "transport": "tcp"},
        0.5,
    )

    assert len(FakeTimer.created) == 2
    assert FakeTimer.created[0].cancelled is False
    assert FakeTimer.created[1].cancelled is False


def test_send_notify_for_zones_blocks_ipv6_ula_targets_by_default(monkeypatch) -> None:
    """Brief: ULA IPv6 NOTIFY targets are blocked when private targets are disallowed."""

    class Plugin(_DummyPlugin):
        def __init__(self) -> None:
            super().__init__()
            self._axfr_notify_static_targets = [
                {"host": "fd00::7", "port": 53, "transport": "tcp"},
            ]
            self._axfr_notify_min_interval_seconds = 0.0

    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        notify, "_is_local_notify_target", lambda _t: False, raising=True
    )
    monkeypatch.setattr(
        notify,
        "send_notify_to_target",
        lambda z, t: calls.append((z, dict(t))),
        raising=True,
    )

    notify.send_notify_for_zones(Plugin(), ["example.com"])
    assert calls == []


def test_send_notify_for_zones_allows_ipv6_global_target(monkeypatch) -> None:
    """Brief: globally-routable IPv6 targets are allowed when private blocking is enabled."""

    class Plugin(_DummyPlugin):
        def __init__(self) -> None:
            super().__init__()
            self._axfr_notify_static_targets = [
                {"host": "2606:4700:4700::1111", "port": 53, "transport": "tcp"},
            ]
            self._axfr_notify_min_interval_seconds = 0.0

    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        notify, "_is_local_notify_target", lambda _t: False, raising=True
    )
    monkeypatch.setattr(
        notify,
        "send_notify_to_target",
        lambda z, t: calls.append((z, dict(t))),
        raising=True,
    )

    notify.send_notify_for_zones(Plugin(), ["example.com"])
    assert len(calls) == 1


def test_is_local_notify_target_matches_ipv6_local_interface_ip(monkeypatch) -> None:
    """Brief: self-loop detection works for IPv6 interface addresses."""
    target = {"host": "resolver-v6.local", "port": 5300}
    monkeypatch.setattr(
        notify,
        "_resolve_target_ips",
        lambda _h: {"2001:db8::44"},
        raising=True,
    )
    monkeypatch.setattr(
        notify,
        "_get_local_interface_ips",
        lambda: {"2001:db8::44"},
        raising=True,
    )
    monkeypatch.setattr(
        notify,
        "_get_local_dns_listener_endpoints",
        lambda: {("127.0.0.1", 5300)},
        raising=True,
    )
    assert notify._is_local_notify_target(target) is True
