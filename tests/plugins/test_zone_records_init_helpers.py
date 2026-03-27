"""Brief: Unit tests for zone_records __init__ helper branch coverage.

Inputs:
  - Monkeypatched helper functions, runtime snapshot stubs, and synthetic DNS wires.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from dnslib import DNSHeader, DNSQuestion, DNSRecord, OPCODE, QTYPE, RCODE

import foghorn.plugins.resolve.zone_records as mod
from foghorn.plugins.resolve.base import PluginContext


class _Plugin:
    """Brief: Minimal plugin-like object for helper tests.

    Inputs:
      - axfr_zones: Optional AXFR zone configuration entries.

    Outputs:
      - _Plugin with AXFR metadata attributes expected by helper functions.
    """

    def __init__(self, axfr_zones: list[object] | None = None) -> None:
        self._axfr_zones = list(axfr_zones or [])
        self._axfr_zone_metadata: object = {}


@pytest.fixture(autouse=True)
def _reset_notify_caches() -> None:
    """Brief: Reset shared NOTIFY caches and state between tests.

    Inputs:
      - None

    Outputs:
      - None
    """

    mod._NOTIFY_RESOLVE_CACHE.clear()
    mod._NOTIFY_RATE_LIMIT_STATE.clear()
    mod._NOTIFY_REFRESH_INFLIGHT.clear()
    mod._NOTIFY_REFRESH_STATE.clear()
    if hasattr(mod._zone_has_axfr_config, "cache_clear"):
        mod._zone_has_axfr_config.cache_clear()
    yield
    mod._NOTIFY_RESOLVE_CACHE.clear()
    mod._NOTIFY_RATE_LIMIT_STATE.clear()
    mod._NOTIFY_REFRESH_INFLIGHT.clear()
    mod._NOTIFY_REFRESH_STATE.clear()
    if hasattr(mod._zone_has_axfr_config, "cache_clear"):
        mod._zone_has_axfr_config.cache_clear()


def test_upstream_fingerprint_normalizes_and_sorts_entries() -> None:
    """Brief: _upstream_fingerprint lower-cases/sorts entries and skips non-dicts.

    Inputs:
      - None

    Outputs:
      - None
    """

    fingerprint = mod._upstream_fingerprint(
        [
            {"host": "B.EXAMPLE", "port": 5353, "transport": "DoT"},
            "skip-me",
            {
                "host": "a.example",
                "port": 53,
                "transport": "tcp",
                "server_name": "NS.A",
            },
        ]
    )
    assert fingerprint == "a.example|53|tcp|ns.a||b.example|5353|dot|"
    assert mod._upstream_fingerprint(["skip-only"]) == ""


def test_is_ip_literal_returns_false_for_non_ip_values() -> None:
    """Brief: _is_ip_literal returns False for hostnames/non-IP text.

    Inputs:
      - None

    Outputs:
      - None
    """

    assert mod._is_ip_literal("example.com") is False
    assert mod._is_ip_literal("not-an-ip") is False


def test_resolve_host_ips_handles_lookup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _resolve_host_ips returns an empty set when getaddrinfo fails.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    def _raise(*_args, **_kwargs):
        raise OSError("dns failure")

    monkeypatch.setattr(mod.socket, "getaddrinfo", _raise, raising=True)
    assert mod._resolve_host_ips("example.com") == set()


def test_resolve_host_ips_skips_bad_entries_and_collects_valid_ips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _resolve_host_ips ignores malformed entries and blank IPs.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    monkeypatch.setattr(
        mod.socket,
        "getaddrinfo",
        lambda *_a, **_k: [
            (None, None, None, None, ("203.0.113.10", 0)),
            (None, None, None, None, (" 2001:db8::77 ", 0, 0, 0)),
            ("bad-entry",),  # no sockaddr tuple
            (None, None, None, None, ("", 0)),  # blank ip
        ],
        raising=True,
    )
    assert mod._resolve_host_ips("resolver.example") == {"203.0.113.10", "2001:db8::77"}


def test_sender_matches_upstream_covers_input_validation_and_matching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _sender_matches_upstream validates shape and supports literal/DNS matching.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    assert mod._sender_matches_upstream("192.0.2.5", "bad") is False
    assert mod._sender_matches_upstream("192.0.2.5", {"host": 123}) is False
    assert mod._sender_matches_upstream("", {"host": "192.0.2.5"}) is False
    assert mod._sender_matches_upstream("192.0.2.5", {"host": ""}) is False
    assert mod._sender_matches_upstream("192.0.2.5", {"host": "192.0.2.5"}) is True
    assert mod._sender_matches_upstream("2001:db8::9", {"host": "2001:DB8::9"}) is True

    monkeypatch.setattr(
        mod,
        "_resolve_host_ips",
        lambda _host: {"198.51.100.7"},
        raising=True,
    )
    assert (
        mod._sender_matches_upstream("198.51.100.7", {"host": "notify.example"}) is True
    )


def test_resolve_notify_sender_upstream_from_candidates_handles_cache_and_empty_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Candidate resolver handles empty inputs and reuses cached matches.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    assert (
        mod._resolve_notify_sender_upstream_from_candidates(
            "",
            [{"host": "a.example"}],
            cache_scope="scope",
        )
        is None
    )
    assert (
        mod._resolve_notify_sender_upstream_from_candidates(
            "   ",
            [{"host": "a.example"}],
            cache_scope="scope-blank",
        )
        is None
    )
    assert (
        mod._resolve_notify_sender_upstream_from_candidates(
            "192.0.2.8",
            [],
            cache_scope="scope",
        )
        is None
    )

    class _FlakySenderValue:
        def __init__(self) -> None:
            self.calls = 0

        def __str__(self) -> str:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("first stringify fails")
            return "192.0.2.8"

    assert (
        mod._resolve_notify_sender_upstream_from_candidates(
            _FlakySenderValue(),
            [{"host": "x.example"}],
            cache_scope="scope-flaky",
        )
        is None
    )

    calls: list[str] = []

    def _matcher(_sender: str, upstream: dict) -> bool:
        calls.append(str(upstream.get("host")))
        return upstream.get("host") == "b.example"

    monkeypatch.setattr(mod, "_sender_matches_upstream", _matcher, raising=True)

    upstreams = [{"host": "a.example"}, {"host": "b.example"}]
    match = mod._resolve_notify_sender_upstream_from_candidates(
        "192.0.2.8",
        upstreams,
        cache_scope="scope-a",
    )
    assert match == {"host": "b.example"}
    assert calls == ["a.example", "b.example"]

    calls.clear()
    match_cached = mod._resolve_notify_sender_upstream_from_candidates(
        "192.0.2.8",
        upstreams,
        cache_scope="scope-a",
    )
    assert match_cached == {"host": "b.example"}
    assert calls == []


def test_resolve_notify_sender_upstream_from_candidates_caches_none_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Candidate resolver caches no-match results to avoid repeat checks.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    calls = {"n": 0}

    def _matcher(_sender: str, _upstream: dict) -> bool:
        calls["n"] += 1
        return False

    monkeypatch.setattr(mod, "_sender_matches_upstream", _matcher, raising=True)
    upstreams = [{"host": "none.example"}]
    assert (
        mod._resolve_notify_sender_upstream_from_candidates(
            "192.0.2.99",
            upstreams,
            cache_scope="scope-none",
        )
        is None
    )
    assert calls["n"] == 1
    assert (
        mod._resolve_notify_sender_upstream_from_candidates(
            "192.0.2.99",
            upstreams,
            cache_scope="scope-none",
        )
        is None
    )
    assert calls["n"] == 1


def test_resolve_notify_sender_upstream_handles_runtime_snapshot_cases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Global upstream resolver handles runtime exceptions/empty snapshots.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    import foghorn.runtime_config as runtime_config

    assert mod._resolve_notify_sender_upstream("") is None

    def _boom() -> object:
        raise RuntimeError("snapshot boom")

    monkeypatch.setattr(runtime_config, "get_runtime_snapshot", _boom, raising=True)
    assert mod._resolve_notify_sender_upstream("192.0.2.1") is None

    monkeypatch.setattr(
        runtime_config,
        "get_runtime_snapshot",
        lambda: SimpleNamespace(upstream_addrs=None),
        raising=True,
    )
    assert mod._resolve_notify_sender_upstream("192.0.2.1") is None

    captured: dict[str, object] = {}

    def _resolver(sender: str, upstreams: list[dict], cache_scope: str):
        captured["sender"] = sender
        captured["upstreams"] = list(upstreams)
        captured["scope"] = cache_scope
        return {"host": "198.51.100.7"}

    monkeypatch.setattr(
        runtime_config,
        "get_runtime_snapshot",
        lambda: SimpleNamespace(upstream_addrs=[{"host": "198.51.100.7"}]),
        raising=True,
    )
    monkeypatch.setattr(
        mod,
        "_resolve_notify_sender_upstream_from_candidates",
        _resolver,
        raising=True,
    )
    result = mod._resolve_notify_sender_upstream("192.0.2.1")
    assert result == {"host": "198.51.100.7"}
    assert captured["sender"] == "192.0.2.1"
    assert captured["upstreams"] == [{"host": "198.51.100.7"}]
    assert captured["scope"] == "global-upstreams"


def test_resolve_notify_sender_for_zone_normalizes_zone_and_filters_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Zone-scoped sender resolver ignores bad entries and normalizes zones.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    plugin = _Plugin(
        axfr_zones=[
            "skip",
            {"zone": "other.example", "upstreams": [{"host": "203.0.113.1"}]},
            {"zone": "Example.COM.", "upstreams": [{"host": "198.51.100.9"}]},
        ]
    )

    captured: dict[str, object] = {}

    def _resolver(sender: str, upstreams: list[dict], cache_scope: str):
        captured["sender"] = sender
        captured["upstreams"] = list(upstreams)
        captured["scope"] = cache_scope
        return {"host": "198.51.100.9"}

    monkeypatch.setattr(
        mod,
        "_resolve_notify_sender_upstream_from_candidates",
        _resolver,
        raising=True,
    )
    result = mod._resolve_notify_sender_for_zone(plugin, "example.com.", "192.0.2.5")
    assert result == {"host": "198.51.100.9"}
    assert captured["sender"] == "192.0.2.5"
    assert captured["upstreams"] == [{"host": "198.51.100.9"}]
    assert captured["scope"] == "zone:example.com"
    assert mod._resolve_notify_sender_for_zone(plugin, ".", "192.0.2.5") is None
    assert (
        mod._resolve_notify_sender_for_zone(plugin, "missing.example", "192.0.2.5")
        is None
    )


def test_zone_has_axfr_config_handles_invalid_entries() -> None:
    """Brief: _zone_has_axfr_config ignores non-dict entries and matches normalized zones.

    Inputs:
      - None

    Outputs:
      - None
    """

    plugin = _Plugin(axfr_zones=["skip", {"zone": "Example.COM."}])
    assert mod._zone_has_axfr_config(plugin, "example.com") is True
    assert mod._zone_has_axfr_config(plugin, "missing.example") is False
    assert mod._zone_has_axfr_config(plugin, ".") is False


def test_get_zone_notify_min_refresh_seconds_normalizes_and_handles_bad_values() -> (
    None
):
    """Brief: Zone min-refresh helper clamps negatives and handles parse failures.

    Inputs:
      - None

    Outputs:
      - None
    """

    plugin_ok = _Plugin(
        axfr_zones=[
            "skip",
            {"zone": "other.example", "minimum_reload_time": 99},
            {"zone": "example.com", "minimum_reload_time": "2.5"},
        ]
    )
    assert mod._get_zone_notify_min_refresh_seconds(plugin_ok, "example.com") == 2.5
    assert mod._get_zone_notify_min_refresh_seconds(plugin_ok, "missing.example") == 0.0

    plugin_negative = _Plugin(
        axfr_zones=[{"zone": "example.com", "minimum_reload_time": -9}]
    )
    assert (
        mod._get_zone_notify_min_refresh_seconds(plugin_negative, "example.com") == 0.0
    )

    plugin_bad = _Plugin(
        axfr_zones=[{"zone": "example.com", "minimum_reload_time": "bad"}]
    )
    assert mod._get_zone_notify_min_refresh_seconds(plugin_bad, "example.com") == 0.0


def test_notify_sender_is_rate_limited_token_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Sender rate limiter blocks repeated calls until tokens replenish.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    monkeypatch.setattr(mod, "_NOTIFY_RATE_LIMIT_BURST", 1.0, raising=True)
    monkeypatch.setattr(mod, "_NOTIFY_RATE_LIMIT_PER_SECOND", 1.0, raising=True)
    times = iter([100.0, 100.0, 100.1, 101.2])
    monkeypatch.setattr(mod.time, "time", lambda: next(times), raising=True)

    assert mod._notify_sender_is_rate_limited("192.0.2.44") is False
    assert mod._notify_sender_is_rate_limited("192.0.2.44") is True
    assert mod._notify_sender_is_rate_limited("192.0.2.44") is True
    assert mod._notify_sender_is_rate_limited("192.0.2.44") is False


def test_build_notify_response_falls_back_to_header_id_for_bad_wire() -> None:
    """Brief: _build_notify_response returns a minimal response for malformed requests.

    Inputs:
      - None

    Outputs:
      - None
    """

    wire = mod._build_notify_response(b"\x12\x34not-a-dns-message", int(RCODE.REFUSED))
    response = DNSRecord.parse(wire)
    assert response.header.id == 0x1234
    assert response.header.rcode == int(RCODE.REFUSED)


def test_build_notify_response_uses_server_helpers_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _build_notify_response invokes EDNS/EDE helper hooks for parsed requests.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    import foghorn.servers.server as server_mod

    req = DNSRecord(DNSHeader(id=22), q=DNSQuestion("example.com", QTYPE.SOA))
    req.header.opcode = OPCODE.NOTIFY

    calls: dict[str, object] = {}

    def _echo(_req: DNSRecord, _reply: DNSRecord) -> None:
        calls["echo"] = True

    def _attach(
        _req: DNSRecord, _reply: DNSRecord, code: int, text: str | None
    ) -> None:
        calls["ede"] = (code, text)

    def _set_id(wire: bytes, req_id: int) -> bytes:
        calls["set_id"] = req_id
        return wire

    monkeypatch.setattr(server_mod, "_echo_client_edns", _echo, raising=True)
    monkeypatch.setattr(server_mod, "_attach_ede_option", _attach, raising=True)
    monkeypatch.setattr(server_mod, "_set_response_id", _set_id, raising=True)

    response_wire = mod._build_notify_response(
        req.pack(),
        int(RCODE.NOERROR),
        ede_code=15,
        ede_text="blocked",
    )
    response = DNSRecord.parse(response_wire)
    assert response.header.rcode == int(RCODE.NOERROR)
    assert calls["echo"] is True
    assert calls["ede"] == (15, "blocked")
    assert calls["set_id"] == 22


def test_handle_notify_opcode_returns_none_for_non_notify_opcode() -> None:
    """Brief: _handle_notify_opcode does not handle non-NOTIFY opcodes.

    Inputs:
      - None

    Outputs:
      - None
    """

    plugin = _Plugin()
    ctx = PluginContext(client_ip="192.0.2.1", listener="tcp")
    req = DNSRecord.question("example.com", "SOA").pack()
    decision = mod._handle_notify_opcode(
        plugin,
        int(OPCODE.QUERY),
        "example.com",
        int(QTYPE.SOA),
        req,
        ctx,
    )
    assert decision is None


def test_handle_notify_opcode_returns_formerr_for_malformed_wire() -> None:
    """Brief: _handle_notify_opcode returns FORMERR for malformed NOTIFY payloads.

    Inputs:
      - None

    Outputs:
      - None
    """

    plugin = _Plugin()
    ctx = PluginContext(client_ip="192.0.2.1", listener="tcp")
    decision = mod._handle_notify_opcode(
        plugin,
        int(OPCODE.NOTIFY),
        "example.com",
        int(QTYPE.SOA),
        b"bad",
        ctx,
    )
    assert decision is not None
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == int(RCODE.FORMERR)


def test_handle_notify_opcode_uses_fallback_qname_and_skips_global_when_zone_has_axfr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Zone-bound authorization failure refuses without global-upstream fallback.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    plugin = _Plugin(axfr_zones=[{"zone": "example.com", "upstreams": [{"host": "x"}]}])
    ctx = PluginContext(client_ip="192.0.2.2", listener="tcp")
    req = DNSRecord(DNSHeader(id=9, opcode=OPCODE.NOTIFY)).pack()  # no questions

    monkeypatch.setattr(
        mod, "_notify_sender_is_rate_limited", lambda _ip: False, raising=True
    )
    monkeypatch.setattr(
        mod,
        "_resolve_notify_sender_for_zone",
        lambda *_a, **_k: None,
        raising=True,
    )

    global_calls = {"n": 0}

    def _global_lookup(_sender_ip: str):
        global_calls["n"] += 1
        return {"host": "198.51.100.99"}

    monkeypatch.setattr(
        mod, "_resolve_notify_sender_upstream", _global_lookup, raising=True
    )

    decision = mod._handle_notify_opcode(
        plugin,
        int(OPCODE.NOTIFY),
        "example.com",
        int(QTYPE.SOA),
        req,
        ctx,
    )
    assert decision is not None
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == int(RCODE.REFUSED)
    assert global_calls["n"] == 0


def test_handle_notify_opcode_uses_global_fallback_and_initializes_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Global sender authorization path schedules refresh and initializes metadata.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    plugin = _Plugin(axfr_zones=[])
    plugin._axfr_zone_metadata = None
    ctx = PluginContext(client_ip="192.0.2.7", listener="tcp")
    req = DNSRecord.question("example.com", "SOA")
    req.header.opcode = OPCODE.NOTIFY
    upstream = {"host": "198.51.100.7", "port": 53}

    monkeypatch.setattr(
        mod, "_notify_sender_is_rate_limited", lambda _ip: False, raising=True
    )
    monkeypatch.setattr(
        mod,
        "_resolve_notify_sender_for_zone",
        lambda *_a, **_k: None,
        raising=True,
    )
    monkeypatch.setattr(
        mod,
        "_resolve_notify_sender_upstream",
        lambda _ip: upstream,
        raising=True,
    )

    scheduled: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        mod,
        "_schedule_notify_axfr_refresh",
        lambda zone, target: scheduled.append((str(zone), dict(target))),
        raising=True,
    )

    decision = mod._handle_notify_opcode(
        plugin,
        int(OPCODE.NOTIFY),
        "example.com",
        int(QTYPE.SOA),
        req.pack(),
        ctx,
    )
    assert decision is not None
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == int(RCODE.NOERROR)
    assert scheduled == [("example.com", upstream)]
    assert isinstance(plugin._axfr_zone_metadata, dict)
    assert "last_notify" in plugin._axfr_zone_metadata["example.com"]


def test_handle_notify_opcode_refuses_rate_limited_sender(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _handle_notify_opcode refuses NOTIFY when sender is rate limited.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    plugin = _Plugin()
    ctx = PluginContext(client_ip="192.0.2.7", listener="tcp")
    req = DNSRecord.question("example.com", "SOA")
    req.header.opcode = OPCODE.NOTIFY
    monkeypatch.setattr(
        mod, "_notify_sender_is_rate_limited", lambda _ip: True, raising=True
    )

    decision = mod._handle_notify_opcode(
        plugin,
        int(OPCODE.NOTIFY),
        "example.com",
        int(QTYPE.SOA),
        req.pack(),
        ctx,
    )
    assert decision is not None
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == int(RCODE.REFUSED)


def test_axfr_wrapper_functions_delegate_to_transfer_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Backward-compat wrappers pass arguments through to transfer module.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None
    """

    monkeypatch.setattr(
        mod.transfer,
        "_client_allowed_for_axfr",
        lambda ip: ip == "192.0.2.33",
        raising=True,
    )
    assert mod._client_allowed_for_axfr("192.0.2.33") is True
    assert mod._client_allowed_for_axfr("192.0.2.34") is False

    req = DNSRecord.question("example.com", "AXFR")
    captured: dict[str, object] = {}

    def _iter(req_obj: DNSRecord, client_ip: str | None, req_wire: bytes | None):
        captured["req"] = req_obj
        captured["client_ip"] = client_ip
        captured["req_wire"] = req_wire
        return [b"chunk-a", b"chunk-b"]

    monkeypatch.setattr(mod.transfer, "iter_axfr_messages", _iter, raising=True)
    chunks = mod.iter_axfr_messages(req, client_ip="192.0.2.44", req_wire=b"wire")
    assert chunks == [b"chunk-a", b"chunk-b"]
    assert captured["req"] is req
    assert captured["client_ip"] == "192.0.2.44"
    assert captured["req_wire"] == b"wire"
