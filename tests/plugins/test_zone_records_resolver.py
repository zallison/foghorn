"""Brief: Targeted branch tests for zone_records resolver helpers."""

from __future__ import annotations

import builtins
from typing import Any

import pytest
from dnslib import OPCODE, QTYPE, RCODE, DNSRecord

from foghorn.plugins.resolve.base import PluginContext
from foghorn.plugins.resolve.zone_records import resolver


def _make_query(name: str, qtype: int) -> bytes:
    """Brief: Build a minimal DNS query wire payload.

    Inputs:
      - name: Query owner name.
      - qtype: Numeric DNS QTYPE code.

    Outputs:
      - bytes: DNS query wire bytes.
    """
    qtype_name = QTYPE.get(qtype, str(qtype))
    return DNSRecord.question(name, qtype=qtype_name).pack()


class _Plugin:
    """Brief: Minimal plugin-like object for resolver unit tests.

    Inputs:
      - targets_return: Return value for targets(ctx).
      - records: Optional (name, qtype) -> (ttl, values, source-meta) mapping.
      - name_index: Optional owner -> rrsets mapping.
      - zone_soa: Optional authoritative SOA mapping.
      - nxdomain_zones: Optional suffix list for synthetic NXDOMAIN mode.
      - dns_update_config: Optional dns_update config mapping.

    Outputs:
      - _Plugin object with attributes consumed by resolver.handle_opcode()
        and resolver.pre_resolve().
    """

    def __init__(
        self,
        *,
        targets_return: bool = True,
        records: dict[tuple[str, int], tuple[int, list[str], list[str]]] | None = None,
        name_index: (
            dict[str, dict[int, tuple[int, list[str], list[str]]]] | None
        ) = None,
        zone_soa: dict[str, tuple[int, list[str], list[str]]] | None = None,
        nxdomain_zones: list[object] | None = None,
        dns_update_config: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self._targets_return = bool(targets_return)
        self._records_lock = None
        self.records = records or {}
        self._name_index = name_index or {}
        self._zone_soa = zone_soa or {}
        self.mapping: dict[int, Any] = {}
        self._wildcard_owners: list[str] = []
        self._nxdomain_zones = list(nxdomain_zones or [])
        self._axfr_zone_metadata: dict[str, dict[str, object]] = {}
        self._dns_update_config = dns_update_config
        self.config = config or {}
        self._any_query_enabled = bool(self.config.get("any_query_enabled", False))
        self._any_answer_rrset_limit = int(
            self.config.get("any_answer_rrset_limit", 16)
        )
        self._any_answer_record_limit = int(
            self.config.get("any_answer_record_limit", 64)
        )

    def targets(self, _ctx: object) -> bool:
        """Brief: Return canned target-match status for tests.

        Inputs:
          - _ctx: Ignored plugin context argument.

        Outputs:
          - bool: Configured targets return value.
        """
        return self._targets_return


@pytest.fixture
def _stub_dnssec_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: Install simple dnssec stubs for deterministic resolver branch tests.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; monkeypatches resolver.dnssec helpers.
    """
    monkeypatch.setattr(resolver.dnssec, "client_wants_dnssec", lambda _req: False)
    monkeypatch.setattr(
        resolver.dnssec,
        "is_dnssec_rrtype",
        lambda qcode: int(qcode)
        in {
            int(QTYPE.RRSIG),
            int(QTYPE.DNSKEY),
            int(QTYPE.NSEC3),
            int(QTYPE.NSEC3PARAM),
        },
    )
    monkeypatch.setattr(
        resolver.dnssec,
        "add_rrset_to_reply",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        resolver.dnssec,
        "add_dnssec_rrsets",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        resolver.dnssec,
        "add_nsec3_denial_of_existence",
        lambda *_args, **_kwargs: None,
    )


def test_handle_opcode_update_returns_none_when_disabled() -> None:
    """Brief: UPDATE opcode falls through when dns_update is disabled.

    Inputs:
      - None.

    Outputs:
      - None; asserts None decision for disabled DNS UPDATE.
    """
    plugin = _Plugin(dns_update_config={"enabled": False})
    ctx = PluginContext(client_ip="192.0.2.1", listener="udp")
    decision = resolver.handle_opcode(
        plugin,
        int(getattr(OPCODE, "UPDATE", 5)),
        "example.com",
        int(QTYPE.SOA),
        b"",
        ctx,
    )
    assert decision is None


def test_handle_opcode_update_returns_none_when_zone_not_configured() -> None:
    """Brief: UPDATE opcode falls through when no configured zone matches qname.

    Inputs:
      - None.

    Outputs:
      - None; asserts None decision when zone lookup misses.
    """
    plugin = _Plugin(
        dns_update_config={
            "enabled": True,
            "zones": [{"zone": "other.example"}],
        }
    )
    ctx = PluginContext(client_ip="192.0.2.1", listener="udp")
    decision = resolver.handle_opcode(
        plugin,
        int(getattr(OPCODE, "UPDATE", 5)),
        "example.com",
        int(QTYPE.SOA),
        b"",
        ctx,
    )
    assert decision is None


def test_handle_opcode_update_dispatches_processor_with_ctx_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: UPDATE path uses process_update_message and tolerates ctx attr failures.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts override decision and fallback listener/client_ip values.
    """

    class _Ctx:
        @property
        def listener(self) -> str:  # pragma: no cover - reached via exception path
            raise RuntimeError("listener boom")

        @property
        def client_ip(self) -> str:  # pragma: no cover - reached via exception path
            raise RuntimeError("client boom")

    plugin = _Plugin(
        dns_update_config={
            "enabled": True,
            "zones": [{"zone": "example.com", "psk": {"tokens": []}}],
        }
    )
    captured: dict[str, object] = {}

    def _fake_process(
        req: bytes,
        *,
        zone_apex: str,
        zone_config: dict[str, object],
        plugin: object,
        client_ip: str,
        listener: str | None,
    ) -> bytes:
        captured["zone_apex"] = zone_apex
        captured["zone_config"] = zone_config
        captured["plugin"] = plugin
        captured["client_ip"] = client_ip
        captured["listener"] = listener
        captured["req"] = req
        return b"update-response-wire"

    monkeypatch.setattr(
        resolver.update_processor,
        "process_update_message",
        _fake_process,
        raising=True,
    )

    decision = resolver.handle_opcode(
        plugin,
        int(getattr(OPCODE, "UPDATE", 5)),
        "Example.COM.",
        int(QTYPE.SOA),
        b"raw-update-wire",
        _Ctx(),  # type: ignore[arg-type]
    )

    assert decision is not None
    assert decision.action == "override"
    assert decision.response == b"update-response-wire"
    assert captured["zone_apex"] == "example.com"
    assert captured["client_ip"] == ""
    assert captured["listener"] is None


def test_handle_opcode_notify_returns_override_when_server_import_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: NOTIFY still returns REFUSED when optional server helper import fails.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts override decision with REFUSED response.
    """
    plugin = _Plugin()
    ctx = PluginContext(client_ip="192.0.2.1", listener="udp")
    req = _make_query("example.com", int(QTYPE.SOA))

    orig_import = builtins.__import__

    def _fake_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "foghorn.servers":
            raise ImportError("boom")
        return orig_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _fake_import)

    decision = resolver.handle_opcode(
        plugin,
        int(OPCODE.NOTIFY),
        "example.com",
        int(QTYPE.SOA),
        req,
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == RCODE.REFUSED


def test_handle_opcode_notify_refuses_udp_listener() -> None:
    """Brief: NOTIFY requests on UDP listeners are refused.

    Inputs:
      - None.

    Outputs:
      - None; asserts override action with REFUSED response.
    """
    plugin = _Plugin()
    ctx = PluginContext(client_ip="192.0.2.1", listener="udp")
    req = _make_query("example.com", int(QTYPE.SOA))

    decision = resolver.handle_opcode(
        plugin,
        int(OPCODE.NOTIFY),
        "example.com",
        int(QTYPE.SOA),
        req,
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == RCODE.REFUSED


def test_handle_opcode_notify_denies_unknown_sender(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: NOTIFY requests from unknown upstreams are refused.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts override action with REFUSED response.
    """
    plugin = _Plugin()
    ctx = PluginContext(client_ip="192.0.2.1", listener="tcp")
    req = _make_query("example.com", int(QTYPE.SOA))

    import foghorn.plugins.resolve.zone_records as zone_records_mod

    monkeypatch.setattr(
        zone_records_mod,
        "_resolve_notify_sender_upstream",
        lambda _ip: None,
        raising=True,
    )

    decision = resolver.handle_opcode(
        plugin,
        int(OPCODE.NOTIFY),
        "example.com",
        int(QTYPE.SOA),
        req,
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == RCODE.REFUSED


def test_handle_opcode_notify_valid_sender_returns_noerror_and_updates_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Valid NOTIFY sender schedules refresh and returns NOERROR override.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts schedule call, metadata update, and NOERROR response.
    """
    plugin = _Plugin()
    ctx = PluginContext(client_ip="192.0.2.1", listener="tcp")
    req = _make_query("example.com", int(QTYPE.SOA))

    import foghorn.plugins.resolve.zone_records as zone_records_mod

    calls: list[tuple[str, dict[str, object]]] = []
    upstream = {"host": "198.51.100.10", "port": 53, "transport": "tcp"}
    plugin._axfr_zones = [{"zone": "example.com", "upstreams": [upstream]}]

    monkeypatch.setattr(
        zone_records_mod,
        "_resolve_notify_sender_for_zone",
        lambda *_args, **_kwargs: upstream,
        raising=True,
    )
    monkeypatch.setattr(
        zone_records_mod,
        "_schedule_notify_axfr_refresh",
        lambda zone, target: calls.append((str(zone), dict(target))),
        raising=True,
    )

    decision = resolver.handle_opcode(
        plugin,
        int(OPCODE.NOTIFY),
        "Example.COM.",
        int(QTYPE.SOA),
        req,
        ctx,
    )

    assert decision is not None
    assert decision.action == "override"
    assert calls == [("example.com", upstream)]

    reply = DNSRecord.parse(decision.response or b"")
    assert reply.header.rcode == RCODE.NOERROR
    assert "last_notify" in plugin._axfr_zone_metadata["example.com"]


def test_pre_resolve_returns_none_when_targets_do_not_match(
    _stub_dnssec_defaults: None,
) -> None:
    """Brief: pre_resolve exits early when plugin.targets(ctx) is False.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.

    Outputs:
      - None; asserts None decision.
    """
    plugin = _Plugin(targets_return=False)
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("no-target.example", int(QTYPE.A))
    assert (
        resolver.pre_resolve(plugin, "no-target.example", int(QTYPE.A), req, ctx)
        is None
    )


def test_pre_resolve_allows_ctx_none_branch(
    _stub_dnssec_defaults: None,
) -> None:
    """Brief: pre_resolve handles ctx=None without failing qname/targets checks.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.

    Outputs:
      - None; asserts override for exact legacy entry with ctx=None.
    """
    plugin = _Plugin(
        records={("exact.example", int(QTYPE.A)): (300, ["192.0.2.10"], ["src"])}
    )
    req = _make_query("exact.example", int(QTYPE.A))
    decision = resolver.pre_resolve(
        plugin,
        "exact.example",
        int(QTYPE.A),
        req,
        None,  # type: ignore[arg-type]
    )
    assert decision is not None
    assert decision.action == "override"


def test_pre_resolve_legacy_exact_match_returns_none_when_add_rrset_fails(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Legacy exact-match branch returns None when answer synthesis fails.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts None when add_rrset_to_reply() returns False.
    """
    plugin = _Plugin(
        records={("legacy.example", int(QTYPE.A)): (300, ["192.0.2.11"], ["src"])}
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("legacy.example", int(QTYPE.A))

    monkeypatch.setattr(
        resolver.dnssec,
        "add_rrset_to_reply",
        lambda *_args, **_kwargs: False,
        raising=True,
    )

    decision = resolver.pre_resolve(plugin, "legacy.example", int(QTYPE.A), req, ctx)
    assert decision is None


def test_pre_resolve_nxdomain_zones_skips_bad_and_blank_zone_entries(
    _stub_dnssec_defaults: None,
) -> None:
    """Brief: nxdomain_zones loop ignores bad str() and blank suffix entries.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.

    Outputs:
      - None; asserts NXDOMAIN override after skipping invalid zone entries.
    """

    class _BadStr:
        def __str__(self) -> str:
            raise ValueError("bad zone text")

    plugin = _Plugin(nxdomain_zones=[_BadStr(), ".", "private.test"])
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("missing.private.test", int(QTYPE.A))

    decision = resolver.pre_resolve(
        plugin,
        "missing.private.test",
        int(QTYPE.A),
        req,
        ctx,
    )
    assert decision is not None
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == RCODE.NXDOMAIN


def test_handle_opcode_update_skips_non_dict_zone_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: UPDATE zone scanning skips non-dict entries before matching.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts update override when a later dict zone matches.
    """
    plugin = _Plugin(
        dns_update_config={
            "enabled": True,
            "zones": ["bad-entry", {"zone": "example.com"}],
        }
    )
    ctx = PluginContext(client_ip="192.0.2.1", listener="udp")

    monkeypatch.setattr(
        resolver.update_processor,
        "process_update_message",
        lambda *_args, **_kwargs: b"update-wire",
        raising=True,
    )

    decision = resolver.handle_opcode(
        plugin,
        int(getattr(OPCODE, "UPDATE", 5)),
        "example.com",
        int(QTYPE.SOA),
        b"raw",
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"
    assert decision.response == b"update-wire"


def test_handle_opcode_notify_tolerates_listener_getattr_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: NOTIFY listener-gating tolerates context listener access exceptions.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts REFUSED override response after listener access error.
    """

    class _Ctx:
        client_ip = "192.0.2.1"

        @property
        def listener(self) -> str:
            raise RuntimeError("listener boom")

    plugin = _Plugin()
    req = _make_query("example.com", int(QTYPE.SOA))

    import foghorn.plugins.resolve.zone_records as zone_records_mod

    monkeypatch.setattr(
        zone_records_mod,
        "_resolve_notify_sender_upstream",
        lambda _ip: None,
        raising=True,
    )

    decision = resolver.handle_opcode(
        plugin,
        int(OPCODE.NOTIFY),
        "example.com",
        int(QTYPE.SOA),
        req,
        _Ctx(),  # type: ignore[arg-type]
    )
    assert decision is not None
    assert decision.action == "override"
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == RCODE.REFUSED


def test_handle_opcode_notify_handles_upstream_resolution_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: NOTIFY upstream-resolution exceptions are treated as unknown sender.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts REFUSED override response.
    """
    plugin = _Plugin()
    ctx = PluginContext(client_ip="192.0.2.1", listener="tcp")
    req = _make_query("example.com", int(QTYPE.SOA))

    import foghorn.plugins.resolve.zone_records as zone_records_mod

    monkeypatch.setattr(
        zone_records_mod,
        "_resolve_notify_sender_upstream",
        lambda _ip: (_ for _ in ()).throw(RuntimeError("boom")),
        raising=True,
    )

    decision = resolver.handle_opcode(
        plugin,
        int(OPCODE.NOTIFY),
        "example.com",
        int(QTYPE.SOA),
        req,
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == RCODE.REFUSED


def test_handle_opcode_notify_updates_existing_zone_metadata_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: NOTIFY writes last_notify when per-zone metadata already exists.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts metadata timestamp update.
    """
    plugin = _Plugin()
    plugin._axfr_zone_metadata = {"example.com": {"seed": 1}}
    ctx = PluginContext(client_ip="192.0.2.1", listener="tcp")
    req = _make_query("example.com", int(QTYPE.SOA))

    import foghorn.plugins.resolve.zone_records as zone_records_mod

    monkeypatch.setattr(
        zone_records_mod,
        "_resolve_notify_sender_for_zone",
        lambda *_args, **_kwargs: {"host": "198.51.100.10", "port": 53},
        raising=True,
    )
    monkeypatch.setattr(
        zone_records_mod,
        "_schedule_notify_axfr_refresh",
        lambda *_args, **_kwargs: None,
        raising=True,
    )

    decision = resolver.handle_opcode(
        plugin,
        int(OPCODE.NOTIFY),
        "example.com",
        int(QTYPE.SOA),
        req,
        ctx,
    )
    assert decision is not None
    assert "last_notify" in plugin._axfr_zone_metadata["example.com"]


def test_pre_resolve_nxdomain_zone_cname_branch_without_dnssec(
    _stub_dnssec_defaults: None,
) -> None:
    """Brief: nxdomain_zones CNAME path returns override when DNSSEC is not requested.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.

    Outputs:
      - None; asserts override decision.
    """
    plugin = _Plugin(
        nxdomain_zones=["private.test"],
        name_index={
            "alias.private.test": {
                int(QTYPE.CNAME): (60, ["target.example."], ["src"]),
            }
        },
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("alias.private.test", int(QTYPE.A))
    decision = resolver.pre_resolve(
        plugin,
        "alias.private.test",
        int(QTYPE.A),
        req,
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"


def test_pre_resolve_nxdomain_zone_any_handles_partial_add_failures_without_dnssec(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: nxdomain_zones ANY path tolerates per-rrset add failures with DO=0.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts override when at least one RRset add succeeds.
    """
    plugin = _Plugin(
        nxdomain_zones=["private.test"],
        name_index={
            "host.private.test": {
                int(QTYPE.A): (60, ["192.0.2.27"], ["src"]),
                int(QTYPE.AAAA): (60, ["2001:db8::27"], ["src"]),
            }
        },
        config={"any_query_enabled": True},
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.private.test", int(QTYPE.ANY))
    add_calls = {"n": 0}

    def _add_rrset(*_args: object, **_kwargs: object) -> bool:
        add_calls["n"] += 1
        return bool(add_calls["n"] > 1)

    monkeypatch.setattr(resolver.dnssec, "add_rrset_to_reply", _add_rrset, raising=True)

    decision = resolver.pre_resolve(
        plugin,
        "host.private.test",
        int(QTYPE.ANY),
        req,
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"


def test_pre_resolve_nxdomain_zone_exact_qtype_success_path(
    _stub_dnssec_defaults: None,
) -> None:
    """Brief: nxdomain_zones exact-qtype path returns override on successful add.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.

    Outputs:
      - None; asserts override decision.
    """
    plugin = _Plugin(
        nxdomain_zones=["private.test"],
        name_index={
            "host.private.test": {
                int(QTYPE.A): (60, ["192.0.2.28"], ["src"]),
            }
        },
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.private.test", int(QTYPE.A))
    decision = resolver.pre_resolve(
        plugin,
        "host.private.test",
        int(QTYPE.A),
        req,
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"


def test_pre_resolve_nxdomain_zone_nodata_dnssec_skips_nsec3_for_wildcard_match(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: nxdomain_zones NODATA skips NSEC3 helper when wildcard owner matched.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts NOERROR override without NSEC3 helper call.
    """
    plugin = _Plugin(nxdomain_zones=["private.test"], name_index={})
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.private.test", int(QTYPE.AAAA))
    nsec3_calls: list[tuple] = []

    monkeypatch.setattr(resolver.dnssec, "client_wants_dnssec", lambda _req: True)
    monkeypatch.setattr(
        resolver.helpers,
        "find_best_rrsets_for_name",
        lambda *_args, **_kwargs: (
            "*.private.test",
            {int(QTYPE.A): (60, ["192.0.2.29"], ["src"])},
        ),
        raising=True,
    )
    monkeypatch.setattr(
        resolver.dnssec,
        "add_nsec3_denial_of_existence",
        lambda *args, **kwargs: nsec3_calls.append((args, kwargs)),
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "host.private.test",
        int(QTYPE.AAAA),
        req,
        ctx,
    )
    assert decision is not None
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == RCODE.NOERROR
    assert not nsec3_calls


def test_pre_resolve_authoritative_nodata_dnssec_skips_nsec3_for_wildcard_owner(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Authoritative NODATA with wildcard expansion skips NSEC3 helper.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts NOERROR override and no add_nsec3_denial_of_existence call.
    """
    plugin = _Plugin(
        zone_soa={
            "example.com": (
                300,
                ["ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"],
                ["src"],
            )
        },
        name_index={
            "*.example.com": {
                int(QTYPE.A): (60, ["192.0.2.30"], ["src"]),
            }
        },
    )
    plugin._wildcard_owners = ["*.example.com"]
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("x.example.com", int(QTYPE.AAAA))
    calls: list[tuple] = []

    monkeypatch.setattr(resolver.dnssec, "client_wants_dnssec", lambda _req: True)
    monkeypatch.setattr(
        resolver.dnssec,
        "add_nsec3_denial_of_existence",
        lambda *args, **kwargs: calls.append((args, kwargs)),
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "x.example.com",
        int(QTYPE.AAAA),
        req,
        ctx,
    )
    assert decision is not None
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == RCODE.NOERROR
    assert not calls


def test_pre_resolve_nxdomain_zone_exact_qtype_second_lookup_path_with_dnssec(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: nxdomain_zones exact-qtype path can be reached after initial no-entry lookup.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts override and add_dnssec_rrsets call for exact-qtype branch.
    """
    plugin = _Plugin(nxdomain_zones=["private.test"], name_index={})
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.private.test", int(QTYPE.A))
    helper_calls = {"n": 0}
    dnssec_calls: list[tuple] = []

    def _find_best(
        *_args: object, **_kwargs: object
    ) -> tuple[str | None, dict[int, tuple[int, list[str], list[str]]]]:
        helper_calls["n"] += 1
        if helper_calls["n"] == 1:
            return None, {}
        return (
            "host.private.test",
            {int(QTYPE.A): (60, ["192.0.2.31"], ["src"])},
        )

    monkeypatch.setattr(resolver.dnssec, "client_wants_dnssec", lambda _req: True)
    monkeypatch.setattr(
        resolver.helpers,
        "find_best_rrsets_for_name",
        _find_best,
        raising=True,
    )
    monkeypatch.setattr(
        resolver.dnssec,
        "add_dnssec_rrsets",
        lambda *args, **kwargs: dnssec_calls.append((args, kwargs)),
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "host.private.test",
        int(QTYPE.A),
        req,
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"
    assert dnssec_calls


def test_pre_resolve_nxdomain_zone_exact_qtype_second_lookup_add_failure(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: nxdomain_zones exact-qtype path returns None when RRset add fails.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts None decision from exact-qtype add failure.
    """
    plugin = _Plugin(nxdomain_zones=["private.test"], name_index={})
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.private.test", int(QTYPE.A))
    helper_calls = {"n": 0}

    def _find_best(
        *_args: object, **_kwargs: object
    ) -> tuple[str | None, dict[int, tuple[int, list[str], list[str]]]]:
        helper_calls["n"] += 1
        if helper_calls["n"] == 1:
            return None, {}
        return (
            "host.private.test",
            {int(QTYPE.A): (60, ["192.0.2.32"], ["src"])},
        )

    monkeypatch.setattr(
        resolver.helpers,
        "find_best_rrsets_for_name",
        _find_best,
        raising=True,
    )
    monkeypatch.setattr(
        resolver.dnssec,
        "add_rrset_to_reply",
        lambda *_args, **_kwargs: False,
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "host.private.test",
        int(QTYPE.A),
        req,
        ctx,
    )
    assert decision is None


def test_pre_resolve_nxdomain_zone_exact_qtype_second_lookup_without_dnssec(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: nxdomain_zones exact-qtype path returns override when DO=0.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts override and no dnssec-rrset augmentation.
    """
    plugin = _Plugin(nxdomain_zones=["private.test"], name_index={})
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.private.test", int(QTYPE.A))
    helper_calls = {"n": 0}
    dnssec_calls: list[tuple] = []

    def _find_best(
        *_args: object, **_kwargs: object
    ) -> tuple[str | None, dict[int, tuple[int, list[str], list[str]]]]:
        helper_calls["n"] += 1
        if helper_calls["n"] == 1:
            return None, {}
        return (
            "host.private.test",
            {int(QTYPE.A): (60, ["192.0.2.33"], ["src"])},
        )

    monkeypatch.setattr(resolver.dnssec, "client_wants_dnssec", lambda _req: False)
    monkeypatch.setattr(
        resolver.helpers,
        "find_best_rrsets_for_name",
        _find_best,
        raising=True,
    )
    monkeypatch.setattr(
        resolver.dnssec,
        "add_dnssec_rrsets",
        lambda *args, **kwargs: dnssec_calls.append((args, kwargs)),
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "host.private.test",
        int(QTYPE.A),
        req,
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"
    assert not dnssec_calls


def test_pre_resolve_nxdomain_zone_cname_branch_covers_add_failure(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: nxdomain_zones CNAME branch returns None when CNAME add fails.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts None decision on failed CNAME RRset add.
    """
    plugin = _Plugin(
        nxdomain_zones=["private.test"],
        name_index={
            "alias.private.test": {
                int(QTYPE.CNAME): (60, ["target.example."], ["src"]),
            }
        },
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("alias.private.test", int(QTYPE.A))

    monkeypatch.setattr(
        resolver.dnssec,
        "add_rrset_to_reply",
        lambda *_args, **_kwargs: False,
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "alias.private.test",
        int(QTYPE.A),
        req,
        ctx,
    )
    assert decision is None


def test_pre_resolve_nxdomain_zone_cname_branch_adds_dnssec_when_requested(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: nxdomain_zones CNAME branch appends DNSSEC rrsets when requested.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts override and add_dnssec_rrsets call.
    """
    plugin = _Plugin(
        nxdomain_zones=["private.test"],
        name_index={
            "alias.private.test": {
                int(QTYPE.CNAME): (60, ["target.example."], ["src"]),
            }
        },
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("alias.private.test", int(QTYPE.A))
    calls: list[tuple] = []

    monkeypatch.setattr(resolver.dnssec, "client_wants_dnssec", lambda _req: True)
    monkeypatch.setattr(
        resolver.dnssec,
        "add_dnssec_rrsets",
        lambda *args, **kwargs: calls.append((args, kwargs)),
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "alias.private.test",
        int(QTYPE.A),
        req,
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"
    assert calls


def test_pre_resolve_nxdomain_zone_any_branch_returns_none_when_all_rrs_filtered(
    _stub_dnssec_defaults: None,
) -> None:
    """Brief: nxdomain_zones ANY returns None when DO=0 filters all DNSSEC-only rrsets.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.

    Outputs:
      - None; asserts None when added_any remains False.
    """
    plugin = _Plugin(
        nxdomain_zones=["private.test"],
        name_index={
            "host.private.test": {
                int(QTYPE.RRSIG): (60, ["A 13 2 300 1 1 1 example. AAA="], ["src"])
            }
        },
        config={"any_query_enabled": True},
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.private.test", int(QTYPE.ANY))

    decision = resolver.pre_resolve(
        plugin,
        "host.private.test",
        int(QTYPE.ANY),
        req,
        ctx,
    )
    assert decision is None


def test_pre_resolve_nxdomain_zone_any_branch_with_dnssec_adds_rrsets(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: nxdomain_zones ANY path includes rrsets and DNSSEC when requested.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts override and add_dnssec_rrsets call.
    """
    plugin = _Plugin(
        nxdomain_zones=["private.test"],
        name_index={
            "host.private.test": {
                int(QTYPE.A): (60, ["192.0.2.20"], ["src"]),
            }
        },
        config={"any_query_enabled": True},
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.private.test", int(QTYPE.ANY))
    calls: list[tuple] = []

    monkeypatch.setattr(resolver.dnssec, "client_wants_dnssec", lambda _req: True)
    monkeypatch.setattr(
        resolver.dnssec,
        "add_dnssec_rrsets",
        lambda *args, **kwargs: calls.append((args, kwargs)),
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "host.private.test",
        int(QTYPE.ANY),
        req,
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"
    assert calls


def test_pre_resolve_nxdomain_zone_exact_qtype_returns_none_when_add_fails(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: nxdomain_zones exact-qtype branch returns None on add_rrset failure.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts None decision.
    """
    plugin = _Plugin(
        nxdomain_zones=["private.test"],
        name_index={
            "host.private.test": {
                int(QTYPE.A): (60, ["192.0.2.21"], ["src"]),
            }
        },
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.private.test", int(QTYPE.A))

    monkeypatch.setattr(
        resolver.dnssec,
        "add_rrset_to_reply",
        lambda *_args, **_kwargs: False,
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "host.private.test",
        int(QTYPE.A),
        req,
        ctx,
    )
    assert decision is None


def test_pre_resolve_nxdomain_zone_nodata_with_dnssec_adds_nsec3(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: nxdomain_zones NODATA branch adds denial proof when owner is concrete.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts NOERROR override and add_nsec3_denial_of_existence call.
    """
    plugin = _Plugin(
        nxdomain_zones=["private.test"],
        name_index={
            "host.private.test": {
                int(QTYPE.A): (60, ["192.0.2.22"], ["src"]),
            }
        },
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.private.test", int(QTYPE.AAAA))
    calls: list[tuple] = []

    monkeypatch.setattr(resolver.dnssec, "client_wants_dnssec", lambda _req: True)
    monkeypatch.setattr(
        resolver.dnssec,
        "add_nsec3_denial_of_existence",
        lambda *args, **kwargs: calls.append((args, kwargs)),
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "host.private.test",
        int(QTYPE.AAAA),
        req,
        ctx,
    )
    assert decision is not None
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == RCODE.NOERROR
    assert calls


def test_pre_resolve_authoritative_cname_logs_and_returns_none_on_add_failure(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Brief: Authoritative CNAME+other-rrset path logs warning and handles add failure.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.
      - caplog: pytest logging capture fixture.

    Outputs:
      - None; asserts warning is logged and decision is None.
    """
    plugin = _Plugin(
        zone_soa={
            "example.com": (
                300,
                ["ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"],
                ["src"],
            )
        },
        name_index={
            "www.example.com": {
                int(QTYPE.CNAME): (60, ["target.example.com."], ["src"]),
                int(QTYPE.A): (60, ["192.0.2.23"], ["src"]),
            }
        },
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("www.example.com", int(QTYPE.A))

    monkeypatch.setattr(
        resolver.dnssec,
        "add_rrset_to_reply",
        lambda *_args, **_kwargs: False,
        raising=True,
    )

    with caplog.at_level("WARNING"):
        decision = resolver.pre_resolve(
            plugin,
            "www.example.com",
            int(QTYPE.A),
            req,
            ctx,
        )

    assert decision is None
    assert "CNAME and other RRsets" in caplog.text


def test_pre_resolve_authoritative_cname_adds_dnssec_when_requested(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Authoritative CNAME path appends DNSSEC rrsets when requested.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts override and add_dnssec_rrsets call.
    """
    plugin = _Plugin(
        zone_soa={
            "example.com": (
                300,
                ["ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"],
                ["src"],
            )
        },
        name_index={
            "www.example.com": {
                int(QTYPE.CNAME): (60, ["target.example.com."], ["src"]),
            }
        },
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("www.example.com", int(QTYPE.A))
    calls: list[tuple] = []

    monkeypatch.setattr(resolver.dnssec, "client_wants_dnssec", lambda _req: True)
    monkeypatch.setattr(
        resolver.dnssec,
        "add_dnssec_rrsets",
        lambda *args, **kwargs: calls.append((args, kwargs)),
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "www.example.com",
        int(QTYPE.A),
        req,
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"
    assert calls


def test_pre_resolve_authoritative_any_returns_none_when_all_rrsets_filtered(
    _stub_dnssec_defaults: None,
) -> None:
    """Brief: Authoritative ANY returns None when DO=0 filters all DNSSEC-only types.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.

    Outputs:
      - None; asserts None decision.
    """
    plugin = _Plugin(
        zone_soa={
            "example.com": (
                300,
                ["ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"],
                ["src"],
            )
        },
        name_index={
            "host.example.com": {
                int(QTYPE.RRSIG): (60, ["A 13 2 300 1 1 1 example. AAA="], ["src"])
            }
        },
        config={"any_query_enabled": True},
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.example.com", int(QTYPE.ANY))

    decision = resolver.pre_resolve(
        plugin,
        "host.example.com",
        int(QTYPE.ANY),
        req,
        ctx,
    )
    assert decision is None


def test_pre_resolve_authoritative_any_handles_partial_add_failures_and_dnssec(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Authoritative ANY tolerates add failures and still adds DNSSEC on success.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts override decision and add_dnssec_rrsets call.
    """
    plugin = _Plugin(
        zone_soa={
            "example.com": (
                300,
                ["ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"],
                ["src"],
            )
        },
        name_index={
            "host.example.com": {
                int(QTYPE.A): (60, ["192.0.2.24"], ["src"]),
                int(QTYPE.AAAA): (60, ["2001:db8::24"], ["src"]),
            }
        },
        config={"any_query_enabled": True},
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.example.com", int(QTYPE.ANY))
    calls: list[tuple] = []
    add_calls = {"n": 0}

    def _add_rrset(*_args: object, **_kwargs: object) -> bool:
        add_calls["n"] += 1
        return bool(add_calls["n"] > 1)

    monkeypatch.setattr(resolver.dnssec, "client_wants_dnssec", lambda _req: True)
    monkeypatch.setattr(resolver.dnssec, "add_rrset_to_reply", _add_rrset, raising=True)
    monkeypatch.setattr(
        resolver.dnssec,
        "add_dnssec_rrsets",
        lambda *args, **kwargs: calls.append((args, kwargs)),
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "host.example.com",
        int(QTYPE.ANY),
        req,
        ctx,
    )
    assert decision is not None
    assert decision.action == "override"
    assert calls


def test_pre_resolve_any_refused_when_disabled(
    _stub_dnssec_defaults: None,
) -> None:
    """Brief: QTYPE=ANY is refused by default when any_query_enabled is false.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.

    Outputs:
      - None; asserts REFUSED response.
    """
    plugin = _Plugin(
        zone_soa={
            "example.com": (
                300,
                ["ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"],
                ["src"],
            )
        },
        name_index={"host.example.com": {int(QTYPE.A): (60, ["192.0.2.24"], ["src"])}},
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.example.com", int(QTYPE.ANY))
    decision = resolver.pre_resolve(
        plugin,
        "host.example.com",
        int(QTYPE.ANY),
        req,
        ctx,
    )
    assert decision is not None
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == RCODE.REFUSED


def test_pre_resolve_targets_exception_fails_closed(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: pre_resolve returns None when targets() raises to avoid fail-open.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts None decision on targets() error.
    """
    plugin = _Plugin(
        records={("exact.example", int(QTYPE.A)): (300, ["192.0.2.10"], ["src"])}
    )
    ctx = PluginContext(client_ip="192.0.2.1")

    def _boom(_ctx: object) -> bool:
        raise RuntimeError("targets boom")

    monkeypatch.setattr(plugin, "targets", _boom, raising=True)
    req = _make_query("exact.example", int(QTYPE.A))
    assert resolver.pre_resolve(plugin, "exact.example", int(QTYPE.A), req, ctx) is None


def test_pre_resolve_ad_bit_unset_by_default(
    _stub_dnssec_defaults: None,
) -> None:
    """Brief: AD flag is not set on authoritative replies by default.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.

    Outputs:
      - None; asserts AD bit is false.
    """
    plugin = _Plugin(
        zone_soa={
            "example.com": (
                300,
                ["ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"],
                ["src"],
            )
        },
        name_index={"host.example.com": {int(QTYPE.A): (60, ["192.0.2.24"], ["src"])}},
        config={"any_query_enabled": True},
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.example.com", int(QTYPE.A))
    decision = resolver.pre_resolve(
        plugin,
        "host.example.com",
        int(QTYPE.A),
        req,
        ctx,
    )
    assert decision is not None
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.ad == 0


def test_pre_resolve_authoritative_nodata_with_missing_soa_entry_still_overrides(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Authoritative NODATA returns override even when no SOA entry is present.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts NOERROR override without requiring authority SOA.
    """
    plugin = _Plugin(
        zone_soa={},
        name_index={
            "host.example.com": {
                int(QTYPE.A): (60, ["192.0.2.25"], ["src"]),
            }
        },
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.example.com", int(QTYPE.AAAA))

    monkeypatch.setattr(
        resolver.helpers,
        "find_zone_for_name",
        lambda _name, _soa: "example.com",
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "host.example.com",
        int(QTYPE.AAAA),
        req,
        ctx,
    )
    assert decision is not None
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == RCODE.NOERROR


def test_pre_resolve_authoritative_nodata_dnssec_adds_nsec3_for_concrete_owner(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Authoritative NODATA with DO=1 attaches NSEC3 denial for concrete owner.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts add_nsec3_denial_of_existence is called.
    """
    plugin = _Plugin(
        zone_soa={
            "example.com": (
                300,
                ["ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"],
                ["src"],
            )
        },
        name_index={
            "host.example.com": {
                int(QTYPE.A): (60, ["192.0.2.26"], ["src"]),
            }
        },
    )
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("host.example.com", int(QTYPE.AAAA))
    calls: list[tuple] = []

    monkeypatch.setattr(resolver.dnssec, "client_wants_dnssec", lambda _req: True)
    monkeypatch.setattr(
        resolver.dnssec,
        "add_nsec3_denial_of_existence",
        lambda *args, **kwargs: calls.append((args, kwargs)),
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "host.example.com",
        int(QTYPE.AAAA),
        req,
        ctx,
    )
    assert decision is not None
    assert calls


def test_pre_resolve_authoritative_nxdomain_without_soa_entry_still_overrides(
    _stub_dnssec_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Authoritative NXDOMAIN path works even when SOA entry is unavailable.

    Inputs:
      - _stub_dnssec_defaults: fixture for dnssec stubs.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts NXDOMAIN override.
    """
    plugin = _Plugin(zone_soa={}, name_index={})
    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("missing.example.com", int(QTYPE.A))

    monkeypatch.setattr(
        resolver.helpers,
        "find_zone_for_name",
        lambda _name, _soa: "example.com",
        raising=True,
    )

    decision = resolver.pre_resolve(
        plugin,
        "missing.example.com",
        int(QTYPE.A),
        req,
        ctx,
    )
    assert decision is not None
    response = DNSRecord.parse(decision.response or b"")
    assert response.header.rcode == RCODE.NXDOMAIN
