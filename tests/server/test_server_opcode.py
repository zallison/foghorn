"""Brief: Unit tests for non-QUERY opcode handling in server_opcode.

Inputs:
  - None.

Outputs:
  - None; validates branch behavior of _handle_non_query_opcode().
"""

from types import SimpleNamespace
import builtins

import dns.message
import dns.opcode
import dns.rcode
import dns.tsigkeyring
import dns.update

from dnslib import OPCODE, QTYPE, RCODE, DNSRecord

from foghorn.plugins.resolve.base import PluginDecision
from foghorn.servers import server_opcode as opcode_mod
from foghorn.servers.server_opcode import _handle_non_query_opcode


def _make_non_query_wire(
    name: str = "opcode.example",
    qtype: str = "A",
    *,
    opcode: int = OPCODE.NOTIFY,
    request_id: int = 0x1234,
) -> bytes:
    """Brief: Build a query wire payload with a non-QUERY opcode.

    Inputs:
      - name: DNS owner name to encode in the question section.
      - qtype: DNS qtype mnemonic for the question.
      - opcode: Header opcode integer to set on the query.
      - request_id: DNS message ID to place in the header.

    Outputs:
      - bytes: Wire-format DNS request suitable for _handle_non_query_opcode.
    """

    q = dns.message.make_query(name, qtype)
    q.id = request_id
    q.set_opcode(int(opcode))
    return q.to_wire()


def _call_non_query(opcode: int, data: bytes, plugins: list[object]):
    """Brief: Invoke _handle_non_query_opcode with a minimal handler object.

    Inputs:
      - opcode: Parsed opcode value.
      - data: Original DNS wire bytes.
      - plugins: Plugins exposed via handler.plugins.

    Outputs:
      - Optional[_ResolveCoreResult] as returned by _handle_non_query_opcode.
    """

    # Clear module-local caches to keep tests deterministic (rate limiter and
    # plugin sort caching are process-global in server_opcode).
    try:
        import foghorn.servers.server_opcode as _op

        _op._OP_RATE_BUCKETS.clear()
        _op._OP_PLUGINS_SORT_CACHE.clear()
    except Exception:
        pass

    handler = SimpleNamespace(plugins=plugins)
    return _handle_non_query_opcode(
        opcode=opcode,
        data=data,
        client_ip="127.0.0.1",
        listener="udp",
        secure=False,
        handler=handler,
    )


def test_opcode_zero_returns_none() -> None:
    """Brief: QUERY opcode is ignored by the non-query helper.

    Inputs:
      - None.

    Outputs:
      - None; asserts the helper returns None for opcode 0.
    """

    wire = _make_non_query_wire(opcode=OPCODE.QUERY)
    assert _call_non_query(OPCODE.QUERY, wire, plugins=[]) is None


def test_unhandled_non_query_opcode_returns_notimp_and_keeps_id() -> None:
    """Brief: Unhandled non-QUERY opcodes produce NOTIMP with the request ID.

    Inputs:
      - None.

    Outputs:
      - None; asserts NOTIMP response code and ID preservation.
    """

    wire = _make_non_query_wire(opcode=OPCODE.NOTIFY, request_id=0xA1B2)
    result = _call_non_query(OPCODE.NOTIFY, wire, plugins=[])

    assert result is not None
    assert result.rcode_name == "NOTIMP"
    resp = DNSRecord.parse(result.wire)
    assert resp.header.id == 0xA1B2
    assert resp.header.rcode == RCODE.NOTIMP


def test_unparseable_request_wire_uses_bare_notimp_fallback() -> None:
    """Brief: Invalid wire bytes still yield a synthetic NOTIMP response.

    Inputs:
      - None.

    Outputs:
      - None; asserts fallback NOTIMP generation when parsing fails.
    """

    wire = b"\x12\x34\x20\x00"
    result = _call_non_query(OPCODE.NOTIFY, wire, plugins=[])

    assert result is not None
    assert result.rcode_name == "NOTIMP"
    resp = DNSRecord.parse(result.wire)
    assert resp.header.id == 0x1234
    assert resp.header.rcode == RCODE.NOTIMP


def test_bad_question_attributes_fall_back_to_empty_qname_and_qtype(
    monkeypatch,
) -> None:
    """Brief: Question extraction failures reset qname/qtype to safe defaults.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts qname/qtype fallback to ('', 0) on extraction errors.
    """

    class _BadQuestion:
        name = "bad.example."
        rdtype = object()

    class _BadMessage:
        question = [_BadQuestion()]

    monkeypatch.setattr(dns.message, "from_wire", lambda _wire: _BadMessage())

    seen: dict[str, object] = {}

    class _CapturePlugin:
        def handle_opcode(self, opcode, qname, qtype, data, ctx):  # noqa: ANN001
            seen["qname"] = qname
            seen["qtype"] = qtype
            return PluginDecision(action="drop")

    result = _call_non_query(OPCODE.NOTIFY, b"ignored", plugins=[_CapturePlugin()])

    assert result is not None
    assert result.rcode_name == "DROP"
    assert seen["qname"] == ""
    assert seen["qtype"] == 0


def test_targets_opcode_false_skips_plugin_and_later_drop_wins() -> None:
    """Brief: targets_opcode(False) skips plugin execution and later plugins run.

    Inputs:
      - None.

    Outputs:
      - None; asserts skip semantics and drop handling.
    """

    class _SkipPlugin:
        pre_priority = 1

        def __init__(self) -> None:
            self.target_calls = 0
            self.handle_calls = 0

        def targets_opcode(self, opcode: int) -> bool:
            self.target_calls += 1
            return False

        def handle_opcode(self, opcode, qname, qtype, data, ctx):  # noqa: ANN001
            self.handle_calls += 1
            return PluginDecision(action="drop")

    class _DropPlugin:
        pre_priority = 2

        def handle_opcode(self, opcode, qname, qtype, data, ctx):  # noqa: ANN001
            return PluginDecision(action="drop")

    skip = _SkipPlugin()
    wire = _make_non_query_wire(opcode=OPCODE.NOTIFY)
    result = _call_non_query(OPCODE.NOTIFY, wire, plugins=[_DropPlugin(), skip])

    assert result is not None
    assert skip.target_calls == 1
    assert skip.handle_calls == 0
    assert result.rcode_name == "DROP"
    assert result.wire == b""


def _make_update_with_tsig(
    *,
    zone: str,
    key_name: str,
    key_secret_b64: str,
    algorithm: str = "hmac-sha256",
    request_id: int = 0x1234,
) -> bytes:
    """Brief: Build a minimal UPDATE message with TSIG.

    Inputs:
      - zone: Zone apex.
      - key_name: TSIG key name.
      - key_secret_b64: Base64 secret.
      - algorithm: TSIG algorithm identifier.
      - request_id: DNS message ID.

    Outputs:
      - bytes: Wire-format DNS UPDATE message.
    """
    keyring = dns.tsigkeyring.from_text({key_name: key_secret_b64})
    msg = dns.update.Update(zone)
    msg.id = int(request_id)
    msg.use_tsig(keyring=keyring, keyname=key_name, algorithm=algorithm)
    msg.add("host", 60, "A", "192.0.2.123")
    return msg.to_wire()


def test_override_response_sets_id_and_passes_qname_qtype_context() -> None:
    """Brief: Override responses keep request ID and preserve plugin context.

    Inputs:
      - None.

    Outputs:
      - None; asserts qname/qtype extraction, context fields, and ID rewrite.
    """

    class _OverridePlugin:
        pre_priority = 1

        def __init__(self) -> None:
            self.seen: dict[str, object] = {}

        def handle_opcode(self, opcode, qname, qtype, data, ctx):  # noqa: ANN001
            self.seen = {
                "opcode": opcode,
                "qname": qname,
                "qtype": qtype,
                "ctx_qname": getattr(ctx, "qname", None),
                "client_ip": ctx.client_ip,
                "listener": ctx.listener,
                "secure": ctx.secure,
            }
            override = DNSRecord.question("override.example", "A").reply()
            override.header.id = 0
            override.header.rcode = RCODE.SERVFAIL
            return PluginDecision(action="override", response=override.pack())

    plugin = _OverridePlugin()
    wire = _make_non_query_wire(
        name="MiXeD.Case.Example.",
        qtype="A",
        opcode=OPCODE.NOTIFY,
        request_id=0xBEEF,
    )
    result = _call_non_query(OPCODE.NOTIFY, wire, plugins=[plugin])

    assert result is not None
    assert result.rcode_name == "SERVFAIL"
    assert plugin.seen["opcode"] == OPCODE.NOTIFY
    assert str(plugin.seen["qname"]).lower() == "mixed.case.example"
    assert not str(plugin.seen["qname"]).endswith(".")
    assert str(plugin.seen["ctx_qname"]).lower() == "mixed.case.example"
    assert plugin.seen["qtype"] == QTYPE.A
    assert plugin.seen["client_ip"] == "127.0.0.1"
    assert plugin.seen["listener"] == "udp"
    assert plugin.seen["secure"] is False

    resp = DNSRecord.parse(result.wire)
    assert resp.header.id == 0xBEEF
    assert resp.header.rcode == RCODE.SERVFAIL


def test_override_with_invalid_wire_sets_override_rcode_name() -> None:
    """Brief: Invalid override payloads map to the synthetic OVERRIDE label.

    Inputs:
      - None.

    Outputs:
      - None; asserts fallback rcode_name when override wire cannot be parsed.
    """

    class _BadOverride:
        def handle_opcode(self, opcode, qname, qtype, data, ctx):  # noqa: ANN001
            return PluginDecision(action="override", response=b"\x00\x01\x02")

    wire = _make_non_query_wire(opcode=OPCODE.NOTIFY, request_id=0xCAFE)
    result = _call_non_query(OPCODE.NOTIFY, wire, plugins=[_BadOverride()])

    assert result is not None
    assert result.rcode_name == "OVERRIDE"
    assert result.wire[:2] == bytes([0xCA, 0xFE])


def test_override_with_non_bytes_input_is_handled_defensively() -> None:
    """Brief: Non-bytes request input should not crash override handling.

    Inputs:
      - None.

    Outputs:
      - None; asserts override path still returns a response for bad input type.
    """

    class _OverridePlugin:
        def handle_opcode(self, opcode, qname, qtype, data, ctx):  # noqa: ANN001
            reply = DNSRecord.question("defensive.example", "A").reply()
            return PluginDecision(action="override", response=reply.pack())

    result = _call_non_query(OPCODE.NOTIFY, "not-bytes", plugins=[_OverridePlugin()])

    assert result is not None
    assert result.rcode_name == "NOERROR"


def test_plugin_exceptions_and_non_decisions_are_ignored_before_deny() -> None:
    """Brief: Exception/non-decision plugins do not stop later deny handling.

    Inputs:
      - None.

    Outputs:
      - None; asserts continued iteration and final REFUSED response.
    """

    class _RaisesPlugin:
        pre_priority = 1

        def handle_opcode(self, opcode, qname, qtype, data, ctx):  # noqa: ANN001
            raise RuntimeError("boom")

    class _NonDecisionPlugin:
        pre_priority = 2

        def handle_opcode(self, opcode, qname, qtype, data, ctx):  # noqa: ANN001
            return "not-a-plugin-decision"

    class _DenyPlugin:
        pre_priority = 3

        def handle_opcode(self, opcode, qname, qtype, data, ctx):  # noqa: ANN001
            return PluginDecision(action="deny")

    wire = _make_non_query_wire(opcode=OPCODE.NOTIFY, request_id=0x1BAD)
    result = _call_non_query(
        OPCODE.NOTIFY,
        wire,
        plugins=[_DenyPlugin(), _NonDecisionPlugin(), _RaisesPlugin()],
    )

    assert result is not None
    assert result.rcode_name == "REFUSED"
    resp = DNSRecord.parse(result.wire)
    assert resp.header.id == 0x1BAD
    assert resp.header.rcode == RCODE.REFUSED


def test_deny_with_unparseable_wire_uses_minimal_refused_fallback() -> None:
    """Brief: Deny still returns REFUSED when request parsing fails.

    Inputs:
      - None.

    Outputs:
      - None; asserts bare REFUSED fallback behavior.
    """

    class _DenyPlugin:
        def handle_opcode(self, opcode, qname, qtype, data, ctx):  # noqa: ANN001
            return PluginDecision(action="deny")

    wire = b"\x22\x22\x20\x00"
    result = _call_non_query(OPCODE.NOTIFY, wire, plugins=[_DenyPlugin()])

    assert result is not None
    assert result.rcode_name == "REFUSED"
    resp = DNSRecord.parse(result.wire)
    assert resp.header.id == 0x2222
    assert resp.header.rcode == RCODE.REFUSED


def test_deny_with_non_bytes_input_uses_mid_zero_fallback() -> None:
    """Brief: Deny fallback uses message ID 0 when request input is non-bytes.

    Inputs:
      - None.

    Outputs:
      - None; asserts defensive REFUSED response with ID zero.
    """

    class _DenyPlugin:
        def handle_opcode(self, opcode, qname, qtype, data, ctx):  # noqa: ANN001
            return PluginDecision(action="deny")

    result = _call_non_query(OPCODE.NOTIFY, "not-bytes", plugins=[_DenyPlugin()])

    assert result is not None
    assert result.rcode_name == "REFUSED"
    resp = DNSRecord.parse(result.wire)
    assert resp.header.id == 0
    assert resp.header.rcode == RCODE.REFUSED


def test_override_without_response_falls_back_to_notimp() -> None:
    """Brief: Override decisions without response bytes are treated as unhandled.

    Inputs:
      - None.

    Outputs:
      - None; asserts fallback NOTIMP behavior.
    """

    class _NoResponseOverridePlugin:
        def handle_opcode(self, opcode, qname, qtype, data, ctx):  # noqa: ANN001
            return PluginDecision(action="override", response=None)

    wire = _make_non_query_wire(opcode=OPCODE.NOTIFY)
    result = _call_non_query(OPCODE.NOTIFY, wire, plugins=[_NoResponseOverridePlugin()])

    assert result is not None
    assert result.rcode_name == "NOTIMP"
    resp = DNSRecord.parse(result.wire)
    assert resp.header.rcode == RCODE.NOTIMP


def test_default_notimp_with_non_bytes_input_uses_mid_zero_fallback() -> None:
    """Brief: Unhandled non-bytes input returns defensive NOTIMP with ID zero.

    Inputs:
      - None.

    Outputs:
      - None; asserts fallback NOTIMP response and zero message ID.
    """

    result = _call_non_query(OPCODE.NOTIFY, "not-bytes", plugins=[])

    assert result is not None
    assert result.rcode_name == "NOTIMP"
    resp = DNSRecord.parse(result.wire)
    assert resp.header.id == 0
    assert resp.header.rcode == RCODE.NOTIMP


def test_tsig_signed_update_refused_when_no_keys_configured(monkeypatch) -> None:
    """Brief: TSIG-signed non-QUERY messages are refused when no keys exist.

    Inputs:
      - None.

    Outputs:
      - None; asserts REFUSED response for TSIG-signed UPDATE when keyring config
        is absent.
    """

    wire = _make_update_with_tsig(
        zone="example.com.",
        key_name="key.example.com.",
        key_secret_b64="dGVzdHNlY3JldA==",
        request_id=0xBEEF,
    )

    # Ensure server_opcode sees had_tsig=True even when parsing without keyring.
    keyring = dns.tsigkeyring.from_text({"key.example.com.": "dGVzdHNlY3JldA=="})
    signed_msg = dns.message.from_wire(wire, keyring=keyring)
    assert getattr(signed_msg, "had_tsig", False) is True

    def _fake_from_wire(w, *args, **kwargs):  # noqa: ANN001
        # Simulate a first parse error (no keyring supplied) and then a
        # continue_on_error parse that yields a TSIG-bearing message.
        if kwargs.get("continue_on_error"):
            return signed_msg
        raise Exception("parse failed")

    monkeypatch.setattr(dns.message, "from_wire", _fake_from_wire)

    handler = SimpleNamespace(plugins=[])
    result = _handle_non_query_opcode(
        opcode=OPCODE.UPDATE,
        data=wire,
        client_ip="127.0.0.1",
        listener="udp",
        secure=False,
        handler=handler,
    )

    assert result is not None
    assert result.rcode_name == "REFUSED"
    resp = DNSRecord.parse(result.wire)
    assert resp.header.id == 0xBEEF
    assert resp.header.rcode == RCODE.REFUSED


def test_tsig_signed_update_refused_on_bad_signature(monkeypatch) -> None:
    """Brief: TSIG-signed messages are refused when MAC verification fails.

    Inputs:
      - None.

    Outputs:
      - None; asserts REFUSED when configured TSIG secret does not match.
    """

    wire = _make_update_with_tsig(
        zone="example.com.",
        key_name="key.example.com.",
        key_secret_b64="dGVzdHNlY3JldA==",
        request_id=0xCAFE,
    )

    # Ensure server_opcode sees had_tsig=True on the initial parsing path while
    # still allowing update_processor.verify_tsig_auth() to call the real parser
    # with a keyring.
    keyring = dns.tsigkeyring.from_text({"key.example.com.": "dGVzdHNlY3JldA=="})
    signed_msg = dns.message.from_wire(wire, keyring=keyring)
    assert getattr(signed_msg, "had_tsig", False) is True

    real_from_wire = dns.message.from_wire

    def _fake_from_wire(w, *args, **kwargs):  # noqa: ANN001
        if "keyring" in kwargs:
            return real_from_wire(w, *args, **kwargs)
        if kwargs.get("continue_on_error"):
            return signed_msg
        raise Exception("parse failed")

    monkeypatch.setattr(dns.message, "from_wire", _fake_from_wire)

    class _KeysPlugin:
        _dns_update_tsig_key_source_loaders = None
        _dns_update_config = {
            "zones": [
                {
                    "zone": "example.com",
                    "tsig": {
                        "keys": [
                            {
                                "name": "key.example.com.",
                                "algorithm": "hmac-sha256",
                                "secret": "b3RoZXJzZWNyZXQ=",
                            }
                        ]
                    },
                }
            ]
        }

    handler = SimpleNamespace(plugins=[_KeysPlugin()])
    result = _handle_non_query_opcode(
        opcode=OPCODE.UPDATE,
        data=wire,
        client_ip="127.0.0.1",
        listener="udp",
        secure=False,
        handler=handler,
    )

    assert result is not None
    assert result.rcode_name == "REFUSED"
    resp = DNSRecord.parse(result.wire)
    assert resp.header.id == 0xCAFE
    assert resp.header.rcode == RCODE.REFUSED


def test_oversized_non_query_refused() -> None:
    """Brief: Oversized non-QUERY messages are refused before parsing.

    Inputs:
      - None.

    Outputs:
      - None; asserts REFUSED when payload exceeds MAX_NON_QUERY_BYTES.
    """

    oversized = b"\x12\x34\x20\x00" + (b"x" * (int(opcode_mod.MAX_NON_QUERY_BYTES) + 1))
    handler = SimpleNamespace(plugins=[])

    result = _handle_non_query_opcode(
        opcode=OPCODE.NOTIFY,
        data=oversized,
        client_ip="127.0.0.1",
        listener="udp",
        secure=False,
        handler=handler,
    )

    assert result is not None
    assert result.rcode_name == "REFUSED"
    resp = DNSRecord.parse(result.wire)
    assert resp.header.id == 0x1234
    assert resp.header.rcode == RCODE.REFUSED


def test_non_query_rate_limit_refused(monkeypatch) -> None:
    """Brief: Non-QUERY opcode safety rate limiter refuses excess requests.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts (limit+1)th request in same time bucket is REFUSED.
    """

    opcode_mod._OP_RATE_BUCKETS.clear()

    # Freeze bucket time so all calls fall into the same 1-second window.
    monkeypatch.setattr(opcode_mod.time, "time", lambda: 1700000000.0)

    handler = SimpleNamespace(plugins=[])
    wire = _make_non_query_wire(opcode=OPCODE.NOTIFY, request_id=0x1111)
    limit = int(opcode_mod.NON_QUERY_RATE_LIMIT_PER_SEC)

    last = None
    for _ in range(limit + 1):
        last = _handle_non_query_opcode(
            opcode=OPCODE.NOTIFY,
            data=wire,
            client_ip="127.0.0.1",
            listener="udp",
            secure=False,
            handler=handler,
        )

    assert last is not None
    assert last.rcode_name == "REFUSED"
    resp = DNSRecord.parse(last.wire)
    assert resp.header.id == 0x1111
    assert resp.header.rcode == RCODE.REFUSED


def test_non_query_rate_bucket_pruning_and_cap(monkeypatch) -> None:
    """Brief: Rate buckets are pruned and bounded to avoid unbounded growth.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts stale buckets are evicted and overflow is capped.
    """

    handler = SimpleNamespace(plugins=[])
    wire = _make_non_query_wire(opcode=OPCODE.NOTIFY, request_id=0x1212)

    opcode_mod._OP_RATE_BUCKETS.clear()
    opcode_mod._OP_RATE_BUCKETS.update(
        {
            (4, "stale-client"): (100, 1),
            (4, "fresh-client"): (104, 1),
        }
    )
    opcode_mod._OP_RATE_LAST_PRUNE_BUCKET = -1
    monkeypatch.setattr(opcode_mod, "_OP_RATE_BUCKET_RETENTION_SECONDS", 2)
    monkeypatch.setattr(opcode_mod, "_OP_RATE_BUCKET_MAX_ENTRIES", 10)
    monkeypatch.setattr(opcode_mod.time, "time", lambda: 105.0)

    _handle_non_query_opcode(
        opcode=OPCODE.NOTIFY,
        data=wire,
        client_ip="trigger-prune",
        listener="udp",
        secure=False,
        handler=handler,
    )

    assert (4, "stale-client") not in opcode_mod._OP_RATE_BUCKETS
    assert (4, "fresh-client") in opcode_mod._OP_RATE_BUCKETS

    opcode_mod._OP_RATE_BUCKETS.clear()
    opcode_mod._OP_RATE_BUCKETS.update(
        {
            (4, "client-1"): (200, 1),
            (4, "client-2"): (200, 1),
            (4, "client-3"): (200, 1),
            (4, "client-4"): (200, 1),
            (4, "client-5"): (200, 1),
        }
    )
    opcode_mod._OP_RATE_LAST_PRUNE_BUCKET = 200
    monkeypatch.setattr(opcode_mod, "_OP_RATE_BUCKET_RETENTION_SECONDS", 9999)
    monkeypatch.setattr(opcode_mod, "_OP_RATE_BUCKET_MAX_ENTRIES", 3)
    monkeypatch.setattr(opcode_mod.time, "time", lambda: 200.0)

    _handle_non_query_opcode(
        opcode=OPCODE.NOTIFY,
        data=wire,
        client_ip="client-5",
        listener="udp",
        secure=False,
        handler=handler,
    )

    assert len(opcode_mod._OP_RATE_BUCKETS) <= 3
    assert (4, "client-1") not in opcode_mod._OP_RATE_BUCKETS
    assert (4, "client-2") not in opcode_mod._OP_RATE_BUCKETS


def test_notify_allowlist_refuses_disallowed_client(monkeypatch) -> None:
    """Brief: NOTIFY is refused when AXFR policy is enabled and client not allowed.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts REFUSED for disallowed client_ip.
    """

    monkeypatch.setattr(
        "foghorn.runtime_config.get_runtime_snapshot",
        lambda: SimpleNamespace(axfr_enabled=True, axfr_allow_clients=["192.0.2.0/24"]),
    )

    handler = SimpleNamespace(plugins=[])
    wire = _make_non_query_wire(opcode=OPCODE.NOTIFY, request_id=0x2222)
    result = _handle_non_query_opcode(
        opcode=OPCODE.NOTIFY,
        data=wire,
        client_ip="198.51.100.1",
        listener="udp",
        secure=False,
        handler=handler,
    )

    assert result is not None
    assert result.rcode_name == "REFUSED"
    resp = DNSRecord.parse(result.wire)
    assert resp.header.id == 0x2222
    assert resp.header.rcode == RCODE.REFUSED


def test_notify_allowlist_allows_allowed_client_and_falls_through_notimp(
    monkeypatch,
) -> None:
    """Brief: Allowed NOTIFY clients proceed to default NOTIMP when unhandled.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts NOTIMP for allowed client when no plugin handles opcode.
    """

    monkeypatch.setattr(
        "foghorn.runtime_config.get_runtime_snapshot",
        lambda: SimpleNamespace(axfr_enabled=True, axfr_allow_clients=["192.0.2.0/24"]),
    )

    handler = SimpleNamespace(plugins=[])
    wire = _make_non_query_wire(opcode=OPCODE.NOTIFY, request_id=0x3333)
    result = _handle_non_query_opcode(
        opcode=OPCODE.NOTIFY,
        data=wire,
        client_ip="192.0.2.1",
        listener="udp",
        secure=False,
        handler=handler,
    )

    assert result is not None
    assert result.rcode_name == "NOTIMP"
    resp = DNSRecord.parse(result.wire)
    assert resp.header.id == 0x3333
    assert resp.header.rcode == RCODE.NOTIMP


def test_dnspython_missing_returns_notimp(monkeypatch) -> None:
    """Brief: When dnspython is unavailable, non-QUERY handling returns NOTIMP.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts NOTIMP and ID preservation.
    """

    real_import = builtins.__import__

    def _fake_import(
        name, globals=None, locals=None, fromlist=(), level=0
    ):  # noqa: ANN001
        if name == "dns" or name.startswith("dns."):
            raise ImportError("dnspython missing")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _fake_import)

    handler = SimpleNamespace(plugins=[])
    wire = _make_non_query_wire(opcode=OPCODE.NOTIFY, request_id=0x4444)
    result = _handle_non_query_opcode(
        opcode=OPCODE.NOTIFY,
        data=wire,
        client_ip="127.0.0.1",
        listener="udp",
        secure=False,
        handler=handler,
    )

    assert result is not None
    assert result.rcode_name == "NOTIMP"
    resp = DNSRecord.parse(result.wire)
    assert resp.header.id == 0x4444
    assert resp.header.rcode == RCODE.NOTIMP


def test_unhandled_tsig_update_preserves_update_opcode_in_response() -> None:
    """Brief: Unhandled TSIG-signed UPDATE replies retain UPDATE opcode.

    Inputs:
      - None.

    Outputs:
      - None; asserts fallback NOTIMP response uses opcode UPDATE.
    """

    key_name = "monkey.zaa."
    key_secret = "ilMpyS6H5z9tvSNlW7BJsdYhEn+H3ZrQuuZmiT43EM0="
    keyring = dns.tsigkeyring.from_text({key_name: key_secret})

    update = dns.update.Update("zaa.")
    update.id = 0xBACE
    update.use_tsig(keyring=keyring, keyname=key_name, algorithm="hmac-sha256")
    update.add("test.dyn.zaa.", 300, "A", "192.168.99.1")
    wire = update.to_wire()

    result = _call_non_query(OPCODE.UPDATE, wire, plugins=[])
    assert result is not None
    assert result.rcode_name == "NOTIMP"

    response = dns.message.from_wire(result.wire, ignore_trailing=True)
    assert response.id == 0xBACE
    assert response.opcode() == dns.opcode.UPDATE
    assert response.rcode() == dns.rcode.NOTIMP
