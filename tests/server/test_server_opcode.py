"""Brief: Unit tests for non-QUERY opcode handling in server_opcode.

Inputs:
  - None.

Outputs:
  - None; validates branch behavior of _handle_non_query_opcode().
"""

from types import SimpleNamespace
import dns.message

from dnslib import OPCODE, QTYPE, RCODE, DNSRecord

from foghorn.plugins.resolve.base import PluginDecision
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
