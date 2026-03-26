from __future__ import annotations

import threading
from types import SimpleNamespace
from typing import Any, Callable, Optional

import dns.exception
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.update
import pytest
from dnslib import QTYPE

from foghorn.plugins.resolve.zone_records import update_processor as up


def _zone_cfg(
    *,
    key_name: str,
    secret_b64: str,
    extra_keys: Optional[list[Any]] = None,
) -> dict:
    """Brief: Build TSIG zone config used by process_update_message tests.

    Inputs:
      - key_name: TSIG key name.
      - secret_b64: Base64 TSIG secret.
      - extra_keys: Optional additional key entries (including malformed items).

    Outputs:
      - dict: zone_config payload containing tsig.keys.
    """
    keys: list[Any] = [
        {
            "name": key_name,
            "algorithm": "hmac-sha256",
            "secret": secret_b64,
            "allow_names": ["*.example.com", "example.com"],
        }
    ]
    if extra_keys:
        keys = list(extra_keys) + keys
    return {"tsig": {"keys": keys}}


def _signed_update_wire(
    *,
    zone: str = "example.com.",
    key_name: str = "key.example.com.",
    secret_b64: str = "dGVzdHNlY3JldA==",
    owner: str = "host",
    ttl: int = 60,
    rtype: str = "A",
    values: Optional[list[str]] = None,
    fudge: Optional[int] = None,
) -> tuple[bytes, dns.tsigkeyring.Keyring]:
    """Brief: Build a TSIG-signed UPDATE wire payload for branch tests.

    Inputs:
      - zone/key_name/secret_b64: TSIG signing inputs.
      - owner/ttl/rtype/values: UPDATE RRset data.
      - fudge: Optional TSIG fudge.

    Outputs:
      - tuple[bytes, Keyring]: Wire payload and keyring for response verification.
    """
    keyring = dns.tsigkeyring.from_text({key_name: secret_b64})
    msg = dns.update.Update(zone)
    if fudge is None:
        msg.use_tsig(keyring=keyring, keyname=key_name, algorithm="hmac-sha256")
    else:
        msg.use_tsig(
            keyring=keyring,
            keyname=key_name,
            algorithm="hmac-sha256",
            fudge=int(fudge),
        )
    for value in values or ["192.0.2.10"]:
        msg.add(owner, int(ttl), rtype, value)
    return msg.to_wire(), keyring


class _RRset:
    """Brief: Minimal RRset-like object used by helper branch tests."""

    def __init__(
        self,
        *,
        name: Any,
        rdtype: int,
        rdclass: int,
        ttl: int = 0,
        values: Optional[list[str]] = None,
    ) -> None:
        self.name = name
        self.rdtype = int(rdtype)
        self.rdclass = int(rdclass)
        self.ttl = int(ttl)
        self._values = list(values or [])

    def __iter__(self):
        return iter(self._values)


def test_verify_tsig_auth_peer_bad_key_and_iteration_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: verify_tsig_auth covers PeerBadKey and config iteration continue paths."""
    wire, _ = _signed_update_wire()

    monkeypatch.setattr(
        dns.message,
        "from_wire",
        lambda *_a, **_kw: (_ for _ in ()).throw(dns.tsig.PeerBadKey("badkey")),
    )
    ok, err, cfg = up.verify_tsig_auth(
        wire,
        key_configs=[
            {
                "name": "key.example.com.",
                "secret": "dGVzdA==",
                "algorithm": "hmac-sha256",
            }
        ],
    )
    assert ok is False
    assert cfg is None
    assert err is not None and "unknown tsig key" in err.lower()

    class _Msg:
        had_tsig = True
        tsig = [SimpleNamespace(fudge=0)]
        keyname = "key.example.com."
        keyalgorithm = "hmac-sha256."

    monkeypatch.setattr(dns.message, "from_wire", lambda *_a, **_kw: _Msg())
    ok2, err2, cfg2 = up.verify_tsig_auth(
        wire,
        key_configs=[
            "bad-entry",
            {
                "name": "other.example.com.",
                "secret": "dGVzdA==",
                "algorithm": "hmac-sha256",
            },
            {
                "name": "key.example.com.",
                "secret": "dGVzdA==",
                "algorithm": "hmac-sha256",
            },
        ],
    )
    assert ok2 is True
    assert err2 is None
    assert cfg2 is not None and cfg2["name"] == "key.example.com."


@pytest.mark.parametrize(
    "exc_factory",
    [
        lambda: dns.tsig.PeerBadKey("bad"),
        dns.tsig.BadSignature,
        lambda: dns.tsig.PeerBadTime("time"),
        lambda: dns.exception.DNSException("dns"),
    ],
)
def test_process_update_message_tsig_parse_error_recovery_notauth(
    monkeypatch: pytest.MonkeyPatch,
    exc_factory: Callable[[], Exception],
) -> None:
    """Brief: TSIG parse failures recover to protocol response with NOTAUTH."""
    request_wire, _ = _signed_update_wire()
    original_from_wire = dns.message.from_wire

    def _fake_from_wire(data, *args, **kwargs):
        if kwargs.get("keyring") is not None:
            raise exc_factory()
        if kwargs.get("continue_on_error"):
            return original_from_wire(request_wire, ignore_trailing=True)
        return original_from_wire(data, *args, **kwargs)

    monkeypatch.setattr(dns.message, "from_wire", _fake_from_wire)
    plugin = SimpleNamespace(records={})
    response_wire = up.process_update_message(
        request_wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )
    response = original_from_wire(response_wire, ignore_trailing=True)
    assert response.rcode() == dns.rcode.NOTAUTH


def test_process_update_message_worst_case_fallback_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Worst-case fallback returns NOTAUTH/FORMERR for unrecoverable parse cases."""
    original_from_wire = dns.message.from_wire

    def _always_fail_with_tsig(data, *args, **kwargs):
        if kwargs.get("keyring") is not None:
            raise dns.tsig.BadSignature()
        raise ValueError("parse boom")

    monkeypatch.setattr(dns.message, "from_wire", _always_fail_with_tsig)
    plugin = SimpleNamespace(records={})
    resp_notauth = up.process_update_message(
        None,  # type: ignore[arg-type]
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )
    parsed_notauth = original_from_wire(resp_notauth, ignore_trailing=True)
    assert parsed_notauth.rcode() == dns.rcode.NOTAUTH

    monkeypatch.setattr(
        dns.message,
        "from_wire",
        lambda *_a, **_kw: (_ for _ in ()).throw(ValueError("parse boom")),
    )
    resp_formerr = up.process_update_message(
        None,  # type: ignore[arg-type]
        zone_apex="example.com",
        zone_config={},
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )
    parsed_formerr = original_from_wire(resp_formerr, ignore_trailing=True)
    assert parsed_formerr.rcode() == dns.rcode.FORMERR


def test_process_update_message_opcode_and_zone_validation_exception_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Opcode/zone extraction exception branches return FORMERR/NOTZONE."""
    req_wire = dns.update.Update("example.com.").to_wire()
    original_from_wire = dns.message.from_wire

    msg_bad_opcode = original_from_wire(req_wire, ignore_trailing=True)
    msg_bad_opcode.opcode = lambda: (_ for _ in ()).throw(RuntimeError("opcode boom"))  # type: ignore[assignment]
    monkeypatch.setattr(
        dns.message,
        "make_response",
        lambda *_a, **_kw: dns.message.Message(id=1234),
    )
    monkeypatch.setattr(dns.message, "from_wire", lambda *_a, **_kw: msg_bad_opcode)
    resp_opcode = up.process_update_message(
        req_wire,
        zone_apex="example.com",
        zone_config={},
        plugin=SimpleNamespace(records={}),
        client_ip="192.0.2.1",
    )
    parsed_opcode = original_from_wire(resp_opcode, ignore_trailing=True)
    assert parsed_opcode.rcode() == dns.rcode.FORMERR

    class _BadZone:
        def __iter__(self):
            raise RuntimeError("zone iter boom")

        def __bool__(self) -> bool:
            return True

    msg_zone_iter = original_from_wire(req_wire, ignore_trailing=True)
    msg_zone_iter.zone = _BadZone()  # type: ignore[assignment]
    monkeypatch.setattr(dns.message, "from_wire", lambda *_a, **_kw: msg_zone_iter)
    resp_notzone_a = up.process_update_message(
        req_wire,
        zone_apex="example.com",
        zone_config={},
        plugin=SimpleNamespace(records={}),
        client_ip="192.0.2.1",
    )
    parsed_notzone_a = original_from_wire(resp_notzone_a, ignore_trailing=True)
    assert parsed_notzone_a.rcode() == dns.rcode.NOTZONE

    class _BadRRset:
        @property
        def name(self):
            raise RuntimeError("name boom")

        @property
        def rdclass(self):
            raise RuntimeError("class boom")

        @property
        def rdtype(self):
            raise RuntimeError("type boom")

    msg_bad_rrset = original_from_wire(req_wire, ignore_trailing=True)
    msg_bad_rrset.zone = [_BadRRset()]  # type: ignore[assignment]
    monkeypatch.setattr(dns.message, "from_wire", lambda *_a, **_kw: msg_bad_rrset)
    resp_notzone_b = up.process_update_message(
        req_wire,
        zone_apex="example.com",
        zone_config={},
        plugin=SimpleNamespace(records={}),
        client_ip="192.0.2.1",
    )
    parsed_notzone_b = original_from_wire(resp_notzone_b, ignore_trailing=True)
    assert parsed_notzone_b.rcode() == dns.rcode.NOTZONE


def test_process_update_message_replica_and_client_auth_refusal_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Replica forward-mode and client allowlist refusal branches return REFUSED."""
    wire, keyring = _signed_update_wire()
    parsed_req = dns.message.from_wire(wire, keyring=keyring)

    replica_plugin = SimpleNamespace(
        records={},
        _dns_update_config={
            "replication": {"role": "replica", "reject_direct_update_on_replica": False}
        },
    )
    resp_replica = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=replica_plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )
    parsed_replica = dns.message.from_wire(
        resp_replica,
        keyring=keyring,
        request_mac=parsed_req.mac,
    )
    assert parsed_replica.rcode() == dns.rcode.REFUSED

    monkeypatch.setattr(
        up,
        "verify_client_authorization",
        lambda *_a, **_kw: (False, "nope"),
    )
    client_refuse_plugin = SimpleNamespace(records={})
    resp_client = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=client_refuse_plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )
    parsed_client = dns.message.from_wire(
        resp_client,
        keyring=keyring,
        request_mac=parsed_req.mac,
    )
    assert parsed_client.rcode() == dns.rcode.REFUSED


def test_process_update_message_normalize_failures_and_no_tsig_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Key-normalization failure and no-TSIG request paths return NOTAUTH."""
    wire, keyring = _signed_update_wire()
    parsed_req = dns.message.from_wire(wire, keyring=keyring)
    zone_cfg = _zone_cfg(
        key_name="key.example.com.",
        secret_b64="dGVzdHNlY3JldA==",
        extra_keys=["bad-entry"],
    )
    plugin = SimpleNamespace(records={})

    original_norm = up._normalize_dns_name
    key_norm_state = {"raised": False}

    def _flaky_norm(value: Any) -> str:
        normalized = original_norm(value)
        if normalized == "key.example.com" and not key_norm_state["raised"]:
            key_norm_state["raised"] = True
            raise ValueError("norm boom")
        return normalized

    monkeypatch.setattr(up, "_normalize_dns_name", _flaky_norm)
    response_wire = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=zone_cfg,
        plugin=plugin,
        client_ip="192.0.2.1",
        listener="udp",
    )
    response = dns.message.from_wire(
        response_wire,
        keyring=keyring,
        request_mac=parsed_req.mac,
    )
    assert response.rcode() == dns.rcode.NOTAUTH

    unsigned_wire = dns.update.Update("example.com.").to_wire()
    monkeypatch.setattr(
        dns.tsigkeyring,
        "from_text",
        lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("keyring boom")),
    )
    resp_unsigned = up.process_update_message(
        unsigned_wire,
        zone_apex="example.com",
        zone_config=zone_cfg,
        plugin=SimpleNamespace(records={}),
        client_ip="192.0.2.1",
        listener="udp",
    )
    parsed_unsigned = dns.message.from_wire(resp_unsigned, ignore_trailing=True)
    assert parsed_unsigned.rcode() == dns.rcode.NOTAUTH


def test_process_update_message_fudge_and_security_limit_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Fudge enforcement and per-message security checks return expected rcodes."""
    oversized_fudge_wire, keyring_fudge = _signed_update_wire(
        fudge=up.TSIG_TIMESTAMP_FUDGE + 1
    )
    req_fudge = dns.message.from_wire(oversized_fudge_wire, keyring=keyring_fudge)
    resp_fudge = up.process_update_message(
        oversized_fudge_wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=SimpleNamespace(records={}),
        client_ip="192.0.2.1",
        listener="udp",
    )
    parsed_fudge = dns.message.from_wire(
        resp_fudge,
        keyring=keyring_fudge,
        request_mac=req_fudge.mac,
    )
    assert parsed_fudge.rcode() == dns.rcode.NOTAUTH

    wire_a, keyring_a = _signed_update_wire(owner="toolongownername")
    req_a = dns.message.from_wire(wire_a, keyring=keyring_a)
    plugin_a = SimpleNamespace(
        records={},
        _dns_update_config={"security": {"max_owner_length": 3}},
    )
    resp_a = up.process_update_message(
        wire_a,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=plugin_a,
        client_ip="192.0.2.1",
    )
    parsed_a = dns.message.from_wire(resp_a, keyring=keyring_a, request_mac=req_a.mac)
    assert parsed_a.rcode() == dns.rcode.REFUSED

    wire_ttl, keyring_ttl = _signed_update_wire(ttl=120)
    req_ttl = dns.message.from_wire(wire_ttl, keyring=keyring_ttl)
    plugin_ttl = SimpleNamespace(
        records={},
        _dns_update_config={"security": {"max_ttl_range": 60}},
    )
    resp_ttl = up.process_update_message(
        wire_ttl,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=plugin_ttl,
        client_ip="192.0.2.1",
    )
    parsed_ttl = dns.message.from_wire(
        resp_ttl, keyring=keyring_ttl, request_mac=req_ttl.mac
    )
    assert parsed_ttl.rcode() == dns.rcode.REFUSED

    wire_multi, keyring_multi = _signed_update_wire(values=["192.0.2.10"])
    original_from_wire = dns.message.from_wire
    req_multi = original_from_wire(wire_multi, keyring=keyring_multi)
    msg_multi = original_from_wire(wire_multi, keyring=keyring_multi)
    msg_multi.update = [  # type: ignore[assignment]
        _RRset(
            name="host.example.com",
            rdtype=int(dns.rdatatype.A),
            rdclass=int(dns.rdataclass.IN),
            ttl=60,
            values=["192.0.2.10", "192.0.2.11"],
        )
    ]
    monkeypatch.setattr(dns.message, "from_wire", lambda *_a, **_kw: msg_multi)
    plugin_multi = SimpleNamespace(
        records={},
        _dns_update_config={"security": {"max_rr_values_per_rrset": 1}},
    )
    resp_multi = up.process_update_message(
        wire_multi,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=plugin_multi,
        client_ip="192.0.2.1",
    )
    parsed_multi = original_from_wire(
        resp_multi, keyring=keyring_multi, request_mac=req_multi.mac
    )
    assert parsed_multi.rcode() == dns.rcode.REFUSED
    monkeypatch.setattr(dns.message, "from_wire", original_from_wire)

    wire_txt, keyring_txt = _signed_update_wire(
        rtype="TXT",
        values=['"this-text-is-way-too-long-for-the-limit"'],
    )
    req_txt = dns.message.from_wire(wire_txt, keyring=keyring_txt)
    plugin_txt = SimpleNamespace(
        records={},
        _dns_update_config={"security": {"max_rdata_length": 4}},
    )
    resp_txt = up.process_update_message(
        wire_txt,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=plugin_txt,
        client_ip="192.0.2.1",
    )
    parsed_txt = dns.message.from_wire(
        resp_txt, keyring=keyring_txt, request_mac=req_txt.mac
    )
    assert parsed_txt.rcode() == dns.rcode.REFUSED


def test_process_update_message_rate_limits_prereq_scope_and_update_error_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Rate limit, prerequisite rejection, scope, and update error branches."""
    wire, keyring = _signed_update_wire()
    req = dns.message.from_wire(wire, keyring=keyring)

    plugin_client_limit = SimpleNamespace(
        records={},
        _dns_update_config={"security": {"rate_limit_per_client": 1}},
        _dns_update_rate_buckets={"client:192.0.2.1": {"start": 1.0e15, "count": 1}},
        _dns_update_rate_limit_hits="bad",
    )
    resp_client = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=plugin_client_limit,
        client_ip="192.0.2.1",
    )
    parsed_client = dns.message.from_wire(
        resp_client, keyring=keyring, request_mac=req.mac
    )
    assert parsed_client.rcode() == dns.rcode.REFUSED

    plugin_key_limit = SimpleNamespace(
        records={},
        _dns_update_config={"security": {"rate_limit_per_key": 1}},
        _dns_update_rate_buckets={
            "tsig:key.example.com.": {"start": 1.0e15, "count": 1}
        },
        _dns_update_rate_limit_hits="bad",
    )
    resp_key = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=plugin_key_limit,
        client_ip="192.0.2.1",
    )
    parsed_key = dns.message.from_wire(resp_key, keyring=keyring, request_mac=req.mac)
    assert parsed_key.rcode() == dns.rcode.REFUSED

    plugin_reset = SimpleNamespace(
        records={},
        _dns_update_config={"security": {"rate_limit_per_client": 5}},
        _dns_update_rate_buckets={"client:192.0.2.1": {"start": 0.0, "count": 9}},
    )
    monkeypatch.setattr(up, "apply_update_operations", lambda *_a, **_kw: (0, None))
    resp_reset = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=plugin_reset,
        client_ip="192.0.2.1",
    )
    parsed_reset = dns.message.from_wire(
        resp_reset, keyring=keyring, request_mac=req.mac
    )
    assert parsed_reset.rcode() == dns.rcode.NOERROR
    assert plugin_reset._dns_update_rate_buckets["client:192.0.2.1"]["count"] == 1

    original_from_wire = dns.message.from_wire
    msg_with_prereq = original_from_wire(wire, keyring=keyring)
    msg_with_prereq.prerequisite = [object()]  # type: ignore[assignment]
    monkeypatch.setattr(dns.message, "from_wire", lambda *_a, **_kw: msg_with_prereq)
    monkeypatch.setattr(up, "check_prerequisites", lambda *_a, **_kw: (6, "prereq"))
    resp_prereq = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=SimpleNamespace(records={}),
        client_ip="192.0.2.1",
    )
    parsed_prereq = original_from_wire(
        resp_prereq, keyring=keyring, request_mac=req.mac
    )
    assert parsed_prereq.rcode() == 6

    class _Ctx:
        def __init__(
            self, zone_apex: str, client_ip: str, listener: Any, plugin: object
        ):
            self.zone_apex = zone_apex
            self.client_ip = client_ip
            self.listener = listener
            self.plugin = plugin
            self.is_authorized = False
            self.auth_method = None
            self.request_snapshot = None
            self.tsig_key_config = None
            self.psk_token_config = {"scope": "psk"}

        def __setattr__(self, name: str, value: Any) -> None:
            if name == "tsig_key_config" and hasattr(self, "tsig_key_config"):
                object.__setattr__(self, name, None)
                return
            object.__setattr__(self, name, value)

    captured_scope: dict[str, Any] = {}
    monkeypatch.setattr(up, "UpdateContext", _Ctx)
    monkeypatch.setattr(dns.message, "from_wire", original_from_wire)
    monkeypatch.setattr(
        up,
        "verify_name_authorization",
        lambda _name, _zone, auth_scope_config=None: captured_scope.setdefault(
            "scope", auth_scope_config
        )
        or True,
    )
    monkeypatch.setattr(up, "verify_value_authorization", lambda *_a, **_kw: True)
    monkeypatch.setattr(up, "apply_update_operations", lambda *_a, **_kw: (0, None))
    resp_scope = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=SimpleNamespace(records={}),
        client_ip="192.0.2.1",
    )
    parsed_scope = original_from_wire(resp_scope, keyring=keyring, request_mac=req.mac)
    assert parsed_scope.rcode() == dns.rcode.NOERROR
    assert captured_scope.get("scope") == {"scope": "psk"}

    class _BadOwnerRR:
        rdtype = int(QTYPE.A)

        @property
        def name(self):
            raise RuntimeError("owner boom")

        def __iter__(self):
            return iter([])

    msg_bad_owner = original_from_wire(wire, keyring=keyring)
    msg_bad_owner.update = [_BadOwnerRR()]  # type: ignore[assignment]
    monkeypatch.setattr(dns.message, "from_wire", lambda *_a, **_kw: msg_bad_owner)
    resp_bad_owner = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=SimpleNamespace(records={}),
        client_ip="192.0.2.1",
    )
    parsed_bad_owner = original_from_wire(
        resp_bad_owner, keyring=keyring, request_mac=req.mac
    )
    assert parsed_bad_owner.rcode() == dns.rcode.NOERROR

    class _BadIterRR:
        name = "host.example.com."
        rdtype = int(QTYPE.A)

        def __iter__(self):
            raise RuntimeError("iter boom")

    msg_bad_iter = original_from_wire(wire, keyring=keyring)
    msg_bad_iter.update = [_BadIterRR()]  # type: ignore[assignment]
    monkeypatch.setattr(dns.message, "from_wire", lambda *_a, **_kw: msg_bad_iter)
    resp_bad_iter = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=SimpleNamespace(records={}),
        client_ip="192.0.2.1",
    )
    parsed_bad_iter = original_from_wire(
        resp_bad_iter, keyring=keyring, request_mac=req.mac
    )
    assert parsed_bad_iter.rcode() == dns.rcode.NOERROR

    class _ExplodingJournalWriter:
        def __init__(self, *, zone_apex: str, base_dir: str):
            self.zone_apex = zone_apex
            self.base_dir = base_dir

        def acquire_lock(self) -> bool:
            return True

        def release_lock(self) -> None:
            raise RuntimeError("release boom")

        def close(self) -> None:
            raise RuntimeError("close boom")

    import foghorn.plugins.resolve.zone_records.journal as journal_mod

    monkeypatch.setattr(journal_mod, "JournalWriter", _ExplodingJournalWriter)
    monkeypatch.setattr(up, "apply_update_operations", lambda *_a, **_kw: (2, "failed"))
    plugin_journal = SimpleNamespace(
        records={},
        _dns_update_config={"persistence": {"enabled": True, "state_dir": "/tmp"}},
    )
    resp_update_error = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=plugin_journal,
        client_ip="192.0.2.1",
    )
    parsed_update_error = original_from_wire(
        resp_update_error, keyring=keyring, request_mac=req.mac
    )
    assert parsed_update_error.rcode() == 2


def test_check_prerequisites_branch_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: check_prerequisites covers owner/class/type/ttl branch variants."""
    records = {
        ("host.example.com", int(QTYPE.A)): (300, ["192.0.2.10"], ["src"]),
        ("name.example.com", int(QTYPE.TXT)): (300, ['"v"'], ["src"]),
    }

    class _BadZone:
        def __str__(self) -> str:
            return "example.com."

    monkeypatch.setattr(
        up,
        "_normalize_dns_name",
        lambda *_a, **_kw: (_ for _ in ()).throw(ValueError("norm boom")),
    )
    rcode_bad_zone, _ = up.check_prerequisites([], records, _BadZone())  # type: ignore[arg-type]
    assert rcode_bad_zone == 0

    monkeypatch.undo()
    out_of_zone = _RRset(
        name="outside.net",
        rdtype=int(dns.rdatatype.A),
        rdclass=int(dns.rdataclass.NONE),
        values=[],
    )
    rcode_out, _ = up.check_prerequisites([out_of_zone], records, "example.com")
    assert rcode_out == 9

    none_any_exists = _RRset(
        name="name.example.com",
        rdtype=int(dns.rdatatype.ANY),
        rdclass=int(dns.rdataclass.NONE),
        values=[],
    )
    rcode_none_any, _ = up.check_prerequisites(
        [none_any_exists], records, "example.com"
    )
    assert rcode_none_any == 1

    none_specific_exists = _RRset(
        name="host.example.com",
        rdtype=int(dns.rdatatype.A),
        rdclass=int(dns.rdataclass.NONE),
        values=[],
    )
    rcode_none_specific, _ = up.check_prerequisites(
        [none_specific_exists], records, "example.com"
    )
    assert rcode_none_specific == 1

    in_any_missing = _RRset(
        name="missing.example.com",
        rdtype=int(dns.rdatatype.ANY),
        rdclass=int(dns.rdataclass.IN),
        values=[],
    )
    rcode_in_any, _ = up.check_prerequisites([in_any_missing], records, "example.com")
    assert rcode_in_any == 1

    in_specific_missing = _RRset(
        name="missing.example.com",
        rdtype=int(dns.rdatatype.A),
        rdclass=int(dns.rdataclass.IN),
        values=[],
    )
    rcode_in_specific, _ = up.check_prerequisites(
        [in_specific_missing], records, "example.com"
    )
    assert rcode_in_specific == 1

    in_specific_rr_missing = _RRset(
        name="host.example.com",
        rdtype=int(dns.rdatatype.A),
        rdclass=int(dns.rdataclass.IN),
        ttl=60,
        values=["192.0.2.99"],
    )
    rcode_rr_missing, _ = up.check_prerequisites(
        [in_specific_rr_missing], records, "example.com"
    )
    assert rcode_rr_missing == 1

    any_any_missing = _RRset(
        name="missing.example.com",
        rdtype=int(dns.rdatatype.ANY),
        rdclass=int(dns.rdataclass.ANY),
        values=[],
    )
    rcode_any_any, _ = up.check_prerequisites([any_any_missing], records, "example.com")
    assert rcode_any_any == 1

    any_specific_missing = _RRset(
        name="missing.example.com",
        rdtype=int(dns.rdatatype.A),
        rdclass=int(dns.rdataclass.ANY),
        values=[],
    )
    rcode_any_specific, _ = up.check_prerequisites(
        [any_specific_missing], records, "example.com"
    )
    assert rcode_any_specific == 1

    unsupported_class = _RRset(
        name="host.example.com",
        rdtype=int(dns.rdatatype.A),
        rdclass=12345,
        values=[],
    )
    rcode_unsupported, _ = up.check_prerequisites(
        [unsupported_class], records, "example.com"
    )
    assert rcode_unsupported == 1


def test_check_prerequisites_positive_loop_break_paths() -> None:
    """Brief: check_prerequisites hits positive has-any and exact-rdata match break paths."""
    records = {
        ("host.example.com", int(QTYPE.A)): (300, ["192.0.2.10"], ["src"]),
        ("name.example.com", int(QTYPE.TXT)): (300, ['"v"'], ["src"]),
    }

    in_any_exists = _RRset(
        name="name.example.com",
        rdtype=int(dns.rdatatype.ANY),
        rdclass=int(dns.rdataclass.IN),
        values=[],
    )
    in_specific_exact = _RRset(
        name="host.example.com",
        rdtype=int(dns.rdatatype.A),
        rdclass=int(dns.rdataclass.IN),
        ttl=60,
        values=["192.0.2.10"],
    )
    any_any_exists = _RRset(
        name="host.example.com",
        rdtype=int(dns.rdatatype.ANY),
        rdclass=int(dns.rdataclass.ANY),
        values=[],
    )
    rcode, err = up.check_prerequisites(
        [in_any_exists, in_specific_exact, any_any_exists],
        records,
        "example.com",
    )
    assert rcode == 0
    assert err is None


def test_apply_update_operations_branch_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: apply_update_operations covers operation/error/journal/notif branch variants."""
    plugin = SimpleNamespace(
        records={
            ("example.com", int(QTYPE.SOA)): (
                300,
                ["ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"],
                ["src"],
            ),
            ("del.example.com", int(QTYPE.A)): (
                300,
                ["192.0.2.10", "192.0.2.11"],
                ["src"],
            ),
        },
        _records_lock=threading.RLock(),
        _update_managed_owners=set(),
    )

    class _BadOwner:
        def __str__(self) -> str:
            raise ValueError("owner boom")

    rcode_bad_owner, _ = up.apply_update_operations(
        [
            _RRset(
                name=_BadOwner(),
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.IN),
                values=["192.0.2.10"],
            )
        ],
        plugin=plugin,
        zone_apex="example.com",
    )
    assert rcode_bad_owner == 1

    rcode_outside, _ = up.apply_update_operations(
        [
            _RRset(
                name="outside.net",
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.IN),
                values=["192.0.2.10"],
            )
        ],
        plugin=plugin,
        zone_apex="example.com",
    )
    assert rcode_outside == 9

    rcode_none_any, _ = up.apply_update_operations(
        [
            _RRset(
                name="host.example.com",
                rdtype=int(dns.rdatatype.ANY),
                rdclass=int(dns.rdataclass.NONE),
                values=[],
            )
        ],
        plugin=plugin,
        zone_apex="example.com",
    )
    assert rcode_none_any == 1

    rcode_in_any, _ = up.apply_update_operations(
        [
            _RRset(
                name="host.example.com",
                rdtype=int(dns.rdatatype.ANY),
                rdclass=int(dns.rdataclass.IN),
                values=[],
            )
        ],
        plugin=plugin,
        zone_apex="example.com",
    )
    assert rcode_in_any == 1

    rcode_bad_class, _ = up.apply_update_operations(
        [
            _RRset(
                name="host.example.com",
                rdtype=int(dns.rdatatype.A),
                rdclass=99999,
                values=["192.0.2.10"],
            )
        ],
        plugin=plugin,
        zone_apex="example.com",
    )
    assert rcode_bad_class == 1

    rcode_delete, err_delete = up.apply_update_operations(
        [
            _RRset(
                name="del.example.com",
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.ANY),
                values=["192.0.2.10"],
            ),
            _RRset(
                name="wipe.example.com",
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.IN),
                values=["198.51.100.1"],
            ),
            _RRset(
                name="wipe.example.com",
                rdtype=int(dns.rdatatype.ANY),
                rdclass=int(dns.rdataclass.ANY),
                values=[],
            ),
        ],
        plugin=plugin,
        zone_apex="example.com",
    )
    assert rcode_delete == 0
    assert err_delete is None
    assert ("wipe.example.com", int(QTYPE.A)) not in plugin.records
    assert "wipe.example.com" in plugin._update_managed_owners

    class _JournalWriterFail:
        base_dir = "/tmp"

        def append_entry(self, **_kwargs):
            return None

    before = dict(plugin.records)
    rcode_journal, _ = up.apply_update_operations(
        [
            _RRset(
                name="journal.example.com",
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.IN),
                values=["198.51.100.2"],
            )
        ],
        plugin=plugin,
        zone_apex="example.com",
        journal_writer=_JournalWriterFail(),
        actor={"client_ip": "192.0.2.1"},
    )
    assert rcode_journal == 2
    assert dict(plugin.records) == before

    plugin_malformed = SimpleNamespace(
        records={
            ("example.com", int(QTYPE.SOA)): (300, ["invalid-soa"], ["src"]),
            ("two.example.com", int(QTYPE.A)): (300, ["192.0.2.5"]),
            ("bad.example.com", int(QTYPE.A)): ("bad",),
        },
        _records_lock=threading.RLock(),
        _dns_update_config={"replication": {"notify_on_update": True}},
        _dns_update_notify_failed="bad",
    )

    import foghorn.plugins.resolve.zone_records.notify as notify_mod

    monkeypatch.setattr(
        notify_mod,
        "send_notify_for_zones",
        lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("notify boom")),
    )

    class _FakeJournalWriter:
        base_dir = "/tmp"

        def append_entry(self, **_kwargs):
            return SimpleNamespace(seq=9)

    class _ReaderByBytes:
        def __init__(self, *, zone_apex: str, base_dir: str):
            self.zone_apex = zone_apex
            self.base_dir = base_dir

        def get_size_bytes(self) -> int:
            return 999

        def get_entry_count(self) -> int:
            return 1

    import foghorn.plugins.resolve.zone_records.journal as journal_mod

    monkeypatch.setattr(journal_mod, "JournalReader", _ReaderByBytes)
    monkeypatch.setattr(journal_mod, "compact_zone_journal", lambda *_a, **_kw: True)
    plugin_malformed._dns_update_persistence_config = {"max_journal_bytes": 1}
    plugin_malformed._dns_update_compact_count = "bad"

    rcode_compact_bytes, err_compact_bytes = up.apply_update_operations(
        [
            _RRset(
                name="compact.example.com",
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.IN),
                values=["198.51.100.3"],
            )
        ],
        plugin=plugin_malformed,
        zone_apex="example.com",
        journal_writer=_FakeJournalWriter(),
        actor={"client_ip": "192.0.2.1"},
    )
    assert rcode_compact_bytes == 0
    assert err_compact_bytes is None

    class _ReaderByEntries:
        def __init__(self, *, zone_apex: str, base_dir: str):
            self.zone_apex = zone_apex
            self.base_dir = base_dir

        def get_size_bytes(self) -> int:
            return 1

        def get_entry_count(self) -> int:
            return 99

    monkeypatch.setattr(journal_mod, "JournalReader", _ReaderByEntries)
    plugin_malformed._dns_update_persistence_config = {"max_journal_entries": 1}
    rcode_compact_entries, err_compact_entries = up.apply_update_operations(
        [
            _RRset(
                name="compact2.example.com",
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.IN),
                values=["198.51.100.4"],
            )
        ],
        plugin=plugin_malformed,
        zone_apex="example.com",
        journal_writer=_FakeJournalWriter(),
        actor={"client_ip": "192.0.2.1"},
    )
    assert rcode_compact_entries == 0
    assert err_compact_entries is None

    original_qtype = up.QTYPE
    monkeypatch.setattr(
        up,
        "QTYPE",
        SimpleNamespace(
            SOA=object(),
            A=1,
            AAAA=28,
            ANY=255,
            get=original_qtype.get,
        ),
    )
    rcode_qtype_fallback, err_qtype_fallback = up.apply_update_operations(
        [
            _RRset(
                name="qtype.example.com",
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.IN),
                values=["198.51.100.5"],
            )
        ],
        plugin=plugin_malformed,
        zone_apex="example.com",
    )
    assert rcode_qtype_fallback == 0
    assert err_qtype_fallback is None


def test_apply_update_operations_detects_conflict_without_mutating_live_records() -> (
    None
):
    """Brief: Stale commit is rejected when records change after UPDATE snapshot.

    Inputs:
      - None.

    Outputs:
      - Asserts conflict rcode and that live records were not partially mutated.
    """

    class _ConcurrentMutatingLock:
        """Brief: Simulate an interleaving write before commit lock acquisition."""

        def __init__(self, plugin_ref: SimpleNamespace) -> None:
            self._plugin_ref = plugin_ref
            self._enter_count = 0

        def __enter__(self) -> "_ConcurrentMutatingLock":
            self._enter_count += 1
            if self._enter_count == 2:
                self._plugin_ref.records[("race.example.com", int(dns.rdatatype.A))] = (
                    300,
                    ["198.51.100.200"],
                    ["src"],
                )
            return self

        def __exit__(self, _exc_type, _exc, _tb) -> bool:
            return False

    plugin = SimpleNamespace(
        records={
            ("del.example.com", int(dns.rdatatype.A)): (
                300,
                ["192.0.2.10", "192.0.2.11"],
                ["src"],
            )
        },
        _update_managed_owners=set(),
    )
    plugin._records_lock = _ConcurrentMutatingLock(plugin)

    rcode, err = up.apply_update_operations(
        [
            _RRset(
                name="del.example.com",
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.ANY),
                values=["192.0.2.10"],
            )
        ],
        plugin=plugin,
        zone_apex="example.com",
    )

    assert rcode == 2
    assert err == "Concurrent update conflict detected"
    assert plugin.records[("del.example.com", int(dns.rdatatype.A))][1] == [
        "192.0.2.10",
        "192.0.2.11",
    ]
    assert ("race.example.com", int(dns.rdatatype.A)) in plugin.records


def test_apply_update_operations_add_and_single_value_delete_paths() -> None:
    """Brief: apply_update_operations covers CLASS NONE add and CLASS ANY single-value delete branches."""
    plugin = SimpleNamespace(
        records={
            ("example.com", int(QTYPE.SOA)): (
                300,
                ["ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"],
                ["src"],
            ),
            ("single.example.com", int(QTYPE.A)): (300, ["192.0.2.20"], ["src"]),
        },
        _records_lock=threading.RLock(),
    )

    updates = [
        _RRset(
            name="added.example.com",
            rdtype=int(dns.rdatatype.A),
            rdclass=int(dns.rdataclass.NONE),
            ttl=60,
            values=["198.51.100.30"],
        ),
        _RRset(
            name="single.example.com",
            rdtype=int(dns.rdatatype.A),
            rdclass=int(dns.rdataclass.ANY),
            ttl=0,
            values=["192.0.2.20"],
        ),
    ]
    rcode, err = up.apply_update_operations(
        updates,
        plugin=plugin,
        zone_apex="example.com",
    )
    assert rcode == 0
    assert err is None
    assert ("added.example.com", int(QTYPE.A)) in plugin.records
    assert ("single.example.com", int(QTYPE.A)) not in plugin.records


def test_process_update_message_recovery_formerr_without_tsig_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Non-TSIG parse failure with recoverable message returns FORMERR."""
    request_wire = dns.update.Update("example.com.").to_wire()
    original_from_wire = dns.message.from_wire

    def _fake_from_wire(data, *args, **kwargs):
        if kwargs.get("ignore_trailing"):
            raise ValueError("parse boom")
        if kwargs.get("continue_on_error"):
            return original_from_wire(request_wire, ignore_trailing=True)
        return original_from_wire(data, *args, **kwargs)

    monkeypatch.setattr(dns.message, "from_wire", _fake_from_wire)
    response_wire = up.process_update_message(
        request_wire,
        zone_apex="example.com",
        zone_config={},
        plugin=SimpleNamespace(records={}),
        client_ip="192.0.2.1",
    )
    parsed = original_from_wire(response_wire, ignore_trailing=True)
    assert parsed.rcode() == dns.rcode.FORMERR


def test_process_update_message_value_authorization_rejects_update(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Value authorization failure returns NOTAUTH from update-value loop."""
    wire, keyring = _signed_update_wire()
    request_msg = dns.message.from_wire(wire, keyring=keyring)

    monkeypatch.setattr(up, "verify_name_authorization", lambda *_a, **_kw: True)
    monkeypatch.setattr(up, "verify_value_authorization", lambda *_a, **_kw: False)

    response_wire = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=SimpleNamespace(records={}),
        client_ip="192.0.2.1",
    )
    parsed = dns.message.from_wire(
        response_wire, keyring=keyring, request_mac=request_msg.mac
    )
    assert parsed.rcode() == dns.rcode.NOTAUTH


def test_process_update_message_runtime_state_dir_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Persistence runtime-state fallback builds zone_records state_dir."""
    wire, keyring = _signed_update_wire()
    request_msg = dns.message.from_wire(wire, keyring=keyring)
    created_base_dirs: list[str] = []

    class _JournalWriterProbe:
        def __init__(self, *, zone_apex: str, base_dir: str):
            self.zone_apex = zone_apex
            self.base_dir = base_dir
            created_base_dirs.append(base_dir)

        def acquire_lock(self) -> bool:
            return False

        def release_lock(self) -> None:
            return None

        def close(self) -> None:
            return None

    import foghorn.plugins.resolve.zone_records.journal as journal_mod
    import foghorn.runtime_config as runtime_config_mod

    monkeypatch.setattr(journal_mod, "JournalWriter", _JournalWriterProbe)
    monkeypatch.setattr(
        runtime_config_mod,
        "get_runtime_state_dir",
        lambda: "/tmp/state-root",
        raising=False,
    )
    monkeypatch.setattr(up, "apply_update_operations", lambda *_a, **_kw: (0, None))

    response_wire = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=SimpleNamespace(
            records={},
            _dns_update_config={"persistence": {"enabled": True, "state_dir": None}},
        ),
        client_ip="192.0.2.1",
    )
    parsed = dns.message.from_wire(
        response_wire, keyring=keyring, request_mac=request_msg.mac
    )
    assert parsed.rcode() == dns.rcode.NOERROR
    assert created_base_dirs == ["/tmp/state-root/zone_records"]


def test_process_update_message_per_key_rate_window_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Per-key rate bucket resets after one-minute window elapses."""
    wire, keyring = _signed_update_wire()
    request_msg = dns.message.from_wire(wire, keyring=keyring)
    plugin = SimpleNamespace(
        records={},
        _dns_update_config={"security": {"rate_limit_per_key": 5}},
        _dns_update_rate_buckets={"tsig:key.example.com.": {"start": 0.0, "count": 4}},
    )

    monkeypatch.setattr(up, "apply_update_operations", lambda *_a, **_kw: (0, None))

    response_wire = up.process_update_message(
        wire,
        zone_apex="example.com",
        zone_config=_zone_cfg(
            key_name="key.example.com.",
            secret_b64="dGVzdHNlY3JldA==",
        ),
        plugin=plugin,
        client_ip="192.0.2.1",
    )
    parsed = dns.message.from_wire(
        response_wire, keyring=keyring, request_mac=request_msg.mac
    )
    assert parsed.rcode() == dns.rcode.NOERROR
    assert plugin._dns_update_rate_buckets["tsig:key.example.com."]["count"] == 1


def test_apply_update_operations_zone_apex_normalize_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: apply_update_operations falls back when zone_apex normalization fails."""
    original_normalize_dns_name = up._normalize_dns_name

    def _normalize_with_zone_failure(value: str) -> str:
        if str(value) == "Example.COM.":
            raise ValueError("zone normalize boom")
        return original_normalize_dns_name(value)

    monkeypatch.setattr(up, "_normalize_dns_name", _normalize_with_zone_failure)
    plugin = SimpleNamespace(
        records={},
        _records_lock=threading.RLock(),
        _dns_update_config={"replication": {"notify_on_update": False}},
    )

    rcode, err = up.apply_update_operations(
        [
            _RRset(
                name="host.example.com",
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.IN),
                ttl=60,
                values=["192.0.2.40"],
            )
        ],
        plugin=plugin,
        zone_apex="Example.COM.",
    )
    assert rcode == 0
    assert err is None
    assert ("host.example.com", int(dns.rdatatype.A)) in plugin.records


def test_apply_update_operations_existing_rrset_adds_value_and_tracks_update_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: CLASS NONE append path adds a value and injects update source."""
    plugin = SimpleNamespace(
        records={
            ("host.example.com", int(dns.rdatatype.A)): (
                300,
                ["192.0.2.10"],
                ["static"],
            )
        },
        _records_lock=threading.RLock(),
        _dns_update_config={"replication": {"notify_on_update": False}},
    )

    rcode, err = up.apply_update_operations(
        [
            _RRset(
                name="host.example.com",
                rdtype=int(dns.rdatatype.A),
                rdclass=int(dns.rdataclass.NONE),
                ttl=60,
                values=["192.0.2.11"],
            )
        ],
        plugin=plugin,
        zone_apex="example.com",
    )
    assert rcode == 0
    assert err is None
    ttl, values, sources = plugin.records[("host.example.com", int(dns.rdatatype.A))]
    assert ttl == 60
    assert values == ["192.0.2.10", "192.0.2.11"]
    assert "update" in sources
