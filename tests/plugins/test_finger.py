"""Brief: Tests for foghorn.plugins.resolve.examples.finger module.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import importlib

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.resolve.base import PluginContext


def _make_txt_query(name: str) -> bytes:
    """Brief: Build a minimal TXT DNS query for name.

    Inputs:
      - name: Domain name to query.

    Outputs:
      - Raw DNS query bytes suitable for passing to Finger.pre_resolve.
    """

    q = DNSRecord.question(name, qtype="TXT")
    return q.pack()


def test_finger_module_imports() -> None:
    """Brief: Ensure finger module imports correctly.

    Inputs:
      - None.

    Outputs:
      - Asserts module name matches expected path.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.finger")
    assert mod.__name__ == "foghorn.plugins.resolve.examples.finger"


def test_parse_finger_qname_basic_and_mismatch() -> None:
    """Brief: _parse_finger_qname extracts username for matching qnames.

    Inputs:
      - None (uses hard-coded qname strings).

    Outputs:
      - Asserts parsed username and that non-matching names return None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.finger")
    parse = mod._parse_finger_qname

    labels = ("example", "test")

    # Basic matches: <user>.<domain>
    assert parse("alice.example.test", labels) == "alice"
    assert parse("bob.example.test.", labels) == "bob"

    # Wrong suffix -> None
    assert parse("alice.example.invalid", labels) is None
    # Missing username label -> None
    assert parse("example.test", labels) is None
    # Extra middle label that changes the suffix -> None
    assert parse("alice.notexample.test", labels) is None

    # Different configured domain: users.zaa -> zack.users.zaa
    labels_users = ("users", "zaa")
    assert parse("zack.users.zaa", labels_users) == "zack"


def test_is_user_allowed_cached_policy_allow_and_deny() -> None:
    """Brief: _is_user_allowed_cached honours policy and allow/deny lists.

    Inputs:
      - None (invokes helper with different policies and lists).

    Outputs:
      - Asserts boolean decisions for representative combinations.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.finger")
    is_allowed = mod._is_user_allowed_cached

    # Default allow policy with no allow list -> everyone allowed except denies.
    assert is_allowed("alice", "allow", tuple(), tuple()) is True
    assert is_allowed("mallory", "allow", tuple(), ("mallory",)) is False

    # Allow policy with explicit allow list restricts to allow_users.
    assert is_allowed("alice", "allow", ("alice",), tuple()) is True
    assert is_allowed("bob", "allow", ("alice",), tuple()) is False

    # Deny policy requires explicit allow_users.
    assert is_allowed("alice", "deny", ("alice",), tuple()) is True
    assert is_allowed("bob", "deny", ("alice",), tuple()) is False

    # deny_users always wins.
    assert is_allowed("alice", "deny", ("alice",), ("alice",)) is False


def test_finger_pre_resolve_serves_truncated_finger_file(tmp_path, monkeypatch) -> None:
    """Brief: Finger answers TXT queries with truncated ~/.finger content.

    Inputs:
      - tmp_path: pytest temporary directory for a fake home.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that pre_resolve returns an override decision containing a TXT
        answer with at most max_size bytes of the .finger file.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.finger")
    Finger = mod.Finger

    # Prepare fake $HOME/.finger for user "alice".
    home_dir = tmp_path / "alice_home"
    home_dir.mkdir()
    finger_path = home_dir / ".finger"
    content = b"Hello from finger file for alice"  # 32 bytes
    finger_path.write_bytes(content)

    # Monkeypatch the helper to point to our tmp path rather than real passwd DB.
    def _fake_resolve_user_finger_path(username: str) -> str | None:
        if username == "alice":
            return str(finger_path)
        return None

    monkeypatch.setattr(
        mod, "_resolve_user_finger_path", _fake_resolve_user_finger_path
    )

    plugin = Finger(domain="example.test", max_size=8)
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    qname = "alice.example.test"
    req_bytes = _make_txt_query(qname)

    decision = plugin.pre_resolve(qname, int(QTYPE.TXT), req_bytes, ctx)
    assert decision is not None
    assert decision.action == "override"
    assert decision.response is not None

    resp = DNSRecord.parse(decision.response)
    txt_answers = [rr for rr in resp.rr if rr.rtype == QTYPE.TXT]
    assert len(txt_answers) == 1

    data_txt = str(txt_answers[0].rdata).strip('"')
    # Expect at most max_size bytes of content.
    expected = content[:8].decode("utf-8", errors="replace")
    assert data_txt == expected


def test_finger_pre_resolve_strips_non_printable_characters(
    tmp_path, monkeypatch
) -> None:
    """Brief: Finger TXT answers omit non-printable control characters.

    Inputs:
      - tmp_path: pytest temporary directory.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that non-printable bytes (such as backspace ``"\x08"``) in the
        .finger file do not appear in the TXT response, while printable
        characters remain.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.finger")
    Finger = mod.Finger

    # Prepare a .finger file containing printable text and a trailing backspace.
    finger_path = tmp_path / ".finger"
    finger_path.write_bytes(b"ok\x08")

    def _fake_resolve_user_finger_path(username: str) -> str | None:
        return str(finger_path)

    monkeypatch.setattr(
        mod, "_resolve_user_finger_path", _fake_resolve_user_finger_path
    )

    plugin = Finger(domain="example.test")
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    qname = "alice.example.test"
    req_bytes = _make_txt_query(qname)

    decision = plugin.pre_resolve(qname, int(QTYPE.TXT), req_bytes, ctx)
    assert decision is not None
    assert decision.action == "override"

    resp = DNSRecord.parse(decision.response)
    txt_answers = [rr for rr in resp.rr if rr.rtype == QTYPE.TXT]
    assert len(txt_answers) == 1

    data_txt = str(txt_answers[0].rdata).strip('"')
    # Only printable characters should remain; the backspace must be stripped.
    assert data_txt == "ok"


def test_finger_pre_resolve_respects_policy_and_targets(tmp_path, monkeypatch) -> None:
    """Brief: Finger honours allow/deny policy and BasePlugin targets.

    Inputs:
      - tmp_path: pytest temporary directory.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that deny_users and policy=deny work and that non-targeted
        clients are ignored.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.finger")
    Finger = mod.Finger

    # Use a simple .finger file path for any user; content does not matter.
    finger_path = tmp_path / ".finger"
    finger_path.write_text("ok", encoding="utf-8")

    def _fake_resolve_user_finger_path(username: str) -> str | None:  # noqa: D401
        """Return the same .finger file for any username in tests."""

        return str(finger_path)

    monkeypatch.setattr(
        mod, "_resolve_user_finger_path", _fake_resolve_user_finger_path
    )

    # Policy: default allow but alice explicitly denied.
    plugin_deny_user = Finger(domain="example.test", deny_users=["alice"])
    plugin_deny_user.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    qname = "alice.example.test"
    req_bytes = _make_txt_query(qname)
    assert plugin_deny_user.pre_resolve(qname, int(QTYPE.TXT), req_bytes, ctx) is None

    # Policy: deny by default; only bob is allowed.
    plugin_allow_bob = Finger(domain="example.test", policy="deny", allow_users=["bob"])
    plugin_allow_bob.setup()

    qname_bob = "bob.example.test"
    req_bytes_bob = _make_txt_query(qname_bob)
    decision_bob = plugin_allow_bob.pre_resolve(
        qname_bob, int(QTYPE.TXT), req_bytes_bob, ctx
    )
    assert decision_bob is not None

    qname_alice = "alice.example.test"
    req_bytes_alice = _make_txt_query(qname_alice)
    assert (
        plugin_allow_bob.pre_resolve(qname_alice, int(QTYPE.TXT), req_bytes_alice, ctx)
        is None
    )

    # Targets restriction: client outside configured CIDR should be ignored.
    plugin_targets = Finger(domain="example.test", targets=["10.0.0.0/8"])
    plugin_targets.setup()

    ctx_not_targeted = PluginContext(client_ip="192.0.2.1")
    assert (
        plugin_targets.pre_resolve(
            qname_bob, int(QTYPE.TXT), req_bytes_bob, ctx_not_targeted
        )
        is None
    )


def test_finger_pre_resolve_ignores_non_txt_qtypes(tmp_path, monkeypatch) -> None:
    """Brief: Finger only responds to TXT queries.

    Inputs:
      - tmp_path: pytest temporary directory.
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that pre_resolve returns None for non-TXT qtypes.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.finger")
    Finger = mod.Finger

    finger_path = tmp_path / ".finger"
    finger_path.write_text("ok", encoding="utf-8")

    def _fake_resolve_user_finger_path(username: str) -> str | None:
        return str(finger_path)

    monkeypatch.setattr(
        mod, "_resolve_user_finger_path", _fake_resolve_user_finger_path
    )

    plugin = Finger(domain="example.test")
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    qname = "alice.example.test"
    q = DNSRecord.question(qname, qtype="A")
    assert plugin.pre_resolve(qname, int(QTYPE.A), q.pack(), ctx) is None
