"""Tests for foghorn.utils.ssh_keys helpers.

Brief:
  - Exercise happy-path and error-path flows for fetch_ssh_host_key_hex.
  - Verify the convenience tuple wrapper delegates correctly.
"""

from __future__ import annotations

import binascii

import paramiko
import pytest

from foghorn.utils import ssh_keys as ssh_keys_mod


def test_fetch_ssh_host_key_hex_success(monkeypatch) -> None:
    """Brief: Successful SSH host key fetch returns populated SSHHostKey.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that connection parameters, key type, and hex encoding match
        expectations and that resources are cleaned up.
    """

    created_transports: list[object] = []

    class FakeSocket:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:  # noqa: D401 - simple flag setter
            """Mark the socket as closed without real IO."""

            self.closed = True

    fake_sock = FakeSocket()

    def fake_create_connection(addr, timeout=None):  # noqa: D401, ANN001
        """Return a fake socket while recording connection parameters."""

        assert addr == ("example.test", 2222)
        assert timeout == 1.5
        return fake_sock

    class FakeKey:
        def __init__(self) -> None:
            self._blob = b"test-key-material"

        def asbytes(self) -> bytes:  # noqa: D401
            """Return a deterministic public key blob."""

            return self._blob

        def get_name(self) -> str:  # noqa: D401
            """Return a fixed SSH key type for testing."""

            return "ssh-ed25519"

    class FakeTransport:
        def __init__(self, sock) -> None:  # noqa: D401, ANN001
            """Record the socket and register this instance for inspection."""

            assert sock is fake_sock
            self.closed = False
            self.started_with = None
            created_transports.append(self)

        def start_client(self, timeout=None) -> None:  # noqa: D401, ANN001
            """Record the timeout used for the SSH handshake."""

            self.started_with = timeout

        def get_remote_server_key(self) -> FakeKey:  # noqa: D401
            """Return a fake SSH key object with deterministic bytes."""

            return FakeKey()

        def close(self) -> None:  # noqa: D401
            """Mark the transport as closed without real network IO."""

            self.closed = True

    monkeypatch.setattr(
        ssh_keys_mod.socket,
        "create_connection",
        fake_create_connection,
        raising=True,
    )
    monkeypatch.setattr(ssh_keys_mod.paramiko, "Transport", FakeTransport, raising=True)

    info = ssh_keys_mod.fetch_ssh_host_key_hex(
        "example.test",
        port=2222,
        timeout=1.5,
    )

    assert isinstance(info, ssh_keys_mod.SSHHostKey)
    assert info.hostname == "example.test"
    assert info.port == 2222
    assert info.key_type == "ssh-ed25519"

    expected_hex = binascii.hexlify(b"test-key-material").decode("ascii")
    assert info.key_hex == expected_hex.lower()

    assert fake_sock.closed is True
    assert created_transports
    assert created_transports[0].closed is True
    assert created_transports[0].started_with == 1.5


def test_fetch_ssh_host_key_hex_raises_when_no_key(monkeypatch) -> None:
    """Brief: Missing host key from the server raises SSHException.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that get_remote_server_key returning None raises
        paramiko.SSHException and still closes transport and socket.
    """

    created_transports: list[object] = []

    class FakeSocket:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:  # noqa: D401
            """Mark the socket as closed without real IO."""

            self.closed = True

    fake_sock = FakeSocket()

    def fake_create_connection(addr, timeout=None):  # noqa: D401, ANN001
        """Return a fake socket regardless of address/timeout."""

        return fake_sock

    class FakeTransport:
        def __init__(self, sock) -> None:  # noqa: D401, ANN001
            """Record the socket and register this instance for inspection."""

            assert sock is fake_sock
            self.closed = False
            created_transports.append(self)

        def start_client(self, timeout=None) -> None:  # noqa: D401, ANN001
            """Accept the handshake timeout without side effects."""

            return None

        def get_remote_server_key(self):  # noqa: D401, ANN001
            """Return None to simulate an SSH server without a host key."""

            return None

        def close(self) -> None:  # noqa: D401
            """Mark the transport as closed without real network IO."""

            self.closed = True

    monkeypatch.setattr(
        ssh_keys_mod.socket,
        "create_connection",
        fake_create_connection,
        raising=True,
    )
    monkeypatch.setattr(ssh_keys_mod.paramiko, "Transport", FakeTransport, raising=True)

    with pytest.raises(paramiko.SSHException):
        ssh_keys_mod.fetch_ssh_host_key_hex("example.test", port=22, timeout=0.5)

    assert fake_sock.closed is True
    assert created_transports
    assert created_transports[0].closed is True


def test_fetch_ssh_host_key_hex_tuple_delegates_to_dataclass(monkeypatch) -> None:
    """Brief: fetch_ssh_host_key_hex_tuple delegates to fetch_ssh_host_key_hex.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that the wrapper forwards arguments and unpacks SSHHostKey.
    """

    calls: list[tuple[str, int, float]] = []

    def fake_fetch(hostname: str, port: int, timeout: float) -> ssh_keys_mod.SSHHostKey:
        calls.append((hostname, port, timeout))
        return ssh_keys_mod.SSHHostKey(
            hostname=f"[{hostname}]",
            port=port,
            key_type="ssh-rsa",
            key_hex="deadbeef",
        )

    monkeypatch.setattr(
        ssh_keys_mod, "fetch_ssh_host_key_hex", fake_fetch, raising=True
    )

    host, key_type, key_hex = ssh_keys_mod.fetch_ssh_host_key_hex_tuple(
        "example.test",
        port=2200,
        timeout=2.5,
    )

    assert calls == [("example.test", 2200, 2.5)]
    assert host == "[example.test]"
    assert key_type == "ssh-rsa"
    assert key_hex == "deadbeef"
