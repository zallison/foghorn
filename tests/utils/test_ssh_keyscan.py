"""Tests for foghorn.utils.ssh_keyscan helpers.

Brief:
  - Exercise happy and error paths for fetch_host_key.
  - Verify SSHFP fingerprint helpers and record collection utilities.
"""

from __future__ import annotations

import hashlib
import logging
from typing import List, Tuple

import paramiko

from foghorn.utils import ssh_keyscan as ssh_keyscan_mod


def test_ignore_incompatible_peer_log_filter_respects_message() -> None:
    """Brief: _IgnoreIncompatiblePeerLog drops only matching Paramiko records.

    Inputs:
      - None (constructs synthetic LogRecord instances).

    Outputs:
      - Asserts that messages containing "Incompatible ssh peer" are filtered
        out while other messages pass through.
    """

    flt = ssh_keyscan_mod._IgnoreIncompatiblePeerLog()
    logger = logging.getLogger("paramiko.test")

    keep = logger.makeRecord(
        "paramiko.test",
        logging.INFO,
        __file__,
        0,
        "regular message",
        args=(),
        exc_info=None,
    )
    drop = logger.makeRecord(
        "paramiko.test",
        logging.WARNING,
        __file__,
        0,
        "Incompatible ssh peer for key",
        args=(),
        exc_info=None,
    )

    assert flt.filter(keep) is True
    assert flt.filter(drop) is False


def test_fetch_host_key_success_closes_resources_and_sets_alg(monkeypatch) -> None:
    """Brief: Successful fetch_host_key returns a key and cleans up transport.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that the requested algorithm is configured, a key object is
        returned, and both transport and socket are closed (even on close
        errors).
    """

    created_transports: List[object] = []

    class FakeSocket:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:  # noqa: D401 - simple flag setter
            """Mark the socket as closed and raise to exercise error handler."""

            self.closed = True
            raise RuntimeError("socket close boom")

    fake_sock = FakeSocket()

    def fake_create_connection(addr, timeout=None):  # noqa: D401, ANN001
        """Return a fake socket asserting connection parameters."""

        assert addr == ("example.test", 2222)
        assert timeout == 1.5
        return fake_sock

    class FakeSecurityOptions:
        def __init__(self) -> None:
            self.key_types: List[str] | None = None

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
            self.opts = FakeSecurityOptions()
            created_transports.append(self)

        def get_security_options(self) -> FakeSecurityOptions:  # noqa: D401
            """Return security options container for host key algorithms."""

            return self.opts

        def start_client(self, timeout=None) -> None:  # noqa: D401, ANN001
            """Record the timeout used for the SSH handshake."""

            self.started_with = timeout

        def get_remote_server_key(self) -> FakeKey:  # noqa: D401
            """Return a fake SSH key with deterministic bytes."""

            return FakeKey()

        def close(self) -> None:  # noqa: D401
            """Mark the transport as closed and raise to hit error handler."""

            self.closed = True
            raise RuntimeError("transport close boom")

    monkeypatch.setattr(
        ssh_keyscan_mod.socket,
        "create_connection",
        fake_create_connection,
        raising=True,
    )
    monkeypatch.setattr(
        ssh_keyscan_mod.paramiko,
        "Transport",
        FakeTransport,
        raising=True,
    )

    key = ssh_keyscan_mod.fetch_host_key(
        "example.test",
        port=2222,
        alg="ssh-ed25519",
        timeout=1.5,
    )

    assert isinstance(key, FakeKey)
    assert created_transports
    tr = created_transports[0]
    assert tr.started_with == 1.5
    assert tr.opts.key_types == ["ssh-ed25519"]
    assert tr.closed is True
    assert fake_sock.closed is True


def test_fetch_host_key_incompatible_peer_returns_none(monkeypatch) -> None:
    """Brief: IncompatiblePeer from Paramiko results in a None return value.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that an IncompatiblePeer error is swallowed and yields None
        while still closing the underlying transport and socket.
    """

    class FakeSocket:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:  # noqa: D401
            """Mark the socket as closed without raising."""

            self.closed = True

    fake_sock = FakeSocket()

    def fake_create_connection(addr, timeout=None):  # noqa: D401, ANN001
        """Return a fake socket regardless of address/timeout."""

        return fake_sock

    class FakeSecurityOptions:
        def __init__(self) -> None:
            self.key_types: List[str] | None = None

    class FakeTransport:
        def __init__(self, sock) -> None:  # noqa: D401, ANN001
            """Store socket and prepare security options."""

            assert sock is fake_sock
            self.closed = False
            self.opts = FakeSecurityOptions()

        def get_security_options(self) -> FakeSecurityOptions:  # noqa: D401
            """Return a fake security options container."""

            return self.opts

        def start_client(self, timeout=None) -> None:  # noqa: D401, ANN001
            """Always raise Paramiko IncompatiblePeer for testing."""

            raise paramiko.ssh_exception.IncompatiblePeer("no common algorithm")

        def close(self) -> None:  # noqa: D401
            """Mark the transport as closed without raising."""

            self.closed = True

    monkeypatch.setattr(
        ssh_keyscan_mod.socket,
        "create_connection",
        fake_create_connection,
        raising=True,
    )
    monkeypatch.setattr(
        ssh_keyscan_mod.paramiko,
        "Transport",
        FakeTransport,
        raising=True,
    )

    key = ssh_keyscan_mod.fetch_host_key(
        "example.test",
        port=22,
        alg="ssh-ed25519",
        timeout=0.75,
    )

    assert key is None
    assert fake_sock.closed is True


def test_fetch_host_key_generic_error_returns_none(monkeypatch) -> None:
    """Brief: Generic connection errors cause fetch_host_key to return None.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that an OSError from create_connection leads to a None return
        without propagating the exception.
    """

    def boom(*_args, **_kwargs):  # noqa: D401, ANN001
        """Always raise OSError to simulate a network failure."""

        raise OSError("network down")

    monkeypatch.setattr(
        ssh_keyscan_mod.socket,
        "create_connection",
        boom,
        raising=True,
    )

    key = ssh_keyscan_mod.fetch_host_key(
        "example.test",
        port=22,
        alg="ssh-ed25519",
        timeout=0.25,
    )

    assert key is None


def test_sshfp_records_for_key_returns_two_hashes_for_known_type() -> None:
    """Brief: sshfp_records_for_key yields SHA-1 and SHA-256 entries.

    Inputs:
      - None (constructs a small fake key object).

    Outputs:
      - Asserts that two records are returned with the expected algorithm
        number and digest lengths.
    """

    class FakeKey:
        def __init__(self) -> None:
            self._blob = b"sshfp-test-key"

        def asbytes(self) -> bytes:  # noqa: D401
            """Return deterministic key bytes for hashing."""

            return self._blob

        def get_name(self) -> str:  # noqa: D401
            """Return a supported SSH key type name."""

            return "ssh-ed25519"

    key = FakeKey()
    records = ssh_keyscan_mod.sshfp_records_for_key("host.example", key)

    assert len(records) == 2
    alg_nums = {alg for alg, _fptype, _fp in records}
    assert alg_nums == {ssh_keyscan_mod.SSHFP_ALG_NUMBERS["ssh-ed25519"]}

    digests = [fp for _alg, _fptype, fp in records]
    assert all(len(fp) == len(hashlib.sha1(b"").hexdigest()) for fp in digests[:1])
    assert all(len(fp) == len(hashlib.sha256(b"").hexdigest()) for fp in digests[1:])


def test_sshfp_records_for_key_unknown_type_returns_empty() -> None:
    """Brief: sshfp_records_for_key returns [] for unmapped key types.

    Inputs:
      - None (uses a fake key type that is not in the mapping).

    Outputs:
      - Asserts that no records are produced when the key type is unknown.
    """

    class FakeKey:
        def asbytes(self) -> bytes:  # noqa: D401
            """Return deterministic key bytes for hashing."""

            return b"ignored"

        def get_name(self) -> str:  # noqa: D401
            """Return a key type not present in SSHFP_ALG_NUMBERS."""

            return "ssh-unknown"

    records = ssh_keyscan_mod.sshfp_records_for_key("host.example", FakeKey())
    assert records == []


def test_collect_sshfp_records_default_algs_and_dedup(monkeypatch) -> None:
    """Brief: collect_sshfp_records de-duplicates identical SSHFP entries.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that when multiple algorithms yield the same SSHFP tuples, the
        resulting DNS record strings contain no duplicates and correct host.
    """

    calls: List[Tuple[str, int, str, float]] = []

    class FakeKey:
        def __init__(self, name: str) -> None:
            self._name = name
            self._blob = b"sshfp-blob"

        def get_name(self) -> str:  # noqa: D401
            """Return the configured SSH key type name."""

            return self._name

        def asbytes(self) -> bytes:  # noqa: D401
            """Return deterministic bytes shared across algorithms."""

            return self._blob

    def fake_fetch(host: str, port: int, alg: str, timeout: float) -> FakeKey | None:
        calls.append((host, port, alg, timeout))
        # For the first two algorithms, return keys with the same type and
        # bytes, causing identical SSHFP tuples. Remaining algorithms behave as
        # if unsupported.
        if alg in ssh_keyscan_mod.HOSTKEY_ALGS[:2]:
            return FakeKey("ssh-ed25519")
        return None

    monkeypatch.setattr(
        ssh_keyscan_mod,
        "fetch_host_key",
        fake_fetch,
        raising=True,
    )

    lines = ssh_keyscan_mod.collect_sshfp_records("host.example", port=22, timeout=1.0)

    # At least one algorithm should have been attempted.
    assert calls
    # Two digest types (SHA-1 and SHA-256) should yield two unique lines.
    assert len(lines) == 2
    assert all(line.startswith("host.example IN SSHFP ") for line in lines)


def test_collect_sshfp_records_respects_custom_algs(monkeypatch) -> None:
    """Brief: collect_sshfp_records uses the provided algs iterable as-is.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Asserts that only the requested algorithms are probed and that
        resulting SSHFP lines are constructed for the supplied hostname.
    """

    probed: List[str] = []

    class FakeKey:
        def __init__(self, name: str) -> None:
            self._name = name
            self._blob = b"sshfp-custom-blob"

        def get_name(self) -> str:  # noqa: D401
            """Return the configured SSH key type name."""

            return self._name

        def asbytes(self) -> bytes:  # noqa: D401
            """Return deterministic bytes for hashing."""

            return self._blob

    def fake_fetch(host: str, port: int, alg: str, timeout: float) -> FakeKey | None:
        probed.append(alg)
        # Only one algorithm is considered supported in this scenario.
        if alg == "ssh-ed25519":
            return FakeKey("ssh-ed25519")
        return None

    monkeypatch.setattr(
        ssh_keyscan_mod,
        "fetch_host_key",
        fake_fetch,
        raising=True,
    )

    lines = ssh_keyscan_mod.collect_sshfp_records(
        "other.example",
        port=2200,
        timeout=2.5,
        algs=["ssh-ed25519", "ssh-rsa"],
    )

    # Only the explicitly supplied algorithms should be probed in order.
    assert probed == ["ssh-ed25519", "ssh-rsa"]
    # One algorithm yields a key, the other does not; we still expect SSHFP
    # records for the supported entry.
    assert lines
    assert all(line.startswith("other.example IN SSHFP ") for line in lines)
