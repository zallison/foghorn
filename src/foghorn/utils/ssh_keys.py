from __future__ import annotations

import binascii
import socket
from dataclasses import dataclass
from typing import Tuple

import paramiko


@dataclass
class SSHHostKey:
    """Brief: Information about an SSH server's host key.

    Inputs:
      - hostname: Hostname or IP address of the SSH server.
      - port: TCP port number of the SSH service.
      - key_type: Public key algorithm name reported by the server (e.g. ``ssh-ed25519``).
      - key_hex: Hex-encoded public key blob as advertised in the SSH handshake.

    Outputs:
      - A simple data container suitable for use in scripts and tooling that
        need to materialize SSHFP RDATA (e.g. ``<alg> <fp_type> <fingerprint>``).
    """

    hostname: str
    port: int
    key_type: str
    key_hex: str


def fetch_ssh_host_key_hex(
    hostname: str,
    *,
    port: int = 22,
    timeout: float = 5.0,
) -> SSHHostKey:
    """Brief: Connect to an SSH server and return its public host key in hex.

    Inputs:
      - hostname: Target SSH server hostname or IP address.
      - port: TCP port number to connect to (default: 22).
      - timeout: Socket connect timeout in seconds (default: 5.0).

    Outputs:
      - SSHHostKey: Dataclass containing the server's reported key type and the
        raw public key blob encoded as a lower-case hexadecimal string.

    Behaviour:
      - Establishes a TCP connection to ``hostname:port``.
      - Performs the SSH protocol version exchange and key exchange using
        ``paramiko.Transport`` without authenticating.
      - Extracts the negotiated host key and returns it in hex form, suitable
        for hashing into SSHFP RDATA (for example, applying SHA-256 and
        formatting as hex for ``fp_type`` 2).

    Raises:
      - socket.timeout: If the TCP connection cannot be established within
        ``timeout`` seconds.
      - paramiko.SSHException: If the SSH handshake fails.
      - OSError: For other underlying socket errors.
    """

    sock = socket.create_connection((hostname, int(port)), timeout=timeout)
    try:
        transport = paramiko.Transport(sock)
        try:
            # Start a client-side SSH handshake; we do not authenticate, we only
            # need the server's host key from the KEX.
            transport.start_client(timeout=timeout)
            key = transport.get_remote_server_key()
            if key is None:
                raise paramiko.SSHException("SSH server did not present a host key")

            key_blob = key.asbytes()
            key_type = key.get_name()
            key_hex = binascii.hexlify(key_blob).decode("ascii")
            return SSHHostKey(
                hostname=str(hostname),
                port=int(port),
                key_type=str(key_type),
                key_hex=key_hex.lower(),
            )
        finally:
            # Ensure the SSH transport is closed even if an exception occurs.
            try:
                transport.close()
            except Exception:  # pragma: no cover - defensive cleanup
                pass
    finally:
        try:
            sock.close()
        except Exception:  # pragma: no cover - defensive cleanup
            pass


def fetch_ssh_host_key_hex_tuple(
    hostname: str,
    *,
    port: int = 22,
    timeout: float = 5.0,
) -> Tuple[str, str, str]:
    """Brief: Convenience wrapper returning ``(hostname, key_type, key_hex)``.

    Inputs:
      - hostname: Target SSH server hostname or IP.
      - port: TCP port number (default: 22).
      - timeout: Socket connect timeout in seconds (default: 5.0).

    Outputs:
      - (hostname, key_type, key_hex): A tuple of strings where ``key_hex`` is
        the hex-encoded public key blob from the SSH server.

    Example:

      >>> from foghorn.utils.ssh_keys import fetch_ssh_host_key_hex_tuple
      >>> host, key_type, key_hex = fetch_ssh_host_key_hex_tuple('example.com')
      >>> print(host, key_type, key_hex[:16] + '...')
    """

    info = fetch_ssh_host_key_hex(hostname, port=port, timeout=timeout)
    return info.hostname, info.key_type, info.key_hex
