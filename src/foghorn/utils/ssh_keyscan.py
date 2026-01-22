from __future__ import annotations

"""Helpers for scanning SSH servers and materializing SSHFP records.

Brief:
  This module exposes utilities equivalent to ``ssh-keyscan -D`` using
  Paramiko, returning DNS SSHFP record strings for a single host.

Inputs:
  - See individual functions for parameters.

Outputs:
  - Stateless helpers that can be reused from scripts and other modules to
    obtain SSHFP "<hostname> IN SSHFP <alg> <fptype> <fingerprint>" lines.
"""

import hashlib
import logging
import socket
from typing import Dict, Iterable, List, Optional, Set, Tuple

import paramiko


class _IgnoreIncompatiblePeerLog(logging.Filter):
    """Brief: Drop Paramiko 'Incompatible ssh peer' log records from stderr.

    Inputs:
      - record: A logging.LogRecord from the paramiko logger.

    Outputs:
      - bool: True if the record should be emitted, False if it should be
        dropped.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[name-defined]
        msg = record.getMessage()
        return "Incompatible ssh peer" not in msg


# Attach filter to all Paramiko loggers and silence them to avoid noisy tracebacks.
_paramiko_root_logger = logging.getLogger("paramiko")
_paramiko_root_logger.addFilter(_IgnoreIncompatiblePeerLog())
_paramiko_root_logger.setLevel(logging.CRITICAL)


# Common host key algorithms to probe. Extend if needed.
HOSTKEY_ALGS: List[str] = [
    "ssh-ed25519",
    "ssh-ed448",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ssh-dss",  # legacy DSA
]

# Mapping from Paramiko key type names to SSHFP algorithm numbers (RFC 4255 / 8709).
SSHFP_ALG_NUMBERS: Dict[str, int] = {
    "ssh-rsa": 1,
    "rsa-sha2-256": 1,
    "rsa-sha2-512": 1,
    "ssh-dss": 2,
    "ecdsa-sha2-nistp256": 3,
    "ecdsa-sha2-nistp384": 3,
    "ecdsa-sha2-nistp521": 3,
    "ssh-ed25519": 4,
    "ssh-ed448": 6,
}


def fetch_host_key(
    host: str, port: int, alg: str, timeout: float
) -> Optional[paramiko.PKey]:
    """Brief: Connect with one host key algorithm and return the server's key.

    Inputs:
      - host: Remote SSH server hostname or IP.
      - port: Remote SSH server port.
      - alg: Name of host key algorithm to try, e.g. ``ssh-ed25519``.
      - timeout: Socket and handshake timeout in seconds.

    Outputs:
      - paramiko.PKey | None: Server key if negotiation succeeds, or None if the
        algorithm is not supported or the connection fails.
    """

    sock = None
    transport = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        transport = paramiko.Transport(sock)
        opts = transport.get_security_options()
        # Only offer this specific host key algorithm.
        opts.key_types = [alg]
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        return key
    except paramiko.ssh_exception.IncompatiblePeer:
        # Remote side has no acceptable host key for this algorithm; ignore.
        return None
    except (paramiko.SSHException, OSError, ValueError):
        return None
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def sshfp_records_for_key(
    hostname: str, key: paramiko.PKey
) -> List[Tuple[int, int, str]]:
    """Brief: Compute SSHFP records (algorithm, fptype, hex) for a single key.

    Inputs:
      - hostname: The DNS name to use in the SSHFP records (not modified here).
      - key: A Paramiko public key object from ``get_remote_server_key()``.

    Outputs:
      - list[(algorithm_number, fptype, hex_fingerprint)]:
          * fptype 1: SHA-1
          * fptype 2: SHA-256
        Returns an empty list if the key type is not mapped to an SSHFP
        algorithm.
    """

    key_type = key.get_name()
    alg_num = SSHFP_ALG_NUMBERS.get(key_type)
    if alg_num is None:
        return []

    blob = key.asbytes()
    sha1_hex = hashlib.sha1(blob).hexdigest()
    sha256_hex = hashlib.sha256(blob).hexdigest()

    return [
        (alg_num, 1, sha1_hex),
        (alg_num, 2, sha256_hex),
    ]


def collect_sshfp_records(
    hostname: str,
    *,
    port: int,
    timeout: float,
    algs: Iterable[str] | None = None,
) -> List[str]:
    """Brief: Probe a host for multiple key algorithms and return SSHFP lines.

    Inputs:
      - hostname: Remote SSH server hostname to scan.
      - port: Remote SSH port.
      - timeout: Connection/handshake timeout in seconds.
      - algs: Iterable of host key algorithm names to try. When None, uses the
        default ``HOSTKEY_ALGS`` sequence.

    Outputs:
      - list[str]: DNS-style SSHFP record strings of the form
        "<hostname> IN SSHFP <alg> <fptype> <fingerprint>". Duplicate records
        (same algorithm and fingerprint) are de-duplicated.
    """

    alg_list: Iterable[str]
    if algs is None:
        alg_list = HOSTKEY_ALGS
    else:
        alg_list = algs

    seen: Set[Tuple[int, int, str]] = set()
    lines: List[str] = []

    for alg in alg_list:
        key = fetch_host_key(hostname, port, alg, timeout)
        if key is None:
            continue

        for alg_num, fptype, fp_hex in sshfp_records_for_key(hostname, key):
            record_id = (alg_num, fptype, fp_hex)
            if record_id in seen:
                continue
            seen.add(record_id)
            lines.append(f"{hostname} IN SSHFP {alg_num} {fptype} {fp_hex}")

    return lines
