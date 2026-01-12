#!/usr/bin/env python3
"""Brief: Fetch an SSH server's host key and print its hex-encoded value.

Inputs:
  - Command-line arguments:
    - --host / -H (required): Hostname or IP address of the SSH server.
    - --port / -p (optional, default: 22): SSH TCP port.
    - --timeout / -t (optional, default: 5.0): Socket connect timeout in seconds.

Outputs:
  - On success: prints a single line to stdout in the form:

      <hostname> <port> <key-type> <hex-blob>

    where ``key-type`` is the SSH public key algorithm name (e.g. ``ssh-ed25519``)
    and ``hex-blob`` is the hex-encoded public key blob from the SSH handshake.
  - Exit status 0 on success; non-zero on error.

Example:
  $ ./ssh_host_key_hex.py --host example.com
  example.com 22 ssh-ed25519 1f2a3b...
"""

from __future__ import annotations

import argparse
import sys
from typing import Iterable, Optional

from foghorn.utils.ssh_keys import fetch_ssh_host_key_hex


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    """Brief: Parse command-line arguments for the ssh_host_key_hex script.

    Inputs:
      - argv: Optional iterable of argument strings; defaults to ``sys.argv[1:]``.

    Outputs:
      - argparse.Namespace with attributes:
          - host: Target SSH hostname or IP (required).
          - port: TCP port (int).
          - timeout: Connect timeout in seconds (float).
    """

    parser = argparse.ArgumentParser(
        description="Fetch an SSH server's host key and print its hex-encoded value.",
    )

    parser.add_argument(
        "-H",
        "--host",
        dest="host",
        required=True,
        help="Hostname or IP address of the SSH server (required)",
    )
    parser.add_argument(
        "-p",
        "--port",
        dest="port",
        type=int,
        default=22,
        help="SSH server TCP port (default: 22)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        dest="timeout",
        type=float,
        default=5.0,
        help="TCP connect timeout in seconds (default: 5.0)",
    )

    return parser.parse_args(list(argv) if argv is not None else sys.argv[1:])


def main(argv: Optional[Iterable[str]] = None) -> int:
    """Brief: CLI entrypoint for fetching an SSH host key in hex form.

    Inputs:
      - argv: Optional iterable of command-line argument strings.

    Outputs:
      - int: Exit status (0 on success, non-zero on error).
    """

    args = parse_args(argv)

    try:
        info = fetch_ssh_host_key_hex(
            args.host,
            port=args.port,
            timeout=args.timeout,
        )
    except Exception as exc:
        sys.stderr.write(
            f"error: failed to fetch SSH host key for {args.host}:{args.port}: {exc}\n"
        )
        return 1

    # Print a simple, script-friendly representation: host port type hex
    sys.stdout.write(f"{info.hostname} {info.port} {info.key_type} {info.key_hex}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
