#!/usr/bin/env python3
"""Generate TSIG keys for DNS UPDATE authentication.

Inputs:
  - CLI flags selecting TSIG generation (PSK is not supported).

Outputs:
  - Prints a TSIG shared secret (base64) and optional YAML snippet.

Usage:
    python generate_dns_update_keys.py --tsig --name "key.example.com"
    python generate_dns_update_keys.py --tsig --name "key.example.com" --config-snippet
"""

from __future__ import annotations

import argparse
import base64
import secrets
import sys

_PSK_UNSUPPORTED_MSG = (
    "ERROR: PSK generation is not supported. DNS UPDATE authentication is "
    "TSIG-only. Use --tsig (or: make gen-tsig-key)."
)


def generate_tsig_secret(algorithm: str = "hmac-sha256") -> str:
    """Brief: Generate a secure random TSIG secret.

    Inputs:
      - algorithm: HMAC algorithm name.

    Outputs:
      - Base64-encoded shared secret.
    """

    lengths = {"hmac-md5": 16, "hmac-sha256": 32, "hmac-sha512": 64}
    key_length = lengths.get(algorithm, 32)
    return base64.b64encode(secrets.token_bytes(key_length)).decode("utf-8")


def print_tsig_config(name: str, algorithm: str, secret: str) -> None:
    """Brief: Print a YAML snippet for TSIG configuration.

    Inputs:
      - name: TSIG key name.
      - algorithm: HMAC algorithm.
      - secret: Base64 TSIG shared secret.

    Outputs:
      - None; prints snippet to stdout.
    """

    print("\n        dns_update:")
    print("            enabled: true")
    print("            zones:")
    print("              - zone: example.com")
    print("                tsig:")
    print("                  keys:")
    print(f'                    - name: "{name}"')
    print(f'                      algorithm: "{algorithm}"')
    print(f'                      secret: "{secret}"')


def main() -> int:
    """Brief: CLI entrypoint.

    Inputs:
      - None (reads CLI args).

    Outputs:
      - Process exit code.
    """

    parser = argparse.ArgumentParser(
        description="Generate TSIG keys for DNS UPDATE (TSIG-only; PSK unsupported)"
    )
    parser.add_argument("--tsig", action="store_true", help="Generate TSIG key")
    parser.add_argument(
        "--psk",
        action="store_true",
        help="Unsupported; DNS UPDATE is TSIG-only (exits with error)",
    )
    parser.add_argument("--name", type=str, help="TSIG key name (required for TSIG)")
    parser.add_argument(
        "--algorithm",
        choices=["hmac-md5", "hmac-sha256", "hmac-sha512"],
        default="hmac-sha256",
    )
    parser.add_argument("--config-snippet", action="store_true")
    args = parser.parse_args()

    if args.psk:
        print(_PSK_UNSUPPORTED_MSG, file=sys.stderr)
        return 2

    if args.tsig:
        if not args.name:
            print("ERROR: --name required for --tsig", file=sys.stderr)
            return 1

        secret = generate_tsig_secret(args.algorithm)
        if args.config_snippet:
            print_tsig_config(args.name, args.algorithm, secret)
            return 0

        print(f"TSIG Secret ({args.algorithm}): {secret}")
        return 0

    parser.print_help(sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
