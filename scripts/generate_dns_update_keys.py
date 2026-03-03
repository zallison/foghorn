#!/usr/bin/env python3
"""Generate TSIG keys and PSK tokens for DNS UPDATE authentication.

Inputs:
  - CLI flags selecting TSIG or PSK generation.

Outputs:
  - Prints either a TSIG shared secret (base64) or a PSK token.
  - For PSK, prints both the plaintext token (client secret) and the bcrypt hash
    (server-side config value).

Usage:
    python generate_dns_update_keys.py --tsig --name "key.example.com"
    python generate_dns_update_keys.py --psk
"""

from __future__ import annotations

import argparse
import base64
import secrets
import sys
from typing import Optional, Tuple


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


def generate_psk_token() -> Optional[Tuple[str, str]]:
    """Brief: Generate a PSK token (plaintext + bcrypt hash).

    Inputs:
      - None.

    Outputs:
      - (plaintext_token, bcrypt_hash) on success, or None if bcrypt unavailable.

    Notes:
      - The plaintext token is the client secret. Store it securely; it is only
        printed once.
      - The bcrypt hash is what should be stored in foghorn config.
    """

    try:
        import bcrypt
    except ImportError:
        print("ERROR: pip install bcrypt")
        return None

    # token_urlsafe returns a URL-safe base64-ish token (no quotes/newlines),
    # which is convenient to paste into configs.
    plaintext = secrets.token_urlsafe(48)
    hashed = bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode(
        "utf-8"
    )

    return plaintext, hashed


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


def print_psk_config(hashed_token: str) -> None:
    """Brief: Print a YAML snippet for PSK configuration.

    Inputs:
      - hashed_token: bcrypt hash to store in config.

    Outputs:
      - None; prints snippet to stdout.
    """

    print("\n        dns_update:")
    print("            enabled: true")
    print("            zones:")
    print("              - zone: example.com")
    print("                psk:")
    print("                  tokens:")
    print(f'                    - token: "{hashed_token}"')


def main() -> int:
    """Brief: CLI entrypoint.

    Inputs:
      - None (reads CLI args).

    Outputs:
      - Process exit code.
    """

    parser = argparse.ArgumentParser(
        description="Generate TSIG keys and PSK tokens for DNS UPDATE"
    )
    parser.add_argument("--tsig", action="store_true", help="Generate TSIG key")
    parser.add_argument("--psk", action="store_true", help="Generate PSK token")
    parser.add_argument("--name", type=str, help="TSIG key name (required for TSIG)")
    parser.add_argument(
        "--algorithm",
        choices=["hmac-md5", "hmac-sha256", "hmac-sha512"],
        default="hmac-sha256",
    )
    parser.add_argument("--config-snippet", action="store_true")
    args = parser.parse_args()

    if args.tsig:
        if not args.name:
            print("ERROR: --name required for --tsig")
            return 1

        secret = generate_tsig_secret(args.algorithm)
        if args.config_snippet:
            print_tsig_config(args.name, args.algorithm, secret)
            return 0

        print(f"TSIG Secret ({args.algorithm}): {secret}")
        return 0

    if args.psk:
        token_pair = generate_psk_token()
        if not token_pair:
            return 1

        plaintext, hashed = token_pair

        if args.config_snippet:
            # Keep stdout as a pasteable YAML snippet; print the client secret to stderr.
            print(f"PSK Token (plaintext): {plaintext}", file=sys.stderr)
            print_psk_config(hashed)
            return 0

        print(f"PSK Token (plaintext): {plaintext}")
        print(f"PSK Token (bcrypt): {hashed}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
