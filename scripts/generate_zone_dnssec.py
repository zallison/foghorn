#!/usr/bin/env python3
"""
Brief: Generate DNSSEC keys and sign BIND-style zone files for use with ZoneRecords.

Inputs (CLI arguments):
  --zone: Zone apex (e.g. "example.com.").
  --input: Path to unsigned BIND-style zone file.
  --output: Path to write signed zone file.
  --keys-dir: Directory to store/load key material (default: same as output).
  --algorithm: DNSSEC algorithm (default: ECDSAP256SHA256).
  --force-new-keys: Generate new keys even if existing keys are found.
  --ds-output: Optional path to write DS records for parent delegation.

Outputs:
  - Signed zone file at --output path.
  - Key files (KSK/ZSK) in --keys-dir.
  - Optional DS records file or stdout output.

Example:
  python scripts/generate_zone_dnssec.py \\
    --zone example.com. \\
    --input zones/example.com.zone \\
    --output zones/example.com.signed.zone \\
    --keys-dir keys/

Dependencies:
  - dnspython (dns module)
  - cryptography
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

try:
    from foghorn.dnssec.zone_signer import ALGORITHM_MAP, sign_zone_file
except Exception as e:  # pragma: no cover - import-time failure mapped to CLI error
    print(f"Error: DNSSEC signing helpers are required: {e}", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def main() -> int:
    """Brief: Main entry point for the DNSSEC zone signing script.

    Inputs:
      - CLI arguments (see argparse setup).

    Outputs:
      - int: Exit code (0 for success, non-zero for errors).
    """

    parser = argparse.ArgumentParser(
        description="Generate DNSSEC keys and sign BIND-style zone files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--zone",
        required=True,
        help="Zone apex (e.g., 'example.com.' with trailing dot)",
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to unsigned BIND-style zone file",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path to write signed zone file",
    )
    parser.add_argument(
        "--keys-dir",
        type=Path,
        default=None,
        help="Directory to store/load key material (default: same dir as output)",
    )
    parser.add_argument(
        "--algorithm",
        default="ECDSAP256SHA256",
        choices=list(ALGORITHM_MAP.keys()),
        help="DNSSEC algorithm (default: ECDSAP256SHA256)",
    )
    parser.add_argument(
        "--force-new-keys",
        action="store_true",
        help="Generate new keys even if existing keys are found",
    )
    parser.add_argument(
        "--ds-output",
        type=Path,
        default=None,
        help="Path to write DS records (prints to stdout if not specified)",
    )
    parser.add_argument(
        "--validity-days",
        type=int,
        default=30,
        help="Signature validity period in days (default: 30)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    zone_name_str = args.zone
    if not zone_name_str.endswith("."):
        zone_name_str += "."

    keys_dir = args.keys_dir or args.output.parent

    generate_policy = "yes" if args.force_new_keys else "maybe"

    logger.info("Loading unsigned zone from %s", args.input)

    try:
        ds_lines = sign_zone_file(
            zone_name_str,
            args.input,
            args.output,
            keys_dir=keys_dir,
            algorithm=args.algorithm,
            generate_policy=generate_policy,
            validity_days=args.validity_days,
        )
    except Exception as exc:
        logger.error("Failed to sign zone %s: %s", zone_name_str, exc)
        return 1

    if ds_lines:
        if args.ds_output:
            args.ds_output.parent.mkdir(parents=True, exist_ok=True)
            args.ds_output.write_text("\n".join(ds_lines) + "\n", encoding="utf-8")
            logger.info("DS records written to %s", args.ds_output)
        else:
            print("\n--- DS Records for parent zone ---")
            for line in ds_lines:
                print(line)

    logger.info("Zone signing complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
