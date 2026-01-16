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
import datetime
import json
import logging
import sys
from pathlib import Path
from typing import Optional, Tuple

try:
    import dns.dnssec
    import dns.name
    import dns.node
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype
    import dns.rrset
    import dns.zone
except ImportError as e:
    print(f"Error: dnspython is required: {e}", file=sys.stderr)
    sys.exit(1)

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
except ImportError as e:
    print(f"Error: cryptography is required: {e}", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Supported algorithms and their parameters
ALGORITHM_MAP = {
    "RSASHA256": (dns.dnssec.Algorithm.RSASHA256, "rsa", 2048),
    "RSASHA512": (dns.dnssec.Algorithm.RSASHA512, "rsa", 2048),
    "ECDSAP256SHA256": (dns.dnssec.Algorithm.ECDSAP256SHA256, "ecdsa", 256),
    "ECDSAP384SHA384": (dns.dnssec.Algorithm.ECDSAP384SHA384, "ecdsa", 384),
}


def generate_keypair(
    algorithm_name: str, key_type: str
) -> Tuple[object, dns.dnssec.Algorithm]:
    """Brief: Generate a cryptographic keypair for DNSSEC signing.

    Inputs:
      - algorithm_name: Algorithm name (e.g., "ECDSAP256SHA256").
      - key_type: "ksk" or "zsk".

    Outputs:
      - (private_key, algorithm): Private key object and dnspython algorithm enum.
    """
    if algorithm_name not in ALGORITHM_MAP:
        raise ValueError(f"Unsupported algorithm: {algorithm_name}")

    alg_enum, key_family, key_size = ALGORITHM_MAP[algorithm_name]

    if key_family == "rsa":
        # For KSK, use larger key size
        if key_type == "ksk":
            key_size = max(key_size, 2048)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_family == "ecdsa":
        if key_size == 256:
            curve = ec.SECP256R1()
        elif key_size == 384:
            curve = ec.SECP384R1()
        else:
            raise ValueError(f"Unsupported ECDSA key size: {key_size}")
        private_key = ec.generate_private_key(curve)
    else:
        raise ValueError(f"Unknown key family: {key_family}")

    return private_key, alg_enum


def save_key(
    private_key: object, key_dir: Path, zone_name: str, key_type: str, algorithm: str
) -> Path:
    """Brief: Save a private key to disk in PEM format.

    Inputs:
      - private_key: Cryptographic private key object.
      - key_dir: Directory to save key file.
      - zone_name: Zone apex for filename.
      - key_type: "ksk" or "zsk".
      - algorithm: Algorithm name for metadata.

    Outputs:
      - Path to saved key file.
    """
    key_dir.mkdir(parents=True, exist_ok=True)
    sanitized_zone = zone_name.rstrip(".").replace(".", "_")
    key_path = key_dir / f"K{sanitized_zone}.{key_type}.key"
    meta_path = key_dir / f"K{sanitized_zone}.{key_type}.meta.json"

    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open(key_path, "wb") as f:
        f.write(pem_bytes)

    meta = {
        "zone": zone_name,
        "key_type": key_type,
        "algorithm": algorithm,
        "created": datetime.datetime.utcnow().isoformat(),
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    logger.info("Saved %s key to %s", key_type.upper(), key_path)
    return key_path


def load_key(key_dir: Path, zone_name: str, key_type: str) -> Optional[object]:
    """Brief: Load an existing private key from disk.

    Inputs:
      - key_dir: Directory containing key files.
      - zone_name: Zone apex for filename.
      - key_type: "ksk" or "zsk".

    Outputs:
      - Private key object if found, None otherwise.
    """
    sanitized_zone = zone_name.rstrip(".").replace(".", "_")
    key_path = key_dir / f"K{sanitized_zone}.{key_type}.key"

    if not key_path.exists():
        return None

    with open(key_path, "rb") as f:
        pem_bytes = f.read()

    try:
        private_key = serialization.load_pem_private_key(pem_bytes, password=None)
        logger.info("Loaded existing %s key from %s", key_type.upper(), key_path)
        return private_key
    except Exception as e:
        logger.warning("Failed to load key from %s: %s", key_path, e)
        return None


def make_dnskey_rdata(
    private_key: object, algorithm: dns.dnssec.Algorithm, flags: int
) -> dns.rdata.Rdata:
    """Brief: Create DNSKEY rdata from a private key.

    Inputs:
      - private_key: Cryptographic private key.
      - algorithm: DNSSEC algorithm enum.
      - flags: DNSKEY flags (257 for KSK, 256 for ZSK).

    Outputs:
      - dns.rdata.Rdata for DNSKEY.
    """
    public_key = private_key.public_key()
    return dns.dnssec.make_dnskey(public_key, algorithm, flags=flags)


def sign_zone(
    zone: dns.zone.Zone,
    zone_name: dns.name.Name,
    ksk_private: object,
    zsk_private: object,
    ksk_dnskey: dns.rdata.Rdata,
    zsk_dnskey: dns.rdata.Rdata,
    algorithm: dns.dnssec.Algorithm,
    inception: datetime.datetime,
    expiration: datetime.datetime,
) -> None:
    """Brief: Sign all RRsets in the zone with appropriate keys.

    Inputs:
      - zone: dns.zone.Zone object to sign (mutated in-place).
      - zone_name: Zone apex as dns.name.Name.
      - ksk_private: KSK private key for signing DNSKEY RRset.
      - zsk_private: ZSK private key for signing other RRsets.
      - ksk_dnskey: KSK DNSKEY rdata.
      - zsk_dnskey: ZSK DNSKEY rdata.
      - algorithm: DNSSEC algorithm.
      - inception: Signature inception time.
      - expiration: Signature expiration time.

    Outputs:
      - None; zone is mutated with DNSKEY and RRSIG records added.
    """
    # Add DNSKEY RRset at the zone apex
    apex_node = zone.find_node(zone_name, create=True)
    dnskey_rrset = dns.rrset.RRset(zone_name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    dnskey_rrset.add(ksk_dnskey)
    dnskey_rrset.add(zsk_dnskey)
    apex_node.replace_rdataset(dnskey_rrset)

    # Sign each RRset in the zone
    for name, node in zone.items():
        for rdataset in node:
            rrset = dns.rrset.from_rdata_list(name, rdataset.ttl, list(rdataset))

            # DNSKEY is signed with the KSK; all other RRsets with the ZSK
            if rdataset.rdtype == dns.rdatatype.DNSKEY:
                signing_key = ksk_private
            else:
                signing_key = zsk_private

            # Skip RRSIG records themselves
            if rdataset.rdtype == dns.rdatatype.RRSIG:
                continue

            try:
                rrsig = dns.dnssec.sign(
                    rrset,
                    signing_key,
                    signer=zone_name,
                    dnskey=(
                        ksk_dnskey
                        if rdataset.rdtype == dns.rdatatype.DNSKEY
                        else zsk_dnskey
                    ),
                    inception=inception,
                    expiration=expiration,
                )
                # Add the RRSIG to the node
                rrsig_rdataset = node.find_rdataset(
                    dns.rdataclass.IN, dns.rdatatype.RRSIG, rdataset.rdtype, create=True
                )
                rrsig_rdataset.add(rrsig)
                rrsig_rdataset.update_ttl(rdataset.ttl)
            except Exception as e:
                logger.warning(
                    "Failed to sign %s %s: %s",
                    name,
                    dns.rdatatype.to_text(rdataset.rdtype),
                    e,
                )


def generate_ds_records(
    zone_name: dns.name.Name, ksk_dnskey: dns.rdata.Rdata
) -> list[dns.rdata.Rdata]:
    """Brief: Generate DS records for the KSK.

    Inputs:
      - zone_name: Zone apex.
      - ksk_dnskey: KSK DNSKEY rdata.

    Outputs:
      - List of DS rdata objects (SHA-256 and SHA-384 digests).
    """
    ds_records = []
    for digest_type in (dns.dnssec.DSDigest.SHA256, dns.dnssec.DSDigest.SHA384):
        try:
            ds = dns.dnssec.make_ds(zone_name, ksk_dnskey, digest_type)
            ds_records.append(ds)
        except Exception as e:
            logger.warning("Failed to generate DS with digest %s: %s", digest_type, e)
    return ds_records


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

    # Normalize zone name
    zone_name_str = args.zone
    if not zone_name_str.endswith("."):
        zone_name_str += "."
    zone_name = dns.name.from_text(zone_name_str)

    # Determine keys directory
    keys_dir = args.keys_dir or args.output.parent

    # Load or generate keys
    ksk_private = None
    zsk_private = None

    if not args.force_new_keys:
        ksk_private = load_key(keys_dir, zone_name_str, "ksk")
        zsk_private = load_key(keys_dir, zone_name_str, "zsk")

    alg_enum = ALGORITHM_MAP[args.algorithm][0]

    if ksk_private is None:
        logger.info("Generating new KSK with algorithm %s", args.algorithm)
        ksk_private, _ = generate_keypair(args.algorithm, "ksk")
        save_key(ksk_private, keys_dir, zone_name_str, "ksk", args.algorithm)

    if zsk_private is None:
        logger.info("Generating new ZSK with algorithm %s", args.algorithm)
        zsk_private, _ = generate_keypair(args.algorithm, "zsk")
        save_key(zsk_private, keys_dir, zone_name_str, "zsk", args.algorithm)

    # Create DNSKEY rdata
    ksk_dnskey = make_dnskey_rdata(ksk_private, alg_enum, flags=257)  # KSK: SEP bit
    zsk_dnskey = make_dnskey_rdata(zsk_private, alg_enum, flags=256)  # ZSK

    logger.info("KSK key tag: %d", dns.dnssec.key_id(ksk_dnskey))
    logger.info("ZSK key tag: %d", dns.dnssec.key_id(zsk_dnskey))

    # Load the unsigned zone
    logger.info("Loading unsigned zone from %s", args.input)
    try:
        zone = dns.zone.from_file(str(args.input), origin=zone_name, relativize=False)
    except Exception as e:
        logger.error("Failed to load zone file: %s", e)
        return 1

    # Signature validity times
    now = datetime.datetime.utcnow()
    inception = now - datetime.timedelta(hours=1)  # Allow for clock skew
    expiration = now + datetime.timedelta(days=args.validity_days)

    # Sign the zone
    logger.info("Signing zone with validity from %s to %s", inception, expiration)
    sign_zone(
        zone,
        zone_name,
        ksk_private,
        zsk_private,
        ksk_dnskey,
        zsk_dnskey,
        alg_enum,
        inception,
        expiration,
    )

    # Write signed zone
    logger.info("Writing signed zone to %s", args.output)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        zone.to_file(f, relativize=False)

    # Generate and output DS records
    ds_records = generate_ds_records(zone_name, ksk_dnskey)
    if ds_records:
        ds_lines = []
        for ds in ds_records:
            ds_lines.append(f"{zone_name_str} IN DS {ds.to_text()}")

        if args.ds_output:
            with open(args.ds_output, "w", encoding="utf-8") as f:
                f.write("\n".join(ds_lines) + "\n")
            logger.info("DS records written to %s", args.ds_output)
        else:
            print("\n--- DS Records for parent zone ---")
            for line in ds_lines:
                print(line)

    logger.info("Zone signing complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
