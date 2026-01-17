from __future__ import annotations

"""DNSSEC zone signing helpers shared by scripts and plugins.

Brief: Provide reusable helpers to generate DNSSEC keys and sign zones
using dnspython + cryptography, for use by the generate_zone_dnssec
script and by the ZoneRecords plugin for optional auto-signing.

Inputs:
  - Algorithm name (e.g. "ECDSAP256SHA256").
  - Zone apex name.
  - Unsigned dns.zone.Zone or BIND-style zone file path.
  - Key directory and key-generation policy.

Outputs:
  - Private key objects and DNSKEY rdata.
  - Mutated dns.zone.Zone instances containing DNSKEY/RRSIG.
  - Optional DS record presentation strings.
"""

import datetime
import json
import logging
from pathlib import Path
from typing import Optional, Tuple, List

import dns.dnssec
import dns.name
import dns.node
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.zone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

logger = logging.getLogger(__name__)


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


def _sanitize_zone_name(zone_name: str) -> str:
    zone_str = str(zone_name).rstrip(".")
    return zone_str.replace(".", "_")


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
    sanitized_zone = _sanitize_zone_name(zone_name)
    key_path = key_dir / f"K{sanitized_zone}.{key_type}.key"
    meta_path = key_dir / f"K{sanitized_zone}.{key_type}.meta.json"

    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    key_path.write_bytes(pem_bytes)

    meta = {
        "zone": zone_name,
        "key_type": key_type,
        "algorithm": algorithm,
        "created": datetime.datetime.utcnow().isoformat(),
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

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

    sanitized_zone = _sanitize_zone_name(zone_name)
    key_path = key_dir / f"K{sanitized_zone}.{key_type}.key"
    if not key_path.exists():
        return None

    pem_bytes = key_path.read_bytes()
    try:
        private_key = serialization.load_pem_private_key(pem_bytes, password=None)
        logger.info("Loaded existing %s key from %s", key_type.upper(), key_path)
        return private_key
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to load key from %s: %s", key_path, exc)
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

    apex_node = zone.find_node(zone_name, create=True)
    dnskey_rrset = dns.rrset.RRset(zone_name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    dnskey_rrset.add(ksk_dnskey)
    dnskey_rrset.add(zsk_dnskey)
    apex_node.replace_rdataset(dnskey_rrset)

    for name, node in zone.items():
        for rdataset in node:
            if rdataset.rdtype == dns.rdatatype.RRSIG:
                continue

            rrset = dns.rrset.from_rdata_list(name, rdataset.ttl, list(rdataset))

            if rdataset.rdtype == dns.rdatatype.DNSKEY:
                signing_key = ksk_private
                dnskey_rdata = ksk_dnskey
            else:
                signing_key = zsk_private
                dnskey_rdata = zsk_dnskey

            try:
                rrsig = dns.dnssec.sign(
                    rrset,
                    signing_key,
                    signer=zone_name,
                    dnskey=dnskey_rdata,
                    inception=inception,
                    expiration=expiration,
                )
                rrsig_rdataset = node.find_rdataset(
                    dns.rdataclass.IN,
                    dns.rdatatype.RRSIG,
                    rdataset.rdtype,
                    create=True,
                )
                rrsig_rdataset.add(rrsig)
                rrsig_rdataset.update_ttl(rdataset.ttl)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "Failed to sign %s %s: %s",
                    name,
                    dns.rdatatype.to_text(rdataset.rdtype),
                    exc,
                )


def generate_ds_records(
    zone_name: dns.name.Name, ksk_dnskey: dns.rdata.Rdata
) -> List[dns.rdata.Rdata]:
    """Brief: Generate DS records for the KSK.

    Inputs:
      - zone_name: Zone apex.
      - ksk_dnskey: KSK DNSKEY rdata.

    Outputs:
      - List of DS rdata objects (SHA-256 and SHA-384 digests).
    """

    ds_records: List[dns.rdata.Rdata] = []
    for digest_type in (dns.dnssec.DSDigest.SHA256, dns.dnssec.DSDigest.SHA384):
        try:
            ds = dns.dnssec.make_ds(zone_name, ksk_dnskey, digest_type)
            ds_records.append(ds)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to generate DS with digest %s: %s", digest_type, exc)
    return ds_records


def ensure_zone_keys(
    zone_name: str,
    keys_dir: Path,
    *,
    algorithm: str,
    generate_policy: str,
) -> Tuple[object, object, dns.rdata.Rdata, dns.rdata.Rdata]:
    """Brief: Ensure KSK/ZSK and DNSKEY rdata for a zone under a policy.

    Inputs:
      - zone_name: Zone apex text (may or may not include trailing dot).
      - keys_dir: Directory for key files.
      - algorithm: Algorithm name for ALGORITHM_MAP.
      - generate_policy: 'yes', 'no', or 'maybe'.

    Outputs:
      - (ksk_private, zsk_private, ksk_dnskey, zsk_dnskey).
    """

    zone_name_str = zone_name if zone_name.endswith(".") else zone_name + "."
    alg_enum = ALGORITHM_MAP[algorithm][0]

    keys_dir = keys_dir.resolve()
    keys_dir.mkdir(parents=True, exist_ok=True)

    ksk_private = None
    zsk_private = None

    if generate_policy in {"no", "maybe"}:
        ksk_private = load_key(keys_dir, zone_name_str, "ksk")
        zsk_private = load_key(keys_dir, zone_name_str, "zsk")

    if generate_policy == "no":
        if ksk_private is None or zsk_private is None:
            raise RuntimeError(
                f"DNSSEC keys for {zone_name_str} not found in {keys_dir} and generate_policy=no"
            )
    else:
        if ksk_private is None:
            logger.info("Generating new KSK with algorithm %s", algorithm)
            ksk_private, _ = generate_keypair(algorithm, "ksk")
            save_key(ksk_private, keys_dir, zone_name_str, "ksk", algorithm)
        if zsk_private is None:
            logger.info("Generating new ZSK with algorithm %s", algorithm)
            zsk_private, _ = generate_keypair(algorithm, "zsk")
            save_key(zsk_private, keys_dir, zone_name_str, "zsk", algorithm)

    ksk_dnskey = make_dnskey_rdata(ksk_private, alg_enum, flags=257)
    zsk_dnskey = make_dnskey_rdata(zsk_private, alg_enum, flags=256)

    logger.info("KSK key tag: %d", dns.dnssec.key_id(ksk_dnskey))
    logger.info("ZSK key tag: %d", dns.dnssec.key_id(zsk_dnskey))

    return ksk_private, zsk_private, ksk_dnskey, zsk_dnskey


def sign_zone_object(
    zone: dns.zone.Zone,
    zone_name: dns.name.Name,
    *,
    ksk_private: object,
    zsk_private: object,
    ksk_dnskey: dns.rdata.Rdata,
    zsk_dnskey: dns.rdata.Rdata,
    validity_days: int = 30,
    now: Optional[datetime.datetime] = None,
) -> dns.zone.Zone:
    """Brief: Sign an in-memory zone object and return it.

    Inputs:
      - zone: Unsigned dns.zone.Zone instance.
      - zone_name: Zone apex name.
      - ksk_private/zsk_private: Private keys.
      - ksk_dnskey/zsk_dnskey: DNSKEY rdata.
      - validity_days: Signature validity window.
      - now: Optional current time override.

    Outputs:
      - The same dns.zone.Zone instance, signed in-place.
    """

    now = now or datetime.datetime.utcnow()
    inception = now - datetime.timedelta(hours=1)
    expiration = now + datetime.timedelta(days=int(validity_days))

    alg_enum = ALGORITHM_MAP[next(k for k, v in ALGORITHM_MAP.items() if v[0] == ksk_dnskey.algorithm)][0]  # type: ignore[attr-defined]

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
    return zone


def sign_zone_file(
    zone_name: str,
    input_path: Path,
    output_path: Path,
    *,
    keys_dir: Optional[Path] = None,
    algorithm: str = "ECDSAP256SHA256",
    generate_policy: str = "maybe",
    validity_days: int = 30,
) -> List[str]:
    """Brief: Load, sign, and write a BIND-style zone file.

    Inputs:
      - zone_name: Zone apex text.
      - input_path: Path to unsigned BIND-style zone file.
      - output_path: Path to write signed zone file.
      - keys_dir: Optional key directory (defaults to output parent).
      - algorithm: DNSSEC algorithm name.
      - generate_policy: 'yes', 'no', 'maybe' for key creation.
      - validity_days: Signature validity period in days.

    Outputs:
      - List of DS record presentation strings.
    """

    zone_name_str = zone_name if zone_name.endswith(".") else zone_name + "."
    origin = dns.name.from_text(zone_name_str)

    keys_dir = keys_dir or output_path.parent

    zone = dns.zone.from_file(str(input_path), origin=origin, relativize=False)

    ksk_private, zsk_private, ksk_dnskey, zsk_dnskey = ensure_zone_keys(
        zone_name_str,
        keys_dir,
        algorithm=algorithm,
        generate_policy=generate_policy,
    )

    now = datetime.datetime.utcnow()
    inception = now - datetime.timedelta(hours=1)
    expiration = now + datetime.timedelta(days=int(validity_days))
    alg_enum = ALGORITHM_MAP[algorithm][0]

    sign_zone(
        zone,
        origin,
        ksk_private,
        zsk_private,
        ksk_dnskey,
        zsk_dnskey,
        alg_enum,
        inception,
        expiration,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        zone.to_file(f, relativize=False)

    ds_records = generate_ds_records(origin, ksk_dnskey)
    ds_lines = [f"{zone_name_str} IN DS {ds.to_text()}" for ds in ds_records]
    return ds_lines
