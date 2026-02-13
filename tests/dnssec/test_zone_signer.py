"""Tests for foghorn.dnssec.zone_signer.

Brief: Exercise key generation, persistence, and zone signing helpers so that
zone_signer.py is either covered by tests or explicitly excluded.

Inputs:
  - pytest fixtures (tmp_path, monkeypatch).

Outputs:
  - Assertions about returned keys, signed zones, and written files.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Iterator, Tuple

import dns.name
import dns.rdata
import dns.rdataclass
import dns.node
import dns.rdatatype
import dns.zone
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from foghorn.dnssec import zone_signer


def _make_basic_zone(origin: dns.name.Name) -> dns.zone.Zone:
    """Brief: Create a minimal in-memory zone with an A record and placeholder RRSIG.

    Inputs:
      - origin: Zone origin as an absolute dns.name.Name.

    Outputs:
      - dns.zone.Zone: Zone with www A rrset and an (empty) RRSIG rdataset.
    """

    zone = dns.zone.Zone(origin)
    www = dns.name.from_text(f"www.{origin.to_text()}")
    node = zone.find_node(www, create=True)

    a_rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    a_rdataset = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.A, create=True)
    a_rdataset.add(a_rdata, 300)

    # Pre-create an empty RRSIG rdataset so sign_zone() executes its skip branch.
    node.find_rdataset(
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        dns.rdatatype.A,
        create=True,
    )

    return zone


class _ZoneItemsStrWrapper:
    """Brief: Wrap a Zone but yield string owner names from items() for coverage.

    Inputs:
      - zone: Underlying dns.zone.Zone.

    Outputs:
      - Acts like a Zone for the subset of APIs used by zone_signer.sign_zone().
    """

    def __init__(self, zone: dns.zone.Zone):
        self._zone = zone

    @property
    def origin(self) -> dns.name.Name:
        return self._zone.origin

    def find_node(self, name: dns.name.Name, *, create: bool = False):
        return self._zone.find_node(name, create=create)

    def items(self) -> Iterator[Tuple[object, object]]:
        for i, (name, node) in enumerate(self._zone.items()):
            if i == 0:
                yield name.to_text(), node
            else:
                yield name, node


def test_generate_keypair_variants_and_invalid_algorithm() -> None:
    """Brief: generate_keypair supports RSA/ECDSA variants and rejects unknown algs.

    Inputs:
      - None.

    Outputs:
      - Asserts returned key types and ValueError on unsupported algorithm.
    """

    private_rsa, alg_rsa = zone_signer.generate_keypair("RSASHA256", "ksk")
    assert isinstance(private_rsa, rsa.RSAPrivateKey)
    assert alg_rsa == zone_signer.dns.dnssec.Algorithm.RSASHA256

    private_ec, alg_ec = zone_signer.generate_keypair("ECDSAP384SHA384", "zsk")
    assert isinstance(private_ec, ec.EllipticCurvePrivateKey)
    assert alg_ec == zone_signer.dns.dnssec.Algorithm.ECDSAP384SHA384

    with pytest.raises(ValueError):
        zone_signer.generate_keypair("NO_SUCH_ALG", "zsk")


def test_generate_keypair_unsupported_size_and_unknown_family(monkeypatch) -> None:
    """Brief: generate_keypair raises on unsupported ECDSA sizes / families.

    Inputs:
      - monkeypatch: pytest fixture for temporary ALGORITHM_MAP edits.

    Outputs:
      - Asserts ValueError for patched unsupported configuration.
    """

    monkeypatch.setitem(
        zone_signer.ALGORITHM_MAP,
        "ECDSA_BAD_SIZE",
        (zone_signer.dns.dnssec.Algorithm.ECDSAP256SHA256, "ecdsa", 999),
    )
    with pytest.raises(ValueError):
        zone_signer.generate_keypair("ECDSA_BAD_SIZE", "zsk")

    monkeypatch.setitem(
        zone_signer.ALGORITHM_MAP,
        "UNKNOWN_FAMILY",
        (zone_signer.dns.dnssec.Algorithm.ECDSAP256SHA256, "weird", 123),
    )
    with pytest.raises(ValueError):
        zone_signer.generate_keypair("UNKNOWN_FAMILY", "zsk")


def test_save_and_load_key_including_legacy_filename(tmp_path: Path) -> None:
    """Brief: save_key writes a PEM key and load_key reads both new and legacy names.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts keys load via both domainkey_ and legacy K* filename patterns.
    """

    key_dir = tmp_path / "keys"
    private_key, _ = zone_signer.generate_keypair("ECDSAP256SHA256", "ksk")

    zone_name = "example.test."
    saved = zone_signer.save_key(
        private_key,
        key_dir,
        zone_name,
        "ksk",
        "ECDSAP256SHA256",
    )
    assert saved.exists()

    loaded_primary = zone_signer.load_key(key_dir, zone_name, "ksk")
    assert loaded_primary is not None

    # Remove the new-style key and replace it with a legacy filename.
    legacy_path = key_dir / "Kexample_test.ksk.key"
    legacy_path.write_bytes(saved.read_bytes())
    saved.unlink()

    loaded_legacy = zone_signer.load_key(key_dir, zone_name, "ksk")
    assert loaded_legacy is not None


def test_load_key_invalid_pem_returns_none(tmp_path: Path) -> None:
    """Brief: load_key returns None on invalid PEM key material.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts None is returned for invalid PEM bytes.
    """

    key_dir = tmp_path / "keys"
    key_dir.mkdir(parents=True)

    (key_dir / "domainkey_example_test.ksk.key").write_bytes(b"not-a-pem")
    assert zone_signer.load_key(key_dir, "example.test.", "ksk") is None


def test_sign_zone_normalizes_names_and_skips_rrsig(tmp_path: Path) -> None:
    """Brief: sign_zone normalizes origin/owner names and ignores existing RRSIG sets.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that signing produces RRSIG material without raising.
    """

    origin_abs = dns.name.from_text("example.test.")
    zone = _make_basic_zone(origin_abs)

    keys_dir = tmp_path / "keys"
    ksk_private, zsk_private, ksk_dnskey, zsk_dnskey = zone_signer.ensure_zone_keys(
        "example.test.",
        keys_dir,
        algorithm="ECDSAP256SHA256",
        generate_policy="yes",
    )

    inception = datetime.datetime(2026, 1, 1, 0, 0, 0)
    expiration = datetime.datetime(2026, 2, 1, 0, 0, 0)

    wrapped = _ZoneItemsStrWrapper(zone)
    zone_signer.sign_zone(
        wrapped,
        origin_abs,
        ksk_private,
        zsk_private,
        ksk_dnskey,
        zsk_dnskey,
        zone_signer.ALGORITHM_MAP["ECDSAP256SHA256"][0],
        inception,
        expiration,
    )

    www_node = zone.find_node(dns.name.from_text("www.example.test."))
    rrsig_rdataset = www_node.find_rdataset(
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        dns.rdatatype.A,
    )
    assert len(list(rrsig_rdataset)) >= 1


def test_sign_zone_derelativizes_non_absolute_origin(tmp_path: Path) -> None:
    """Brief: sign_zone derelativizes the origin when the zone stores a relative origin.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts signing succeeds and emits at least one RRSIG.
    """

    class _FakeZone:
        """Brief: Minimal zone-like wrapper that allows a relative origin name.

        Inputs:
          - origin: dns.name.Name (may be relative).

        Outputs:
          - Provides find_node() and items() required by zone_signer.sign_zone().
        """

        def __init__(self, origin: dns.name.Name):
            self.origin = origin
            self._nodes: dict[dns.name.Name, dns.node.Node] = {}

        def find_node(
            self, name: dns.name.Name, *, create: bool = False
        ) -> dns.node.Node:
            if not isinstance(name, dns.name.Name):
                name = dns.name.from_text(str(name))
            node = self._nodes.get(name)
            if node is None:
                if not create:
                    raise KeyError("node not found")
                node = dns.node.Node()
                self._nodes[name] = node
            return node

        def items(self) -> Iterator[Tuple[object, object]]:
            for i, (name, node) in enumerate(self._nodes.items()):
                if i == 0:
                    yield name.to_text(), node
                else:
                    yield name, node

    origin_rel = dns.name.Name((b"example", b"test"))
    origin_abs = dns.name.from_text("example.test.")

    zone = _FakeZone(origin_rel)
    www = dns.name.from_text("www.example.test.")
    node = zone.find_node(www, create=True)

    a_rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    a_rdataset = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.A, create=True)
    a_rdataset.add(a_rdata, 300)

    keys_dir = tmp_path / "keys"
    ksk_private, zsk_private, ksk_dnskey, zsk_dnskey = zone_signer.ensure_zone_keys(
        "example.test.",
        keys_dir,
        algorithm="ECDSAP256SHA256",
        generate_policy="yes",
    )

    inception = datetime.datetime(2026, 1, 1, 0, 0, 0)
    expiration = datetime.datetime(2026, 2, 1, 0, 0, 0)

    zone_signer.sign_zone(
        zone,
        origin_abs,
        ksk_private,
        zsk_private,
        ksk_dnskey,
        zsk_dnskey,
        zone_signer.ALGORITHM_MAP["ECDSAP256SHA256"][0],
        inception,
        expiration,
    )

    rrsig_rdataset = node.find_rdataset(
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        dns.rdatatype.A,
        create=True,
    )
    assert len(list(rrsig_rdataset)) >= 1


def test_sign_zone_handles_signing_error(monkeypatch) -> None:
    """Brief: sign_zone logs and continues when dnspython signing raises.

    Inputs:
      - monkeypatch: pytest fixture to patch dns.dnssec.sign.

    Outputs:
      - Asserts sign_zone does not raise when signing fails.
    """

    origin = dns.name.from_text("err.test.")
    zone = _make_basic_zone(origin)

    ksk_private, alg = zone_signer.generate_keypair("ECDSAP256SHA256", "ksk")
    zsk_private, _ = zone_signer.generate_keypair("ECDSAP256SHA256", "zsk")
    ksk_dnskey = zone_signer.make_dnskey_rdata(ksk_private, alg, flags=257)
    zsk_dnskey = zone_signer.make_dnskey_rdata(zsk_private, alg, flags=256)

    def _boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(zone_signer.dns.dnssec, "sign", _boom)

    now = datetime.datetime(2026, 1, 1, 0, 0, 0)
    zone_signer.sign_zone(
        zone,
        origin,
        ksk_private,
        zsk_private,
        ksk_dnskey,
        zsk_dnskey,
        alg,
        now,
        now + datetime.timedelta(days=1),
    )


def test_generate_ds_records_success_and_error(monkeypatch) -> None:
    """Brief: generate_ds_records returns DS records and tolerates make_ds failures.

    Inputs:
      - monkeypatch: pytest fixture to patch dns.dnssec.make_ds.

    Outputs:
      - Asserts DS list length on success and empty list when make_ds raises.
    """

    origin = dns.name.from_text("ds.test.")
    private_key, alg = zone_signer.generate_keypair("ECDSAP256SHA256", "ksk")
    ksk_dnskey = zone_signer.make_dnskey_rdata(private_key, alg, flags=257)

    ds_records = zone_signer.generate_ds_records(origin, ksk_dnskey)
    assert len(ds_records) == 2

    def _always_fail(*args, **kwargs):
        raise ValueError("nope")

    monkeypatch.setattr(zone_signer.dns.dnssec, "make_ds", _always_fail)
    ds_records_failed = zone_signer.generate_ds_records(origin, ksk_dnskey)
    assert ds_records_failed == []


def test_ensure_zone_keys_policy_no_raises_and_policy_maybe_loads_existing(
    tmp_path: Path, monkeypatch
) -> None:
    """Brief: ensure_zone_keys enforces policy=no and loads existing keys for maybe.

    Inputs:
      - tmp_path: pytest temporary directory.
      - monkeypatch: pytest fixture for patching generate_keypair.

    Outputs:
      - Asserts RuntimeError for policy=no without keys and that policy=maybe
        loads existing keys without re-generation.
    """

    keys_dir = tmp_path / "keys"

    with pytest.raises(RuntimeError):
        zone_signer.ensure_zone_keys(
            "policy.test.",
            keys_dir,
            algorithm="ECDSAP256SHA256",
            generate_policy="no",
        )

    zone_signer.ensure_zone_keys(
        "policy.test.",
        keys_dir,
        algorithm="ECDSAP256SHA256",
        generate_policy="yes",
    )

    def _should_not_be_called(*args, **kwargs):
        raise AssertionError("generate_keypair should not be called when keys exist")

    monkeypatch.setattr(zone_signer, "generate_keypair", _should_not_be_called)

    zone_signer.ensure_zone_keys(
        "policy.test.",
        keys_dir,
        algorithm="ECDSAP256SHA256",
        generate_policy="maybe",
    )


def test_sign_zone_object_signs_and_returns_zone(tmp_path: Path) -> None:
    """Brief: sign_zone_object signs an in-memory zone and returns it.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts RRSIG data exists after signing and the same Zone is returned.
    """

    origin = dns.name.from_text("object.test.")
    zone = _make_basic_zone(origin)

    ksk_private, zsk_private, ksk_dnskey, zsk_dnskey = zone_signer.ensure_zone_keys(
        "object.test.",
        tmp_path / "keys",
        algorithm="ECDSAP256SHA256",
        generate_policy="yes",
    )

    signed = zone_signer.sign_zone_object(
        zone,
        origin,
        ksk_private=ksk_private,
        zsk_private=zsk_private,
        ksk_dnskey=ksk_dnskey,
        zsk_dnskey=zsk_dnskey,
        validity_days=7,
        now=datetime.datetime(2026, 1, 1, 0, 0, 0),
    )
    assert signed is zone

    www_node = zone.find_node(dns.name.from_text("www.object.test."))
    rrsig_rdataset = www_node.find_rdataset(
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        dns.rdatatype.A,
    )
    assert len(list(rrsig_rdataset)) >= 1


def test_sign_zone_file_writes_signed_zone_and_returns_ds(tmp_path: Path) -> None:
    """Brief: sign_zone_file signs a BIND zonefile, writes output, and returns DS.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts output file exists and returned DS lines look correct.
    """

    unsigned = tmp_path / "unsigned.zone"
    unsigned.write_text(
        """\
$ORIGIN file.test.
$TTL 300
@   IN  SOA ns1.file.test. hostmaster.file.test. ( 1 3600 600 604800 300 )
@   IN  NS  ns1.file.test.
www IN  A   192.0.2.2
""",
        encoding="utf-8",
    )

    output = tmp_path / "out" / "signed.zone"

    ds_lines = zone_signer.sign_zone_file(
        "file.test.",
        unsigned,
        output,
        algorithm="ECDSAP256SHA256",
        generate_policy="yes",
        validity_days=7,
    )

    assert output.exists()
    signed_text = output.read_text(encoding="utf-8")
    assert "DNSKEY" in signed_text
    assert "RRSIG" in signed_text

    assert ds_lines
    assert all(" IN DS " in line for line in ds_lines)
