"""Unit tests for the secrets plugin family (file backend + router)."""

from __future__ import annotations

from pathlib import Path

import pytest

from foghorn.plugins.resolve.zone_records import update_helpers
from foghorn.plugins.secrets import (
    SecretRecord,
    SecretsRouter,
    discover_secrets_backends,
    get_secrets_backend_class,
    load_secrets_router,
    set_active_secrets_router,
)
from foghorn.plugins.secrets.file import FileSecrets
from foghorn.plugins.secrets.inline import InlineSecrets
from foghorn.plugins.secrets.resolve import (
    materialize_tls_paths,
    resolve_token_value,
)


def test_discover_file_inline_and_mysql_aliases() -> None:
    """Brief: Registry exposes file/inline/mysql aliases.

    Inputs:
      - None.

    Outputs:
      - Asserts known aliases resolve.
    """

    reg = discover_secrets_backends()
    assert "file" in reg
    assert "inline" in reg
    assert "mysql" in reg or "mariadb" in reg
    assert get_secrets_backend_class("file") is FileSecrets
    assert get_secrets_backend_class("inline") is InlineSecrets


def test_file_backend_tsig_token_tls(tmp_path: Path) -> None:
    """Brief: File backend loads tsig/token/tls entries from path fields only.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - Asserts get/list return expected material.
    """

    secret_file = tmp_path / "tsig.secret"
    secret_file.write_text("dGVzdC1zZWNyZXQ=\n", encoding="utf-8")
    token_file = tmp_path / "api.token"
    token_file.write_text("super-token\n", encoding="utf-8")
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("CERT\n", encoding="utf-8")
    key.write_text("KEY\n", encoding="utf-8")

    store = FileSecrets(
        entries=[
            {
                "id": "k1",
                "kind": "tsig",
                "name": "key.example.com.",
                "algorithm": "hmac-sha256",
                "secret_file": str(secret_file),
            },
            {
                "id": "admin-api",
                "kind": "token",
                "value_file": str(token_file),
            },
            {
                "id": "admin-tls",
                "kind": "tls",
                "cert_file": str(cert),
                "key_file": str(key),
            },
        ]
    )
    assert store.validate_connection() is True
    tsig = store.get("k1")
    assert tsig is not None
    assert tsig.secret == "dGVzdC1zZWNyZXQ="
    assert tsig.as_tsig_key_dict()["name"] == "key.example.com."
    tok = store.get("admin-api")
    assert tok is not None and tok.token == "super-token"
    tls = store.get("admin-tls")
    assert tls is not None and tls.cert_pem == b"CERT\n" and tls.key_pem == b"KEY\n"
    assert len(store.list(kind="tsig")) == 1

    with pytest.raises(ValueError, match="inline fields"):
        FileSecrets(entries=[{"id": "bad", "kind": "token", "token": "nope"}])


def test_inline_backend_tsig_token_tls() -> None:
    """Brief: Inline backend loads embedded PEMs/tokens/secrets only.

    Inputs:
      - None.

    Outputs:
      - Asserts get returns inline material and rejects path fields.
    """

    store = InlineSecrets(
        entries=[
            {
                "id": "k1",
                "kind": "tsig",
                "name": "key.example.com.",
                "algorithm": "hmac-sha256",
                "secret": "dGVzdC1zZWNyZXQ=",
            },
            {"id": "admin-api", "kind": "token", "token": "super-token"},
            {
                "id": "admin-tls",
                "kind": "tls",
                "cert_pem": "CERT\n",
                "key_pem": "KEY\n",
            },
        ]
    )
    assert store.validate_connection() is True
    tsig = store.get("k1")
    assert tsig is not None and tsig.secret == "dGVzdC1zZWNyZXQ="
    tok = store.get("admin-api")
    assert tok is not None and tok.token == "super-token"
    tls = store.get("admin-tls")
    assert tls is not None and tls.cert_pem == b"CERT\n" and tls.key_pem == b"KEY\n"

    with pytest.raises(ValueError, match="file fields"):
        InlineSecrets(
            entries=[
                {
                    "id": "bad",
                    "kind": "token",
                    "value_file": "/tmp/nope",
                }
            ]
        )


def test_router_requires_backend_and_key(tmp_path: Path) -> None:
    """Brief: Consumer refs require backend/id plus lookup key.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - Asserts preferred {id,key} shape and rejects bare strings.
    """

    a = InlineSecrets(
        entries=[
            {"id": "shared", "kind": "token", "token": "from-a"},
            {"id": "server1-tls-cert-secret", "kind": "tls", "cert_pem": "CERT"},
            {"id": "server1-tls-secret", "kind": "tls", "key_pem": "KEY"},
        ]
    )
    b = InlineSecrets(
        entries=[
            {"id": "shared", "kind": "token", "token": "from-b"},
            {"id": "only-b", "kind": "token", "token": "unique"},
        ]
    )
    router = SecretsRouter()
    router.add_backend("admin-tls", a)
    router.add_backend("b", b)

    cert = router.resolve_ref(
        {"id": "admin-tls", "key": "server1-tls-cert-secret"}, require=True
    )
    key = router.resolve_ref(
        {"id": "admin-tls", "key": "server1-tls-secret"}, require=True
    )
    assert cert is not None and cert.cert_pem == b"CERT"
    assert key is not None and key.key_pem == b"KEY"

    rec = router.get("only-b", backend="b", require=True)
    assert rec is not None and rec.token == "unique" and rec.backend_id == "b"

    rec2 = router.resolve_ref({"backend": "admin-tls", "key": "shared"}, require=True)
    assert rec2 is not None and rec2.token == "from-a"

    with pytest.raises(ValueError, match="backend/id and key"):
        router.resolve_ref("shared", require=True)

    with pytest.raises(ValueError, match="missing key"):
        router.resolve_ref({"id": "admin-tls"}, require=True)

    with pytest.raises(ValueError, match="ambiguous"):
        router.get("shared", require=True)


def test_load_secrets_router_from_config(tmp_path: Path) -> None:
    """Brief: load_secrets_router builds backends from config mapping.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - Asserts backend ids and token resolution.
    """

    token_path = tmp_path / "t"
    token_path.write_text("abc123", encoding="utf-8")
    cfg = {
        "backends": [
            {
                "id": "local",
                "module": "file",
                "config": {
                    "entries": [
                        {
                            "id": "admin",
                            "kind": "token",
                            "value_file": str(token_path),
                        }
                    ]
                },
            }
        ]
    }
    router = load_secrets_router(cfg)
    assert router is not None
    assert router.backend_ids == ["local"]
    rec = router.get("admin", backend="local")
    assert rec is not None and rec.token == "abc123"


def test_tsig_key_sources_secrets_loader(tmp_path: Path) -> None:
    """Brief: TSIG key_sources type=secrets pulls from active router.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - Asserts resolve_tsig_key_configs includes store keys.
    """

    store = InlineSecrets(
        entries=[
            {
                "id": "dyn",
                "kind": "tsig",
                "name": "dyn.key.",
                "secret": "c2VjcmV0",
                "algorithm": "hmac-sha256",
            }
        ]
    )
    router = SecretsRouter({"tsig-db": store})
    set_active_secrets_router(router)
    try:
        zone = {
            "tsig": {
                "keys": [],
                "key_sources": [{"type": "secrets", "id": "tsig-db", "key": "dyn"}],
            }
        }
        keys = update_helpers.resolve_tsig_key_configs(zone)
        assert any(
            k.get("name") == "dyn.key." and k.get("secret") == "c2VjcmV0" for k in keys
        )
    finally:
        set_active_secrets_router(None)


def test_token_and_tls_resolve_helpers(tmp_path: Path) -> None:
    """Brief: Consumer helpers resolve token_secret and TLS material.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - Asserts token value and temp PEM path materialization.
    """

    cert = tmp_path / "c.pem"
    key = tmp_path / "k.pem"
    tok_file = tmp_path / "tok.txt"
    cert.write_bytes(b"CERTDATA")
    key.write_bytes(b"KEYDATA")
    tok_file.write_text("tok-value\n", encoding="utf-8")
    store = FileSecrets(
        entries=[
            {
                "id": "tok",
                "kind": "token",
                "value_file": str(tok_file),
            },
            {
                "id": "server1-tls-cert-secret",
                "kind": "tls",
                "cert_file": str(cert),
            },
            {
                "id": "server1-tls-secret",
                "kind": "tls",
                "key_file": str(key),
            },
        ]
    )
    router = SecretsRouter({"admin-tls": store})
    set_active_secrets_router(router)
    try:
        assert (
            resolve_token_value({"token_secret": {"id": "admin-tls", "key": "tok"}})
            == "tok-value"
        )
        cfg = materialize_tls_paths(
            {
                "cert_secret": {
                    "id": "admin-tls",
                    "key": "server1-tls-cert-secret",
                },
                "key_secret": {
                    "id": "admin-tls",
                    "key": "server1-tls-secret",
                },
            }
        )
        assert Path(cfg["cert_file"]).read_bytes() == b"CERTDATA"
        assert Path(cfg["key_file"]).read_bytes() == b"KEYDATA"
    finally:
        set_active_secrets_router(None)


def test_file_dnssec_keys_dir_index(tmp_path: Path) -> None:
    """Brief: keys_dir layout is indexed as dnssec secrets.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - Asserts KSK/ZSK records discovered by zone.
    """

    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    (keys_dir / "domainkey_example_com.ksk.key").write_bytes(b"KSKPEM")
    (keys_dir / "domainkey_example_com.zsk.key").write_bytes(b"ZSKPEM")
    store = FileSecrets(keys_dir=str(keys_dir))
    ksk, zsk = store.get_dnssec_keys_for_zone("example.com.")
    assert ksk is not None and ksk.private_key_pem == b"KSKPEM"
    assert zsk is not None and zsk.private_key_pem == b"ZSKPEM"


def test_secret_record_put_file_backend(tmp_path: Path) -> None:
    """Brief: File backend put stores DNSSEC PEM under keys_dir.

    Inputs:
      - tmp_path: Pytest temp directory.

    Outputs:
      - Asserts put + get round-trip and on-disk file.
    """

    keys_dir = tmp_path / "dnssec"
    store = FileSecrets(keys_dir=str(keys_dir))
    rec = SecretRecord(
        id="example.com-ksk",
        kind="dnssec",
        zone="example.com",
        key_type="ksk",
        algorithm="ECDSAP256SHA256",
        private_key_pem=b"PRIVATE",
    )
    store.put(rec)
    got = store.get("example.com-ksk")
    assert got is not None and got.private_key_pem == b"PRIVATE"
    assert (keys_dir / "domainkey_example_com.ksk.key").read_bytes() == b"PRIVATE"
