import dns.exception
import dns.message
import dns.tsig
import dns.tsigkeyring
import dns.update

from foghorn.plugins.resolve.zone_records import update_processor


def _make_update_with_tsig(
    *,
    zone: str,
    key_name: str,
    key_secret_b64: str,
    algorithm: str = "hmac-sha256",
    fudge: int | None = None,
) -> bytes:
    """Brief: Build a minimal RFC 2136 UPDATE message with TSIG.

    Inputs:
      - zone: Zone apex.
      - key_name: TSIG key name.
      - key_secret_b64: Base64 TSIG secret.
      - algorithm: TSIG algorithm name.
      - fudge: Optional TSIG fudge value.

    Outputs:
      - Wire-format DNS UPDATE message bytes.
    """
    keyring = dns.tsigkeyring.from_text({key_name: key_secret_b64})
    msg = dns.update.Update(zone)
    if fudge is None:
        msg.use_tsig(keyring=keyring, keyname=key_name, algorithm=algorithm)
    else:
        msg.use_tsig(
            keyring=keyring, keyname=key_name, algorithm=algorithm, fudge=fudge
        )
    msg.add("host", 60, "A", "192.0.2.123")
    return msg.to_wire()


def test_verify_tsig_auth_accepts_valid_tsig() -> None:
    """Brief: verify_tsig_auth accepts a valid TSIG-signed message.

    Inputs:
      - None.

    Outputs:
      - Asserts that TSIG verification succeeds and returns matching key config.
    """
    wire = _make_update_with_tsig(
        zone="example.com.",
        key_name="key.example.com.",
        key_secret_b64="dGVzdHNlY3JldA==",
        algorithm="hmac-sha256",
    )

    ok, err, cfg = update_processor.verify_tsig_auth(
        wire,
        key_configs=[
            {
                "name": "key.example.com.",
                "algorithm": "hmac-sha256",
                "secret": "dGVzdHNlY3JldA==",
            }
        ],
    )

    assert ok is True
    assert err is None
    assert cfg is not None
    assert cfg["name"] == "key.example.com."


def test_verify_tsig_auth_rejects_unknown_key() -> None:
    """Brief: verify_tsig_auth rejects TSIG messages signed with an unknown key.

    Inputs:
      - None.

    Outputs:
      - Asserts that verification fails with an unknown key error.
    """
    wire = _make_update_with_tsig(
        zone="example.com.",
        key_name="unknown.example.com.",
        key_secret_b64="dGVzdHNlY3JldA==",
        algorithm="hmac-sha256",
    )

    ok, err, cfg = update_processor.verify_tsig_auth(
        wire,
        key_configs=[
            {
                "name": "key.example.com.",
                "algorithm": "hmac-sha256",
                "secret": "dGVzdHNlY3JldA==",
            }
        ],
    )

    assert ok is False
    assert cfg is None
    assert err is not None
    assert "unknown" in err.lower() and "key" in err.lower()


def test_verify_tsig_auth_rejects_bad_signature() -> None:
    """Brief: verify_tsig_auth rejects TSIG messages with bad signatures.

    Inputs:
      - None.

    Outputs:
      - Asserts that verification fails when the configured secret differs.
    """
    wire = _make_update_with_tsig(
        zone="example.com.",
        key_name="key.example.com.",
        key_secret_b64="dGVzdHNlY3JldA==",
        algorithm="hmac-sha256",
    )

    ok, err, cfg = update_processor.verify_tsig_auth(
        wire,
        key_configs=[
            {
                "name": "key.example.com.",
                "algorithm": "hmac-sha256",
                "secret": "b3RoZXJzZWNyZXQ=",
            }
        ],
    )

    assert ok is False
    assert cfg is None
    assert err is not None
    assert "signature" in err.lower()


def test_verify_tsig_auth_rejects_algorithm_mismatch() -> None:
    """Brief: verify_tsig_auth rejects when message algorithm differs from config.

    Inputs:
      - None.

    Outputs:
      - Asserts that verification fails with an algorithm mismatch.
    """
    wire = _make_update_with_tsig(
        zone="example.com.",
        key_name="key.example.com.",
        key_secret_b64="dGVzdHNlY3JldA==",
        algorithm="hmac-sha256",
    )

    ok, err, cfg = update_processor.verify_tsig_auth(
        wire,
        key_configs=[
            {
                "name": "key.example.com.",
                "algorithm": "hmac-sha512",
                "secret": "dGVzdHNlY3JldA==",
            }
        ],
    )

    assert ok is False
    assert cfg is None
    assert err is not None
    assert "algorithm mismatch" in err.lower()


def test_verify_tsig_auth_rejects_when_no_keys_configured() -> None:
    wire = _make_update_with_tsig(
        zone="example.com.",
        key_name="key.example.com.",
        key_secret_b64="dGVzdHNlY3JldA==",
        algorithm="hmac-sha256",
    )

    ok, err, cfg = update_processor.verify_tsig_auth(wire, key_configs=[])

    assert ok is False
    assert cfg is None
    assert err is not None
    assert "no tsig keys configured" in err.lower()


def test_verify_tsig_auth_rejects_when_no_usable_keys_configured() -> None:
    wire = _make_update_with_tsig(
        zone="example.com.",
        key_name="key.example.com.",
        key_secret_b64="dGVzdHNlY3JldA==",
        algorithm="hmac-sha256",
    )

    ok, err, cfg = update_processor.verify_tsig_auth(
        wire,
        key_configs=[
            {"name": None, "secret": None},
            "not-a-dict",
        ],
    )

    assert ok is False
    assert cfg is None
    assert err is not None
    assert "no usable tsig keys configured" in err.lower()


def test_verify_tsig_auth_rejects_when_no_tsig_present() -> None:
    msg = dns.update.Update("example.com.")
    msg.add("host", 60, "A", "192.0.2.123")
    wire = msg.to_wire()

    ok, err, cfg = update_processor.verify_tsig_auth(
        wire,
        key_configs=[
            {
                "name": "key.example.com.",
                "algorithm": "hmac-sha256",
                "secret": "dGVzdHNlY3JldA==",
            }
        ],
    )

    assert ok is False
    assert cfg is None
    assert err is not None
    assert "no tsig present" in err.lower()


def test_verify_tsig_auth_rejects_when_fudge_too_large() -> None:
    wire = _make_update_with_tsig(
        zone="example.com.",
        key_name="key.example.com.",
        key_secret_b64="dGVzdHNlY3JldA==",
        algorithm="hmac-sha256",
        fudge=update_processor.TSIG_TIMESTAMP_FUDGE + 1,
    )

    ok, err, cfg = update_processor.verify_tsig_auth(
        wire,
        key_configs=[
            {
                "name": "key.example.com.",
                "algorithm": "hmac-sha256",
                "secret": "dGVzdHNlY3JldA==",
            }
        ],
    )

    assert ok is False
    assert cfg is None
    assert err is not None
    assert "fudge too large" in err.lower()


def test_verify_tsig_auth_keyring_build_failure(monkeypatch) -> None:
    wire = _make_update_with_tsig(
        zone="example.com.",
        key_name="key.example.com.",
        key_secret_b64="dGVzdHNlY3JldA==",
        algorithm="hmac-sha256",
    )

    monkeypatch.setattr(
        dns.tsigkeyring,
        "from_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    ok, err, cfg = update_processor.verify_tsig_auth(
        wire,
        key_configs=[
            {
                "name": "key.example.com.",
                "algorithm": "hmac-sha256",
                "secret": "dGVzdHNlY3JldA==",
            }
        ],
    )

    assert ok is False
    assert cfg is None
    assert err is not None
    assert "failed to build tsig keyring" in err.lower()


def test_verify_tsig_auth_handles_peer_bad_time(monkeypatch) -> None:
    wire = _make_update_with_tsig(
        zone="example.com.",
        key_name="key.example.com.",
        key_secret_b64="dGVzdHNlY3JldA==",
        algorithm="hmac-sha256",
    )

    def _raise(*_args, **_kwargs):
        raise dns.tsig.PeerBadTime("bad-time")

    monkeypatch.setattr(dns.message, "from_wire", _raise)

    ok, err, cfg = update_processor.verify_tsig_auth(
        wire,
        key_configs=[
            {
                "name": "key.example.com.",
                "algorithm": "hmac-sha256",
                "secret": "dGVzdHNlY3JldA==",
            }
        ],
    )

    assert ok is False
    assert cfg is None
    assert err is not None
    assert "time verification failed" in err.lower()


def test_verify_tsig_auth_handles_generic_dns_exception(monkeypatch) -> None:
    wire = _make_update_with_tsig(
        zone="example.com.",
        key_name="key.example.com.",
        key_secret_b64="dGVzdHNlY3JldA==",
        algorithm="hmac-sha256",
    )

    def _raise(*_args, **_kwargs):
        raise dns.exception.DNSException("dns")

    monkeypatch.setattr(dns.message, "from_wire", _raise)

    ok, err, cfg = update_processor.verify_tsig_auth(
        wire,
        key_configs=[
            {
                "name": "key.example.com.",
                "algorithm": "hmac-sha256",
                "secret": "dGVzdHNlY3JldA==",
            }
        ],
    )

    assert ok is False
    assert cfg is None
    assert err is not None
    assert "tsig verification error" in err.lower()


def test_verify_tsig_auth_fudge_extraction_failure_defaults_to_zero(
    monkeypatch,
) -> None:
    wire = _make_update_with_tsig(
        zone="example.com.",
        key_name="key.example.com.",
        key_secret_b64="dGVzdHNlY3JldA==",
        algorithm="hmac-sha256",
    )

    class _FakeMsg:
        had_tsig = True
        tsig = []
        keyname = "key.example.com."
        keyalgorithm = "hmac-sha256"

    monkeypatch.setattr(dns.message, "from_wire", lambda *_args, **_kwargs: _FakeMsg())

    ok, err, cfg = update_processor.verify_tsig_auth(
        wire,
        key_configs=[
            {
                "name": "key.example.com.",
                "algorithm": "hmac-sha256",
                "secret": "dGVzdHNlY3JldA==",
            }
        ],
    )

    assert ok is True
    assert err is None
    assert cfg is not None
