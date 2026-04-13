"""Brief: Tests for foghorn.servers.webserver.logging_utils helper branches.

Inputs:
  - pytest fixtures (monkeypatch, tmp_path, caplog)

Outputs:
  - None (pytest assertions)
"""

from __future__ import annotations

import logging
import os
import ssl
from pathlib import Path
from types import SimpleNamespace

from foghorn.servers.webserver import logging_utils as lu


def test_suppress2xx_filter_keeps_record_when_args_are_empty_sequence() -> None:
    flt = lu._Suppress2xxAccessFilter()
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="%s",
        args=(),
        exc_info=None,
    )
    # Force fallback path where args is a sequence but empty.
    record.args = []
    assert flt.filter(record) is True


def test_install_uvicorn_2xx_suppression_scans_existing_non_target_filters() -> None:
    logger_obj = logging.getLogger("uvicorn.access")
    original_filters = list(logger_obj.filters)
    try:
        logger_obj.filters = [logging.Filter("a"), logging.Filter("b")]
        lu.install_uvicorn_2xx_suppression()
        assert any(
            isinstance(f, lu._Suppress2xxAccessFilter) for f in logger_obj.filters
        )
    finally:
        logger_obj.filters = original_filters


def test_infer_ssl_error_hints_file_missing_with_configured_paths() -> None:
    error = FileNotFoundError("No such file or directory")
    hints = lu._infer_ssl_error_hints(
        error,
        cert_file="cert.pem",
        key_file="key.pem",
        ca_file="ca.pem",
    )
    assert any("check paths: cert.pem, key.pem, ca.pem" in hint for hint in hints)


def test_infer_ssl_error_hints_file_missing_without_paths_and_pem_hint() -> None:
    error = RuntimeError("file not found: unable to load certificate PEM")
    hints = lu._infer_ssl_error_hints(error)
    assert "certificate/key/CA file not found" in hints
    assert "certificate or key is not valid PEM/ASN.1 data" in hints


def test_infer_ssl_error_hints_cert_verification_and_protocol() -> None:
    error = ssl.SSLCertVerificationError(
        "certificate verify failed: hostname mismatch; self signed; expired; unsupported protocol"
    )
    hints = lu._infer_ssl_error_hints(error, server_hostname="dns.example")
    assert any(
        "certificate name mismatch for hostname 'dns.example'" in hint for hint in hints
    )
    assert any("certificate chain is not trusted" in hint for hint in hints)
    assert any("validity period is not currently valid" in hint for hint in hints)
    assert any(
        "TLS protocol/cipher mismatch during handshake" in hint for hint in hints
    )


def test_infer_ssl_error_hints_cert_verification_without_hostname_branch() -> None:
    error = ssl.SSLCertVerificationError("certificate verify failed: self signed")
    hints = lu._infer_ssl_error_hints(error)
    assert any("certificate chain is not trusted" in hint for hint in hints)
    assert not any("certificate name mismatch" in hint for hint in hints)


def test_infer_ssl_error_hints_cert_mismatch_without_hostname_and_default() -> None:
    mismatch_error = ssl.SSLCertVerificationError("certificate does not match")
    mismatch_hints = lu._infer_ssl_error_hints(mismatch_error)
    assert any("set server_hostname/SNI correctly" in hint for hint in mismatch_hints)

    generic_error = RuntimeError("totally unrelated")
    generic_hints = lu._infer_ssl_error_hints(generic_error)
    assert generic_hints == [
        "verify certificate/key/CA files, server hostname (SNI), and trust chain"
    ]


def test_format_subject_handles_invalid_and_valid_shapes() -> None:
    assert lu._format_subject(None) is None
    assert lu._format_subject(["bad", ("not", "rdn-shape")]) is None

    subject = (
        (("CN", "example.com"), ("O", "Acme")),
        ("skip-this-rdn",),
        (("OU", "DNS"),),
    )
    assert lu._format_subject(subject) == "CN=example.com, O=Acme, OU=DNS"


def test_decode_cert_subject_from_file_handles_decoder_variants(
    monkeypatch,
    tmp_path: Path,
) -> None:
    cert_path = tmp_path / "cert.pem"
    cert_path.write_text("dummy", encoding="utf-8")

    monkeypatch.setattr(
        lu.ssl, "_ssl", SimpleNamespace(_test_decode_cert=123), raising=False
    )
    assert lu._decode_cert_subject_from_file(str(cert_path)) is None

    monkeypatch.setattr(
        lu.ssl,
        "_ssl",
        SimpleNamespace(_test_decode_cert=lambda _p: ["not-a-dict"]),
        raising=False,
    )
    assert lu._decode_cert_subject_from_file(str(cert_path)) is None

    monkeypatch.setattr(
        lu.ssl,
        "_ssl",
        SimpleNamespace(
            _test_decode_cert=lambda _p: {"subject": ((("CN", "example.com"),),)}
        ),
        raising=False,
    )
    assert lu._decode_cert_subject_from_file(str(cert_path)) == "CN=example.com"

    def _raise_decode(_path: str):
        raise ValueError("decode failure")

    monkeypatch.setattr(
        lu.ssl,
        "_ssl",
        SimpleNamespace(_test_decode_cert=_raise_decode),
        raising=False,
    )
    assert lu._decode_cert_subject_from_file(str(cert_path)) is None


def test_decode_cert_subject_from_der_returns_none_when_conversion_fails(
    monkeypatch,
) -> None:
    def _raise_der_decode(_der: bytes) -> str:
        raise ValueError("bad der")

    monkeypatch.setattr(lu.ssl, "DER_cert_to_PEM_cert", _raise_der_decode)
    assert lu._decode_cert_subject_from_der(b"\x00\x01") is None


def test_decode_cert_subject_from_der_cleans_up_on_success_and_remove_oserror(
    monkeypatch,
) -> None:
    monkeypatch.setattr(lu.ssl, "DER_cert_to_PEM_cert", lambda _der: "PEM DATA")
    monkeypatch.setattr(
        lu, "_decode_cert_subject_from_file", lambda _path: "CN=from-der"
    )

    original_remove = os.remove
    removed_paths: list[str] = []

    def _remove_then_raise(path: str) -> None:
        removed_paths.append(path)
        original_remove(path)
        raise OSError("cleanup warning")

    monkeypatch.setattr(lu.os, "remove", _remove_then_raise)
    assert lu._decode_cert_subject_from_der(b"\x30\x82") == "CN=from-der"
    assert removed_paths
    assert not Path(removed_paths[0]).exists()


def test_decode_cert_subject_from_der_cleans_up_on_decode_exception(
    monkeypatch,
) -> None:
    monkeypatch.setattr(lu.ssl, "DER_cert_to_PEM_cert", lambda _der: "PEM DATA")

    def _raise_subject_decode(_path: str) -> str:
        raise RuntimeError("decode subject failed")

    monkeypatch.setattr(lu, "_decode_cert_subject_from_file", _raise_subject_decode)
    removed_paths: list[str] = []

    original_remove = os.remove

    def _record_remove(path: str) -> None:
        removed_paths.append(path)
        original_remove(path)

    monkeypatch.setattr(lu.os, "remove", _record_remove)
    assert lu._decode_cert_subject_from_der(b"\x30\x82") is None
    assert removed_paths


def test_describe_cert_file_variants(monkeypatch, tmp_path: Path) -> None:
    assert lu._describe_cert_file(None) == "not configured"

    missing = tmp_path / "missing-cert.pem"
    assert "missing" in lu._describe_cert_file(str(missing))

    as_dir = tmp_path / "cert-dir"
    as_dir.mkdir()
    assert "not a regular file" in lu._describe_cert_file(str(as_dir))

    cert_file = tmp_path / "cert.pem"
    cert_file.write_text("data", encoding="utf-8")

    monkeypatch.setattr(lu, "_decode_cert_subject_from_file", lambda _path: "CN=cert")
    assert "Subject: CN=cert" in lu._describe_cert_file(str(cert_file))

    monkeypatch.setattr(lu, "_decode_cert_subject_from_file", lambda _path: None)
    assert "Subject: unavailable" in lu._describe_cert_file(str(cert_file))


def test_describe_key_file_variants(tmp_path: Path) -> None:
    assert lu._describe_key_file(None) == "not configured"

    missing = tmp_path / "missing-key.pem"
    assert "missing" in lu._describe_key_file(str(missing))

    as_dir = tmp_path / "key-dir"
    as_dir.mkdir()
    assert "not a regular file" in lu._describe_key_file(str(as_dir))

    key_file = tmp_path / "key.pem"
    key_file.write_text("data", encoding="utf-8")
    assert lu._describe_key_file(str(key_file)) == f"path={str(key_file)!r}"


def test_describe_ca_source_variants() -> None:
    assert lu._describe_ca_source(verify=False, ca_file=None) == (
        "verification disabled (verify=False)"
    )
    assert lu._describe_ca_source(verify=True, ca_file="/tmp/ca.pem") == (
        "file (/tmp/ca.pem)"
    )
    assert lu._describe_ca_source(verify=True, ca_file=None) == "system trust store"


def test_log_ssl_error_warning_includes_context_and_remote_subject(
    monkeypatch, caplog
) -> None:
    monkeypatch.setattr(lu, "_infer_ssl_error_hints", lambda *_a, **_kw: ["h1", "h2"])
    monkeypatch.setattr(lu, "_describe_cert_file", lambda _p: "cert-desc")
    monkeypatch.setattr(lu, "_describe_key_file", lambda _p: "key-desc")
    monkeypatch.setattr(lu, "_describe_ca_source", lambda **_kw: "ca-desc")

    logger = logging.getLogger("foghorn.tests.logging_utils")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        lu.log_ssl_error_warning(
            logger,
            RuntimeError("boom"),
            context="DoT handshake",
            remote_subject="CN=remote",
            cert_file="/tmp/cert.pem",
            key_file="/tmp/key.pem",
            ca_file="/tmp/ca.pem",
        )

    assert len(caplog.records) == 1
    msg = caplog.records[0].getMessage()
    assert "DoT handshake: SSL/TLS error (boom)." in msg
    assert "Remote cert Subject: CN=remote." in msg
    assert "Local cert: cert-desc. Local key: key-desc. CA source: ca-desc." in msg
    assert "Likely causes: h1; h2" in msg


def test_log_ssl_error_warning_uses_unavailable_remote_subject(
    monkeypatch, caplog
) -> None:
    monkeypatch.setattr(lu, "_infer_ssl_error_hints", lambda *_a, **_kw: ["fallback"])
    monkeypatch.setattr(lu, "_describe_cert_file", lambda _p: "cert")
    monkeypatch.setattr(lu, "_describe_key_file", lambda _p: "key")
    monkeypatch.setattr(lu, "_describe_ca_source", lambda **_kw: "system trust store")

    logger = logging.getLogger("foghorn.tests.logging_utils.unavailable")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        lu.log_ssl_error_warning(
            logger,
            RuntimeError("boom"),
            context="TLS probe",
        )

    assert len(caplog.records) == 1
    assert "Remote cert Subject: unavailable." in caplog.records[0].getMessage()
