"""
Brief: Branch-focused unit tests for DoT transport helpers and pooling/query flows.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import os
import socket
import ssl
import time
import types

import pytest

from foghorn.servers.transports import dot


class _ProbeRawSocket:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _ProbeTLSSocket:
    def __init__(self, cert_dict: object, der_cert: bytes | None = None) -> None:
        self._cert_dict = cert_dict
        self._der_cert = der_cert
        self.closed = False

    def getpeercert(self, binary_form: bool = False):
        if binary_form:
            return self._der_cert
        return self._cert_dict

    def close(self) -> None:
        self.closed = True


class _ProbeContext:
    def __init__(self, tls_socket: _ProbeTLSSocket) -> None:
        self._tls_socket = tls_socket
        self.wrap_calls: list[tuple[object, object]] = []

    def wrap_socket(self, raw_sock: object, server_hostname=None):
        self.wrap_calls.append((raw_sock, server_hostname))
        return self._tls_socket


class _ConnRawSocket:
    def __init__(self) -> None:
        self.closed = False
        self.sockopts: list[tuple[int, int, int]] = []

    def setsockopt(self, level: int, name: int, value: int) -> None:
        self.sockopts.append((level, name, value))

    def close(self) -> None:
        self.closed = True


class _ConnTLSSocket:
    def __init__(self) -> None:
        self.closed = False
        self.timeout: float | None = None
        self.payloads: list[bytes] = []

    def settimeout(self, timeout_s: float) -> None:
        self.timeout = timeout_s

    def sendall(self, payload: bytes) -> None:
        self.payloads.append(payload)

    def close(self) -> None:
        self.closed = True


class _ConnContext:
    def __init__(
        self,
        tls_socket: _ConnTLSSocket | None = None,
        wrap_error: BaseException | None = None,
    ) -> None:
        self._tls_socket = tls_socket
        self._wrap_error = wrap_error
        self.wrap_calls: list[tuple[object, object]] = []

    def wrap_socket(self, raw_sock: object, server_hostname=None):
        self.wrap_calls.append((raw_sock, server_hostname))
        if self._wrap_error is not None:
            raise self._wrap_error
        return self._tls_socket


class _PoolConn:
    def __init__(
        self,
        *,
        response: bytes = b"OK",
        should_raise: bool = False,
        last_used: float | None = None,
    ) -> None:
        self.response = response
        self.should_raise = should_raise
        self.closed = False
        self._tls = object()
        self._last_used = time.time() if last_used is None else float(last_used)
        self.connect_calls: list[int] = []
        self.send_calls: list[tuple[bytes, int]] = []

    def connect(self, connect_timeout_ms: int) -> None:
        self.connect_calls.append(int(connect_timeout_ms))

    def send(self, query: bytes, read_timeout_ms: int) -> bytes:
        self.send_calls.append((query, int(read_timeout_ms)))
        if self.should_raise:
            raise RuntimeError("send failed")
        return self.response

    def close(self) -> None:
        self.closed = True
        self._tls = None


class _QueryRawSocket:
    def __init__(self) -> None:
        self.closed = False
        self.sockopts: list[tuple[int, int, int]] = []

    def setsockopt(self, level: int, name: int, value: int) -> None:
        self.sockopts.append((level, name, value))

    def close(self) -> None:
        self.closed = True


class _QueryTLSSocket:
    def __init__(self) -> None:
        self.closed = False
        self.timeout_s: float | None = None
        self.payloads: list[bytes] = []

    def settimeout(self, timeout_s: float) -> None:
        self.timeout_s = timeout_s

    def sendall(self, payload: bytes) -> None:
        self.payloads.append(payload)

    def close(self) -> None:
        self.closed = True


class _QueryContext:
    def __init__(
        self,
        tls_socket: _QueryTLSSocket | None = None,
        wrap_error: BaseException | None = None,
    ) -> None:
        self._tls_socket = tls_socket
        self._wrap_error = wrap_error
        self.server_hostnames: list[object] = []

    def wrap_socket(self, raw_sock: object, server_hostname=None):
        self.server_hostnames.append(server_hostname)
        if self._wrap_error is not None:
            raise self._wrap_error
        return self._tls_socket


class _RecvSocket:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.timeout_s: float | None = None

    def settimeout(self, timeout_s: float) -> None:
        self.timeout_s = timeout_s

    def recv(self, n: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class _NoSetAttrError(Exception):
    def __setattr__(self, name: str, value) -> None:
        raise RuntimeError("attribute assignment denied")


class _DummySSLContext:
    def __init__(self) -> None:
        self.minimum_version = None


def _make_pool(
    monkeypatch: pytest.MonkeyPatch,
    *,
    max_connections: int = 2,
    idle_timeout_s: int = 5,
) -> dot.DotConnectionPool:
    monkeypatch.setattr(dot, "_build_ssl_context", lambda *args, **kwargs: object())
    return dot.DotConnectionPool(
        "127.0.0.1",
        853,
        None,
        False,
        None,
        max_connections=max_connections,
        idle_timeout_s=idle_timeout_s,
    )


def test_format_subject_valid_and_invalid_paths():
    subject = [
        [("CN", "dns.example")],
        "skip-this-rdn",
        [("O", "Example Org"), ("", "ignored-empty-key")],
        [("incomplete-only-one-element",)],
        [("OU", "DNS Team")],
    ]
    assert dot._format_subject(subject) == "CN=dns.example, O=Example Org, OU=DNS Team"
    assert dot._format_subject("invalid-subject") is None
    assert dot._format_subject([["not-a-tuple-attribute"]]) is None


def test_decode_cert_subject_from_file_decoder_variants(monkeypatch):
    monkeypatch.setattr(
        dot.ssl,
        "_ssl",
        types.SimpleNamespace(_test_decode_cert=None),
        raising=False,
    )
    assert dot._decode_cert_subject_from_file("/tmp/cert.pem") is None

    monkeypatch.setattr(
        dot.ssl,
        "_ssl",
        types.SimpleNamespace(_test_decode_cert=lambda _: []),
        raising=False,
    )
    assert dot._decode_cert_subject_from_file("/tmp/cert.pem") is None

    monkeypatch.setattr(
        dot.ssl,
        "_ssl",
        types.SimpleNamespace(
            _test_decode_cert=lambda _: {"subject": [[("CN", "decoded.example")]]}
        ),
        raising=False,
    )
    assert dot._decode_cert_subject_from_file("/tmp/cert.pem") == "CN=decoded.example"

    def _raise_decode_error(_):
        raise RuntimeError("decode failed")

    monkeypatch.setattr(
        dot.ssl,
        "_ssl",
        types.SimpleNamespace(_test_decode_cert=_raise_decode_error),
        raising=False,
    )
    assert dot._decode_cert_subject_from_file("/tmp/cert.pem") is None


def test_decode_cert_subject_from_der_success_removes_temp_file(monkeypatch):
    removed_paths: list[str] = []
    real_remove = os.remove

    def _track_remove(path: str) -> None:
        removed_paths.append(path)
        real_remove(path)

    monkeypatch.setattr(dot.ssl, "DER_cert_to_PEM_cert", lambda _: "PEM DATA")
    monkeypatch.setattr(dot, "_decode_cert_subject_from_file", lambda _: "CN=from-der")
    monkeypatch.setattr(dot.os, "remove", _track_remove)

    assert dot._decode_cert_subject_from_der(b"\x30\x82") == "CN=from-der"
    assert len(removed_paths) == 1
    assert not os.path.exists(removed_paths[0])


def test_decode_cert_subject_from_der_returns_none_on_error(monkeypatch):
    def _raise_der_error(_):
        raise ValueError("invalid DER")

    monkeypatch.setattr(dot.ssl, "DER_cert_to_PEM_cert", _raise_der_error)
    assert dot._decode_cert_subject_from_der(b"bad-der") is None


def test_decode_cert_subject_from_der_ignores_remove_oserror(monkeypatch):
    monkeypatch.setattr(dot.ssl, "DER_cert_to_PEM_cert", lambda _: "PEM DATA")
    monkeypatch.setattr(dot, "_decode_cert_subject_from_file", lambda _: "CN=from-der")
    monkeypatch.setattr(
        dot.os, "remove", lambda _path: (_ for _ in ()).throw(OSError("busy"))
    )

    assert dot._decode_cert_subject_from_der(b"\x30\x82") == "CN=from-der"


def test_probe_remote_cert_subject_prefers_cert_subject(monkeypatch):
    raw_sock = _ProbeRawSocket()
    tls_sock = _ProbeTLSSocket({"subject": [[("CN", "remote.example")]]})
    ctx = _ProbeContext(tls_sock)
    monkeypatch.setattr(
        dot.socket, "create_connection", lambda *_args, **_kwargs: raw_sock
    )
    monkeypatch.setattr(dot.ssl, "_create_unverified_context", lambda: ctx)

    subject = dot._probe_remote_cert_subject(
        "127.0.0.1",
        853,
        server_hostname="remote.example",
    )

    assert subject == "CN=remote.example"
    assert ctx.wrap_calls == [(raw_sock, "remote.example")]
    assert tls_sock.closed is True
    assert raw_sock.closed is True


def test_probe_remote_cert_subject_falls_back_to_der(monkeypatch):
    raw_sock = _ProbeRawSocket()
    tls_sock = _ProbeTLSSocket({}, der_cert=b"\x30\x82der")
    ctx = _ProbeContext(tls_sock)
    monkeypatch.setattr(
        dot.socket, "create_connection", lambda *_args, **_kwargs: raw_sock
    )
    monkeypatch.setattr(dot.ssl, "_create_unverified_context", lambda: ctx)
    monkeypatch.setattr(
        dot, "_decode_cert_subject_from_der", lambda _der: "CN=from-der"
    )

    subject = dot._probe_remote_cert_subject("127.0.0.1", 853)

    assert subject == "CN=from-der"
    assert tls_sock.closed is True
    assert raw_sock.closed is True


def test_probe_remote_cert_subject_returns_none_on_network_error(monkeypatch):
    monkeypatch.setattr(
        dot.socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unreachable")),
    )
    assert dot._probe_remote_cert_subject("127.0.0.1", 853) is None


def test_probe_remote_cert_subject_returns_none_when_no_subject_or_der(monkeypatch):
    raw_sock = _ProbeRawSocket()
    tls_sock = _ProbeTLSSocket({})
    ctx = _ProbeContext(tls_sock)
    monkeypatch.setattr(
        dot.socket, "create_connection", lambda *_args, **_kwargs: raw_sock
    )
    monkeypatch.setattr(dot.ssl, "_create_unverified_context", lambda: ctx)

    assert dot._probe_remote_cert_subject("127.0.0.1", 853) is None
    assert tls_sock.closed is True
    assert raw_sock.closed is True


def test_probe_remote_cert_subject_handles_none_raw_socket(monkeypatch):
    class _WrapFailContext:
        def wrap_socket(self, _raw_sock, server_hostname=None):
            raise RuntimeError(f"wrap failed: {server_hostname}")

    monkeypatch.setattr(dot.socket, "create_connection", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        dot.ssl, "_create_unverified_context", lambda: _WrapFailContext()
    )

    assert dot._probe_remote_cert_subject("127.0.0.1", 853) is None


def test_probe_remote_cert_subject_handles_none_raw_socket_on_success(monkeypatch):
    tls_sock = _ProbeTLSSocket({"subject": [[("CN", "none-raw-sock.example")]]})
    ctx = _ProbeContext(tls_sock)
    monkeypatch.setattr(dot.socket, "create_connection", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(dot.ssl, "_create_unverified_context", lambda: ctx)

    subject = dot._probe_remote_cert_subject("127.0.0.1", 853)
    assert subject == "CN=none-raw-sock.example"
    assert tls_sock.closed is True


def test_probe_remote_cert_subject_ignores_close_errors(monkeypatch):
    class _FailingRawSocket(_ProbeRawSocket):
        def close(self) -> None:  # type: ignore[override]
            raise RuntimeError("raw close failed")

    class _FailingTLSSocket(_ProbeTLSSocket):
        def close(self) -> None:  # type: ignore[override]
            raise RuntimeError("tls close failed")

    raw_sock = _FailingRawSocket()
    tls_sock = _FailingTLSSocket({}, der_cert=None)
    ctx = _ProbeContext(tls_sock)
    monkeypatch.setattr(
        dot.socket, "create_connection", lambda *_args, **_kwargs: raw_sock
    )
    monkeypatch.setattr(dot.ssl, "_create_unverified_context", lambda: ctx)

    assert dot._probe_remote_cert_subject("127.0.0.1", 853) is None


def test_describe_local_cert_file_variants(tmp_path, monkeypatch):
    assert dot._describe_local_cert_file(None) == "not configured"

    missing_path = tmp_path / "missing-cert.pem"
    assert "(missing)" in dot._describe_local_cert_file(str(missing_path))

    cert_dir = tmp_path / "cert-dir"
    cert_dir.mkdir()
    assert "(not a regular file)" in dot._describe_local_cert_file(str(cert_dir))

    cert_file = tmp_path / "cert.pem"
    cert_file.write_text("dummy")
    monkeypatch.setattr(
        dot, "_decode_cert_subject_from_file", lambda _: "CN=local-cert"
    )
    assert "Subject: CN=local-cert" in dot._describe_local_cert_file(str(cert_file))

    monkeypatch.setattr(dot, "_decode_cert_subject_from_file", lambda _: None)
    assert "Subject: unavailable" in dot._describe_local_cert_file(str(cert_file))


def test_describe_local_key_file_variants(tmp_path):
    assert dot._describe_local_key_file(None) == "not configured"

    missing_path = tmp_path / "missing-key.pem"
    assert "(missing)" in dot._describe_local_key_file(str(missing_path))

    key_dir = tmp_path / "key-dir"
    key_dir.mkdir()
    assert "(not a regular file)" in dot._describe_local_key_file(str(key_dir))

    key_file = tmp_path / "key.pem"
    key_file.write_text("dummy")
    assert dot._describe_local_key_file(str(key_file)) == f"path={str(key_file)!r}"


def test_describe_ca_source_variants():
    assert dot._describe_ca_source(verify=False, ca_file=None) == (
        "verification disabled (verify=False)"
    )
    assert dot._describe_ca_source(verify=True, ca_file="/tmp/ca.pem") == (
        "file (/tmp/ca.pem)"
    )
    assert dot._describe_ca_source(verify=True, ca_file=None) == "system trust store"


def test_infer_ssl_error_hints_cover_key_paths():
    hints_missing = dot._infer_ssl_error_hints(
        FileNotFoundError("No such file"),
        ca_file="/tmp/ca.pem",
    )
    assert "CA file not found: /tmp/ca.pem" in hints_missing

    hints_pem = dot._infer_ssl_error_hints(Exception("no start line in PEM data"))
    assert "certificate/key is not valid PEM/ASN.1 data" in hints_pem

    verification_error = ssl.SSLCertVerificationError(
        1,
        "hostname mismatch certificate verify failed expired",
    )
    hints_verify = dot._infer_ssl_error_hints(
        verification_error,
        server_hostname="dns.example",
    )
    assert any("name mismatch" in hint for hint in hints_verify)
    assert any("not trusted" in hint for hint in hints_verify)
    assert any("validity period" in hint for hint in hints_verify)

    hints_protocol = dot._infer_ssl_error_hints(Exception("wrong version number"))
    assert "TLS protocol/cipher mismatch during handshake" in hints_protocol

    hints_fallback = dot._infer_ssl_error_hints(Exception("totally-unrelated-error"))
    assert hints_fallback == [
        "verify CA bundle path, certificate format, and TLS server hostname/SNI"
    ]


def test_infer_ssl_error_hints_file_not_found_without_ca():
    hints = dot._infer_ssl_error_hints(FileNotFoundError("No such file"), ca_file=None)
    assert hints == ["certificate/key/CA file not found"]


def test_infer_ssl_error_hints_cert_verification_without_server_hostname():
    class _HostnameMismatchError(ssl.SSLCertVerificationError):
        def __str__(self) -> str:
            return (
                "hostname mismatch certificate verify failed "
                "unable to get local issuer certificate not yet valid"
            )

    hints = dot._infer_ssl_error_hints(_HostnameMismatchError(), server_hostname=None)
    assert any("set server_name/server_hostname" in hint for hint in hints)
    assert any("not trusted" in hint for hint in hints)
    assert any("validity period" in hint for hint in hints)


def test_infer_ssl_error_hints_protocol_variants():
    hints = dot._infer_ssl_error_hints(
        Exception("unsupported protocol during handshake")
    )
    assert "TLS protocol/cipher mismatch during handshake" in hints


def test_infer_ssl_error_hints_verification_without_hostname_clause():
    class _TrustedChainError(ssl.SSLCertVerificationError):
        def __str__(self) -> str:
            return "certificate verify failed self signed"

    hints = dot._infer_ssl_error_hints(
        _TrustedChainError(),
        server_hostname="dns.example",
    )
    assert not any("name mismatch" in hint for hint in hints)
    assert any("not trusted" in hint for hint in hints)
    assert not any("validity period" in hint for hint in hints)


def test_infer_ssl_error_hints_verification_hostname_only_message():
    class _HostnameOnlyError(ssl.SSLCertVerificationError):
        def __str__(self) -> str:
            return "hostname does not match"

    hints = dot._infer_ssl_error_hints(
        _HostnameOnlyError(),
        server_hostname="dns.example",
    )
    assert any("name mismatch" in hint for hint in hints)
    assert not any("not trusted" in hint for hint in hints)
    assert not any("validity period" in hint for hint in hints)


def test_warn_ssl_error_details_logs_once_per_exception(monkeypatch):
    warning_calls: list[tuple] = []
    monkeypatch.setattr(
        dot, "_infer_ssl_error_hints", lambda *_args, **_kwargs: ["hint"]
    )
    monkeypatch.setattr(
        dot,
        "_probe_remote_cert_subject",
        lambda *_args, **_kwargs: "CN=remote-cert",
    )
    monkeypatch.setattr(
        dot, "_describe_local_cert_file", lambda *_args, **_kwargs: "cert"
    )
    monkeypatch.setattr(
        dot, "_describe_local_key_file", lambda *_args, **_kwargs: "key"
    )
    monkeypatch.setattr(
        dot, "_describe_ca_source", lambda *_args, **_kwargs: "ca-source"
    )
    monkeypatch.setattr(
        dot.logger, "warning", lambda *args, **_kwargs: warning_calls.append(args)
    )

    err = ssl.SSLError("handshake failed")
    dot._warn_ssl_error_details(
        err,
        phase="handshake",
        host="127.0.0.1",
        port=853,
        verify=True,
        server_hostname="dns.example",
        cert_file="/tmp/cert.pem",
        key_file="/tmp/key.pem",
        ca_file="/tmp/ca.pem",
    )
    dot._warn_ssl_error_details(
        err,
        phase="handshake",
        host="127.0.0.1",
        port=853,
    )

    assert len(warning_calls) == 1
    _, phase, target, *_rest = warning_calls[0]
    assert phase == "handshake"
    assert target == " for 127.0.0.1:853"


def test_warn_ssl_error_details_handles_setattr_failure(monkeypatch):
    warning_calls: list[tuple] = []
    monkeypatch.setattr(
        dot, "_infer_ssl_error_hints", lambda *_args, **_kwargs: ["hint"]
    )
    monkeypatch.setattr(
        dot.logger, "warning", lambda *args, **_kwargs: warning_calls.append(args)
    )

    err = _NoSetAttrError("immutable")
    dot._warn_ssl_error_details(err, phase="context setup")
    assert len(warning_calls) == 1


def test_build_ssl_context_verified_and_unverified_paths(monkeypatch):
    dot._build_ssl_context.cache_clear()
    verified_ctx = _DummySSLContext()
    unverified_ctx = _DummySSLContext()
    cafile_args: list[object] = []

    def _fake_default_context(cafile=None):
        cafile_args.append(cafile)
        return verified_ctx

    monkeypatch.setattr(dot.ssl, "create_default_context", _fake_default_context)
    ctx = dot._build_ssl_context(
        "dns.example",
        verify=True,
        ca_file="/tmp/ca.pem",
    )
    assert ctx is verified_ctx
    assert cafile_args == ["/tmp/ca.pem"]
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    dot._build_ssl_context.cache_clear()
    monkeypatch.setattr(dot.ssl, "_create_unverified_context", lambda: unverified_ctx)
    ctx_unverified = dot._build_ssl_context(
        None,
        verify=False,
        ca_file=None,
    )
    assert ctx_unverified is unverified_ctx
    assert ctx_unverified.minimum_version == ssl.TLSVersion.TLSv1_2


def test_build_ssl_context_reports_context_setup_errors(monkeypatch):
    dot._build_ssl_context.cache_clear()
    warning_calls: list[tuple[tuple, dict]] = []

    def _raise_context_error(cafile=None):
        raise ValueError(f"bad ca file: {cafile}")

    monkeypatch.setattr(dot.ssl, "create_default_context", _raise_context_error)
    monkeypatch.setattr(
        dot,
        "_warn_ssl_error_details",
        lambda *args, **kwargs: warning_calls.append((args, kwargs)),
    )

    with pytest.raises(ValueError, match="bad ca file"):
        dot._build_ssl_context(
            "dns.example",
            verify=True,
            ca_file="/tmp/missing-ca.pem",
        )

    assert len(warning_calls) == 1
    assert warning_calls[0][1]["phase"] == "context setup"


def test_dot_conn_connect_success_and_ssl_failure(monkeypatch):
    raw_sock = _ConnRawSocket()
    tls_sock = _ConnTLSSocket()
    monkeypatch.setattr(
        dot.socket, "create_connection", lambda *_args, **_kwargs: raw_sock
    )
    ctx = _ConnContext(tls_socket=tls_sock)

    conn = dot._DotConn(
        "127.0.0.1",
        853,
        ctx,
        "dns.example",
        True,
        "/tmp/ca.pem",
    )
    conn.connect(300)
    assert conn._sock is raw_sock
    assert conn._tls is tls_sock
    assert raw_sock.sockopts == [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]
    assert ctx.wrap_calls == [(raw_sock, "dns.example")]

    raw_sock_fail = _ConnRawSocket()
    monkeypatch.setattr(
        dot.socket,
        "create_connection",
        lambda *_args, **_kwargs: raw_sock_fail,
    )
    warning_calls: list[dict] = []
    fail_ctx = _ConnContext(wrap_error=ssl.SSLError("tls handshake failed"))
    monkeypatch.setattr(
        dot,
        "_warn_ssl_error_details",
        lambda *_args, **kwargs: warning_calls.append(kwargs),
    )

    conn_fail = dot._DotConn(
        "127.0.0.1",
        853,
        fail_ctx,
        "dns.example",
        True,
        "/tmp/ca.pem",
    )
    with pytest.raises(ssl.SSLError):
        conn_fail.connect(300)
    assert raw_sock_fail.closed is True
    assert warning_calls and warning_calls[0]["phase"] == "handshake"


def test_dot_conn_connect_ignores_close_error_after_handshake_failure(monkeypatch):
    class _CloseFailRawSocket(_ConnRawSocket):
        def close(self) -> None:  # type: ignore[override]
            raise RuntimeError("close failed")

    raw_sock = _CloseFailRawSocket()
    monkeypatch.setattr(
        dot.socket, "create_connection", lambda *_args, **_kwargs: raw_sock
    )
    fail_ctx = _ConnContext(wrap_error=ssl.SSLError("tls handshake failed"))

    conn_fail = dot._DotConn(
        "127.0.0.1",
        853,
        fail_ctx,
        "dns.example",
        True,
        "/tmp/ca.pem",
    )
    with pytest.raises(ssl.SSLError):
        conn_fail.connect(300)


def test_dot_conn_send_and_close(monkeypatch):
    conn = dot._DotConn("127.0.0.1", 853, object(), None, False, None)
    tls_sock = _ConnTLSSocket()
    raw_sock = _ConnRawSocket()
    conn._tls = tls_sock
    conn._sock = raw_sock

    recv_values = [b"\x00\x03", b"abc"]
    monkeypatch.setattr(
        dot, "_recv_exact", lambda *_args, **_kwargs: recv_values.pop(0)
    )

    response = conn.send(b"abc", 400)
    assert response == b"abc"
    assert tls_sock.timeout == 0.4
    assert tls_sock.payloads == [b"\x00\x03abc"]

    conn.close()
    assert tls_sock.closed is True
    assert raw_sock.closed is True
    assert conn._tls is None
    assert conn._sock is None


def test_dot_conn_idle_for_returns_elapsed_seconds():
    conn = dot._DotConn("127.0.0.1", 853, object(), None, False, None)
    conn._last_used = time.time() - 1.5
    assert conn.idle_for() >= 1.4


def test_pool_set_limits_clamps_values(monkeypatch):
    pool = _make_pool(monkeypatch, max_connections=2, idle_timeout_s=5)
    pool.set_limits(max_connections=0, idle_timeout_s=0)
    assert pool._max == 1
    assert pool._idle == 1


def test_pool_set_limits_can_update_single_field(monkeypatch):
    pool = _make_pool(monkeypatch, max_connections=3, idle_timeout_s=10)
    pool.set_limits(max_connections=5)
    assert pool._max == 5
    assert pool._idle == 10

    pool.set_limits(idle_timeout_s=7)
    assert pool._max == 5
    assert pool._idle == 7

    pool.set_limits()
    assert pool._max == 5
    assert pool._idle == 7


def test_pool_send_reuses_connection_and_cleans_idle(monkeypatch):
    pool = _make_pool(monkeypatch, max_connections=2, idle_timeout_s=5)
    stale = _PoolConn(response=b"stale", last_used=time.time() - 30)
    live = _PoolConn(response=b"live", last_used=time.time())
    pool._stack = [stale, live]

    response = pool.send(b"q", 200, 300)

    assert response == b"live"
    assert stale.closed is True
    assert live.send_calls == [(b"q", 300)]
    assert live in pool._stack


def test_pool_send_creates_connection_when_empty(monkeypatch):
    pool = _make_pool(monkeypatch, max_connections=2, idle_timeout_s=5)
    created = _PoolConn(response=b"new")
    monkeypatch.setattr(dot, "_DotConn", lambda *_args, **_kwargs: created)

    response = pool.send(b"q", 111, 222)

    assert response == b"new"
    assert created.connect_calls == [111]
    assert created.send_calls == [(b"q", 222)]
    assert created in pool._stack


def test_pool_send_closes_connection_on_send_error(monkeypatch):
    pool = _make_pool(monkeypatch, max_connections=2, idle_timeout_s=5)
    failing = _PoolConn(should_raise=True)
    pool._stack = [failing]

    with pytest.raises(RuntimeError, match="send failed"):
        pool.send(b"q", 100, 100)

    assert failing.closed is True
    assert failing not in pool._stack


def test_pool_send_closes_connection_when_pool_is_full(monkeypatch):
    pool = _make_pool(monkeypatch, max_connections=0, idle_timeout_s=5)
    conn = _PoolConn(response=b"ok")
    pool._stack = [conn]

    response = pool.send(b"q", 100, 100)

    assert response == b"ok"
    assert conn.closed is True
    assert pool._stack == []


def test_get_dot_pool_reuses_same_key(monkeypatch):
    dot._POOLS.clear()
    monkeypatch.setattr(dot, "_build_ssl_context", lambda *args, **kwargs: object())

    pool_a = dot.get_dot_pool("127.0.0.1", 853, None, False, None)
    pool_b = dot.get_dot_pool("127.0.0.1", 853, None, False, None)
    pool_c = dot.get_dot_pool("127.0.0.1", 853, "dns.example", False, None)

    assert pool_a is pool_b
    assert pool_c is not pool_a


def test_dot_query_success_verify_true_uses_server_name(monkeypatch):
    raw_sock = _QueryRawSocket()
    tls_sock = _QueryTLSSocket()
    ctx = _QueryContext(tls_socket=tls_sock)
    monkeypatch.setattr(
        dot.socket, "create_connection", lambda *_args, **_kwargs: raw_sock
    )
    monkeypatch.setattr(dot, "_build_ssl_context", lambda *_args, **_kwargs: ctx)

    recv_values = [b"\x00\x03", b"abc"]
    monkeypatch.setattr(
        dot, "_recv_exact", lambda *_args, **_kwargs: recv_values.pop(0)
    )

    response = dot.dot_query(
        "127.0.0.1",
        853,
        b"abc",
        server_name="dns.example",
        verify=True,
        connect_timeout_ms=250,
        read_timeout_ms=350,
    )

    assert response == b"abc"
    assert ctx.server_hostnames == ["dns.example"]
    assert tls_sock.timeout_s == 0.35
    assert tls_sock.payloads == [b"\x00\x03abc"]
    assert tls_sock.closed is True
    assert raw_sock.closed is True


def test_dot_query_success_verify_false_omits_server_name(monkeypatch):
    raw_sock = _QueryRawSocket()
    tls_sock = _QueryTLSSocket()
    ctx = _QueryContext(tls_socket=tls_sock)
    monkeypatch.setattr(
        dot.socket, "create_connection", lambda *_args, **_kwargs: raw_sock
    )
    monkeypatch.setattr(dot, "_build_ssl_context", lambda *_args, **_kwargs: ctx)

    recv_values = [b"\x00\x03", b"abc"]
    monkeypatch.setattr(
        dot, "_recv_exact", lambda *_args, **_kwargs: recv_values.pop(0)
    )

    response = dot.dot_query(
        "127.0.0.1",
        853,
        b"abc",
        server_name="dns.example",
        verify=False,
        connect_timeout_ms=250,
        read_timeout_ms=350,
    )

    assert response == b"abc"
    assert ctx.server_hostnames == [None]


def test_dot_query_ssl_error_is_wrapped_as_dot_error(monkeypatch):
    raw_sock = _QueryRawSocket()
    ctx = _QueryContext(wrap_error=ssl.SSLError("handshake failed"))
    warning_calls: list[dict] = []
    monkeypatch.setattr(
        dot.socket, "create_connection", lambda *_args, **_kwargs: raw_sock
    )
    monkeypatch.setattr(dot, "_build_ssl_context", lambda *_args, **_kwargs: ctx)
    monkeypatch.setattr(
        dot,
        "_warn_ssl_error_details",
        lambda *_args, **kwargs: warning_calls.append(kwargs),
    )

    with pytest.raises(dot.DoTError, match="TLS error"):
        dot.dot_query(
            "127.0.0.1",
            853,
            b"abc",
            server_name="dns.example",
            verify=True,
            connect_timeout_ms=250,
            read_timeout_ms=350,
        )

    assert warning_calls and warning_calls[0]["phase"] == "handshake"
    assert raw_sock.closed is True


def test_dot_query_network_error_is_wrapped_as_dot_error(monkeypatch):
    monkeypatch.setattr(
        dot.socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unreachable")),
    )

    with pytest.raises(dot.DoTError, match="Network error"):
        dot.dot_query(
            "127.0.0.1",
            853,
            b"abc",
            verify=False,
            connect_timeout_ms=250,
            read_timeout_ms=350,
        )


def test_recv_exact_reads_to_length_or_until_eof():
    sock_full = _RecvSocket([b"ab", b"cd", b"e"])
    assert dot._recv_exact(sock_full, 5, 300) == b"abcde"
    assert sock_full.timeout_s == 0.3

    sock_eof = _RecvSocket([b"ab", b""])
    assert dot._recv_exact(sock_eof, 5, 300) == b"ab"
