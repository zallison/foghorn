"""Logging and in-memory log buffer helpers for the admin webserver.

This module contains uvicorn access-log suppression logic and re-exports a
thread-safe RingBuffer (implemented in :mod:`foghorn.servers.runtime_state`) for
exposing recent log entries via the FastAPI admin API.
"""

from __future__ import annotations

import logging
import os
import ssl
import tempfile

from foghorn.servers.runtime_state import RingBuffer


class _Suppress2xxAccessFilter(logging.Filter):
    """Logging filter that drops uvicorn access records for HTTP 2xx responses.

    Inputs:
      - record: logging.LogRecord instance from uvicorn.access or other loggers.

    Outputs:
      - bool: False for records that clearly correspond to HTTP 2xx status codes,
        True otherwise (including when no status code can be determined).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Fast-path: use explicit status_code attribute if present
        status = getattr(record, "status_code", None)

        # Fallbacks: inspect record.args as used by uvicorn access logger
        if status is None:
            args = getattr(record, "args", None)
            if isinstance(args, dict):
                # Common uvicorn mapping keys: status_code or status
                status = args.get("status_code") or args.get("status")
            elif isinstance(args, (tuple, list)) and args:
                # Heuristic: last positional arg is often the status code
                status = args[-1]

        try:
            code = int(status)
        except Exception:
            # If we cannot confidently determine a numeric status code, keep record
            return True

        # Suppress all 2xx access logs
        return not (200 <= code <= 299)


def install_uvicorn_2xx_suppression() -> None:
    """Attach _Suppress2xxAccessFilter to uvicorn.access logger if not present.

    Inputs:
      - None (operates on the global logging configuration).

    Outputs:
      - None. The uvicorn.access logger will drop 2xx HTTP access records.
    """

    access_logger = logging.getLogger("uvicorn.access")
    # Avoid adding duplicate filters if called multiple times (e.g., reloads)
    for f in getattr(access_logger, "filters", []):
        if isinstance(f, _Suppress2xxAccessFilter):
            return
    access_logger.addFilter(_Suppress2xxAccessFilter())


def _infer_ssl_error_hints(
    error: BaseException,
    *,
    server_hostname: str | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
    ca_file: str | None = None,
) -> list[str]:
    """Infer likely causes for a TLS failure from the exception details.

    Inputs:
      - error: Caught SSL/TLS-related exception.
      - server_hostname: Optional TLS SNI/verification hostname.
      - cert_file: Optional certificate path involved in the operation.
      - key_file: Optional private-key path involved in the operation.
      - ca_file: Optional CA bundle path involved in the operation.

    Outputs:
      - list[str]: Human-readable probable causes suitable for warning logs.
    """

    message = str(error)
    lowered = message.lower()
    hints: list[str] = []

    configured_paths = [p for p in (cert_file, key_file, ca_file) if p]

    if (
        isinstance(error, FileNotFoundError)
        or "no such file" in lowered
        or "file not found" in lowered
    ):
        if configured_paths:
            hints.append(
                "certificate/key/CA file not found (check paths: "
                + ", ".join(configured_paths)
                + ")"
            )
        else:
            hints.append("certificate/key/CA file not found")

    if (
        "pem" in lowered
        or "asn1" in lowered
        or "bad base64 decode" in lowered
        or "no start line" in lowered
        or "unable to load certificate" in lowered
        or "unable to load private key" in lowered
    ):
        hints.append("certificate or key is not valid PEM/ASN.1 data")

    if isinstance(error, ssl.SSLCertVerificationError):
        if (
            "hostname" in lowered
            or "ip address mismatch" in lowered
            or "doesn't match" in lowered
            or "does not match" in lowered
        ):
            if server_hostname:
                hints.append(
                    f"certificate name mismatch for hostname {server_hostname!r}"
                )
            else:
                hints.append(
                    "certificate name mismatch (set server_hostname/SNI correctly)"
                )

        if (
            "certificate verify failed" in lowered
            or "self signed" in lowered
            or "unknown ca" in lowered
            or "unable to get local issuer certificate" in lowered
        ):
            hints.append("certificate chain is not trusted by the configured CA set")

        if "expired" in lowered or "not yet valid" in lowered:
            hints.append("certificate validity period is not currently valid")

    if (
        "wrong version number" in lowered
        or "unsupported protocol" in lowered
        or "protocol version" in lowered
        or "handshake failure" in lowered
    ):
        hints.append("TLS protocol/cipher mismatch during handshake")

    if not hints:
        hints.append(
            "verify certificate/key/CA files, server hostname (SNI), and trust chain"
        )

    return hints


def _format_subject(subject: object) -> str | None:
    """Format decoded certificate subject tuples into `key=value` components.

    Inputs:
      - subject: Subject object from decoded certificate metadata.

    Outputs:
      - str | None: Comma-separated subject string when available.
    """

    if not isinstance(subject, (list, tuple)):
        return None
    components: list[str] = []
    for rdn in subject:
        if not isinstance(rdn, (list, tuple)):
            continue
        for attribute in rdn:
            if (
                isinstance(attribute, (list, tuple))
                and len(attribute) >= 2
                and attribute[0]
            ):
                components.append(f"{attribute[0]}={attribute[1]}")
    return ", ".join(components) if components else None


def _decode_cert_subject_from_file(cert_file: str) -> str | None:
    """Decode a certificate file and return a formatted `Subject:` value.

    Inputs:
      - cert_file: Path to the certificate file.

    Outputs:
      - str | None: Formatted subject string, or None when unavailable.
    """

    try:
        decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
        if not callable(decoder):
            return None
        decoded = decoder(cert_file)
        if not isinstance(decoded, dict):
            return None
        return _format_subject(decoded.get("subject"))
    except Exception:
        return None


def _decode_cert_subject_from_der(der_cert: bytes) -> str | None:
    """Decode DER certificate bytes and return a formatted subject string.

    Inputs:
      - der_cert: DER-encoded certificate bytes.

    Outputs:
      - str | None: Formatted subject string, or None if decode fails.
    """

    tmp_path: str | None = None
    try:
        pem_text = ssl.DER_cert_to_PEM_cert(der_cert)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".pem", delete=False
        ) as tmp:
            tmp.write(pem_text)
            tmp_path = tmp.name
        return _decode_cert_subject_from_file(tmp_path)
    except Exception:
        return None
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def _describe_cert_file(cert_file: str | None) -> str:
    """Describe local certificate file details including parsed subject if possible.

    Inputs:
      - cert_file: Optional certificate path.

    Outputs:
      - str: Human-readable description for warning logs.
    """

    if not cert_file:
        return "not configured"
    if not os.path.exists(cert_file):
        return f"path={cert_file!r} (missing)"
    if not os.path.isfile(cert_file):
        return f"path={cert_file!r} (not a regular file)"
    subject = _decode_cert_subject_from_file(cert_file)
    if subject:
        return f"path={cert_file!r}, Subject: {subject}"
    return f"path={cert_file!r}, Subject: unavailable"


def _describe_key_file(key_file: str | None) -> str:
    """Describe local key file details for warning logs.

    Inputs:
      - key_file: Optional private-key path.

    Outputs:
      - str: Human-readable key-file description.
    """

    if not key_file:
        return "not configured"
    if not os.path.exists(key_file):
        return f"path={key_file!r} (missing)"
    if not os.path.isfile(key_file):
        return f"path={key_file!r} (not a regular file)"
    return f"path={key_file!r}"


def _describe_ca_source(*, verify: bool | None, ca_file: str | None) -> str:
    """Describe which CA trust source was used for TLS verification.

    Inputs:
      - verify: Whether TLS verification is enabled.
      - ca_file: Optional custom CA bundle path.

    Outputs:
      - str: CA source description.
    """

    if verify is False:
        return "verification disabled (verify=False)"
    if ca_file:
        return f"file ({ca_file})"
    return "system trust store"


def log_ssl_error_warning(
    logger: logging.Logger,
    error: BaseException,
    *,
    context: str,
    verify: bool | None = None,
    server_hostname: str | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
    ca_file: str | None = None,
    remote_subject: str | None = None,
) -> None:
    """Emit a warning log with likely causes when a TLS error occurs.

    Inputs:
      - logger: Logger used to emit the warning.
      - error: Caught SSL/TLS-related exception.
      - context: Short operation context (e.g. "DoT handshake").
      - verify: Optional TLS verification flag.
      - server_hostname: Optional TLS SNI/verification hostname.
      - cert_file: Optional certificate path involved in the operation.
      - key_file: Optional private-key path involved in the operation.
      - ca_file: Optional CA bundle path involved in the operation.
      - remote_subject: Optional remote certificate subject string.

    Outputs:
      - None. Emits one warning log with likely-cause hints.
    """

    hints = _infer_ssl_error_hints(
        error,
        server_hostname=server_hostname,
        cert_file=cert_file,
        key_file=key_file,
        ca_file=ca_file,
    )
    local_cert_desc = _describe_cert_file(cert_file)
    local_key_desc = _describe_key_file(key_file)
    ca_source = _describe_ca_source(verify=verify, ca_file=ca_file)
    logger.warning(
        "%s: SSL/TLS error (%s). Remote cert Subject: %s. Local cert: %s. Local key: %s. CA source: %s. Likely causes: %s",
        context,
        error,
        remote_subject or "unavailable",
        local_cert_desc,
        local_key_desc,
        ca_source,
        "; ".join(hints),
    )
