"""Admin TLS certificate helpers (optional self-signed generation via openssl)."""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger("foghorn.webserver")


def normalize_generate_policy(value: object) -> str:
    """Brief: Normalize server.http.generate into yes/no/maybe.

    Inputs:
      - value: Raw generate policy from configuration.

    Outputs:
      - str: One of "yes", "no", or "maybe".

    Example:
      >>> normalize_generate_policy(True)
      'yes'
      >>> normalize_generate_policy("MAYBE")
      'maybe'
    """

    if value is None:
        return "no"
    if isinstance(value, bool):
        return "yes" if value else "no"

    normalized = str(value).strip().lower()
    if not normalized:
        return "no"

    alias_map = {
        "true": "yes",
        "false": "no",
        "on": "yes",
        "off": "no",
        "1": "yes",
        "0": "no",
    }
    normalized = alias_map.get(normalized, normalized)
    if normalized not in {"yes", "no", "maybe"}:
        raise ValueError(
            "server.http.generate must be one of: yes, no, maybe "
            "(aliases: true/false, on/off, 1/0)"
        )
    return normalized


def _normalize_optional_path(value: Any) -> str | None:
    """Brief: Normalize an optional filesystem path config value.

    Inputs:
      - value: Raw config value (path string or empty/None).

    Outputs:
      - str | None: Non-empty path string, else None.
    """

    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _config_base_dir(config_path: str | None) -> Path:
    """Brief: Resolve the base directory allowed for admin TLS material.

    Inputs:
      - config_path: Optional active config file path.

    Outputs:
      - Path: Parent of config_path when set, else current working directory.
    """

    if config_path and str(config_path).strip():
        return Path(config_path).expanduser().resolve().parent
    return Path.cwd().resolve()


def _is_path_within(path: Path, base: Path) -> bool:
    """Brief: Return True when path is base or a descendant of base.

    Inputs:
      - path: Candidate filesystem path.
      - base: Allowed root directory.

    Outputs:
      - bool
    """

    try:
        path_r = path.expanduser().resolve(strict=False)
        base_r = base.expanduser().resolve(strict=False)
        path_r.relative_to(base_r)
        return True
    except Exception:
        return False


def enforce_admin_tls_path_allowlist(
    *paths: str | None,
    config_path: str | None = None,
) -> None:
    """Brief: Require admin TLS paths stay under the config directory.

    Inputs:
      - paths: cert_file/key_file/keys_dir path strings (None ignored).
      - config_path: Optional active config file path. When unset/blank, the
        allowlist is not enforced (no trusted config root is known).

    Outputs:
      - None. Raises ValueError when a path escapes the allowed base directory.
    """

    if not (config_path and str(config_path).strip()):
        return

    base = _config_base_dir(config_path)
    for raw in paths:
        if not raw:
            continue
        candidate = Path(str(raw)).expanduser()
        # For non-existing files, resolve parent + name without requiring existence.
        try:
            resolved = candidate.resolve(strict=False)
        except Exception as exc:
            raise ValueError(f"invalid admin TLS path {raw!r}: {exc}") from exc
        if not _is_path_within(resolved, base):
            raise ValueError(
                f"admin TLS path {str(resolved)!r} must be under config directory "
                f"{str(base)!r} (server.http.cert_file/key_file/keys_dir)"
            )


def default_admin_tls_paths(
    *,
    config_path: str | None = None,
    keys_dir: str | None = None,
) -> tuple[str, str]:
    """Brief: Choose default admin cert/key paths for auto-generation.

    Inputs:
      - config_path: Optional active config file path (used to place keys nearby).
      - keys_dir: Optional explicit keys directory override.

    Outputs:
      - tuple[str, str]: (cert_file, key_file) absolute or relative paths.
    """

    if keys_dir and str(keys_dir).strip():
        base = Path(str(keys_dir).strip())
    elif config_path:
        base = Path(config_path).expanduser().resolve().parent / "keys"
    else:
        base = Path("keys")
    return str(base / "foghorn_admin.pem"), str(base / "foghorn_admin.key")


def resolve_admin_tls_files(web_cfg: dict[str, Any]) -> tuple[str | None, str | None]:
    """Brief: Resolve optional admin TLS cert/key paths from server.http.

    Inputs:
      - web_cfg: server.http configuration mapping.

    Outputs:
      - tuple[str | None, str | None]: (cert_file, key_file). Either both set
        or both None. Raises ValueError when only one side is configured.
    """

    cert_file = _normalize_optional_path(web_cfg.get("cert_file"))
    key_file = _normalize_optional_path(web_cfg.get("key_file"))
    if bool(cert_file) ^ bool(key_file):
        raise ValueError(
            "server.http TLS requires both cert_file and key_file (or neither)"
        )
    return cert_file, key_file


def _openssl_available() -> str | None:
    """Brief: Return openssl executable path when available.

    Inputs:
      - None.

    Outputs:
      - str | None: Absolute path to openssl, else None.
    """

    return shutil.which("openssl")


def _subject_cn_for_host(host: str) -> str:
    """Brief: Choose a certificate CN for the admin bind host.

    Inputs:
      - host: Listener host string.

    Outputs:
      - str: CN value for the self-signed certificate.
    """

    normalized = str(host or "").strip() or "localhost"
    if normalized in {"0.0.0.0", "::", "[::]"}:
        try:
            return socket.gethostname() or "foghorn-admin"
        except Exception:
            return "foghorn-admin"
    return normalized


def _san_extension(host: str, cn: str) -> str:
    """Brief: Build an openssl -addext subjectAltName value.

    Inputs:
      - host: Bind host.
      - cn: Certificate CN.

    Outputs:
      - str: subjectAltName extension string.
    """

    names: list[str] = []
    for candidate in (cn, host, "localhost"):
        value = str(candidate or "").strip()
        if not value or value in {"0.0.0.0", "::", "[::]"}:
            continue
        try:
            ipaddress.ip_address(value)
            entry = f"IP:{value}"
        except ValueError:
            entry = f"DNS:{value}"
        if entry not in names:
            names.append(entry)
    if "DNS:localhost" not in names:
        names.append("DNS:localhost")
    if "IP:127.0.0.1" not in names:
        names.append("IP:127.0.0.1")
    return "subjectAltName = " + ", ".join(names)


def generate_self_signed_admin_tls(
    *,
    cert_file: str,
    key_file: str,
    host: str = "localhost",
    days: int = 3650,
    openssl_bin: str | None = None,
) -> None:
    """Brief: Generate a self-signed admin TLS cert/key pair with openssl.

    Inputs:
      - cert_file: Destination certificate path.
      - key_file: Destination private key path.
      - host: Bind host used for CN/SAN selection.
      - days: Certificate validity window in days.
      - openssl_bin: Optional openssl executable path.

    Outputs:
      - None. Writes cert_file and key_file. Raises RuntimeError on failure.

    Notes:
      - Intended for internal/LAN encryption where trust is not the goal.
      - Requires the openssl CLI on PATH (or openssl_bin).
    """

    openssl = openssl_bin or _openssl_available()
    if not openssl:
        raise RuntimeError(
            "openssl is not available; cannot auto-generate server.http TLS material"
        )

    cert_path = Path(cert_file).expanduser()
    key_path = Path(key_file).expanduser()
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    cn = _subject_cn_for_host(host)
    san = _san_extension(host, cn)
    # Write key and cert as separate PEM files (matches cert_file/key_file shape).
    cmd = [
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-days",
        str(max(1, int(days))),
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-subj",
        f"/O=Foghorn/CN={cn}",
        "-addext",
        san,
    ]
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("openssl timed out generating admin TLS material") from exc
    except OSError as exc:
        raise RuntimeError(f"failed to execute openssl: {exc}") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(
            f"openssl failed generating admin TLS material (rc={completed.returncode}): {detail}"
        )

    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    logger.warning(
        "Generated self-signed admin TLS material for internal use "
        "(not a trust anchor): cert_file=%s key_file=%s cn=%s. "
        "Prefer a CA-signed pair via the Makefile, e.g. "
        "`make ssl-cert CNAME=%s` (writes keys/foghorn_%s.crt + .key) or "
        "`make ssl-cert-pem CNAME=%s` (combined .pem); then set "
        "server.http.cert_file / key_file (and generate: no). See docs/open-ssl-make-easy.md.",
        cert_path,
        key_path,
        cn,
        cn,
        cn,
        cn,
    )


def warn_if_default_admin_tls_unused(
    *,
    config_path: str | None = None,
    keys_dir: str | None = None,
) -> None:
    """Brief: Warn when default admin TLS files exist but HTTPS is not enabled.

    Inputs:
      - config_path: Optional config path used to locate default keys/.
      - keys_dir: Optional keys directory override (same as server.http.keys_dir).

    Outputs:
      - None. Logs a warning when default foghorn_admin cert/key files exist
        on disk but server.http has no cert_file/key_file (TLS not enabled).
    """

    default_cert, default_key = default_admin_tls_paths(
        config_path=config_path, keys_dir=keys_dir
    )
    cert_exists = os.path.isfile(default_cert)
    key_exists = os.path.isfile(default_key)
    if not (cert_exists or key_exists):
        return

    logger.warning(
        "Default admin TLS files are present but server.http TLS is not enabled "
        "(cert_exists=%s key_exists=%s; cert_file=%s key_file=%s). "
        "Set server.http.cert_file and server.http.key_file to those paths to enable HTTPS, "
        "or remove unused files. To build CA-signed keys: "
        "`make ssl-cert CNAME=<name>` or `make ssl-cert-pem CNAME=<name>` "
        "(see docs/open-ssl-make-easy.md).",
        cert_exists,
        key_exists,
        default_cert,
        default_key,
    )


def ensure_admin_tls_files(
    web_cfg: dict[str, Any],
    *,
    host: str = "127.0.0.1",
    config_path: str | None = None,
) -> tuple[str | None, str | None]:
    """Brief: Resolve admin TLS paths and optionally auto-generate missing files.

    Inputs:
      - web_cfg: server.http mapping (may be mutated with default paths).
      - host: Bind host used for CN/SAN when generating.
      - config_path: Optional config path for default key placement.

    Outputs:
      - tuple[str | None, str | None]: Effective (cert_file, key_file).

    Behaviour:
      - generate=no (default): never create files; both paths or neither.
      - generate=maybe|yes: if openssl is available and cert/key files are
        missing, create a self-signed pair. If paths are unset, defaults under
        <config_dir>/keys or ./keys are used.
      - yes differs from maybe only in that missing openssl is an error when
        generation is required; maybe logs and continues without TLS.
    """

    if not isinstance(web_cfg, dict):
        return None, None

    policy = normalize_generate_policy(web_cfg.get("generate", "no"))
    cert_file, key_file = resolve_admin_tls_files(web_cfg)
    keys_dir = _normalize_optional_path(web_cfg.get("keys_dir"))

    # Always constrain configured TLS paths to the config directory tree.
    enforce_admin_tls_path_allowlist(
        cert_file,
        key_file,
        keys_dir,
        config_path=config_path,
    )

    if policy == "no":
        if cert_file is None and key_file is None:
            warn_if_default_admin_tls_unused(
                config_path=config_path,
                keys_dir=keys_dir,
            )
        return cert_file, key_file

    # Fill default paths when auto-generation is requested and none configured.
    if cert_file is None and key_file is None:
        cert_file, key_file = default_admin_tls_paths(
            config_path=config_path, keys_dir=keys_dir
        )
        enforce_admin_tls_path_allowlist(cert_file, key_file, config_path=config_path)
        web_cfg["cert_file"] = cert_file
        web_cfg["key_file"] = key_file

    assert cert_file is not None and key_file is not None
    cert_exists = os.path.isfile(cert_file)
    key_exists = os.path.isfile(key_file)
    if cert_exists and key_exists:
        return cert_file, key_file

    # One present, one missing: do not half-overwrite; require operator fix
    # unless both missing.
    if cert_exists ^ key_exists:
        raise ValueError(
            "server.http TLS files are incomplete "
            f"(cert_exists={cert_exists}, key_exists={key_exists}); "
            "provide both files or remove both and set generate=maybe"
        )

    openssl = _openssl_available()
    if not openssl:
        msg = (
            "server.http.generate=%s but openssl is unavailable and TLS files "
            "are missing (cert_file=%s key_file=%s)" % (policy, cert_file, key_file)
        )
        if policy == "yes":
            raise RuntimeError(msg)
        logger.warning("%s; starting without TLS", msg)
        # Clear paths so callers do not attempt to load missing files.
        return None, None

    days_raw = web_cfg.get("tls_days", web_cfg.get("generate_days", 3650))
    try:
        days = int(days_raw)
    except Exception:
        days = 3650

    generate_self_signed_admin_tls(
        cert_file=cert_file,
        key_file=key_file,
        host=host,
        days=days,
        openssl_bin=openssl,
    )
    return cert_file, key_file
