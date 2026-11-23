"""Helpers for resolving secret refs in consumer config surfaces.

Inputs:
  - Structured refs {id|backend, key} selecting a backend and secret key.
  - Optional active SecretsRouter (defaults to process-wide router).

Outputs:
  - Token strings, TLS PEM material, or path writes for legacy consumers.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

from .base import SecretRecord
from .router import SecretsRouter, get_active_secrets_router

logger = logging.getLogger(__name__)


def _router(router: SecretsRouter | None = None) -> SecretsRouter | None:
    """Brief: Return provided router or the process-wide active router.

    Inputs:
      - router: Optional explicit SecretsRouter.

    Outputs:
      - SecretsRouter or None.
    """

    return router if router is not None else get_active_secrets_router()


def resolve_secret_string(
    value: object,
    *,
    router: SecretsRouter | None = None,
    prefer: tuple[str, ...] = ("token", "secret", "password"),
) -> str | None:
    """Brief: Resolve a plain string or secrets ref mapping to a secret string.

    Inputs:
      - value: Plain string, or {id|backend, key} secrets ref.
      - router: Optional secrets router override.
      - prefer: Ordered SecretRecord fields to try for the string value.

    Outputs:
      - Resolved non-empty string, or None when missing/unresolvable.

    Example:
      >>> resolve_secret_string({"id": "local", "key": "admin-password"})
    """

    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if not isinstance(value, dict):
        return None

    r = _router(router)
    if r is None:
        logger.warning("secrets ref provided but no secrets backends are configured")
        return None
    try:
        rec = r.resolve_ref(value, require=False)
    except Exception as exc:
        logger.warning("Failed resolving secrets ref: %s", exc)
        return None
    if rec is None:
        return None
    for field_name in prefer:
        raw = getattr(rec, field_name, None)
        if raw is None and field_name == "password":
            # password is not a SecretRecord field; fall through.
            continue
        if raw is None:
            continue
        text = str(raw).strip()
        if text:
            return text
    # TLS PEMs are bytes; allow decoding for rare string consumers.
    for pem_attr in ("cert_pem", "key_pem", "ca_pem", "private_key_pem"):
        pem = getattr(rec, pem_attr, None)
        if isinstance(pem, (bytes, bytearray)) and pem:
            try:
                return bytes(pem).decode("utf-8").strip() or None
            except Exception:
                continue
    return None


def resolve_token_value(
    auth_cfg: dict[str, Any] | None,
    *,
    router: SecretsRouter | None = None,
) -> str | None:
    """Brief: Resolve server.http.auth token from inline value or secret ref.

    Inputs:
      - auth_cfg: server.http.auth mapping.
      - router: Optional secrets router override.

    Outputs:
      - Token string when available; None when unset.

    Notes:
      - Prefers inline auth.token when non-empty.
      - Falls back to auth.token_secret ref:
        {id|backend: <backend>, key: <secret-key>}.
    """

    if not isinstance(auth_cfg, dict):
        return None
    inline = str(auth_cfg.get("token") or "").strip()
    if inline:
        return inline

    ref = auth_cfg.get("token_secret")
    if ref is None:
        return None
    return resolve_secret_string(ref, router=router, prefer=("token", "secret"))


def resolve_tls_material(
    ref: object,
    *,
    router: SecretsRouter | None = None,
    field: str = "cert",
) -> bytes | None:
    """Brief: Resolve TLS PEM bytes from a secret ref.

    Inputs:
      - ref: Secret ref {id|backend, key}.
      - router: Optional secrets router.
      - field: cert | key | ca selecting which PEM to return.

    Outputs:
      - PEM bytes or None.
    """

    r = _router(router)
    if r is None or ref is None:
        return None
    try:
        rec = r.resolve_ref(ref, require=False)
    except Exception as exc:
        logger.warning("Failed resolving TLS secret ref: %s", exc)
        return None
    if rec is None or str(rec.kind).lower() not in {"tls", "certificate", "cert"}:
        # Still allow kind-agnostic PEM fields.
        if rec is None:
            return None
    field_l = str(field or "cert").strip().lower()
    if field_l in {"cert", "certificate", "cert_pem"}:
        return rec.cert_pem
    if field_l in {"key", "key_pem", "private_key"}:
        return rec.key_pem
    if field_l in {"ca", "ca_pem", "chain"}:
        return rec.ca_pem
    return None


def materialize_tls_paths(
    cfg: dict[str, Any],
    *,
    router: SecretsRouter | None = None,
    prefix: str = "foghorn-tls",
    config_path: str | None = None,
) -> dict[str, Any]:
    """Brief: Expand cert_secret/key_secret/ca_secret refs into filesystem paths.

    Inputs:
      - cfg: Mapping that may contain cert_file/key_file/ca_file and *_secret refs.
      - router: Optional secrets router.
      - prefix: Temp file name prefix when PEMs must be written.
      - config_path: Optional config file path; when set, temp PEMs are written
        under ``<config_dir>/keys/.foghorn-secrets-tls`` so admin TLS path
        allowlisting accepts them.

    Outputs:
      - Shallow-copied mapping with cert_file/key_file/ca_file filled when
        corresponding *_secret refs resolve. Existing explicit paths win.

    Notes:
      - Prefers original source paths from file-backed secrets (no copy).
      - Inline/DB PEMs are written under the config keys dir when possible,
        otherwise a process temp dir.
    """

    if not isinstance(cfg, dict):
        return {}
    out = dict(cfg)
    r = _router(router)
    if r is None:
        return out

    field_to_path_attr = {
        "cert": "cert_path",
        "key": "key_path",
        "ca": "ca_path",
    }

    staging_dir: Path | None = None
    if config_path and str(config_path).strip():
        try:
            base = Path(str(config_path)).expanduser().resolve(strict=False).parent
            staging_dir = (base / "keys" / ".foghorn-secrets-tls").resolve(strict=False)
        except Exception:
            staging_dir = None

    mapping = (
        ("cert_secret", "cert_file", "cert"),
        ("key_secret", "key_file", "key"),
        ("ca_secret", "ca_file", "ca"),
    )
    for secret_key, path_key, field in mapping:
        if out.get(path_key):
            continue
        ref = out.get(secret_key)
        if ref is None:
            continue
        try:
            rec = r.resolve_ref(ref, require=False)
        except Exception as exc:
            logger.warning("TLS secret ref %s resolve failed: %s", secret_key, exc)
            continue
        if rec is None:
            logger.warning("TLS secret ref %s did not resolve", secret_key)
            continue

        # Prefer original file path from file-backed secrets.
        src_attr = field_to_path_attr.get(field)
        src_path = getattr(rec, src_attr, None) if src_attr else None
        if isinstance(src_path, str) and src_path.strip() and Path(src_path).is_file():
            out[path_key] = src_path
            continue

        pem = resolve_tls_material(ref, router=r, field=field)
        if not pem:
            logger.warning("TLS secret ref %s did not resolve PEM material", secret_key)
            continue
        try:
            if staging_dir is not None:
                staging_dir.mkdir(parents=True, exist_ok=True)
                try:
                    staging_dir.chmod(0o700)
                except Exception:
                    pass
                path = staging_dir / f"{prefix}-{field}.pem"
                path.write_bytes(pem)
                try:
                    path.chmod(0o600)
                except Exception:
                    pass
                out[path_key] = str(path)
            else:
                fd, path_s = tempfile.mkstemp(
                    prefix=f"{prefix}-{field}-", suffix=".pem"
                )
                with open(fd, "wb") as fh:
                    fh.write(pem)
                Path(path_s).chmod(0o600)
                out[path_key] = path_s
        except Exception as exc:
            logger.warning("Failed materializing TLS %s path: %s", field, exc)
    return out


def resolve_secret_record(
    ref: object,
    *,
    router: SecretsRouter | None = None,
    require: bool = False,
) -> SecretRecord | None:
    """Brief: Resolve an arbitrary secret ref to a SecretRecord.

    Inputs:
      - ref: Secret reference.
      - router: Optional router override.
      - require: Raise on miss/ambiguity when True.

    Outputs:
      - SecretRecord or None.
    """

    r = _router(router)
    if r is None:
        if require:
            raise RuntimeError("no secrets backends configured")
        return None
    return r.resolve_ref(ref, require=require)
