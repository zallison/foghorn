"""In-config (inline) secrets store.

Brief:
  Loads named secrets from YAML catalog entries whose material is embedded
  in the config mapping (token/secret/PEM strings). File path fields are
  rejected; use the ``file`` backend for filesystem material.

Inputs:
  - config.entries: list of secret entry mappings with inline values

Outputs:
  - InlineSecrets instance implementing SecretsStore.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import SecretRecord, SecretsStore, secret_aliases

logger = logging.getLogger(__name__)

_TSIG_EXTRA_KEYS = (
    "allow_names",
    "allow_names_files",
    "block_names",
    "block_names_files",
    "allow_update_ips",
    "allow_update_ips_files",
    "block_update_ips",
    "block_update_ips_files",
    "allow_clients",
    "allow_clients_files",
)

_FILE_FIELD_KEYS = frozenset(
    {
        "cert_file",
        "cert",
        "key_file",
        "key",
        "ca_file",
        "ca",
        "secret_file",
        "value_file",
        "token_file",
        "private_key_file",
        "keys_dir",
        "root",
        "base_dir",
    }
)


def _reject_file_fields(entry: dict[str, Any], *, sid: str) -> None:
    """Brief: Raise when a file-path field appears on an inline entry.

    Inputs:
      - entry: Catalog entry mapping.
      - sid: Secret id for error text.

    Outputs:
      - None.

    Raises:
      - ValueError when any filesystem field is present.
    """

    bad = sorted(k for k in _FILE_FIELD_KEYS if k in entry and entry.get(k) is not None)
    if bad:
        raise ValueError(
            f"inline secrets entry {sid!r} has file fields {bad}; "
            "use module 'file' for path-backed secrets"
        )


@secret_aliases("inline", "config", "embedded", "literal")
class InlineSecrets(SecretsStore):
    """Brief: In-config secrets backend (no filesystem paths).

    Inputs (**config):
      - entries: Optional list of secret entry dicts with inline values.
      - writable: When true (default), put() updates the in-memory catalog.

    Outputs:
      - InlineSecrets instance.
    """

    def __init__(self, **config: object) -> None:
        """Brief: Build in-memory catalog from inline entries.

        Inputs:
          - **config: See class docstring.

        Outputs:
          - None.
        """

        super().__init__(**config)
        if (
            config.get("keys_dir") is not None
            and str(config.get("keys_dir") or "").strip()
        ):
            raise ValueError(
                "inline secrets backend does not support keys_dir; use module 'file'"
            )
        self._records: dict[str, SecretRecord] = {}
        self._writable = bool(config.get("writable", True))

        entries = config.get("entries")
        if isinstance(entries, list):
            for item in entries:
                if isinstance(item, dict):
                    self._ingest_entry(item)

    def _ingest_entry(self, entry: dict[str, Any]) -> None:
        """Brief: Parse one inline catalog entry into a SecretRecord.

        Inputs:
          - entry: Mapping with id/kind and kind-specific inline fields.

        Outputs:
          - None; stores into self._records.

        Raises:
          - ValueError when file path fields are present or required inline
            material is missing.
        """

        sid = str(entry.get("id") or entry.get("name") or "").strip()
        kind = str(entry.get("kind") or entry.get("type") or "").strip().lower()

        if not sid or not kind:
            logger.warning("Ignoring secrets entry missing id/kind: %r", entry)
            return

        _reject_file_fields(entry, sid=sid)
        rec = SecretRecord(id=sid, kind=kind, backend_id=self.backend_id)

        if kind == "tls":
            if entry.get("cert_pem"):
                rec.cert_pem = str(entry.get("cert_pem")).encode("utf-8")
            if entry.get("key_pem"):
                rec.key_pem = str(entry.get("key_pem")).encode("utf-8")
            if entry.get("ca_pem"):
                rec.ca_pem = str(entry.get("ca_pem")).encode("utf-8")
            if rec.cert_pem is None and rec.key_pem is None and rec.ca_pem is None:
                raise ValueError(
                    f"inline secrets entry {sid!r} kind=tls requires "
                    "cert_pem and/or key_pem and/or ca_pem"
                )

        elif kind == "tsig":
            rec.name = str(entry.get("name") or sid).strip() or None
            rec.algorithm = str(entry.get("algorithm") or "hmac-sha256").strip()
            if entry.get("secret") is None:
                raise ValueError(
                    f"inline secrets entry {sid!r} kind=tsig requires secret"
                )
            rec.secret = str(entry.get("secret"))
            extra: dict[str, Any] = {}
            for k in _TSIG_EXTRA_KEYS:
                if k in entry:
                    extra[k] = entry[k]
            rec.extra = extra

        elif kind == "token":
            if entry.get("token") is not None:
                rec.token = str(entry.get("token"))
            elif entry.get("value") is not None:
                rec.token = str(entry.get("value"))
            elif entry.get("secret") is not None:
                rec.token = str(entry.get("secret"))
            else:
                raise ValueError(
                    f"inline secrets entry {sid!r} kind=token requires "
                    "token, value, or secret"
                )

        elif kind == "dnssec":
            from foghorn.utils import dns_names

            rec.zone = dns_names.normalize_name(entry.get("zone") or "")
            rec.key_type = str(entry.get("key_type") or "").strip().lower() or None
            rec.algorithm = str(entry.get("algorithm") or "ECDSAP256SHA256").strip()
            raw = entry.get("private_key_pem")
            if raw is None:
                raise ValueError(
                    f"inline secrets entry {sid!r} kind=dnssec requires private_key_pem"
                )
            rec.private_key_pem = (
                raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode("utf-8")
            )

        elif kind == "gnupg":
            # Reserved: accept and store opaque meta only.
            rec.meta = {
                k: v
                for k, v in entry.items()
                if k not in {"id", "name", "kind", "type", "comment"}
            }
        else:
            logger.warning(
                "Unknown secrets kind %r for id %r; storing meta only", kind, sid
            )
            rec.meta = dict(entry)

        self._records[sid] = rec

    def validate_connection(self) -> bool:
        """Brief: Always True for an in-memory inline catalog.

        Inputs:
          - None.

        Outputs:
          - bool: True.
        """

        return True

    def get(self, secret_id: str) -> SecretRecord | None:
        """Brief: Fetch one secret by id.

        Inputs:
          - secret_id: Catalog id.

        Outputs:
          - SecretRecord or None.
        """

        rec = self._records.get(str(secret_id).strip())
        if rec is None:
            return None
        return SecretRecord(
            id=rec.id,
            kind=rec.kind,
            backend_id=self.backend_id or rec.backend_id,
            cert_pem=rec.cert_pem,
            key_pem=rec.key_pem,
            ca_pem=rec.ca_pem,
            cert_path=rec.cert_path,
            key_path=rec.key_path,
            ca_path=rec.ca_path,
            name=rec.name,
            algorithm=rec.algorithm,
            secret=rec.secret,
            token=rec.token,
            zone=rec.zone,
            key_type=rec.key_type,
            private_key_pem=rec.private_key_pem,
            extra=dict(rec.extra or {}),
            meta=dict(rec.meta or {}),
        )

    def list(self, kind: str | None = None) -> list[SecretRecord]:
        """Brief: List secrets optionally filtered by kind.

        Inputs:
          - kind: Optional kind filter.

        Outputs:
          - list[SecretRecord].
        """

        kind_n = str(kind).strip().lower() if kind else None
        out: list[SecretRecord] = []
        for sid in sorted(self._records.keys()):
            rec = self.get(sid)
            if rec is None:
                continue
            if kind_n and str(rec.kind).lower() != kind_n:
                continue
            out.append(rec)
        return out

    def put(self, record: SecretRecord) -> None:
        """Brief: Persist a secret into the in-memory catalog.

        Inputs:
          - record: SecretRecord to store.

        Outputs:
          - None.
        """

        if not self._writable:
            raise RuntimeError("InlineSecrets backend is read-only")

        sid = str(record.id).strip()
        if not sid:
            raise ValueError("SecretRecord.id is required for put()")

        self._records[sid] = SecretRecord(
            id=sid,
            kind=str(record.kind).strip().lower(),
            backend_id=self.backend_id,
            cert_pem=record.cert_pem,
            key_pem=record.key_pem,
            ca_pem=record.ca_pem,
            name=record.name,
            algorithm=record.algorithm,
            secret=record.secret,
            token=record.token,
            zone=record.zone,
            key_type=record.key_type,
            private_key_pem=record.private_key_pem,
            extra=dict(record.extra or {}),
            meta=dict(record.meta or {}),
        )

    def reload(self) -> None:
        """Brief: Rebuild catalog from original config.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        cfg = dict(self._config)
        self._records.clear()
        entries = cfg.get("entries")
        if isinstance(entries, list):
            for item in entries:
                if isinstance(item, dict):
                    self._ingest_entry(item)
