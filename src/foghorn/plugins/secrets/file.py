"""Filesystem-backed secrets store.

Brief:
  Loads named secrets from YAML catalog path fields and/or a DNSSEC
  keys_dir layout compatible with zone_signer
  (domainkey_<apex>.{ksk,zsk}.key). Inline PEMs/tokens/secrets are not
  accepted; use the ``inline`` backend for in-config material.

Inputs:
  - config.entries: list of secret entry mappings (path fields only)
  - config.keys_dir: optional DNSSEC key directory to index
  - config.root / base_dir: optional path prefix for relative files

Outputs:
  - FileSecrets instance implementing SecretsStore.
"""

from __future__ import annotations

import logging
from pathlib import Path
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

_INLINE_FIELD_KEYS = frozenset(
    {
        "cert_pem",
        "key_pem",
        "ca_pem",
        "token",
        "value",
        "secret",
        "private_key_pem",
    }
)


def _reject_inline_fields(entry: dict[str, Any], *, sid: str) -> None:
    """Brief: Raise when inline secret material appears on a file entry.

    Inputs:
      - entry: Catalog entry mapping.
      - sid: Secret id for error text.

    Outputs:
      - None.

    Raises:
      - ValueError when any inline value field is present.
    """

    bad = sorted(
        k for k in _INLINE_FIELD_KEYS if k in entry and entry.get(k) is not None
    )
    if bad:
        raise ValueError(
            f"file secrets entry {sid!r} has inline fields {bad}; "
            "use module 'inline' for in-config secrets or path fields "
            "(value_file/secret_file/cert_file/...) on module 'file'"
        )


def _read_bytes(path: Path) -> bytes:
    """Brief: Read file bytes.

    Inputs:
      - path: Filesystem path.

    Outputs:
      - bytes content.
    """

    return path.read_bytes()


def _read_text(path: Path) -> str:
    """Brief: Read file text stripped of surrounding whitespace.

    Inputs:
      - path: Filesystem path.

    Outputs:
      - str content.
    """

    return path.read_text(encoding="utf-8").strip()


def _resolve_path(raw: object, *, base: Path | None) -> Path | None:
    """Brief: Resolve an optional path relative to base.

    Inputs:
      - raw: Path string or None.
      - base: Optional base directory.

    Outputs:
      - Path or None.
    """

    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    candidate = Path(text).expanduser()
    if not candidate.is_absolute() and base is not None:
        candidate = (base / candidate).expanduser()
    return candidate.resolve(strict=False)


def _sanitize_zone_name(zone_name: str) -> str:
    """Brief: Sanitize zone apex for DNSSEC key filenames.

    Inputs:
      - zone_name: Zone apex text.

    Outputs:
      - Filename-safe apex fragment.
    """

    name = str(zone_name or "").strip().rstrip(".")
    return name.replace(".", "_")


@secret_aliases("file", "files", "filesystem", "local")
class FileSecrets(SecretsStore):
    """Brief: Local filesystem secrets backend.

    Inputs (**config):
      - entries: Optional list of secret entry dicts (path fields only).
      - keys_dir: Optional DNSSEC key directory (domainkey_ layout).
      - root / base_dir: Optional base path for relative file fields.
      - zones: Optional list of zone apexes to index under keys_dir
        (when omitted, keys_dir is scanned for domainkey_*.ksk.key files).

    Outputs:
      - FileSecrets instance.
    """

    def __init__(self, **config: object) -> None:
        """Brief: Build in-memory catalog from entries and keys_dir.

        Inputs:
          - **config: See class docstring.

        Outputs:
          - None.
        """

        super().__init__(**config)
        root_raw = config.get("root", config.get("base_dir"))
        self._base = (
            Path(str(root_raw)).expanduser().resolve(strict=False)
            if root_raw is not None and str(root_raw).strip()
            else None
        )
        self._records: dict[str, SecretRecord] = {}
        self._keys_dir = _resolve_path(config.get("keys_dir"), base=self._base)
        self._writable = bool(config.get("writable", True))

        entries = config.get("entries")
        if isinstance(entries, list):
            for item in entries:
                if isinstance(item, dict):
                    self._ingest_entry(item)

        if self._keys_dir is not None:
            zones = config.get("zones")
            zone_list = (
                [str(z) for z in zones if str(z).strip()]
                if isinstance(zones, list)
                else None
            )
            self._index_keys_dir(self._keys_dir, zones=zone_list)

    def _ingest_entry(self, entry: dict[str, Any]) -> None:
        """Brief: Parse one path-backed catalog entry into a SecretRecord.

        Inputs:
          - entry: Mapping with id/kind and kind-specific path fields.

        Outputs:
          - None; stores into self._records.

        Raises:
          - ValueError when inline value fields are present or required
            path material is missing/unreadable.
        """

        sid = str(entry.get("id") or entry.get("name") or "").strip()
        kind = str(entry.get("kind") or entry.get("type") or "").strip().lower()
        if not sid or not kind:
            logger.warning("Ignoring secrets entry missing id/kind: %r", entry)
            return

        _reject_inline_fields(entry, sid=sid)
        rec = SecretRecord(id=sid, kind=kind, backend_id=self.backend_id)

        if kind == "tls":
            cert_path = _resolve_path(
                entry.get("cert_file") or entry.get("cert"), base=self._base
            )
            key_path = _resolve_path(
                entry.get("key_file") or entry.get("key"), base=self._base
            )
            ca_path = _resolve_path(
                entry.get("ca_file") or entry.get("ca"), base=self._base
            )
            if cert_path and cert_path.is_file():
                rec.cert_pem = _read_bytes(cert_path)
                rec.cert_path = str(cert_path)
            if key_path and key_path.is_file():
                rec.key_pem = _read_bytes(key_path)
                rec.key_path = str(key_path)
            if ca_path and ca_path.is_file():
                rec.ca_pem = _read_bytes(ca_path)
                rec.ca_path = str(ca_path)
            if rec.cert_pem is None and rec.key_pem is None and rec.ca_pem is None:
                tried = []
                if cert_path is not None:
                    tried.append(f"cert_file={cert_path}")
                if key_path is not None:
                    tried.append(f"key_file={key_path}")
                if ca_path is not None:
                    tried.append(f"ca_file={ca_path}")
                detail = (
                    ", ".join(tried) if tried else "no cert_file/key_file/ca_file set"
                )
                raise ValueError(
                    f"file secrets entry {sid!r} kind=tls requires readable "
                    f"cert_file and/or key_file and/or ca_file ({detail}; "
                    f"cwd={Path.cwd()})"
                )

        elif kind == "tsig":
            rec.name = str(entry.get("name") or sid).strip() or None
            rec.algorithm = str(entry.get("algorithm") or "hmac-sha256").strip()
            secret_file = _resolve_path(entry.get("secret_file"), base=self._base)
            if not secret_file or not secret_file.is_file():
                raise ValueError(
                    f"file secrets entry {sid!r} kind=tsig requires readable "
                    f"secret_file (path={secret_file}; cwd={Path.cwd()})"
                )
            rec.secret = _read_text(secret_file)
            extra: dict[str, Any] = {}
            for k in _TSIG_EXTRA_KEYS:
                if k in entry:
                    extra[k] = entry[k]
            rec.extra = extra

        elif kind == "token":
            value_file = _resolve_path(
                entry.get("value_file")
                or entry.get("token_file")
                or entry.get("secret_file"),
                base=self._base,
            )
            if not value_file or not value_file.is_file():
                raise ValueError(
                    f"file secrets entry {sid!r} kind=token requires readable "
                    f"value_file (path={value_file}; cwd={Path.cwd()})"
                )
            rec.token = _read_text(value_file)

        elif kind == "dnssec":
            from foghorn.utils import dns_names

            rec.zone = dns_names.normalize_name(entry.get("zone") or "")
            rec.key_type = str(entry.get("key_type") or "").strip().lower() or None
            rec.algorithm = str(entry.get("algorithm") or "ECDSAP256SHA256").strip()
            key_file = _resolve_path(
                entry.get("key_file") or entry.get("private_key_file"),
                base=self._base,
            )
            if not key_file or not key_file.is_file():
                raise ValueError(
                    f"file secrets entry {sid!r} kind=dnssec requires readable "
                    f"key_file (path={key_file}; cwd={Path.cwd()})"
                )
            rec.private_key_pem = _read_bytes(key_file)

        elif kind == "gnupg":
            # Reserved: accept and store opaque meta only (no secret blobs).
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

    def _index_keys_dir(self, keys_dir: Path, *, zones: list[str] | None) -> None:
        """Brief: Index DNSSEC PEM keys under keys_dir.

        Inputs:
          - keys_dir: Directory containing domainkey_*.{ksk,zsk}.key files.
          - zones: Optional explicit zone list; otherwise scan directory.

        Outputs:
          - None; populates self._records for discovered keys.
        """

        from foghorn.utils import dns_names

        if not keys_dir.is_dir():
            logger.warning("secrets keys_dir %s is not a directory", keys_dir)
            return

        discovered: list[tuple[str, str, Path]] = []  # zone, key_type, path

        if zones:
            for zone in zones:
                zone_n = dns_names.normalize_name(zone)
                sanitized = _sanitize_zone_name(zone_n)
                for key_type in ("ksk", "zsk"):
                    primary = keys_dir / f"domainkey_{sanitized}.{key_type}.key"
                    legacy = keys_dir / f"K{sanitized}.{key_type}.key"
                    path = primary if primary.is_file() else legacy
                    if path.is_file():
                        discovered.append((zone_n, key_type, path))
        else:
            for path in sorted(keys_dir.glob("*.key")):
                name = path.name
                key_type = None
                base = None
                if name.endswith(".ksk.key"):
                    key_type = "ksk"
                    base = name[: -len(".ksk.key")]
                elif name.endswith(".zsk.key"):
                    key_type = "zsk"
                    base = name[: -len(".zsk.key")]
                else:
                    continue
                if base.startswith("domainkey_"):
                    apex = base[len("domainkey_") :].replace("_", ".")
                elif base.startswith("K"):
                    apex = base[1:].replace("_", ".")
                else:
                    continue
                zone_n = dns_names.normalize_name(apex)
                discovered.append((zone_n, key_type, path))

        for zone_n, key_type, path in discovered:
            sid = f"{zone_n}-{key_type}"
            if sid in self._records:
                continue
            try:
                pem = _read_bytes(path)
            except Exception as exc:
                logger.warning("Failed reading DNSSEC key %s: %s", path, exc)
                continue
            self._records[sid] = SecretRecord(
                id=sid,
                kind="dnssec",
                backend_id=self.backend_id,
                zone=zone_n,
                key_type=key_type,
                private_key_pem=pem,
                algorithm="ECDSAP256SHA256",
            )

    def validate_connection(self) -> bool:
        """Brief: Return True when catalog paths are readable enough to use.

        Inputs:
          - None.

        Outputs:
          - bool: False only when keys_dir was configured but missing.
        """

        if self._keys_dir is not None and not self._keys_dir.exists():
            # Directory may be created on generate; warn but allow maybe/yes.
            logger.debug("secrets keys_dir %s does not exist yet", self._keys_dir)
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
        # Return a shallow copy so callers can set backend_id safely.
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
        """Brief: Persist a secret into the in-memory catalog and optional keys_dir.

        Inputs:
          - record: SecretRecord to store.

        Outputs:
          - None.

        Notes:
          - DNSSEC keys are also written under keys_dir when configured.
        """

        if not self._writable:
            raise RuntimeError("FileSecrets backend is read-only")

        sid = str(record.id).strip()
        if not sid:
            raise ValueError("SecretRecord.id is required for put()")

        stored = SecretRecord(
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
        self._records[sid] = stored

        if (
            stored.kind == "dnssec"
            and self._keys_dir is not None
            and stored.private_key_pem
            and stored.zone
            and stored.key_type
        ):
            self._keys_dir.mkdir(parents=True, exist_ok=True)
            sanitized = _sanitize_zone_name(stored.zone)
            key_path = self._keys_dir / f"domainkey_{sanitized}.{stored.key_type}.key"
            key_path.write_bytes(stored.private_key_pem)
            try:
                key_path.chmod(0o600)
            except Exception:
                pass

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
        if self._keys_dir is not None:
            zones = cfg.get("zones")
            zone_list = (
                [str(z) for z in zones if str(z).strip()]
                if isinstance(zones, list)
                else None
            )
            self._index_keys_dir(self._keys_dir, zones=zone_list)
