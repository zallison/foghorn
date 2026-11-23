"""Abstract base for secrets backends.

Brief:
  Defines SecretRecord kinds and the SecretsStore interface used by file,
  MySQL, and future secret backends. Concrete stores are discovered via
  registry aliases (same pattern as cache/querylog plugins).

Inputs:
  - Backend constructors take free-form config mappings from secrets.backends[].

Outputs:
  - SecretRecord / SecretsStore types and secret_aliases decorator.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

SECRET_KINDS = frozenset({"tls", "tsig", "token", "dnssec", "gnupg"})


def secret_aliases(*aliases: str):
    """Brief: Decorator to set discovery aliases on a SecretsStore subclass.

    Inputs:
      - *aliases: Variable number of alias strings.

    Outputs:
      - Callable that applies aliases to a SecretsStore subclass and returns it.
    """

    def _wrap(cls: type) -> type:
        cls.aliases = tuple(aliases)
        return cls

    return _wrap


@dataclass
class SecretRecord:
    """Brief: One named secret retrieved from a backend.

    Inputs (fields):
      - id: Secret id within the backend.
      - kind: tls | tsig | token | dnssec | gnupg.
      - backend_id: Owning backend instance id (set by router when known).
      - Kind-specific optional fields (tls PEMs, tsig name/secret, etc.).
      - meta: Optional free-form metadata (never logged as secrets).

    Outputs:
      - Immutable-ish record; callers must not log secret-bearing fields.
    """

    id: str
    kind: str
    backend_id: str | None = None
    # tls
    cert_pem: bytes | None = None
    key_pem: bytes | None = None
    ca_pem: bytes | None = None
    # Optional original filesystem paths (file backend); preferred over temp PEMs.
    cert_path: str | None = None
    key_path: str | None = None
    ca_path: str | None = None
    # tsig
    name: str | None = None
    algorithm: str | None = None
    secret: str | None = None
    # token
    token: str | None = None
    # dnssec
    zone: str | None = None
    key_type: str | None = None  # ksk | zsk
    private_key_pem: bytes | None = None
    # opaque extras (scopes, allow lists, etc. for tsig keys)
    extra: dict[str, Any] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)

    def as_tsig_key_dict(self) -> dict[str, Any]:
        """Brief: Project this record into a TSIG key config dict.

        Inputs:
          - None (uses self).

        Outputs:
          - dict with name/secret/algorithm plus any extra allow/block fields.
        """

        out: dict[str, Any] = dict(self.extra or {})
        if self.name:
            out["name"] = self.name
        if self.secret is not None:
            out["secret"] = self.secret
        out["algorithm"] = self.algorithm or "hmac-sha256"
        return out


class SecretsStore:
    """Brief: Base class for a single secrets backend instance.

    Inputs:
      - Subclasses accept backend-specific **config in __init__.

    Outputs:
      - SecretsStore interface for get/list/put/validate/reload/close.

    Notes:
      - Process-wide multi-backend resolution is handled by SecretsRouter.
    """

    aliases: tuple[str, ...] = ()

    def __init__(self, **config: object) -> None:
        """Brief: Initialize with backend-specific configuration.

        Inputs:
          - **config: Free-form backend options from secrets.backends[].config.

        Outputs:
          - None in base; subclasses perform setup.
        """

        self.backend_id: str | None = None
        self._config = dict(config)

    def validate_connection(self) -> bool:
        """Brief: Return True when the backend is usable.

        Inputs:
          - None.

        Outputs:
          - bool: True when probe succeeds (file paths ok / DB reachable).
        """

        raise NotImplementedError(
            "SecretsStore.validate_connection() must be implemented"
        )

    def get(self, secret_id: str) -> SecretRecord | None:
        """Brief: Fetch one secret by id within this backend.

        Inputs:
          - secret_id: Secret identifier.

        Outputs:
          - SecretRecord or None when missing.
        """

        raise NotImplementedError("SecretsStore.get() must be implemented")

    def list(self, kind: str | None = None) -> list[SecretRecord]:
        """Brief: List secrets, optionally filtered by kind.

        Inputs:
          - kind: Optional kind filter (tls/tsig/token/dnssec/gnupg).

        Outputs:
          - list[SecretRecord] (may omit secret material for some backends).
        """

        raise NotImplementedError("SecretsStore.list() must be implemented")

    def put(self, record: SecretRecord) -> None:
        """Brief: Persist or replace a secret (writable backends).

        Inputs:
          - record: SecretRecord to store.

        Outputs:
          - None.

        Raises:
          - NotImplementedError when the backend is read-only.
        """

        raise NotImplementedError(f"{type(self).__name__} does not support put()")

    def reload(self) -> None:
        """Brief: Refresh cached material from the underlying store.

        Inputs:
          - None.

        Outputs:
          - NotImplementedError when reload is called.
        """
        raise NotImplementedError("SecretsStore.re;pad() must be implemented")

    def close(self) -> None:
        """Brief: Release backend resources.

        Inputs:
          - None.

        Outputs:
          - None; default is a no-op.
        """

        return

    def get_tsig_keys(
        self,
        *,
        secret_ids: Sequence[str] | None = None,
        kind: str | None = "tsig",
    ) -> list[dict[str, Any]]:
        """Brief: Return TSIG key dicts from this backend.

        Inputs:
          - secret_ids: Optional explicit ids; when None, list by kind.
          - kind: Kind filter when listing (default tsig).

        Outputs:
          - list of TSIG key config dicts (name/secret/algorithm/...).
        """

        records: list[SecretRecord] = []
        if secret_ids:
            for sid in secret_ids:
                rec = self.get(str(sid))
                if rec is not None:
                    records.append(rec)
        else:
            records = self.list(kind=kind)
        out: list[dict[str, Any]] = []
        for rec in records:
            if str(rec.kind).lower() != "tsig":
                continue
            key = rec.as_tsig_key_dict()
            if key.get("name") and key.get("secret"):
                out.append(key)
        return out

    def get_dnssec_keys_for_zone(
        self,
        zone: str,
        *,
        ksk_id: str | None = None,
        zsk_id: str | None = None,
    ) -> tuple[SecretRecord | None, SecretRecord | None]:
        """Brief: Resolve KSK/ZSK records for a zone.

        Inputs:
          - zone: Zone apex (with or without trailing dot).
          - ksk_id / zsk_id: Optional explicit secret ids.

        Outputs:
          - (ksk_record_or_None, zsk_record_or_None).
        """

        from foghorn.utils import dns_names

        zone_n = dns_names.normalize_name(zone)

        def _match(rec: SecretRecord, key_type: str) -> bool:
            if str(rec.kind).lower() != "dnssec":
                return False
            if str(rec.key_type or "").lower() != key_type:
                return False
            rec_zone = dns_names.normalize_name(rec.zone or "")
            return rec_zone == zone_n

        ksk: SecretRecord | None = None
        zsk: SecretRecord | None = None
        if ksk_id:
            ksk = self.get(str(ksk_id))
        if zsk_id:
            zsk = self.get(str(zsk_id))
        if ksk is None or zsk is None:
            for rec in self.list(kind="dnssec"):
                if ksk is None and _match(rec, "ksk"):
                    ksk = rec
                if zsk is None and _match(rec, "zsk"):
                    zsk = rec
                if ksk is not None and zsk is not None:
                    break
        return ksk, zsk
