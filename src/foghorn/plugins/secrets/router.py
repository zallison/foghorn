"""Process-wide multi-backend secrets router.

Brief:
  Holds named SecretsStore instances loaded from secrets.backends[] and
  resolves consumer refs across backends (explicit backend or unique id).

Inputs:
  - load_secrets_router(cfg) builds from top-level secrets config.

Outputs:
  - SecretsRouter with get/list/tsig/dnssec helpers and lifecycle methods.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import SecretRecord, SecretsStore
from .registry import get_secrets_backend_class

logger = logging.getLogger(__name__)

# Process-wide router installed at startup (optional).
_ACTIVE_ROUTER: SecretsRouter | None = None


def get_active_secrets_router() -> SecretsRouter | None:
    """Brief: Return the process-wide secrets router when installed.

    Inputs:
      - None.

    Outputs:
      - SecretsRouter or None.
    """

    return _ACTIVE_ROUTER


def set_active_secrets_router(router: SecretsRouter | None) -> None:
    """Brief: Install or clear the process-wide secrets router.

    Inputs:
      - router: SecretsRouter instance or None to clear.

    Outputs:
      - None.
    """

    global _ACTIVE_ROUTER
    _ACTIVE_ROUTER = router


class SecretsRouter:
    """Brief: Resolve secret refs across multiple named backends.

    Inputs (constructor):
      - backends: Mapping of backend_id -> SecretsStore.

    Outputs:
      - Router API used by TSIG/TLS/token/DNSSEC consumers.
    """

    def __init__(self, backends: dict[str, SecretsStore] | None = None) -> None:
        """Brief: Initialize router with an optional backend map.

        Inputs:
          - backends: Mapping of backend id to store instance.

        Outputs:
          - None.
        """

        self._backends: dict[str, SecretsStore] = {}
        for bid, store in (backends or {}).items():
            self.add_backend(str(bid), store)

    def add_backend(self, backend_id: str, store: SecretsStore) -> None:
        """Brief: Register a backend under a stable id.

        Inputs:
          - backend_id: Unique backend instance id.
          - store: SecretsStore instance.

        Outputs:
          - None.
        """

        bid = str(backend_id).strip()
        if not bid:
            raise ValueError("secrets backend id must be a non-empty string")
        if bid in self._backends:
            raise ValueError(f"duplicate secrets backend id {bid!r}")
        store.backend_id = bid
        self._backends[bid] = store

    @property
    def backend_ids(self) -> list[str]:
        """Brief: Return ordered backend ids.

        Inputs:
          - None.

        Outputs:
          - list[str] of backend ids.
        """

        return list(self._backends.keys())

    def get_backend(self, backend_id: str) -> SecretsStore | None:
        """Brief: Return a backend by id.

        Inputs:
          - backend_id: Backend instance id.

        Outputs:
          - SecretsStore or None.
        """

        return self._backends.get(str(backend_id).strip())

    def resolve_ref(
        self,
        ref: object,
        *,
        require: bool = False,
    ) -> SecretRecord | None:
        """Brief: Resolve a consumer secret reference to a SecretRecord.

        Inputs:
          - ref: Mapping that selects a backend and a lookup key:
              * preferred: {id|backend: <backend>, key: <secret-key>}
              * also accepted: {backend: <backend>, id: <secret-key>} (legacy)
              * multi-key TSIG sources use key/keys separately (see
                get_tsig_keys_from_source).
            Bare strings are rejected for consumer refs (use id+key).
          - require: When True, raise on miss/invalid shape.

        Outputs:
          - SecretRecord or None when not require and missing.

        Example:
          >>> router.resolve_ref({"id": "admin-tls", "key": "server1-cert"})
        """

        backend_id: str | None = None
        secret_key: str | None = None

        if isinstance(ref, str):
            # Consumer refs must name backend/id and key explicitly.
            if require:
                raise ValueError(
                    "secret ref must be a mapping with backend/id and key "
                    f"(got bare string {ref!r})"
                )
            return None

        if not isinstance(ref, dict):
            if require:
                raise TypeError(f"invalid secret ref type: {type(ref).__name__}")
            return None

        backend_raw = ref.get("backend") or ref.get("store")
        if backend_raw is not None and str(backend_raw).strip():
            backend_id = str(backend_raw).strip()

        # Preferred lookup field is `key` (secret identifier within a backend).
        key_raw = ref.get("key")
        if key_raw is None:
            key_raw = ref.get("secret_key")
        if key_raw is not None and str(key_raw).strip():
            secret_key = str(key_raw).strip()

        id_raw = ref.get("id")
        id_s = str(id_raw).strip() if id_raw is not None else ""

        if secret_key is not None:
            # {id|backend: backend, key: secret} — id names the backend.
            if backend_id is None and id_s:
                backend_id = id_s
        else:
            # No key= provided.
            if backend_id is not None and id_s:
                # Legacy: {backend: backend, id: secret-key}.
                secret_key = id_s
            elif backend_id is None and id_s:
                # {id: backend} without key — backend known, key missing.
                backend_id = id_s
            elif ref.get("secret") is not None and str(ref.get("secret")).strip():
                secret_key = str(ref.get("secret")).strip()
            elif ref.get("secret_id") is not None and str(ref.get("secret_id")).strip():
                secret_key = str(ref.get("secret_id")).strip()

        if not secret_key:
            if require:
                raise ValueError(
                    "secret ref missing key (expected {id|backend, key: <name>})"
                )
            return None

        if not backend_id:
            if require:
                raise ValueError(
                    "secret ref missing backend/id (expected {id|backend, key: <name>})"
                )
            return None

        store = self._backends.get(backend_id)
        if store is None:
            if require:
                raise KeyError(f"unknown secrets backend {backend_id!r}")
            return None
        rec = store.get(secret_key)
        if rec is None:
            if require:
                raise KeyError(
                    f"secret key {secret_key!r} not found in backend {backend_id!r}"
                )
            return None
        rec.backend_id = backend_id
        return rec

    def get(
        self,
        secret_key: str,
        *,
        backend: str | None = None,
        require: bool = False,
    ) -> SecretRecord | None:
        """Brief: Convenience wrapper around resolve_ref.

        Inputs:
          - secret_key: Secret lookup key within a backend.
          - backend: Backend id (required for consumer-style resolution).
          - require: Raise when missing/invalid.

        Outputs:
          - SecretRecord or None.
        """

        if not backend:
            # Internal convenience: unique key search across backends.
            matches: list[SecretRecord] = []
            for bid, store in self._backends.items():
                rec = store.get(str(secret_key))
                if rec is None:
                    continue
                rec.backend_id = bid
                matches.append(rec)
            if not matches:
                if require:
                    raise KeyError(
                        f"secret key {secret_key!r} not found in any backend"
                    )
                return None
            if len(matches) > 1:
                owners = sorted({m.backend_id or "?" for m in matches})
                raise ValueError(
                    f"secret key {secret_key!r} is ambiguous across backends: "
                    f"{owners}; specify backend/id explicitly"
                )
            return matches[0]

        ref: dict[str, str] = {
            "backend": str(backend),
            "key": str(secret_key),
        }
        return self.resolve_ref(ref, require=require)

    def list(
        self,
        *,
        kind: str | None = None,
        backend: str | None = None,
    ) -> list[SecretRecord]:
        """Brief: List secrets across one or all backends.

        Inputs:
          - kind: Optional kind filter.
          - backend: Optional single backend id.

        Outputs:
          - list[SecretRecord].
        """

        out: list[SecretRecord] = []
        if backend:
            store = self._backends.get(str(backend).strip())
            if store is None:
                return []
            for rec in store.list(kind=kind):
                rec.backend_id = store.backend_id
                out.append(rec)
            return out
        for bid, store in self._backends.items():
            for rec in store.list(kind=kind):
                rec.backend_id = bid
                out.append(rec)
        return out

    def get_tsig_keys_from_source(self, source: dict) -> list[dict[str, Any]]:
        """Brief: Load TSIG key dicts for a key_sources entry of type secrets.

        Inputs:
          - source: Mapping selecting backend and secret keys:
              * backend or id: secrets backend instance id (required)
              * key / keys: secret lookup key(s) within that backend
              * kind: optional filter when listing all tsig in the backend

        Outputs:
          - list of TSIG key config dicts.

        Example:
          {type: secrets, id: tsig-db, key: dyn-key-1}
          {type: secrets, backend: tsig-db, keys: [k1, k2]}
        """

        if not isinstance(source, dict):
            return []

        backend_raw = source.get("backend") or source.get("store")
        backend_id_s = str(backend_raw).strip() if backend_raw is not None else ""

        # Collect secret lookup keys.
        secret_keys: list[str] = []
        if source.get("key") is not None and str(source.get("key")).strip():
            secret_keys.append(str(source.get("key")).strip())
        raw_keys = source.get("keys")
        if isinstance(raw_keys, list):
            secret_keys.extend(str(x).strip() for x in raw_keys if str(x).strip())

        # When key/keys present, `id` names the backend.
        # Legacy without key: `id`/`ids` are secret keys and `backend` is required.
        id_raw = source.get("id")
        id_s = str(id_raw).strip() if id_raw is not None else ""
        if secret_keys:
            if not backend_id_s and id_s:
                backend_id_s = id_s
        else:
            if id_s:
                secret_keys.append(id_s)
            raw_ids = source.get("ids")
            if isinstance(raw_ids, list):
                secret_keys.extend(str(x).strip() for x in raw_ids if str(x).strip())

        secret_keys = [k for k in secret_keys if k]
        kind = str(source.get("kind") or "tsig").strip().lower() or "tsig"

        if not backend_id_s:
            logger.warning(
                "TSIG key source type=secrets requires backend or id "
                "(backend instance id)"
            )
            return []

        store = self._backends.get(backend_id_s)
        if store is None:
            logger.warning("TSIG key source secrets backend %r not found", backend_id_s)
            return []
        return store.get_tsig_keys(
            secret_ids=secret_keys or None,
            kind=None if secret_keys else kind,
        )

    def get_dnssec_keys(
        self,
        zone: str,
        *,
        backend: str | None = None,
        ksk_id: str | None = None,
        zsk_id: str | None = None,
    ) -> tuple[SecretRecord | None, SecretRecord | None]:
        """Brief: Resolve DNSSEC KSK/ZSK for a zone from secrets backends.

        Inputs:
          - zone: Zone apex.
          - backend: Optional backend id to search.
          - ksk_id / zsk_id: Optional explicit secret ids.

        Outputs:
          - (ksk_record_or_None, zsk_record_or_None).
        """

        if backend:
            store = self._backends.get(str(backend).strip())
            if store is None:
                return None, None
            return store.get_dnssec_keys_for_zone(zone, ksk_id=ksk_id, zsk_id=zsk_id)

        # Prefer explicit ids via global resolve when provided.
        ksk: SecretRecord | None = None
        zsk: SecretRecord | None = None
        if ksk_id:
            try:
                ksk = self.get(str(ksk_id), require=False)
            except Exception:
                ksk = None
        if zsk_id:
            try:
                zsk = self.get(str(zsk_id), require=False)
            except Exception:
                zsk = None
        if ksk is not None and zsk is not None:
            return ksk, zsk

        for store in self._backends.values():
            found_ksk, found_zsk = store.get_dnssec_keys_for_zone(
                zone,
                ksk_id=None if ksk is not None else ksk_id,
                zsk_id=None if zsk is not None else zsk_id,
            )
            if ksk is None:
                ksk = found_ksk
            if zsk is None:
                zsk = found_zsk
            if ksk is not None and zsk is not None:
                break
        return ksk, zsk

    def put(self, record: SecretRecord, *, backend: str | None = None) -> None:
        """Brief: Persist a secret into a writable backend.

        Inputs:
          - record: SecretRecord to store.
          - backend: Target backend id (required when more than one backend).

        Outputs:
          - None.
        """

        bid = backend or record.backend_id
        if not bid:
            if len(self._backends) == 1:
                bid = next(iter(self._backends))
            else:
                raise ValueError("put() requires backend when multiple backends exist")
        store = self._backends.get(str(bid))
        if store is None:
            raise KeyError(f"unknown secrets backend {bid!r}")
        store.put(record)

    def validate_all(self) -> dict[str, bool]:
        """Brief: Probe every backend connectivity.

        Inputs:
          - None.

        Outputs:
          - Mapping backend_id -> ok bool.
        """

        results: dict[str, bool] = {}
        for bid, store in self._backends.items():
            try:
                results[bid] = bool(store.validate_connection())
            except Exception:
                logger.warning(
                    "secrets backend %s validate_connection raised",
                    bid,
                    exc_info=True,
                )
                results[bid] = False
        return results

    def reload_all(self) -> None:
        """Brief: Reload every backend.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        for bid, store in self._backends.items():
            try:
                store.reload()
            except Exception:
                logger.warning("secrets backend %s reload failed", bid, exc_info=True)

    def close_all(self) -> None:
        """Brief: Close every backend.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        for bid, store in self._backends.items():
            try:
                store.close()
            except Exception:
                logger.warning("secrets backend %s close failed", bid, exc_info=True)


def _normalize_backend_id(raw: object, *, module: str, index: int) -> str:
    """Brief: Derive a stable backend id from config entry fields.

    Inputs:
      - raw: Explicit id/name value or None.
      - module: Backend module alias.
      - index: Position in backends list.

    Outputs:
      - Non-empty backend id string.
    """

    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    base = str(module or "secrets").strip() or "secrets"
    if index == 0:
        return base
    return f"{base}{index + 1}"


def load_secrets_router(secrets_cfg: object | None) -> SecretsRouter | None:
    """Brief: Build a SecretsRouter from top-level secrets config.

    Inputs:
      - secrets_cfg: Mapping with backends list, or None.

    Outputs:
      - SecretsRouter when backends are configured; None when absent/empty.

    Example:
      secrets:
        backends:
          - id: local-files
            module: file
            config: { entries: [...] }
    """

    if not isinstance(secrets_cfg, dict):
        return None

    backends_cfg = secrets_cfg.get("backends")
    if not isinstance(backends_cfg, list) or not backends_cfg:
        # Allow single-backend shorthand: secrets.module + secrets.config
        module = secrets_cfg.get("module")
        if not module:
            return None
        backends_cfg = [
            {
                "id": secrets_cfg.get("id") or secrets_cfg.get("name") or str(module),
                "module": module,
                "config": (
                    secrets_cfg.get("config")
                    if isinstance(secrets_cfg.get("config"), dict)
                    else {}
                ),
                "abort_on_failure": secrets_cfg.get("abort_on_failure"),
            }
        ]

    router = SecretsRouter()
    for index, entry in enumerate(backends_cfg):
        if not isinstance(entry, dict):
            continue
        module = entry.get("module") or entry.get("backend") or entry.get("type")
        if not module:
            logger.warning("secrets.backends[%d] missing module; skipping", index)
            continue
        module_s = str(module).strip()
        bid = _normalize_backend_id(
            entry.get("id") or entry.get("name"),
            module=module_s,
            index=index,
        )
        conf = entry.get("config")
        if not isinstance(conf, dict):
            conf = {
                k: v
                for k, v in entry.items()
                if k
                not in {
                    "id",
                    "name",
                    "module",
                    "backend",
                    "type",
                    "config",
                    "abort_on_failure",
                    "abort_on_fail",
                    "comment",
                    "enabled",
                }
            }

        abort = entry.get("abort_on_failure", entry.get("abort_on_fail", True))
        try:
            cls = get_secrets_backend_class(module_s)
            store = cls(**dict(conf))
            router.add_backend(bid, store)
        except Exception as exc:
            if abort:
                raise RuntimeError(
                    f"secrets backend {bid!r} (module={module_s}) failed to initialize: {exc}"
                ) from exc
            logger.warning(
                "secrets backend %s failed to initialize; continuing: %s",
                bid,
                exc,
                exc_info=True,
            )
            continue

        # Per-backend connectivity probe at load time when abort requested.
        try:
            ok = bool(store.validate_connection())
        except Exception as exc:
            ok = False
            if abort:
                raise RuntimeError(
                    f"secrets backend {bid!r} validate_connection failed: {exc}"
                ) from exc
            logger.warning(
                "secrets backend %s validate_connection failed; continuing: %s",
                bid,
                exc,
            )
        if not ok and abort:
            raise RuntimeError(
                f"secrets backend {bid!r} failed validate_connection probe"
            )
        if not ok:
            logger.warning(
                "secrets backend %s failed validate_connection; continuing", bid
            )

    if not router.backend_ids:
        return None
    return router
