"""Secrets backend family (TLS, TSIG, tokens, DNSSEC keys).

Inputs:
  - Top-level secrets.backends[] configuration.

Outputs:
  - SecretsStore / SecretsRouter loaders and process-wide active router helpers.
"""

from __future__ import annotations

from .base import SECRET_KINDS, SecretRecord, SecretsStore, secret_aliases
from .registry import discover_secrets_backends, get_secrets_backend_class
from .router import (
    SecretsRouter,
    get_active_secrets_router,
    load_secrets_router,
    set_active_secrets_router,
)

__all__ = [
    "SECRET_KINDS",
    "SecretRecord",
    "SecretsRouter",
    "SecretsStore",
    "discover_secrets_backends",
    "get_active_secrets_router",
    "get_secrets_backend_class",
    "load_secrets_router",
    "secret_aliases",
    "set_active_secrets_router",
]
