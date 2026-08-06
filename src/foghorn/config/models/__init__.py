"""Pydantic configuration models for Foghorn (schema source of truth).

Inputs:
  - Imported by the schema generator and (optionally) tooling.

Outputs:
  - Re-exports of root and section models.
"""

from __future__ import annotations

from foghorn.config.models.plugins import PluginInstance
from foghorn.config.models.root import FoghornConfig
from foghorn.config.models.server import (
    DecoratedCacheOverride,
    ServerConfig,
)
from foghorn.config.models.upstreams import (
    UpstreamDoh,
    UpstreamHost,
    UpstreamsConfig,
    UpstreamUrl,
)

__all__ = [
    "DecoratedCacheOverride",
    "FoghornConfig",
    "PluginInstance",
    "ServerConfig",
    "UpstreamDoh",
    "UpstreamHost",
    "UpstreamUrl",
    "UpstreamsConfig",
]
